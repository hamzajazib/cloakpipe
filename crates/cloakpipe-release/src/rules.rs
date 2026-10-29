//! Per-tool rules of the v1 manifest beyond argument constraints: the
//! effect class, idempotency key templates, conditional approval (`when`)
//! and durations (`ttl`).
//!
//! Everything here is parsed when the manifest loads, so a malformed rule
//! stops the gate from starting instead of misbehaving on a live call.

use crate::contract::{child, cmp_number, Violation, ViolationCode};
use serde::Deserialize;
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// What a call does to the world (`effect:`). `side_effect: true` is `write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Read,
    Write,
    Irreversible,
}

impl Effect {
    /// Whether calls are operations (tracked, deduplicated).
    pub fn is_side_effect(self) -> bool {
        self != Effect::Read
    }
}

/// A tool's `approval:` block.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRule {
    /// `None`: every call needs approval.
    pub when: Option<Condition>,
    /// Free-form routing strings (`slack:#support-leads`) for an external
    /// broker; the gate reports them and never interprets them.
    pub approvers: Vec<String>,
    /// The longest validity window (`notAfter - approvedAt`) a receipt for
    /// this tool may carry, in seconds.
    pub ttl_secs: Option<u64>,
    /// `show`: the top-level arguments whose values an approval broker may
    /// see in a request, so a human can decide (default: none). Every
    /// other value stays on the gate's host.
    pub show: Vec<String>,
}

impl ApprovalRule {
    /// The values of a call's [`Self::show`] arguments that it carries
    /// (top level only; nothing for a call whose arguments are not an
    /// object). Scalar values only (string, number, boolean, null): an
    /// object or array value of an untyped argument is left out. No other
    /// value is ever in it.
    pub fn shown(&self, arguments: Option<&Value>) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        let Some(args) = arguments.and_then(Value::as_object) else { return out };
        for name in &self.show {
            if let Some(v) = args.get(name).filter(|v| !v.is_object() && !v.is_array()) {
                out.insert(name.clone(), v.clone());
            }
        }
        out
    }
}

/// Parse a duration: one or more `<digits><unit>` groups, units `d`, `h`,
/// `m`, `s` in that order, each at most once (`15m`, `1h30m`). Zero is refused.
pub fn parse_duration(src: &str) -> Result<u64, String> {
    let bad = || format!("invalid duration {src:?}: expected e.g. 30s, 15m, 1h30m, 1d");
    let units = [('d', 86_400u64), ('h', 3_600), ('m', 60), ('s', 1)];
    let mut next_unit = 0;
    let mut total: u64 = 0;
    let mut digits = String::new();
    for c in src.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let Some(i) = units.iter().position(|(u, _)| *u == c) else { return Err(bad()) };
        if digits.is_empty() || i < next_unit {
            return Err(bad());
        }
        let n: u64 = digits.parse().map_err(|_| bad())?;
        total = n.checked_mul(units[i].1).and_then(|v| total.checked_add(v)).ok_or_else(bad)?;
        digits.clear();
        next_unit = i + 1;
    }
    if !digits.is_empty() || total == 0 {
        return Err(bad());
    }
    Ok(total)
}

// ── idempotency key templates ────────────────────────────────────────────

/// `idempotency_key: "{ticket_id}:{sha256(body)}"`: literal text with
/// placeholders. `{a.b}` is the argument at that dotted path, `{task.k}` a
/// trusted task context value, and `{sha256(path)}` the lowercase hex
/// SHA-256 of the value. A string value renders as itself, any other value
/// as its RFC 8785 JSON encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKey {
    source: String,
    parts: Vec<Part>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Field { path: Vec<String>, task: bool, hashed: bool },
}

impl IdempotencyKey {
    pub fn parse(src: &str) -> Result<Self, String> {
        let bad = |why: &str| format!("invalid idempotency_key {src:?}: {why}");
        let mut parts = Vec::new();
        let mut rest = src;
        while !rest.is_empty() {
            match rest.find(['{', '}']) {
                Some(i) if rest.as_bytes()[i] == b'}' => return Err(bad("unmatched '}'")),
                Some(i) => {
                    if i > 0 {
                        parts.push(Part::Literal(rest[..i].to_string()));
                    }
                    let after = &rest[i + 1..];
                    let end = after.find('}').ok_or_else(|| bad("unclosed '{'"))?;
                    let inner = &after[..end];
                    if inner.contains('{') {
                        return Err(bad("nested '{'"));
                    }
                    let (path, hashed) = match inner.strip_prefix("sha256(").and_then(|p| p.strip_suffix(')')) {
                        Some(p) => (p, true),
                        None => (inner, false),
                    };
                    let segments: Vec<String> = path.split('.').map(str::to_string).collect();
                    let valid = |s: &String| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                    if !segments.iter().all(valid) {
                        return Err(bad("a placeholder must be {path} or {sha256(path)} over a dotted path"));
                    }
                    let task = segments.len() > 1 && segments[0] == "task";
                    let path = if task { segments[1..].to_vec() } else { segments };
                    parts.push(Part::Field { path, task, hashed });
                    rest = &after[end + 1..];
                }
                None => {
                    parts.push(Part::Literal(rest.to_string()));
                    rest = "";
                }
            }
        }
        if !parts.iter().any(|p| matches!(p, Part::Field { .. })) {
            return Err(bad("it needs at least one placeholder"));
        }
        Ok(IdempotencyKey { source: src.to_string(), parts })
    }

    /// The template as written.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The first segment of every argument placeholder (task placeholders
    /// excluded): each must be a declared argument.
    pub fn argument_roots(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|p| match p {
            Part::Field { path, task: false, .. } => path.first().map(String::as_str),
            _ => None,
        })
    }

    /// Render the key for one call. A missing argument is `argument_missing`
    /// at its path; a missing task value is `task_context_missing`.
    pub fn render(&self, arguments: Option<&Value>, task: Option<&Value>) -> Result<String, Violation> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Literal(s) => out.push_str(s),
                Part::Field { path, task: from_task, hashed } => {
                    let value = if *from_task {
                        lookup(task, path).ok_or(Violation { code: ViolationCode::TaskContextMissing, path: None })?
                    } else {
                        lookup(arguments, path).ok_or_else(|| Violation {
                            code: ViolationCode::ArgumentMissing,
                            path: Some(path.iter().fold(String::new(), |p, s| child(&p, s))),
                        })?
                    };
                    let text = match value {
                        Value::String(s) => s.clone(),
                        other => serde_json_canonicalizer::to_string(other).expect("a JSON value encodes"),
                    };
                    if *hashed {
                        out.push_str(&hex::encode(Sha256::digest(text.as_bytes())));
                    } else {
                        out.push_str(&text);
                    }
                }
            }
        }
        Ok(out)
    }
}

fn lookup<'a>(root: Option<&'a Value>, path: &[String]) -> Option<&'a Value> {
    let mut v = root?;
    for s in path {
        v = v.as_object()?.get(s)?;
    }
    Some(v)
}

// ── the `when` condition language ────────────────────────────────────────

/// `approval.when`: comparisons `path OP literal` (OP one of `>`, `>=`, `<`,
/// `<=`, `==`, `!=`; literal a number, a quoted string or `true`/`false`)
/// joined by `&&` and `||` (`&&` binds tighter) with parentheses. `path` is
/// a dotted path into the call's arguments. Ordering operators take number
/// literals only.
///
/// Evaluation is total and fails closed: every comparison is evaluated (no
/// short-circuit), and if any one meets a missing value or a value of
/// another type than its literal, the condition holds, so approval is
/// required.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    source: String,
    expr: Expr,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Cmp { path: Vec<String>, op: Op, literal: Literal },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

#[derive(Debug, Clone, PartialEq)]
enum Literal {
    Number(Number),
    String(String),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Path(Vec<String>),
    Lit(Literal),
    Op(Op),
    And,
    Or,
    Open,
    Close,
}

fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let two = b.get(i + 1).copied();
        match c {
            b' ' | b'\t' => i += 1,
            b'(' => {
                out.push(Token::Open);
                i += 1;
            }
            b')' => {
                out.push(Token::Close);
                i += 1;
            }
            b'&' if two == Some(b'&') => {
                out.push(Token::And);
                i += 2;
            }
            b'|' if two == Some(b'|') => {
                out.push(Token::Or);
                i += 2;
            }
            b'>' | b'<' | b'=' | b'!' => {
                let op = match (c, two) {
                    (b'>', Some(b'=')) => Op::Ge,
                    (b'<', Some(b'=')) => Op::Le,
                    (b'=', Some(b'=')) => Op::Eq,
                    (b'!', Some(b'=')) => Op::Ne,
                    (b'>', _) => Op::Gt,
                    (b'<', _) => Op::Lt,
                    _ => return Err(format!("unexpected {:?} at {i}", c as char)),
                };
                i += if matches!(op, Op::Gt | Op::Lt) { 1 } else { 2 };
                out.push(Token::Op(op));
            }
            b'\'' | b'"' => {
                let end = src[i + 1..].find(c as char).ok_or_else(|| format!("unterminated string at {i}"))?;
                out.push(Token::Lit(Literal::String(src[i + 1..i + 1 + end].to_string())));
                i += end + 2;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                i += 1;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    i += 1;
                }
                let text = &src[start..i];
                let valid = {
                    let digits = text.strip_prefix('-').unwrap_or(text);
                    let (int, frac) = digits.split_once('.').map_or((digits, None), |(a, f)| (a, Some(f)));
                    !int.is_empty()
                        && int.bytes().all(|d| d.is_ascii_digit())
                        && frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|d| d.is_ascii_digit()))
                };
                let n: Option<Number> = valid.then(|| serde_json::from_str(text).ok()).flatten();
                out.push(Token::Lit(Literal::Number(n.ok_or_else(|| format!("invalid number {text:?}"))?)));
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                    i += 1;
                }
                let word = &src[start..i];
                out.push(match word {
                    "true" => Token::Lit(Literal::Bool(true)),
                    "false" => Token::Lit(Literal::Bool(false)),
                    _ => {
                        let path: Vec<String> = word.split('.').map(str::to_string).collect();
                        if path.iter().any(String::is_empty) {
                            return Err(format!("invalid path {word:?}"));
                        }
                        Token::Path(path)
                    }
                });
            }
            _ => return Err(format!("unexpected {:?} at {i}", c as char)),
        }
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

impl Parser {
    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.at).cloned();
        self.at += 1;
        t
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut left = self.and()?;
        while self.peek() == Some(&Token::Or) {
            self.at += 1;
            left = Expr::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut left = self.atom()?;
        while self.peek() == Some(&Token::And) {
            self.at += 1;
            left = Expr::And(Box::new(left), Box::new(self.atom()?));
        }
        Ok(left)
    }

    fn atom(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Token::Open) => {
                let e = self.or()?;
                match self.next() {
                    Some(Token::Close) => Ok(e),
                    _ => Err("expected ')'".into()),
                }
            }
            Some(Token::Path(path)) => {
                let Some(Token::Op(op)) = self.next() else { return Err("expected a comparison operator after a path".into()) };
                let Some(Token::Lit(literal)) = self.next() else { return Err("expected a literal after the operator".into()) };
                if matches!(op, Op::Gt | Op::Ge | Op::Lt | Op::Le) && !matches!(literal, Literal::Number(_)) {
                    return Err("<, <=, > and >= compare numbers only".into());
                }
                Ok(Expr::Cmp { path, op, literal })
            }
            _ => Err("expected a comparison `path OP literal` or '('".into()),
        }
    }
}

impl Condition {
    pub fn parse(src: &str) -> Result<Self, String> {
        let bad = |why: String| format!("invalid condition {src:?}: {why}");
        let mut p = Parser { tokens: tokenize(src).map_err(bad)?, at: 0 };
        let expr = p.or().map_err(bad)?;
        if p.at != p.tokens.len() {
            return Err(bad("unexpected trailing input".into()));
        }
        Ok(Condition { source: src.to_string(), expr })
    }

    /// The condition as written.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The first segment of every path: each must be a declared argument.
    pub fn argument_roots(&self) -> Vec<&str> {
        fn walk<'a>(e: &'a Expr, out: &mut Vec<&'a str>) {
            match e {
                Expr::Or(a, b) | Expr::And(a, b) => {
                    walk(a, out);
                    walk(b, out);
                }
                Expr::Cmp { path, .. } => out.extend(path.first().map(String::as_str)),
            }
        }
        let mut out = Vec::new();
        walk(&self.expr, &mut out);
        out
    }

    /// Whether the condition holds for these arguments (see the type docs:
    /// an evaluation error counts as holding).
    pub fn matches(&self, arguments: &Value) -> bool {
        eval(&self.expr, arguments).unwrap_or(true)
    }
}

fn eval(e: &Expr, args: &Value) -> Result<bool, ()> {
    match e {
        // Both sides always: an error anywhere fails closed.
        Expr::Or(a, b) => {
            let (x, y) = (eval(a, args), eval(b, args));
            Ok(x? | y?)
        }
        Expr::And(a, b) => {
            let (x, y) = (eval(a, args), eval(b, args));
            Ok(x? & y?)
        }
        Expr::Cmp { path, op, literal } => {
            let v = lookup(Some(args), path).ok_or(())?;
            let ord = match (literal, v) {
                (Literal::Number(n), Value::Number(m)) => cmp_number(m, n).ok_or(())?,
                (Literal::String(s), Value::String(t)) => t.as_str().cmp(s.as_str()),
                (Literal::Bool(x), Value::Bool(y)) => y.cmp(x),
                _ => return Err(()),
            };
            Ok(match op {
                Op::Gt => ord == Ordering::Greater,
                Op::Ge => ord != Ordering::Less,
                Op::Lt => ord == Ordering::Less,
                Op::Le => ord != Ordering::Greater,
                Op::Eq => ord == Ordering::Equal,
                Op::Ne => ord != Ordering::Equal,
            })
        }
    }
}
