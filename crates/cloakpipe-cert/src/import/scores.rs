//! Shared machinery of the score-based importers: a JSON value that keeps
//! duplicate object keys, and turning per-case scores into a [`CaseResult`].

use super::ImportError;
use crate::model::{CaseResult, CaseStatus};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// How scores become a case status (see the module docs of `import`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreRules {
    /// A case passes iff every score is `>=` this; must be finite and within
    /// `0..=1`. Default `0.5`.
    pub pass_threshold: f64,
}

impl Default for ScoreRules {
    fn default() -> Self {
        ScoreRules { pass_threshold: 0.5 }
    }
}

impl ScoreRules {
    /// Problems with the rules themselves.
    pub(super) fn issues(&self) -> Vec<String> {
        let t = self.pass_threshold;
        if t.is_finite() && (0.0..=1.0).contains(&t) {
            Vec::new()
        } else {
            vec![format!("pass threshold {t} must be a finite number within 0..=1")]
        }
    }
}

/// A parsed JSON value that, unlike `serde_json::Value`, keeps every entry
/// of an object, so duplicate keys can be detected instead of silently
/// resolved to the last one.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub(super) fn parse(json: &str) -> Result<J, serde_json::Error> {
        serde_json::from_str(json.strip_prefix('\u{feff}').unwrap_or(json))
    }

    /// The JSON type name, for messages.
    pub(super) fn kind(&self) -> &'static str {
        match self {
            J::Null => "null",
            J::Bool(_) => "a bool",
            J::Num(_) => "a number",
            J::Str(_) => "a string",
            J::Arr(_) => "an array",
            J::Obj(_) => "an object",
        }
    }

    /// The value of `key` when `self` is an object and `key` is present and
    /// not `null`. A key given more than once is an error; `None` for any
    /// non-object.
    pub(super) fn get(&self, key: &str) -> Result<Option<&J>, String> {
        let J::Obj(entries) = self else {
            return Ok(None);
        };
        let mut found = entries.iter().filter(|(k, _)| k == key).map(|(_, v)| v);
        match (found.next(), found.next()) {
            (Some(_), Some(_)) => Err(format!("duplicate key {key:?}")),
            (Some(J::Null), None) | (None, _) => Ok(None),
            (Some(v), None) => Ok(Some(v)),
        }
    }

    /// `true` for `null`, `""`, `[]` and `{}`.
    pub(super) fn is_empty(&self) -> bool {
        match self {
            J::Null => true,
            J::Str(s) => s.is_empty(),
            J::Arr(v) => v.is_empty(),
            J::Obj(v) => v.is_empty(),
            J::Bool(_) | J::Num(_) => false,
        }
    }
}

impl<'de> Deserialize<'de> for J {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<J, D::Error> {
        d.deserialize_any(JVisitor)
    }
}

struct JVisitor;

impl<'de> Visitor<'de> for JVisitor {
    type Value = J;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<J, E> {
        Ok(J::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<J, E> {
        Ok(J::Num(v as f64))
    }
    fn visit_u64<E>(self, v: u64) -> Result<J, E> {
        Ok(J::Num(v as f64))
    }
    fn visit_f64<E>(self, v: f64) -> Result<J, E> {
        Ok(J::Num(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<J, E> {
        Ok(J::Str(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<J, E> {
        Ok(J::Str(v))
    }
    fn visit_unit<E>(self) -> Result<J, E> {
        Ok(J::Null)
    }
    fn visit_none<E>(self) -> Result<J, E> {
        Ok(J::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<J, D::Error> {
        J::deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<J, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element()? {
            out.push(v);
        }
        Ok(J::Arr(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<J, A::Error> {
        let mut out = Vec::new();
        while let Some(entry) = map.next_entry::<String, J>()? {
            out.push(entry);
        }
        Ok(J::Obj(out))
    }
}

/// A `serde_json::Error` carrying `msg`, for errors found outside serde_json
/// (e.g. a JSONL line number).
pub(super) fn json_error(msg: impl fmt::Display) -> ImportError {
    ImportError::Json(<serde_json::Error as de::Error>::custom(msg))
}

/// The scores collected for one case.
#[derive(Debug)]
pub(super) struct CaseScores {
    /// How the case is named in issues.
    who: String,
    names: BTreeSet<String>,
    values: BTreeMap<String, f64>,
}

impl CaseScores {
    pub(super) fn new(who: String) -> Self {
        CaseScores { who, names: BTreeSet::new(), values: BTreeMap::new() }
    }

    /// Note a score name; a name seen twice on one case is an issue, even
    /// if one occurrence carries no value.
    pub(super) fn name(&mut self, name: &str, issues: &mut Vec<String>) -> bool {
        if self.names.insert(name.to_string()) {
            true
        } else {
            issues.push(format!("{}: score {name:?} given more than once", self.who));
            false
        }
    }

    /// Record score `name` = `value` (call [`CaseScores::name`] first).
    pub(super) fn value(&mut self, name: &str, value: f64, issues: &mut Vec<String>) {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            self.values.insert(name.to_string(), value);
        } else {
            issues.push(format!("{}: score {name:?}: {value} is not within 0..=1", self.who));
        }
    }

    /// An issue about this case.
    pub(super) fn issue(&self, what: impl fmt::Display) -> String {
        format!("{}: {what}", self.who)
    }

    /// The case: `Error` on an explicit error or when nothing was scored
    /// (no evidence: fail closed), else `Pass` iff every score meets the
    /// threshold. `score` is the mean; each score is `metrics["score.<name>"]`.
    pub(super) fn into_case(
        self,
        id: String,
        critical: bool,
        error: bool,
        rules: &ScoreRules,
        mut metrics: BTreeMap<String, f64>,
        duration_ms: Option<u64>,
    ) -> CaseResult {
        let n = self.values.len();
        let score = (n > 0).then(|| self.values.values().sum::<f64>() / n as f64);
        let status = if error || n == 0 {
            CaseStatus::Error
        } else if self.values.values().all(|&s| s >= rules.pass_threshold) {
            CaseStatus::Pass
        } else {
            CaseStatus::Fail
        };
        for (name, v) in self.values {
            metrics.insert(format!("score.{name}"), v);
        }
        CaseResult { id, critical, status, score, metrics, duration_ms }
    }
}
