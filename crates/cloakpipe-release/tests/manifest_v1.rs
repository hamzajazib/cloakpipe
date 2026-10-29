//! The single-file v1 manifest (`cloakpipe.manifest.yaml`, `cloakpipe_release::v1`):
//! parsing, digests, the closed-by-default contract it compiles to,
//! `one_of_context`/`or_pattern`, idempotency key templates and conditional
//! approval.

use cloakpipe_release::contract::{Violation, ViolationCode};
use cloakpipe_release::v1::{detect, parse_duration, Condition, Effect, Manifest, ManifestKind};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/v1")
}

fn support() -> Manifest {
    Manifest::parse_path(&testdata().join("support.manifest.yaml")).unwrap()
}

/// Parse `src` with `testdata/v1` as the base directory.
fn parse(src: &str) -> Result<Manifest, String> {
    Manifest::parse_str(src, &testdata()).map_err(|e| e.to_string())
}

/// A manifest with one tool `t` whose declaration is `tool` (YAML flow).
fn one_tool(tool: &str) -> Result<Manifest, String> {
    parse(&format!("release: r\nversion: \"1\"\ntools:\n  t: {tool}\n"))
}

fn check(m: &Manifest, tool: &str, args: Value, task: Option<Value>) -> Result<(), (ViolationCode, Option<String>)> {
    m.rule(tool).expect("declared").check(Some(&args), task.as_ref()).map_err(|Violation { code, path }| (code, path))
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn task() -> Value {
    json!({"taskId": "t-1042", "ticket": {"id": "T-1042", "customer_email": "dana@customer.example"}})
}

// ── format and digests ───────────────────────────────────────────────────

#[test]
fn the_spec_example_parses() {
    let m = support();
    assert_eq!(m.release, "support-agent");
    assert_eq!(m.version, "2026.10.3");
    let tools: Vec<&str> = m.tools().keys().map(String::as_str).collect();
    assert_eq!(tools, ["issue_refund", "read_ticket", "send_email"]);
    let policy = m.policy.as_ref().expect("a policy");
    assert_eq!(policy.declared, "./policies/support.cedar");
    assert_eq!(policy.path, testdata().join("./policies/support.cedar"));
    assert_eq!(policy.source, std::fs::read(testdata().join("policies/support.cedar")).unwrap());
}

#[test]
fn the_manifest_digest_is_sha256_over_the_jcs_form() {
    let src = std::fs::read_to_string(testdata().join("support.manifest.yaml")).unwrap();
    let parsed: Value = serde_yaml::from_str(&src).unwrap();
    let jcs = serde_json_canonicalizer::to_vec(&parsed).unwrap();
    assert_eq!(support().digest().to_string(), format!("sha256:{}", sha256_hex(&jcs)));
}

#[test]
fn the_digest_ignores_formatting_but_not_content() {
    let a = parse("release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { type: string } } }\n").unwrap();
    let b = parse("# a comment\ntools:\n  t:\n    args:\n      x:\n        type: string\nversion: \"1\"\nrelease: r\n").unwrap();
    assert_eq!(a.digest(), b.digest(), "key order, flow style and comments are not content");
    let c = parse("release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { type: number } } }\n").unwrap();
    assert_ne!(a.digest(), c.digest());
    let d = parse("release: r\nversion: \"2\"\ntools:\n  t: { args: { x: { type: string } } }\n").unwrap();
    assert_ne!(a.digest(), d.digest(), "the version is part of the manifest");
}

#[test]
fn the_policy_digest_covers_the_policy_file_bytes() {
    let m = support();
    let bytes = std::fs::read(testdata().join("policies/support.cedar")).unwrap();
    assert_eq!(m.policy_digest().unwrap().to_string(), format!("sha256:{}", sha256_hex(&bytes)));
    // A policy change leaves the manifest digest alone: it is reported separately.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("policies")).unwrap();
    std::fs::copy(testdata().join("support.manifest.yaml"), dir.path().join("m.yaml")).unwrap();
    std::fs::write(dir.path().join("policies/support.cedar"), "forbid (principal, action, resource);\n").unwrap();
    let edited = Manifest::parse_path(&dir.path().join("m.yaml")).unwrap();
    assert_eq!(edited.digest(), m.digest());
    assert_ne!(edited.policy_digest(), m.policy_digest());
}

#[test]
fn a_manifest_without_policy_or_tools_is_valid_and_declares_nothing() {
    let m = Manifest::parse_path(&testdata().join("minimal.manifest.yaml")).unwrap();
    assert!(m.policy.is_none() && m.policy_digest().is_none());
    assert!(m.tools().is_empty());
    assert!(m.rule("anything").is_none());
}

#[test]
fn a_numeric_version_is_read_as_written() {
    assert_eq!(parse("release: r\nversion: 3\n").unwrap().version, "3");
}

#[test]
fn format_detection() {
    assert_eq!(detect("release: r\nversion: \"1\"\n").unwrap(), ManifestKind::V1);
    assert_eq!(detect("apiVersion: cloakpipe.co/v1alpha1\nkind: AgentRelease\n").unwrap(), ManifestKind::Legacy);
    assert_eq!(detect("{\"apiVersion\": \"cloakpipe.co/v1alpha1\"}").unwrap(), ManifestKind::Legacy);
    for bad in ["kind: AgentRelease\n", "- a\n", "release: r\napiVersion: x\n", ": : :"] {
        assert!(detect(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn malformed_manifests_are_refused_at_load() {
    let cases = [
        ("missing release", "version: \"1\"\n"),
        ("missing version", "release: r\n"),
        ("empty release", "release: \"\"\nversion: \"1\"\n"),
        ("unknown top-level key", "release: r\nversion: \"1\"\ntoolz: {}\n"),
        ("duplicate key", "release: r\nversion: \"1\"\nversion: \"2\"\n"),
        ("missing policy file", "release: r\nversion: \"1\"\npolicy: ./policies/nope.cedar\n"),
        ("unknown tool key", "release: r\nversion: \"1\"\ntools:\n  t: { sideEffect: true }\n"),
        ("unknown constraint key", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { type: string, maxLength: 3 } } }\n"),
        ("null type", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { type: \"null\" } } }\n"),
        ("bad pattern", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { type: string, pattern: \"(\" } } }\n"),
        ("bad or_pattern", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { one_of_context: [a], or_pattern: \"(\" } } }\n"),
        ("or_pattern alone", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { type: string, or_pattern: \"x\" } } }\n"),
        ("empty context path", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { one_of_context: [\"a..b\"] } } }\n"),
        ("string keyword on a number", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { type: number, max_len: 3 } } }\n"),
        ("unrestricted argument", "release: r\nversion: \"1\"\ntools:\n  t: { args: { x: { required: true } } }\n"),
    ];
    for (what, src) in cases {
        assert!(parse(src).is_err(), "{what} must not load");
    }
}

// ── closed by default ────────────────────────────────────────────────────

#[test]
fn a_tool_without_args_accepts_no_arguments() {
    let m = one_tool("{}").unwrap();
    assert_eq!(check(&m, "t", json!({}), None), Ok(()));
    assert_eq!(m.rule("t").unwrap().check(None, None), Ok(()));
    assert_eq!(check(&m, "t", json!({"x": 1}), None), Err((ViolationCode::UndeclaredArgument, None)));
}

#[test]
fn undeclared_arguments_are_refused_without_naming_them() {
    let m = support();
    let err = check(&m, "read_ticket", json!({"ticket_id": "T-1042", "secret_extra": "x"}), None).unwrap_err();
    assert_eq!(err, (ViolationCode::UndeclaredArgument, None));
    assert_eq!(ViolationCode::UndeclaredArgument.code(), "undeclared_argument");
    // Nested objects are closed too.
    let m = one_tool("{ args: { o: { type: object, properties: { a: { type: string } } } } }").unwrap();
    assert_eq!(check(&m, "t", json!({"o": {"a": "x", "b": 1}}), None), Err((ViolationCode::UndeclaredArgument, Some("/o".into()))));
}

#[test]
fn arguments_are_optional_unless_required() {
    let m = one_tool("{ args: { a: { type: string }, b: { type: string, required: true } } }").unwrap();
    assert_eq!(check(&m, "t", json!({"b": "x"}), None), Ok(()));
    assert_eq!(check(&m, "t", json!({"a": "x"}), None), Err((ViolationCode::ArgumentMissing, Some("/b".into()))));
    let m = one_tool("{ args: { o: { type: object, properties: { a: { type: string, required: true } } } } }").unwrap();
    assert_eq!(check(&m, "t", json!({"o": {}}), None), Err((ViolationCode::ArgumentMissing, Some("/o/a".into()))));
}

#[test]
fn the_constraint_keys() {
    let invalid = |p: &str| Err((ViolationCode::ArgumentInvalid, Some(p.to_string())));
    let m = one_tool(
        "{ args: { \
            s: { type: string, min_len: 2, max_len: 4, pattern: \"[a-z]+\" }, \
            n: { type: number, min: 0, max: 500 }, \
            i: { type: integer }, \
            b: { type: boolean }, \
            e: { enum: [red, green] }, \
            k: { const: fixed }, \
            l: { type: array, max_len: 2, items: { type: integer, min: 1 } } } }",
    )
    .unwrap();
    let ok = json!({"s": "abc", "n": 500, "i": 3, "b": true, "e": "green", "k": "fixed", "l": [1, 2]});
    assert_eq!(check(&m, "t", ok.clone(), None), Ok(()));
    let with = |k: &str, v: Value| {
        let mut a = ok.clone();
        a[k] = v;
        a
    };
    assert_eq!(check(&m, "t", with("s", json!("a")), None), invalid("/s"));
    assert_eq!(check(&m, "t", with("s", json!("abcde")), None), invalid("/s"));
    assert_eq!(check(&m, "t", with("s", json!("ab1")), None), invalid("/s"), "pattern is anchored");
    assert_eq!(check(&m, "t", with("n", json!(500.5)), None), invalid("/n"));
    assert_eq!(check(&m, "t", with("n", json!(-1)), None), invalid("/n"));
    assert_eq!(check(&m, "t", with("n", json!("5")), None), invalid("/n"));
    assert_eq!(check(&m, "t", with("i", json!(1.5)), None), invalid("/i"));
    assert_eq!(check(&m, "t", with("b", json!("true")), None), invalid("/b"));
    assert_eq!(check(&m, "t", with("e", json!("blue")), None), invalid("/e"));
    assert_eq!(check(&m, "t", with("k", json!("other")), None), invalid("/k"));
    assert_eq!(check(&m, "t", with("l", json!([1, 2, 3])), None), invalid("/l"), "max_len on an array counts items");
    assert_eq!(check(&m, "t", with("l", json!([0])), None), invalid("/l/items"));
}

// ── one_of_context / or_pattern ──────────────────────────────────────────

#[test]
fn one_of_context_binds_an_argument_to_the_task() {
    let m = support();
    let email = |to: &str| json!({"ticket_id": "T-1042", "to": to, "body": "hi"});
    assert_eq!(check(&m, "send_email", email("dana@customer.example"), Some(task())), Ok(()));
    // or_pattern: an unanchored search.
    assert_eq!(check(&m, "send_email", email("lead@ourcompany.com"), Some(task())), Ok(()));
    let mismatch = Err((ViolationCode::ScopeMismatch, Some("/to".into())));
    assert_eq!(check(&m, "send_email", email("attacker@evil.example"), Some(task())), mismatch);
    assert_eq!(check(&m, "send_email", email("x@ourcompany.com.evil.example"), Some(task())), mismatch);
    // No context: the or_pattern still lets an internal address through...
    assert_eq!(check(&m, "send_email", email("lead@ourcompany.com"), None), Ok(()));
    // ...anything else needs the missing key.
    let missing = Err((ViolationCode::TaskContextMissing, Some("/to".into())));
    assert_eq!(check(&m, "send_email", email("dana@customer.example"), None), missing);
    assert_eq!(check(&m, "send_email", email("dana@customer.example"), Some(json!({"ticket": {}}))), missing);
}

#[test]
fn one_of_context_accepts_any_listed_key_and_array_values() {
    let m = one_tool("{ args: { to: { type: string, one_of_context: [\"task.owner\", \"cc\"] } } }").unwrap();
    let t = json!({"owner": "a@x.example", "cc": ["b@x.example", "c@x.example"]});
    for to in ["a@x.example", "b@x.example", "c@x.example"] {
        assert_eq!(check(&m, "t", json!({"to": to}), Some(t.clone())), Ok(()), "{to}");
    }
    assert_eq!(check(&m, "t", json!({"to": "d@x.example"}), Some(t)), Err((ViolationCode::ScopeMismatch, Some("/to".into()))));
    // One key present but not matching, another missing: the missing key decides.
    assert_eq!(
        check(&m, "t", json!({"to": "d@x.example"}), Some(json!({"owner": "a@x.example"}))),
        Err((ViolationCode::TaskContextMissing, Some("/to".into())))
    );
}

// ── side effects and idempotency keys ────────────────────────────────────

#[test]
fn side_effect_and_effect() {
    let m = support();
    assert!(!m.rule("read_ticket").unwrap().side_effect);
    assert!(m.rule("send_email").unwrap().side_effect);
    assert_eq!(m.rule("send_email").unwrap().effect, Some(Effect::Write));
    let r = one_tool("{ effect: irreversible }").unwrap();
    assert!(r.rule("t").unwrap().side_effect);
    assert_eq!(r.rule("t").unwrap().effect, Some(Effect::Irreversible));
    let r = one_tool("{ effect: read }").unwrap();
    assert!(!r.rule("t").unwrap().side_effect);
    assert_eq!(one_tool("{ side_effect: true, effect: write }").unwrap().rule("t").unwrap().effect, Some(Effect::Write));
    for bad in ["{ side_effect: true, effect: read }", "{ side_effect: false, effect: write }", "{ effect: delete }"] {
        assert!(one_tool(bad).is_err(), "{bad}");
    }
}

#[test]
fn idempotency_key_templates_render_over_the_arguments() {
    let m = support();
    let key = m.rule("send_email").unwrap().idempotency_key.as_ref().expect("a template");
    let args = json!({"ticket_id": "T-1042", "to": "dana@customer.example", "body": "Your refund is on its way."});
    let rendered = key.render(Some(&args), None).unwrap();
    assert_eq!(rendered, format!("T-1042:{}", sha256_hex(b"Your refund is on its way.")));
    // Same key fields, other arguments: the same key.
    let mut other = args.clone();
    other["to"] = json!("lead@ourcompany.com");
    assert_eq!(key.render(Some(&other), None).unwrap(), rendered);
}

#[test]
fn idempotency_key_paths_numbers_and_task_values() {
    let m = one_tool(
        "{ side_effect: true, idempotency_key: \"{task.taskId}/{o.n}/{sha256(o.s)}\", \
           args: { o: { type: object, properties: { n: { type: integer }, s: { type: string } } } } }",
    )
    .unwrap();
    let key = m.rule("t").unwrap().idempotency_key.as_ref().unwrap();
    let args = json!({"o": {"n": 42, "s": "x"}});
    assert_eq!(key.render(Some(&args), Some(&task())).unwrap(), format!("t-1042/42/{}", sha256_hex(b"x")));
    assert_eq!(
        key.render(Some(&json!({"o": {"s": "x"}})), Some(&task())),
        Err(Violation { code: ViolationCode::ArgumentMissing, path: Some("/o/n".into()) })
    );
    assert_eq!(key.render(Some(&args), None), Err(Violation { code: ViolationCode::TaskContextMissing, path: None }));
}

#[test]
fn bad_idempotency_keys_are_refused_at_load() {
    for bad in [
        // Only side-effecting tools have operations.
        "{ idempotency_key: \"{a}\", args: { a: { type: string } } }",
        // A field the tool does not declare.
        "{ side_effect: true, idempotency_key: \"{b}\", args: { a: { type: string } } }",
        "{ side_effect: true, idempotency_key: \"{sha256(b)}\", args: { a: { type: string } } }",
        // Malformed.
        "{ side_effect: true, idempotency_key: \"{a\", args: { a: { type: string } } }",
        "{ side_effect: true, idempotency_key: \"a}\", args: { a: { type: string } } }",
        "{ side_effect: true, idempotency_key: \"{}\", args: { a: { type: string } } }",
        "{ side_effect: true, idempotency_key: \"{md5(a)}\", args: { a: { type: string } } }",
        "{ side_effect: true, idempotency_key: \"\", args: { a: { type: string } } }",
    ] {
        assert!(one_tool(bad).is_err(), "{bad}");
    }
}

// ── conditional approval ─────────────────────────────────────────────────

#[test]
fn approval_when_decides_per_call() {
    let m = support();
    let rule = m.rule("issue_refund").unwrap();
    let approval = rule.approval.as_ref().expect("an approval block");
    assert_eq!(approval.approvers, ["slack:#support-leads"]);
    assert_eq!(approval.ttl_secs, Some(900));
    assert!(!rule.needs_approval(Some(&json!({"ticket_id": "T-1", "amount": 50}))));
    assert!(!rule.needs_approval(Some(&json!({"ticket_id": "T-1", "amount": 100}))));
    assert!(rule.needs_approval(Some(&json!({"ticket_id": "T-1", "amount": 100.01}))));
    assert!(rule.needs_approval(Some(&json!({"ticket_id": "T-1", "amount": 350}))));
    // Fail closed: a condition that cannot be evaluated requires approval.
    assert!(rule.needs_approval(Some(&json!({"ticket_id": "T-1"}))));
    assert!(rule.needs_approval(Some(&json!({"ticket_id": "T-1", "amount": "350"}))));
    assert!(rule.needs_approval(None));
}

#[test]
fn approval_without_when_is_always_required_and_tools_without_it_never() {
    let m = one_tool("{ approval: { approvers: [\"email:lead@x.example\"] } }").unwrap();
    assert!(m.rule("t").unwrap().needs_approval(Some(&json!({}))));
    assert!(m.rule("t").unwrap().requires_approval);
    let m = support();
    assert!(!m.rule("read_ticket").unwrap().needs_approval(Some(&json!({"ticket_id": "T-1042"}))));
}

#[test]
fn approval_show_lists_the_arguments_a_broker_may_see() {
    // Default: nothing is shown.
    let m = support();
    assert!(m.rule("issue_refund").unwrap().approval.as_ref().unwrap().show.is_empty());
    let m = one_tool(
        "{ args: { amount: { type: number }, ticket_id: { type: string }, note: { type: string } }, \
           approval: { approvers: [\"slack:#leads\"], show: [amount, ticket_id] } }",
    )
    .unwrap();
    let approval = m.rule("t").unwrap().approval.clone().unwrap();
    assert_eq!(approval.show, ["amount", "ticket_id"]);
    // Only the listed top-level arguments, never the others.
    let shown = approval.shown(Some(&json!({"amount": 350, "ticket_id": "T-1042", "note": "secret note"})));
    assert_eq!(shown, json!({"amount": 350, "ticket_id": "T-1042"}).as_object().unwrap().clone());
    // A listed argument the call leaves out is not shown.
    let shown = approval.shown(Some(&json!({"amount": 350})));
    assert_eq!(shown, json!({"amount": 350}).as_object().unwrap().clone());
    assert!(approval.shown(None).is_empty());
    assert!(approval.shown(Some(&json!([1, 2]))).is_empty());
}

#[test]
fn bad_approval_show_is_refused_at_load() {
    let args = "args: { amount: { type: number } }";
    // Not a declared argument (a typo would silently show nothing).
    let e = one_tool(&format!("{{ {args}, approval: {{ show: [amonut] }} }}")).unwrap_err();
    assert!(e.contains("approval.show") && e.contains("amonut"), "{e}");
    // Top-level argument names only: no paths.
    assert!(one_tool(&format!("{{ {args}, approval: {{ show: [amount.x] }} }}")).is_err());
    assert!(one_tool(&format!("{{ {args}, approval: {{ show: [\"\"] }} }}")).is_err());
    // No duplicates, and a list of strings.
    assert!(one_tool(&format!("{{ {args}, approval: {{ show: [amount, amount] }} }}")).is_err());
    assert!(one_tool(&format!("{{ {args}, approval: {{ show: amount }} }}")).is_err());
    assert!(one_tool(&format!("{{ {args}, approval: {{ show: [1] }} }}")).is_err());
    assert!(one_tool(&format!("{{ {args}, approval: {{ show: [amount] }} }}")).is_ok());
}

/// A broker shows an approver scalar values (Cloud refuses a request whose
/// `shown` holds an object or an array, so such a request would never be
/// filed): an argument declared as an object or array cannot be shown, and
/// a non-scalar value of an untyped argument is left out.
#[test]
fn approval_show_takes_scalar_values_only() {
    for ty in ["object", "array"] {
        let e = one_tool(&format!("{{ args: {{ items: {{ type: {ty} }} }}, approval: {{ show: [items] }} }}")).unwrap_err();
        assert!(e.contains("approval.show") && e.contains("items") && e.contains("scalar"), "{e}");
    }
    let m = one_tool("{ args: { amount: { min: 0 }, note: { max_len: 50 }, ok: { type: boolean } }, approval: { show: [amount, note, ok] } }").unwrap();
    let approval = m.rule("t").unwrap().approval.clone().unwrap();
    let shown = approval.shown(Some(&json!({"amount": {"value": 350}, "note": ["a"], "ok": true})));
    assert_eq!(shown, json!({"ok": true}).as_object().unwrap().clone());
    let shown = approval.shown(Some(&json!({"amount": 350, "note": null, "ok": false})));
    assert_eq!(shown, json!({"amount": 350, "note": null, "ok": false}).as_object().unwrap().clone());
}

#[test]
fn the_condition_language() {
    let args = json!({"amount": 250, "currency": "EUR", "urgent": true, "o": {"n": -1.5}});
    let eval = |src: &str| Condition::parse(src).unwrap_or_else(|e| panic!("{src}: {e}")).matches(&args);
    assert!(eval("amount > 100"));
    assert!(eval("amount >= 250 && amount <= 250"));
    assert!(!eval("amount < 250"));
    assert!(eval("amount == 250.0"));
    assert!(eval("amount != 1"));
    assert!(eval("currency == 'EUR'"));
    assert!(eval("currency == \"EUR\""));
    assert!(eval("currency != 'USD'"));
    assert!(eval("urgent == true"));
    assert!(eval("o.n < -1"));
    assert!(eval("amount > 1000 || currency == 'EUR'"));
    assert!(!eval("amount > 1000 || (currency == 'EUR' && urgent == false)"));
    // && binds tighter than ||.
    assert!(eval("amount > 1000 && urgent == false || currency == 'EUR'"));
    assert!(!eval("amount > 1000 && (urgent == false || currency == 'EUR')"));
    // A type mismatch or a missing path is an error: the condition holds
    // (approval is required) whatever the operator.
    assert!(eval("currency > 1"));
    assert!(eval("missing == 1"));
    assert!(eval("missing != 1"));
}

#[test]
fn bad_conditions_are_refused_at_load() {
    for bad in [
        "", "amount", "amount >", "> 100", "amount > 100 &&", "(amount > 100", "amount > 100)",
        "amount = 100", "amount > 'x'", "urgent < true", "amount > 1e", "amount > 100 & x == 1",
        "currency == 'EUR", "1 > amount", "amount > other",
    ] {
        assert!(Condition::parse(bad).is_err(), "{bad:?}");
    }
    // A condition on an argument the tool does not declare.
    assert!(one_tool("{ args: { a: { type: number } }, approval: { when: \"b > 1\" } }").is_err());
    assert!(one_tool("{ args: { a: { type: number } }, approval: { when: \"a >\" } }").is_err());
    assert!(one_tool("{ args: { a: { type: number } }, approval: { when: \"a > 1\", ttl: soon } }").is_err());
    assert!(one_tool("{ approval: { approvers: [\"\"] } }").is_err());
}

#[test]
fn durations() {
    assert_eq!(parse_duration("15m"), Ok(900));
    assert_eq!(parse_duration("30s"), Ok(30));
    assert_eq!(parse_duration("2h"), Ok(7200));
    assert_eq!(parse_duration("1d"), Ok(86400));
    assert_eq!(parse_duration("1h30m"), Ok(5400));
    for bad in ["", "15", "m", "0m", "-5m", "1.5h", "15 m", "15min", "1m1h"] {
        assert!(parse_duration(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn parse_path_reports_unreadable_files() {
    let err = Manifest::parse_path(Path::new("/nonexistent/cloakpipe.manifest.yaml")).unwrap_err();
    assert!(err.to_string().contains("cannot read"), "{err}");
}
