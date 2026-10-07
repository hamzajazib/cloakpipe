//! Contract tests for the score-based importers `from_braintrust` and
//! `from_langfuse` (see the `cloakpipe_cert::import` module doc comment).

use cloakpipe_cert::import::{from_braintrust, from_langfuse, ImportError, ImportMeta, ScoreRules};
use cloakpipe_cert::{CaseResult, CaseStatus, EvaluationRun, EvaluatorRef, RunSource, SourceKind, SuiteRef};
use proptest::prelude::*;
use serde_json::{json, Value};
use std::path::Path;

// ── Helpers ─────────────────────────────────────────────────────────────

fn meta() -> ImportMeta {
    ImportMeta {
        run_id: "run-42".into(),
        release: format!("sha256:{}", "ae".repeat(32)),
        suite: SuiteRef { name: "support-critical".into(), version: "23".into() },
        covers: vec!["privacy".into(), "functional".into()],
        dataset: Some("support-golden@2026-09".into()),
        evaluators: vec![EvaluatorRef { name: "llm-judge".into(), version: "4".into() }],
        tool: Some("braintrust".into()),
        critical: vec![],
    }
}

fn rules() -> ScoreRules {
    ScoreRules::default()
}

fn threshold(t: f64) -> ScoreRules {
    ScoreRules { pass_threshold: t }
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/import").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn case<'a>(run: &'a EvaluationRun, id: &str) -> &'a CaseResult {
    run.cases.iter().find(|c| c.id == id).unwrap_or_else(|| {
        let ids: Vec<_> = run.cases.iter().map(|c| c.id.as_str()).collect();
        panic!("no case {id:?} in {ids:?}")
    })
}

fn ids(run: &EvaluationRun) -> Vec<&str> {
    run.cases.iter().map(|c| c.id.as_str()).collect()
}

fn approx(a: Option<f64>, b: f64) {
    let a = a.unwrap_or_else(|| panic!("expected Some({b}), got None"));
    assert!((a - b).abs() < 1e-9, "{a} != {b}");
}

fn expect_invalid(result: Result<EvaluationRun, ImportError>) -> String {
    match result {
        Err(ImportError::Invalid(issues)) => {
            assert!(!issues.is_empty(), "Invalid must carry at least one issue");
            issues.join("\n")
        }
        other => panic!("expected ImportError::Invalid, got {other:?}"),
    }
}

fn expect_json_error(result: Result<EvaluationRun, ImportError>) -> String {
    match result {
        Err(ImportError::Json(e)) => e.to_string(),
        other => panic!("expected ImportError::Json, got {other:?}"),
    }
}

// ── Braintrust helpers ──────────────────────────────────────────────────

/// A minimal root event with a stable case id and the given scores.
fn bt_event(case_id: &str, scores: Value) -> Value {
    json!({
        "id": format!("row-{case_id}"),
        "span_id": format!("span-{case_id}"),
        "root_span_id": format!("span-{case_id}"),
        "span_parents": null,
        "metadata": {"case_id": case_id},
        "scores": scores,
    })
}

fn bt(events: Vec<Value>) -> Result<EvaluationRun, ImportError> {
    from_braintrust(&json!({ "events": events }).to_string(), &meta(), &rules())
}

fn bt_ok(events: Vec<Value>) -> EvaluationRun {
    bt(events).unwrap_or_else(|e| panic!("import failed: {e}"))
}

fn bt_one(event: Value) -> CaseResult {
    let run = bt_ok(vec![event]);
    assert_eq!(run.cases.len(), 1, "{:?}", ids(&run));
    run.cases.into_iter().next().unwrap()
}

fn bt_status(scores: Value, rules: &ScoreRules) -> CaseStatus {
    let doc = json!({ "events": [bt_event("c", scores)] }).to_string();
    from_braintrust(&doc, &meta(), rules).unwrap().cases[0].status
}

// ── Braintrust: realistic fetch output ──────────────────────────────────

#[test]
fn braintrust_fetch_fixture() {
    let run = from_braintrust(&fixture("braintrust_fetch.json"), &meta(), &rules()).unwrap();
    assert_eq!(
        ids(&run),
        ["refunds::requires_identity", "privacy::no_pii_in_tool_args", "ds-rec-7f3a", "refunds::over_limit_escalates"],
        "only root spans are cases, in input order"
    );

    let identity = case(&run, "refunds::requires_identity");
    assert_eq!(identity.status, CaseStatus::Pass);
    assert!(identity.critical, "metadata.critical = true");
    approx(identity.score, 0.95);
    assert_eq!(identity.duration_ms, Some(1412));
    assert_eq!(identity.metrics.get("score.Factuality"), Some(&0.9), "child span scores are not merged");
    assert_eq!(identity.metrics.get("score.refund_policy"), Some(&1.0));
    assert!(!identity.metrics.contains_key("score.Levenshtein"), "null scores are not counted");
    assert_eq!(identity.metrics.get("tokens.prompt"), Some(&812.0));
    assert_eq!(identity.metrics.get("tokens.completion"), Some(&64.0));
    assert_eq!(identity.metrics.get("tokens.total"), Some(&876.0));
    assert_eq!(identity.metrics.len(), 5, "{:?}", identity.metrics);

    let pii = case(&run, "privacy::no_pii_in_tool_args");
    assert_eq!(pii.status, CaseStatus::Fail, "pii_leak_free = 0 is below the threshold");
    assert!(!pii.critical);
    approx(pii.score, 0.4);
    assert_eq!(pii.duration_ms, Some(900));

    let timeout = case(&run, "ds-rec-7f3a");
    assert_eq!(timeout.status, CaseStatus::Error, "an explicit error");
    assert_eq!(timeout.score, None);
    assert_eq!(timeout.duration_ms, Some(30000));

    let unscored = case(&run, "refunds::over_limit_escalates");
    assert_eq!(unscored.status, CaseStatus::Error, "only null scores: unscored, fail closed");
    assert!(!unscored.critical, "metadata.critical = false");
    assert_eq!(unscored.score, None);
    assert!(unscored.metrics.is_empty());
}

#[test]
fn braintrust_run_fields_come_from_meta() {
    let run = from_braintrust(&fixture("braintrust_fetch.json"), &meta(), &rules()).unwrap();
    let m = meta();
    assert_eq!(run.run_id, m.run_id);
    assert_eq!(run.release, m.release);
    assert_eq!(run.suite, m.suite);
    assert_eq!(run.covers, m.covers);
    assert_eq!(run.dataset, m.dataset);
    assert_eq!(run.evaluators, m.evaluators);
    assert_eq!(run.source, RunSource { kind: SourceKind::Braintrust, tool: Some("braintrust".into()) });
    assert!(run.validate().is_empty());
}

#[test]
fn braintrust_accepts_a_top_level_array() {
    let doc: Value = serde_json::from_str(&fixture("braintrust_fetch.json")).unwrap();
    let array = doc["events"].to_string();
    let a = from_braintrust(&array, &meta(), &rules()).unwrap();
    let b = from_braintrust(&fixture("braintrust_fetch.json"), &meta(), &rules()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn braintrust_accepts_jsonl() {
    let doc: Value = serde_json::from_str(&fixture("braintrust_fetch.json")).unwrap();
    let lines: Vec<String> = doc["events"].as_array().unwrap().iter().map(|e| e.to_string()).collect();
    let jsonl = format!("{}\n\n  \n{}\n", lines[..3].join("\n"), lines[3..].join("\r\n"));
    let a = from_braintrust(&jsonl, &meta(), &rules()).unwrap();
    let b = from_braintrust(&fixture("braintrust_fetch.json"), &meta(), &rules()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn braintrust_single_jsonl_line_is_one_event() {
    let line = bt_event("only", json!({"s": 1})).to_string();
    let run = from_braintrust(&line, &meta(), &rules()).unwrap();
    assert_eq!(ids(&run), ["only"]);
}

#[test]
fn braintrust_jsonl_error_names_the_line() {
    let good = bt_event("a", json!({"s": 1})).to_string();
    let jsonl = format!("{good}\n{good}\n{{\"id\": oops}}\n");
    let msg = match from_braintrust(&jsonl, &meta(), &rules()) {
        Err(ImportError::Json(e)) => e.to_string(),
        Err(ImportError::Invalid(issues)) => issues.join("\n"),
        other => panic!("expected an error, got {other:?}"),
    };
    assert!(msg.contains("line 3"), "{msg}");
}

#[test]
fn braintrust_jsonl_line_must_be_an_object() {
    let good = bt_event("a", json!({"s": 1})).to_string();
    let msg = expect_invalid(from_braintrust(&format!("{good}\n42\n"), &meta(), &rules()));
    assert!(msg.contains("line 2"), "{msg}");
}

#[test]
fn braintrust_malformed_json_is_a_json_error() {
    expect_json_error(from_braintrust("{\"events\": [", &meta(), &rules()));
    expect_json_error(from_braintrust("{\n  \"events\": [\n    {\"id\": 1},\n", &meta(), &rules()));
    expect_json_error(from_braintrust("", &meta(), &rules()));
    expect_json_error(from_braintrust("   \n ", &meta(), &rules()));
}

#[test]
fn braintrust_events_must_be_an_array_of_objects() {
    let msg = expect_invalid(from_braintrust(r#"{"events": {"a": 1}}"#, &meta(), &rules()));
    assert!(msg.contains("events"), "{msg}");
    let msg = expect_invalid(from_braintrust(r#"{"events": [1]}"#, &meta(), &rules()));
    assert!(msg.contains("events[0]"), "{msg}");
    let msg = expect_invalid(from_braintrust("[[]]", &meta(), &rules()));
    assert!(msg.contains("events[0]"), "{msg}");
    expect_invalid(from_braintrust("\"x\"", &meta(), &rules()));
}

#[test]
fn braintrust_zero_events_is_allowed() {
    assert!(bt_ok(vec![]).cases.is_empty());
    assert!(from_braintrust("[]", &meta(), &rules()).unwrap().cases.is_empty());
}

// ── Braintrust: root detection ──────────────────────────────────────────

#[test]
fn braintrust_root_rules() {
    let child = |id: &str, extra: Value| {
        let mut e = bt_event(id, json!({"s": 1}));
        e["span_parents"] = json!(["p"]);
        e["root_span_id"] = json!("p");
        for (k, v) in extra.as_object().unwrap() {
            e[k] = v.clone();
        }
        e
    };
    let run = bt_ok(vec![
        child("child", json!({})),
        child("is-root-true", json!({"is_root": true})),
        child("same-span", json!({"root_span_id": "span-same-span"})),
        child("no-parents", json!({"span_parents": null})),
        child("empty-parents", json!({"span_parents": []})),
        {
            let mut e = child("absent-parents", json!({}));
            e.as_object_mut().unwrap().remove("span_parents");
            e
        },
        child("child-is-root-false", json!({"is_root": false})),
    ]);
    assert_eq!(ids(&run), ["is-root-true", "same-span", "no-parents", "empty-parents", "absent-parents"]);
}

#[test]
fn braintrust_non_root_events_are_not_validated() {
    // A child span with no case id and junk scores is simply ignored.
    let run = bt_ok(vec![
        bt_event("a", json!({"s": 1})),
        json!({"span_id": "x", "root_span_id": "span-a", "span_parents": ["span-a"], "scores": {"s": 7}, "metadata": 3}),
    ]);
    assert_eq!(ids(&run), ["a"]);
    assert_eq!(run.cases[0].metrics.get("score.s"), Some(&1.0));
}

#[test]
fn braintrust_is_root_must_be_a_bool() {
    let mut e = bt_event("a", json!({"s": 1}));
    e["is_root"] = json!("yes");
    let msg = expect_invalid(bt(vec![e]));
    assert!(msg.contains("is_root"), "{msg}");
}

// ── Braintrust: case identity ───────────────────────────────────────────

#[test]
fn braintrust_case_id_precedence() {
    let e = |metadata: Value, record: Value| json!({"span_parents": null, "metadata": metadata, "dataset_record_id": record, "scores": {"s": 1}});
    let run = bt_ok(vec![
        e(json!({"cloakpipe_case_id": "cp", "case_id": "x"}), json!("r1")),
        e(json!({"case_id": "ci"}), json!("r2")),
        e(json!({}), json!("rec")),
        e(json!(null), json!("rec-null-metadata")),
    ]);
    assert_eq!(ids(&run), ["cp", "ci", "rec", "rec-null-metadata"]);
}

#[test]
fn braintrust_row_id_is_not_a_case_id() {
    let msg = expect_invalid(bt(vec![json!({"id": "row-1", "span_parents": null, "scores": {"s": 1}})]));
    assert!(msg.contains("events[0]"), "{msg}");
    assert!(msg.contains("case id"), "{msg}");
}

#[test]
fn braintrust_case_id_must_be_a_non_empty_string() {
    for bad in [json!(7), json!(""), json!("  "), json!({"x": 1})] {
        let msg =
            expect_invalid(bt(vec![json!({"span_parents": null, "metadata": {"case_id": bad}, "scores": {"s": 1}})]));
        assert!(msg.contains("case_id"), "{bad}: {msg}");
    }
    let msg = expect_invalid(bt(vec![json!({"span_parents": null, "dataset_record_id": 5, "scores": {"s": 1}})]));
    assert!(msg.contains("dataset_record_id"), "{msg}");
}

#[test]
fn braintrust_null_case_id_falls_through() {
    let run = bt_ok(vec![json!({
        "span_parents": null,
        "metadata": {"cloakpipe_case_id": null, "case_id": "ci"},
        "scores": {"s": 1}
    })]);
    assert_eq!(ids(&run), ["ci"]);
}

#[test]
fn braintrust_metadata_must_be_an_object() {
    let msg = expect_invalid(bt(vec![
        json!({"span_parents": null, "metadata": "x", "dataset_record_id": "r", "scores": {"s": 1}}),
    ]));
    assert!(msg.contains("metadata"), "{msg}");
}

#[test]
fn braintrust_duplicate_case_ids_are_invalid() {
    let msg = expect_invalid(bt(vec![bt_event("a", json!({"s": 1})), bt_event("a", json!({"s": 0}))]));
    assert!(msg.contains("duplicate"), "{msg}");
}

// ── Braintrust: status and scores ───────────────────────────────────────

#[test]
fn braintrust_status_from_scores() {
    assert_eq!(bt_status(json!({"a": 1, "b": 0.5}), &rules()), CaseStatus::Pass, "threshold is inclusive");
    assert_eq!(bt_status(json!({"a": 1, "b": 0.49}), &rules()), CaseStatus::Fail);
    assert_eq!(bt_status(json!({"a": 0.7}), &threshold(0.8)), CaseStatus::Fail);
    assert_eq!(bt_status(json!({"a": 0.7}), &threshold(0.7)), CaseStatus::Pass);
    assert_eq!(bt_status(json!({"a": 0}), &threshold(0.0)), CaseStatus::Pass);
    assert_eq!(bt_status(json!({"a": 0.99}), &threshold(1.0)), CaseStatus::Fail);
    assert_eq!(bt_status(json!({"a": 0.2, "b": null}), &rules()), CaseStatus::Fail, "nulls ignored");
}

#[test]
fn braintrust_unscored_fails_closed() {
    assert_eq!(bt_status(json!({}), &rules()), CaseStatus::Error);
    assert_eq!(bt_status(json!({"a": null}), &rules()), CaseStatus::Error);
    assert_eq!(bt_status(json!(null), &rules()), CaseStatus::Error);
    let mut e = bt_event("c", json!(null));
    e.as_object_mut().unwrap().remove("scores");
    assert_eq!(bt_one(e).status, CaseStatus::Error);
}

#[test]
fn braintrust_explicit_error_wins_over_passing_scores() {
    for err in [json!("boom"), json!({"message": "boom"}), json!(["x"]), json!(1)] {
        let mut e = bt_event("c", json!({"a": 1}));
        e["error"] = err.clone();
        let c = bt_one(e);
        assert_eq!(c.status, CaseStatus::Error, "{err}");
        approx(c.score, 1.0);
    }
    for none in [json!(null), json!(""), json!({}), json!([])] {
        let mut e = bt_event("c", json!({"a": 1}));
        e["error"] = none.clone();
        assert_eq!(bt_one(e).status, CaseStatus::Pass, "{none}");
    }
}

#[test]
fn braintrust_score_is_the_mean_and_each_score_is_a_metric() {
    let c = bt_one(bt_event("c", json!({"Factuality": 0.25, "Exact Match": 1, "x.y": 0.5})));
    approx(c.score, (0.25 + 1.0 + 0.5) / 3.0);
    assert_eq!(c.metrics.get("score.Factuality"), Some(&0.25));
    assert_eq!(c.metrics.get("score.Exact Match"), Some(&1.0), "names verbatim");
    assert_eq!(c.metrics.get("score.x.y"), Some(&0.5));
}

#[test]
fn braintrust_out_of_range_scores_are_invalid() {
    for bad in [json!(1.01), json!(-0.1), json!(2), json!(1e300)] {
        let msg = expect_invalid(bt(vec![bt_event("the-case", json!({"s": bad}))]));
        assert!(msg.contains("the-case"), "{msg}");
        assert!(msg.contains("score"), "{msg}");
    }
}

#[test]
fn braintrust_non_numeric_scores_are_invalid() {
    for bad in [json!("0.9"), json!(true), json!([1]), json!({"v": 1})] {
        let msg = expect_invalid(bt(vec![bt_event("the-case", json!({"s": bad}))]));
        assert!(msg.contains("the-case"), "{bad}: {msg}");
    }
    let msg = expect_invalid(bt(vec![bt_event("the-case", json!([0.5]))]));
    assert!(msg.contains("scores"), "{msg}");
}

#[test]
fn braintrust_duplicate_score_names_are_invalid() {
    let doc = r#"{"events": [{"span_parents": null, "metadata": {"case_id": "dup"}, "scores": {"s": 1, "s": 0.2}}]}"#;
    let msg = expect_invalid(from_braintrust(doc, &meta(), &rules()));
    assert!(msg.contains("dup"), "{msg}");
    assert!(msg.contains("\"s\""), "{msg}");
}

#[test]
fn braintrust_duplicate_keys_read_by_the_importer_are_invalid() {
    let doc =
        r#"[{"span_parents": null, "metadata": {"case_id": "a"}, "metadata": {"case_id": "b"}, "scores": {"s": 1}}]"#;
    let msg = expect_invalid(from_braintrust(doc, &meta(), &rules()));
    assert!(msg.contains("metadata"), "{msg}");
    // Unknown keys may repeat: they are never read.
    let doc = r#"[{"span_parents": null, "metadata": {"case_id": "a"}, "tags": [], "tags": [], "scores": {"s": 1}}]"#;
    from_braintrust(doc, &meta(), &rules()).unwrap();
}

// ── Braintrust: critical ────────────────────────────────────────────────

#[test]
fn braintrust_critical_flag_or_pattern() {
    let flagged = |v: Value| {
        let mut e = bt_event("c", json!({"s": 1}));
        e["metadata"]["critical"] = v;
        e
    };
    assert!(bt_one(flagged(json!(true))).critical);
    assert!(!bt_one(flagged(json!(false))).critical);
    for bad in [json!("true"), json!(1), json!(null)] {
        let msg = expect_invalid(bt(vec![flagged(bad.clone())]));
        assert!(msg.contains("critical"), "{bad}: {msg}");
    }
    let m = ImportMeta { critical: vec!["privacy::*".into()], ..meta() };
    let doc = json!({"events": [bt_event("privacy::x", json!({"s": 1})), bt_event("refunds::y", json!({"s": 1}))]});
    let run = from_braintrust(&doc.to_string(), &m, &rules()).unwrap();
    assert!(case(&run, "privacy::x").critical);
    assert!(!case(&run, "refunds::y").critical);
    // The pattern cannot un-mark a flagged case.
    let run = from_braintrust(&json!([flagged(json!(true))]).to_string(), &m, &rules()).unwrap();
    assert!(run.cases[0].critical);
}

// ── Braintrust: metrics ─────────────────────────────────────────────────

#[test]
fn braintrust_duration_and_tokens() {
    let with_metrics = |m: Value| {
        let mut e = bt_event("c", json!({"s": 1}));
        e["metrics"] = m;
        bt_one(e)
    };
    assert_eq!(with_metrics(json!({"start": 10.0, "end": 10.0})).duration_ms, Some(0));
    assert_eq!(with_metrics(json!({"start": 10, "end": 12.0006})).duration_ms, Some(2001));
    assert_eq!(with_metrics(json!({"start": 12.0, "end": 10.0})).duration_ms, None, "end before start");
    assert_eq!(with_metrics(json!({"start": 10.0})).duration_ms, None);
    assert_eq!(with_metrics(json!({"start": "10", "end": "11"})).duration_ms, None);
    assert_eq!(with_metrics(json!(null)).duration_ms, None);
    let c = with_metrics(json!({"prompt_tokens": 3, "completion_tokens": "x", "tokens": null, "cached": 9}));
    assert_eq!(c.metrics.get("tokens.prompt"), Some(&3.0));
    assert!(!c.metrics.contains_key("tokens.completion"));
    assert!(!c.metrics.contains_key("tokens.total"));
    assert!(!c.metrics.contains_key("cached"), "unknown metrics are not imported");
}

#[test]
fn braintrust_metrics_must_be_an_object() {
    let mut e = bt_event("c", json!({"s": 1}));
    e["metrics"] = json!([1]);
    let msg = expect_invalid(bt(vec![e]));
    assert!(msg.contains("metrics"), "{msg}");
}

// ── Shared: threshold and run validity ──────────────────────────────────

#[test]
fn pass_threshold_must_be_a_finite_unit_value() {
    let doc = json!([bt_event("c", json!({"s": 1}))]).to_string();
    for bad in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
        let msg = expect_invalid(from_braintrust(&doc, &meta(), &threshold(bad)));
        assert!(msg.contains("threshold"), "{bad}: {msg}");
        let msg = expect_invalid(from_langfuse(
            &fixture("langfuse_run.json"),
            &fixture("langfuse_scores.json"),
            &meta(),
            &threshold(bad),
        ));
        assert!(msg.contains("threshold"), "{bad}: {msg}");
    }
    assert_eq!(ScoreRules::default().pass_threshold, 0.5);
}

#[test]
fn meta_must_produce_a_valid_run() {
    let m = ImportMeta { covers: vec![], ..meta() };
    let msg = expect_invalid(from_braintrust(&fixture("braintrust_fetch.json"), &m, &rules()));
    assert!(msg.contains("covers"), "{msg}");
    let msg =
        expect_invalid(from_langfuse(&fixture("langfuse_run.json"), &fixture("langfuse_scores.json"), &m, &rules()));
    assert!(msg.contains("covers"), "{msg}");
}

#[test]
fn run_hash_is_reproducible() {
    let a = from_braintrust(&fixture("braintrust_fetch.json"), &meta(), &rules()).unwrap();
    let b = from_braintrust(&fixture("braintrust_fetch.json"), &meta(), &rules()).unwrap();
    assert_eq!(a.run_hash(), b.run_hash());
}

// ── Langfuse helpers ────────────────────────────────────────────────────

fn lf_meta() -> ImportMeta {
    ImportMeta { tool: Some("langfuse".into()), ..meta() }
}

fn lf_item(case_id: &str, trace: &str, observation: Option<&str>) -> Value {
    json!({"id": format!("ri-{case_id}"), "datasetItemId": case_id, "traceId": trace, "observationId": observation})
}

fn lf_score(name: &str, value: Value, trace: &str, observation: Option<&str>, data_type: &str) -> Value {
    json!({"name": name, "value": value, "traceId": trace, "observationId": observation, "dataType": data_type})
}

fn lf(items: Vec<Value>, scores: Vec<Value>) -> Result<EvaluationRun, ImportError> {
    let run = json!({"name": "r", "datasetRunItems": items});
    let scores = json!({"data": scores, "meta": {"page": 1, "limit": 50, "totalItems": 0, "totalPages": 1}});
    from_langfuse(&run.to_string(), &scores.to_string(), &lf_meta(), &rules())
}

fn lf_ok(items: Vec<Value>, scores: Vec<Value>) -> EvaluationRun {
    lf(items, scores).unwrap_or_else(|e| panic!("import failed: {e}"))
}

fn lf_one(scores: Vec<Value>) -> CaseResult {
    lf_ok(vec![lf_item("c", "t", None)], scores).cases.into_iter().next().unwrap()
}

// ── Langfuse: realistic run + paged scores ──────────────────────────────

#[test]
fn langfuse_fixture() {
    let run =
        from_langfuse(&fixture("langfuse_run.json"), &fixture("langfuse_scores.json"), &lf_meta(), &rules()).unwrap();
    assert_eq!(
        ids(&run),
        [
            "refunds::requires_identity",
            "privacy::no_pii_in_tool_args",
            "refunds::over_limit_escalates",
            "escalation::hands_off_politely"
        ]
    );
    assert_eq!(run.source, RunSource { kind: SourceKind::Langfuse, tool: Some("langfuse".into()) });
    assert_eq!(run.dataset, meta().dataset, "meta.dataset wins");

    let identity = case(&run, "refunds::requires_identity");
    assert_eq!(identity.status, CaseStatus::Pass);
    approx(identity.score, 0.95);
    assert_eq!(identity.metrics.get("score.correctness"), Some(&0.9));
    assert_eq!(identity.metrics.get("score.policy_ok"), Some(&1.0), "BOOLEAN 1");
    assert!(!identity.metrics.contains_key("score.tone"), "CATEGORICAL ignored");
    assert!(!identity.metrics.contains_key("score.helpfulness"), "observation score on a trace-level item");
    assert!(!identity.critical);
    assert_eq!(identity.duration_ms, None);

    let pii = case(&run, "privacy::no_pii_in_tool_args");
    assert_eq!(pii.status, CaseStatus::Fail);
    approx(pii.score, 0.35);
    assert_eq!(pii.metrics.get("score.pii_leak_free"), Some(&0.0), "matching observation score joins");
    assert_eq!(pii.metrics.get("score.correctness"), Some(&0.7), "trace score joins");
    assert!(!pii.metrics.contains_key("score.latency_ok"), "other observation's score");

    let unscored = case(&run, "refunds::over_limit_escalates");
    assert_eq!(unscored.status, CaseStatus::Error, "only categorical scores: unscored");
    assert_eq!(unscored.score, None);

    let handoff = case(&run, "escalation::hands_off_politely");
    assert_eq!(handoff.status, CaseStatus::Pass, "score from page 2");
    approx(handoff.score, 0.6);
    assert!(run.validate().is_empty());
}

#[test]
fn langfuse_dataset_defaults_to_the_run_dataset_name() {
    let m = ImportMeta { dataset: None, ..lf_meta() };
    let run = from_langfuse(&fixture("langfuse_run.json"), &fixture("langfuse_scores.json"), &m, &rules()).unwrap();
    assert_eq!(run.dataset.as_deref(), Some("support-golden"));
    let run = from_langfuse(r#"{"datasetRunItems": []}"#, "[]", &m, &rules()).unwrap();
    assert_eq!(run.dataset, None);
}

#[test]
fn langfuse_score_shapes() {
    let item = || vec![lf_item("c", "t", None)];
    let s = || lf_score("s", json!(0.8), "t", None, "NUMERIC");
    let page = |scores: Vec<Value>| json!({"data": scores, "meta": {"page": 1}});
    let run_json = json!({"datasetRunItems": item()}).to_string();
    for scores in [page(vec![s()]), json!([s()]), json!([page(vec![s()]), page(vec![])])] {
        let run = from_langfuse(&run_json, &scores.to_string(), &lf_meta(), &rules()).unwrap();
        assert_eq!(run.cases[0].status, CaseStatus::Pass, "{scores}");
    }
    for bad in [json!(7), json!({"meta": {}}), json!({"data": 1}), json!([1])] {
        expect_invalid(from_langfuse(&run_json, &bad.to_string(), &lf_meta(), &rules()));
    }
}

#[test]
fn langfuse_malformed_json_is_a_json_error() {
    let run = json!({"datasetRunItems": []}).to_string();
    expect_json_error(from_langfuse("{", "[]", &lf_meta(), &rules()));
    expect_json_error(from_langfuse(&run, "[", &lf_meta(), &rules()));
    expect_json_error(from_langfuse(&run, "", &lf_meta(), &rules()));
}

#[test]
fn langfuse_run_shape() {
    for bad in [json!([]), json!({"name": "r"}), json!({"datasetRunItems": {}}), json!({"datasetRunItems": [1]})] {
        let msg = expect_invalid(from_langfuse(&bad.to_string(), "[]", &lf_meta(), &rules()));
        assert!(msg.contains("datasetRunItems"), "{bad}: {msg}");
    }
}

// ── Langfuse: join ──────────────────────────────────────────────────────

#[test]
fn langfuse_join_rules() {
    let run = lf_ok(
        vec![lf_item("trace-level", "t1", None), lf_item("obs-level", "t2", Some("o2"))],
        vec![
            lf_score("trace", json!(1), "t1", None, "NUMERIC"),
            lf_score("obs", json!(0), "t1", Some("o1"), "NUMERIC"),
            lf_score("trace", json!(1), "t2", None, "NUMERIC"),
            lf_score("mine", json!(1), "t2", Some("o2"), "NUMERIC"),
            lf_score("other", json!(0), "t2", Some("o3"), "NUMERIC"),
            lf_score("stray", json!(0), "t9", None, "NUMERIC"),
        ],
    );
    let names = |id: &str| case(&run, id).metrics.keys().cloned().collect::<Vec<_>>();
    assert_eq!(names("trace-level"), ["score.trace"]);
    assert_eq!(names("obs-level"), ["score.mine", "score.trace"]);
    assert!(run.cases.iter().all(|c| c.status == CaseStatus::Pass));
}

#[test]
fn langfuse_items_sharing_a_trace_both_get_trace_scores() {
    let run = lf_ok(
        vec![lf_item("a", "t", Some("o1")), lf_item("b", "t", Some("o2"))],
        vec![lf_score("q", json!(0.2), "t", None, "NUMERIC")],
    );
    assert!(run.cases.iter().all(|c| c.status == CaseStatus::Fail));
}

#[test]
fn langfuse_scores_without_a_trace_are_ignored() {
    let c = lf_one(vec![
        lf_score("s", json!(1), "t", None, "NUMERIC"),
        json!({"name": "session", "value": 0, "sessionId": "sess-1", "dataType": "NUMERIC"}),
        json!({"name": "run", "value": 0, "traceId": null, "datasetRunId": "r", "dataType": "NUMERIC"}),
    ]);
    assert_eq!(c.status, CaseStatus::Pass);
}

#[test]
fn langfuse_repeated_score_ids_across_pages_count_once() {
    let mut s = lf_score("s", json!(1), "t", None, "NUMERIC");
    s["id"] = json!("sc-1");
    let run_json = json!({"datasetRunItems": [lf_item("c", "t", None)]}).to_string();
    let scores = json!([{"data": [s.clone()]}, {"data": [s]}]).to_string();
    let run = from_langfuse(&run_json, &scores, &lf_meta(), &rules()).unwrap();
    assert_eq!(run.cases[0].status, CaseStatus::Pass);
}

// ── Langfuse: case identity ─────────────────────────────────────────────

#[test]
fn langfuse_case_id_is_the_dataset_item_id() {
    for bad in [json!(null), json!(""), json!(3)] {
        let mut item = lf_item("x", "t", None);
        item["datasetItemId"] = bad.clone();
        let msg = expect_invalid(lf(vec![item], vec![]));
        assert!(msg.contains("datasetItemId"), "{bad}: {msg}");
    }
    let mut item = lf_item("x", "t", None);
    item.as_object_mut().unwrap().remove("datasetItemId");
    expect_invalid(lf(vec![item], vec![]));
}

#[test]
fn langfuse_duplicate_dataset_items_are_invalid() {
    let msg = expect_invalid(lf(vec![lf_item("a", "t1", None), lf_item("a", "t2", None)], vec![]));
    assert!(msg.contains("duplicate"), "{msg}");
}

#[test]
fn langfuse_run_item_needs_a_trace() {
    let mut item = lf_item("a", "t", None);
    item["traceId"] = json!(null);
    let msg = expect_invalid(lf(vec![item], vec![]));
    assert!(msg.contains("traceId"), "{msg}");
    let mut item = lf_item("a", "t", None);
    item["observationId"] = json!(4);
    let msg = expect_invalid(lf(vec![item], vec![]));
    assert!(msg.contains("observationId"), "{msg}");
}

// ── Langfuse: values ────────────────────────────────────────────────────

#[test]
fn langfuse_boolean_scores() {
    assert_eq!(lf_one(vec![lf_score("b", json!(1), "t", None, "BOOLEAN")]).status, CaseStatus::Pass);
    assert_eq!(lf_one(vec![lf_score("b", json!(0), "t", None, "BOOLEAN")]).status, CaseStatus::Fail);
    for bad in [json!(0.5), json!(2), json!(true), json!(null)] {
        let msg = expect_invalid(lf(
            vec![lf_item("the-case", "t", None)],
            vec![lf_score("b", bad.clone(), "t", None, "BOOLEAN")],
        ));
        assert!(msg.contains("the-case"), "{bad}: {msg}");
    }
}

#[test]
fn langfuse_numeric_scores() {
    let c = lf_one(vec![
        lf_score("a", json!(0.25), "t", None, "NUMERIC"),
        lf_score("b", json!(0.75), "t", None, "NUMERIC"),
    ]);
    approx(c.score, 0.5);
    assert_eq!(c.status, CaseStatus::Fail, "0.25 < 0.5");
    // dataType absent (older Langfuse) is NUMERIC.
    let c = lf_one(vec![json!({"name": "a", "value": 0.9, "traceId": "t"})]);
    assert_eq!(c.status, CaseStatus::Pass);
    for bad in [json!(1.5), json!(-1), json!("0.9"), json!(null)] {
        let msg = expect_invalid(lf(
            vec![lf_item("the-case", "t", None)],
            vec![lf_score("a", bad.clone(), "t", None, "NUMERIC")],
        ));
        assert!(msg.contains("the-case"), "{bad}: {msg}");
    }
}

#[test]
fn langfuse_categorical_only_is_unscored() {
    let c = lf_one(vec![lf_score("c", json!(1), "t", None, "CATEGORICAL")]);
    assert_eq!(c.status, CaseStatus::Error);
    assert!(c.metrics.is_empty());
    assert_eq!(lf_one(vec![]).status, CaseStatus::Error);
}

#[test]
fn langfuse_unknown_data_type_is_invalid() {
    let msg =
        expect_invalid(lf(vec![lf_item("the-case", "t", None)], vec![lf_score("x", json!(1), "t", None, "VIBES")]));
    assert!(msg.contains("the-case") && msg.contains("VIBES"), "{msg}");
}

#[test]
fn langfuse_duplicate_score_names_are_invalid() {
    let msg = expect_invalid(lf(
        vec![lf_item("the-case", "t", Some("o"))],
        vec![lf_score("q", json!(1), "t", None, "NUMERIC"), lf_score("q", json!(1), "t", Some("o"), "NUMERIC")],
    ));
    assert!(msg.contains("the-case") && msg.contains("\"q\""), "{msg}");
}

#[test]
fn langfuse_joined_score_needs_a_name() {
    let msg = expect_invalid(lf(vec![lf_item("the-case", "t", None)], vec![json!({"value": 1, "traceId": "t"})]));
    assert!(msg.contains("the-case") && msg.contains("name"), "{msg}");
}

#[test]
fn langfuse_critical_by_pattern_only() {
    let m = ImportMeta { critical: vec!["privacy::*".into()], ..lf_meta() };
    let run = from_langfuse(&fixture("langfuse_run.json"), &fixture("langfuse_scores.json"), &m, &rules()).unwrap();
    assert!(case(&run, "privacy::no_pii_in_tool_args").critical);
    assert!(!case(&run, "refunds::requires_identity").critical);
}

// ── Never panics ────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn braintrust_never_panics(s in "\\PC*") {
        let _ = from_braintrust(&s, &meta(), &rules());
    }

    #[test]
    fn langfuse_never_panics(run in "\\PC*", scores in "\\PC*") {
        let _ = from_langfuse(&run, &scores, &meta(), &rules());
    }

    #[test]
    fn braintrust_never_panics_on_jsonish_input(
        parts in proptest::collection::vec(
            prop_oneof![
                Just("{".to_string()), Just("}".to_string()), Just("[".to_string()), Just("]".to_string()),
                Just(",".to_string()), Just(":".to_string()), Just("\n".to_string()),
                Just("\"events\"".to_string()), Just("\"scores\"".to_string()), Just("\"metadata\"".to_string()),
                Just("\"case_id\"".to_string()), Just("\"span_parents\"".to_string()), Just("\"metrics\"".to_string()),
                Just("\"start\"".to_string()), Just("\"end\"".to_string()), Just("\"error\"".to_string()),
                Just("null".to_string()), Just("true".to_string()), Just("1e308".to_string()), Just("-1e308".to_string()),
                Just("0.5".to_string()), Just("\"x\"".to_string()),
            ],
            0..40,
        ),
        t in prop_oneof![Just(0.5), Just(0.0), Just(1.0), Just(f64::NAN), any::<f64>()],
    ) {
        let s = parts.concat();
        let _ = from_braintrust(&s, &meta(), &threshold(t));
    }

    #[test]
    fn scored_events_always_yield_valid_runs(
        cases in proptest::collection::vec(
            (
                proptest::collection::btree_map("[a-z]{1,3}", proptest::option::of(0.0f64..=1.0), 0..4),
                proptest::option::of(0.0f64..1e6),
                proptest::option::of(0.0f64..1e6),
                any::<bool>(),
            ),
            0..6,
        ),
        t in 0.0f64..=1.0,
    ) {
        let events: Vec<Value> = cases.iter().enumerate().map(|(i, (scores, start, end, err))| {
            json!({
                "span_parents": null,
                "metadata": {"case_id": format!("case-{i}")},
                "scores": scores,
                "metrics": {"start": start, "end": end},
                "error": if *err { json!("e") } else { json!(null) },
            })
        }).collect();
        let run = from_braintrust(&json!(events).to_string(), &meta(), &threshold(t)).unwrap();
        prop_assert!(run.validate().is_empty());
        for (c, (scores, _, _, err)) in run.cases.iter().zip(&cases) {
            let given: Vec<f64> = scores.values().flatten().copied().collect();
            let expected = if *err || given.is_empty() {
                CaseStatus::Error
            } else if given.iter().all(|&s| s >= t) {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            };
            prop_assert_eq!(c.status, expected);
        }
    }
}
