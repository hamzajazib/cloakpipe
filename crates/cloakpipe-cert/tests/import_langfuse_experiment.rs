//! Contract tests for `from_langfuse_experiment`: a Langfuse experiment
//! (`GET /api/public/experiments`) plus its items with their scores
//! (`GET /api/public/experiment-items?fields=core,dataset,scores`); see the
//! `cloakpipe_cert::import` module doc comment.

use cloakpipe_cert::import::{from_langfuse_experiment, ImportError, ImportMeta, ScoreRules};
use cloakpipe_cert::{CaseResult, CaseStatus, EvaluationRun, EvaluatorRef, RunSource, SourceKind, SuiteRef};
use proptest::prelude::*;
use serde_json::{json, Value};
use std::path::Path;

// ── Helpers ─────────────────────────────────────────────────────────────

const EXP: &str = "exp-1";

fn meta() -> ImportMeta {
    ImportMeta {
        run_id: "run-42".into(),
        release: format!("sha256:{}", "ae".repeat(32)),
        suite: SuiteRef { name: "support-critical".into(), version: "23".into() },
        covers: vec!["privacy".into(), "functional".into()],
        dataset: Some("support-golden@2026-09".into()),
        evaluators: vec![EvaluatorRef { name: "llm-judge".into(), version: "4".into() }],
        tool: Some("langfuse".into()),
        critical: vec![],
    }
}

fn rules() -> ScoreRules {
    ScoreRules::default()
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

/// An `ExperimentsResponse` page holding one experiment with `item_count`.
fn experiment(item_count: usize) -> Value {
    json!({"data": [{
        "id": EXP, "name": "nightly", "description": null,
        "startTime": "2026-10-05T09:00:00.000Z", "endTime": "2026-10-05T09:20:00.000Z",
        "itemCount": item_count, "datasetId": "ds-1"
    }], "meta": {}})
}

/// A ScoreV3 object.
fn score(name: &str, data_type: &str, value: Value) -> Value {
    json!({
        "id": format!("sc-{name}"), "projectId": "p", "name": name, "value": value, "dataType": data_type,
        "source": "EVAL", "timestamp": "2026-10-05T09:01:00.000Z", "environment": "default",
        "createdAt": "2026-10-05T09:01:00.000Z", "updatedAt": "2026-10-05T09:01:00.000Z"
    })
}

/// An ExperimentItem of experiment `EXP` with case id `case_id`.
fn item(case_id: &str, scores: Vec<Value>) -> Value {
    json!({
        "id": format!("obs-{case_id}"), "traceId": format!("trace-{case_id}"),
        "startTime": "2026-10-05T09:01:00.000Z", "endTime": "2026-10-05T09:01:02.000Z",
        "level": "DEFAULT", "environment": "default",
        "experimentId": EXP, "experimentName": "nightly", "experimentItemId": case_id,
        "experimentDatasetId": "ds-1", "experimentItemVersion": null,
        "scores": scores
    })
}

/// The last (or only) page of items.
fn page(items: Vec<Value>) -> Value {
    json!({"data": items, "meta": {}})
}

fn import(experiment: &Value, items: &Value, rules: &ScoreRules) -> Result<EvaluationRun, ImportError> {
    from_langfuse_experiment(&experiment.to_string(), &items.to_string(), &meta(), rules)
}

fn lfx(items: Vec<Value>) -> Result<EvaluationRun, ImportError> {
    import(&experiment(items.len()), &page(items), &rules())
}

fn one(scores: Vec<Value>) -> CaseResult {
    lfx(vec![item("c", scores)]).unwrap_or_else(|e| panic!("import failed: {e}")).cases.remove(0)
}

// ── Realistic experiment + two pages of items ───────────────────────────

#[test]
fn experiment_fixture() {
    let run = from_langfuse_experiment(
        &fixture("langfuse_experiment.json"),
        &fixture("langfuse_experiment_items.json"),
        &meta(),
        &rules(),
    )
    .unwrap();
    assert_eq!(run.cases.len(), 4);
    assert_eq!(run.source, RunSource { kind: SourceKind::Langfuse, tool: Some("langfuse".into()) });
    assert_eq!(run.dataset, meta().dataset, "meta.dataset wins");

    let identity = case(&run, "refunds::requires_identity");
    assert_eq!(identity.status, CaseStatus::Pass);
    approx(identity.score, 0.95);
    assert_eq!(identity.metrics.get("score.correctness"), Some(&0.9));
    assert_eq!(identity.metrics.get("score.policy_ok"), Some(&1.0), "BOOLEAN true");
    assert!(!identity.metrics.contains_key("score.tone"), "CATEGORICAL ignored");
    assert!(!identity.critical);
    assert_eq!(identity.duration_ms, None);

    let pii = case(&run, "privacy::no_pii_in_tool_args");
    assert_eq!(pii.status, CaseStatus::Fail);
    approx(pii.score, 0.35);
    assert_eq!(pii.metrics.get("score.pii_leak_free"), Some(&0.0), "BOOLEAN false");

    let unscored = case(&run, "refunds::over_limit_escalates");
    assert_eq!(unscored.status, CaseStatus::Error, "only categorical scores: unscored");
    assert_eq!(unscored.score, None);

    let handoff = case(&run, "escalation::hands_off_politely");
    assert_eq!(handoff.status, CaseStatus::Pass);
    approx(handoff.score, 0.6);
    assert!(run.validate().is_empty());
}

#[test]
fn dataset_defaults_to_the_experiment_dataset_id() {
    let m = ImportMeta { dataset: None, ..meta() };
    let run = from_langfuse_experiment(
        &fixture("langfuse_experiment.json"),
        &fixture("langfuse_experiment_items.json"),
        &m,
        &rules(),
    )
    .unwrap();
    assert_eq!(run.dataset.as_deref(), Some("cm2ds0000001"));
    // An experiment on local data has no dataset.
    let mut exp = experiment(0);
    exp["data"][0]["datasetId"] = Value::Null;
    let run = from_langfuse_experiment(&exp.to_string(), &page(vec![]).to_string(), &m, &rules()).unwrap();
    assert_eq!(run.dataset, None);
}

#[test]
fn critical_comes_from_meta_patterns() {
    let m = ImportMeta { critical: vec!["privacy::*".into()], ..meta() };
    let run = from_langfuse_experiment(
        &fixture("langfuse_experiment.json"),
        &fixture("langfuse_experiment_items.json"),
        &m,
        &rules(),
    )
    .unwrap();
    assert!(case(&run, "privacy::no_pii_in_tool_args").critical);
    assert!(!case(&run, "refunds::requires_identity").critical);
}

#[test]
fn zero_items_is_allowed() {
    let run = lfx(vec![]).unwrap();
    assert!(run.cases.is_empty());
}

// ── Pagination: fail closed ─────────────────────────────────────────────

#[test]
fn a_page_with_a_next_cursor_must_be_followed() {
    // One page whose meta.cursor says there is more.
    let items = json!({"data": [item("a", vec![score("s", "NUMERIC", json!(1))])], "meta": {"cursor": "next-1"}});
    let msg = expect_invalid(import(&experiment(1), &items, &rules()));
    assert!(msg.contains("cursor"), "{msg}");
    assert!(msg.contains("incomplete"), "{msg}");
    // The same as the last of several pages.
    let items = json!([
        {"data": [item("a", vec![score("s", "NUMERIC", json!(1))])], "meta": {"cursor": "next-1"}},
        {"data": [item("b", vec![score("s", "NUMERIC", json!(1))])], "meta": {"cursor": "next-2"}}
    ]);
    let msg = expect_invalid(import(&experiment(2), &items, &rules()));
    assert!(msg.contains("incomplete"), "{msg}");
}

#[test]
fn complete_pagination_is_accepted() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    for last_meta in [json!({}), json!({"cursor": null}), json!({"cursor": ""})] {
        let items = json!([
            {"data": [item("a", s())], "meta": {"cursor": "c1"}},
            {"data": [item("b", s())], "meta": {"cursor": "c2"}},
            {"data": [item("c", s())], "meta": last_meta}
        ]);
        let run = import(&experiment(3), &items, &rules()).unwrap_or_else(|e| panic!("{last_meta}: {e}"));
        assert_eq!(run.cases.len(), 3);
    }
}

#[test]
fn a_page_without_a_cursor_before_the_last_is_invalid() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    let items = json!([
        {"data": [item("a", s())], "meta": {}},
        {"data": [item("b", s())], "meta": {}}
    ]);
    let msg = expect_invalid(import(&experiment(2), &items, &rules()));
    assert!(msg.contains("items[0]"), "{msg}");
    assert!(msg.contains("cursor"), "{msg}");
}

#[test]
fn a_repeated_cursor_is_invalid() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    let items = json!([
        {"data": [item("a", s())], "meta": {"cursor": "c1"}},
        {"data": [item("b", s())], "meta": {"cursor": "c1"}},
        {"data": [item("c", s())], "meta": {}}
    ]);
    let msg = expect_invalid(import(&experiment(3), &items, &rules()));
    assert!(msg.contains("repeat"), "{msg}");
}

#[test]
fn a_missing_page_is_caught_by_the_item_count() {
    // Page 2 of 3 dropped: the cursor chain looks complete, the count does not.
    let s = || vec![score("s", "NUMERIC", json!(1))];
    let items = json!([
        {"data": [item("a", s())], "meta": {"cursor": "c1"}},
        {"data": [item("c", s())], "meta": {}}
    ]);
    let msg = expect_invalid(import(&experiment(3), &items, &rules()));
    assert!(msg.contains("itemCount"), "{msg}");
    assert!(msg.contains('3') && msg.contains('2'), "{msg}");
    // More items than the experiment announces is just as wrong.
    let msg = expect_invalid(import(&experiment(0), &page(vec![item("a", s())]), &rules()));
    assert!(msg.contains("itemCount"), "{msg}");
}

#[test]
fn pages_need_data_and_meta() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    for bad in [
        json!({"data": [item("a", s())]}),                // no meta: cannot tell whether more pages exist
        json!({"data": [item("a", s())], "meta": null}),  // same
        json!({"data": [item("a", s())], "meta": 1}),     // meta of the wrong type
        json!({"data": [item("a", s())], "meta": {"cursor": 7}}),
        json!({"meta": {}}),
        json!({"data": {}, "meta": {}}),
        json!([item("a", s())]),                          // bare items: no pagination evidence
        json!([1]),
        json!(7),
        json!("x"),
    ] {
        let msg = expect_invalid(import(&experiment(1), &bad, &rules()));
        assert!(!msg.is_empty(), "{bad}");
    }
    let msg = expect_invalid(import(&experiment(1), &json!({"data": [item("a", s())]}), &rules()));
    assert!(msg.contains("meta"), "{msg}");
}

// ── Experiment file ─────────────────────────────────────────────────────

#[test]
fn experiment_file_shapes() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    let items = page(vec![item("a", s())]);
    // A page with one experiment, or the bare experiment object.
    let bare = experiment(1)["data"][0].clone();
    for exp in [experiment(1), bare] {
        import(&exp, &items, &rules()).unwrap_or_else(|e| panic!("{exp}: {e}"));
    }
    // Zero or several experiments, or not an experiment at all.
    let mut two = experiment(1);
    let first = two["data"][0].clone();
    two["data"].as_array_mut().unwrap().push(first);
    for (bad, needle) in [
        (json!({"data": [], "meta": {}}), "no experiment"),
        (two, "2 experiments"),
        (json!([]), "experiment"),
        (json!(1), "experiment"),
        (json!({"data": [{"name": "x", "itemCount": 1}], "meta": {}}), "id"),
        (json!({"data": [{"id": "", "itemCount": 1}], "meta": {}}), "id"),
        (json!({"data": [{"id": EXP}], "meta": {}}), "itemCount"),
        (json!({"data": [{"id": EXP, "itemCount": 1.5}], "meta": {}}), "itemCount"),
        (json!({"data": [{"id": EXP, "itemCount": -1}], "meta": {}}), "itemCount"),
        (json!({"data": [{"id": EXP, "itemCount": "1"}], "meta": {}}), "itemCount"),
        (json!({"data": [{"id": EXP, "itemCount": 1, "datasetId": 5}], "meta": {}}), "datasetId"),
    ] {
        let msg = expect_invalid(import(&bad, &items, &rules()));
        assert!(msg.contains(needle), "{bad}: {needle:?} not in {msg}");
    }
}

#[test]
fn items_of_another_experiment_are_invalid() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    let mut other = item("b", s());
    other["experimentId"] = json!("exp-2");
    let msg = expect_invalid(lfx(vec![item("a", s()), other]));
    assert!(msg.contains("exp-2") && msg.contains(EXP), "{msg}");
    // The experiment file and the items file disagree entirely.
    let mut exp = experiment(1);
    exp["data"][0]["id"] = json!("exp-9");
    let msg = expect_invalid(import(&exp, &page(vec![item("a", s())]), &rules()));
    assert!(msg.contains("exp-9"), "{msg}");
}

#[test]
fn malformed_json_is_a_json_error() {
    let exp = experiment(0).to_string();
    let items = page(vec![]).to_string();
    for (e, i) in [("{", items.as_str()), (exp.as_str(), "["), (exp.as_str(), "")] {
        match from_langfuse_experiment(e, i, &meta(), &rules()) {
            Err(ImportError::Json(_)) => {}
            other => panic!("expected ImportError::Json, got {other:?}"),
        }
    }
}

#[test]
fn a_leading_bom_is_ignored() {
    let exp = format!("\u{feff}{}", experiment(1));
    let items = format!("\u{feff}{}", page(vec![item("a", vec![score("s", "NUMERIC", json!(1))])]));
    from_langfuse_experiment(&exp, &items, &meta(), &rules()).unwrap();
}

// ── Items: identity and shape ───────────────────────────────────────────

#[test]
fn case_id_is_the_experiment_item_id() {
    let run = lfx(vec![item("refunds::a", vec![score("s", "NUMERIC", json!(1))])]).unwrap();
    assert_eq!(run.cases[0].id, "refunds::a");
}

#[test]
fn duplicate_items_are_invalid() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    let msg = expect_invalid(lfx(vec![item("a", s()), item("a", s())]));
    assert!(msg.contains("\"a\""), "{msg}");
    // Also across pages.
    let items = json!([
        {"data": [item("a", s())], "meta": {"cursor": "c1"}},
        {"data": [item("a", s())], "meta": {}}
    ]);
    expect_invalid(import(&experiment(2), &items, &rules()));
}

#[test]
fn item_fields_are_type_checked() {
    let s = || vec![score("s", "NUMERIC", json!(1))];
    let set = |key: &str, v: Value| {
        let mut i = item("a", s());
        i[key] = v;
        i
    };
    let without = |key: &str| {
        let mut i = item("a", s());
        i.as_object_mut().unwrap().remove(key);
        i
    };
    for (bad, needle) in [
        (without("experimentItemId"), "experimentItemId"),
        (set("experimentItemId", json!("")), "experimentItemId"),
        (set("experimentItemId", json!(" a")), "whitespace"),
        (set("experimentItemId", json!(1)), "experimentItemId"),
        (without("traceId"), "traceId"),
        (set("traceId", json!(1)), "traceId"),
        (without("experimentId"), "experimentId"),
        (set("experimentId", json!(1)), "experimentId"),
        (set("level", json!(3)), "level"),
        (set("scores", json!({})), "scores"),
        (set("scores", json!([1])), "scores"),
        (json!(1), "object"),
    ] {
        let msg = expect_invalid(lfx(vec![bad.clone()]));
        assert!(msg.contains(needle), "{bad}: {needle:?} not in {msg}");
    }
}

#[test]
fn a_duplicate_key_is_invalid_never_last_wins() {
    let exp = experiment(1).to_string();
    let items = r#"{"data": [{"id": "o", "traceId": "t", "experimentId": "exp-1", "experimentItemId": "a",
        "scores": [{"name": "s", "dataType": "NUMERIC", "value": 0.1, "value": 0.9}]}], "meta": {}}"#;
    let msg = expect_invalid(from_langfuse_experiment(&exp, items, &meta(), &rules()));
    assert!(msg.contains("duplicate key"), "{msg}");
    let items = r#"{"data": [], "meta": {"cursor": null, "cursor": "more"}}"#;
    let msg = expect_invalid(from_langfuse_experiment(&experiment(0).to_string(), items, &meta(), &rules()));
    assert!(msg.contains("duplicate key"), "{msg}");
}

#[test]
fn an_error_level_item_is_an_error() {
    let mut i = item("a", vec![score("s", "NUMERIC", json!(1))]);
    i["level"] = json!("ERROR");
    let run = lfx(vec![i]).unwrap();
    assert_eq!(run.cases[0].status, CaseStatus::Error, "the task failed even if scored");
    for level in ["DEBUG", "DEFAULT", "WARNING"] {
        let mut i = item("a", vec![score("s", "NUMERIC", json!(1))]);
        i["level"] = json!(level);
        assert_eq!(lfx(vec![i]).unwrap().cases[0].status, CaseStatus::Pass, "{level}");
    }
}

// ── Scores ──────────────────────────────────────────────────────────────

#[test]
fn unscored_items_are_errors() {
    assert_eq!(one(vec![]).status, CaseStatus::Error);
    let mut i = item("a", vec![]);
    i["scores"] = Value::Null;
    let run = lfx(vec![i, item("b", vec![score("s", "NUMERIC", json!(1))])]).unwrap();
    assert_eq!(case(&run, "a").status, CaseStatus::Error);
    assert_eq!(case(&run, "b").status, CaseStatus::Pass);
    let c = one(vec![score("tone", "CATEGORICAL", json!("ok")), score("note", "TEXT", json!("t"))]);
    assert_eq!(c.status, CaseStatus::Error, "no numeric score");
    assert_eq!(one(vec![score("fix", "CORRECTION", json!(""))]).status, CaseStatus::Error);
}

#[test]
fn items_fetched_without_scores_are_invalid() {
    // fields=scores not requested: no item carries `scores` at all.
    let strip = |mut i: Value| {
        i.as_object_mut().unwrap().remove("scores");
        i
    };
    let msg = expect_invalid(lfx(vec![strip(item("a", vec![])), strip(item("b", vec![]))]));
    assert!(msg.contains("fields=") && msg.contains("scores"), "{msg}");
}

#[test]
fn possibly_truncated_scores_are_invalid() {
    // scoreLimit caps the scores returned per item at 50: a full list may be cut short.
    let full: Vec<Value> = (0..50).map(|n| score(&format!("s{n}"), "NUMERIC", json!(1))).collect();
    let msg = expect_invalid(lfx(vec![item("a", full)]));
    assert!(msg.contains("scoreLimit"), "{msg}");
    let almost: Vec<Value> = (0..49).map(|n| score(&format!("s{n}"), "NUMERIC", json!(1))).collect();
    assert_eq!(lfx(vec![item("a", almost)]).unwrap().cases[0].status, CaseStatus::Pass);
}

#[test]
fn numeric_and_boolean_values() {
    let c = one(vec![score("a", "NUMERIC", json!(0.25)), score("b", "BOOLEAN", json!(true))]);
    assert_eq!(c.status, CaseStatus::Fail);
    approx(c.score, 0.625);
    assert_eq!(c.metrics.get("score.b"), Some(&1.0));
    let c = one(vec![score("b", "BOOLEAN", json!(false))]);
    assert_eq!(c.status, CaseStatus::Fail);
    assert_eq!(c.metrics.get("score.b"), Some(&0.0));
}

#[test]
fn wrong_score_types_are_invalid() {
    for (bad, needle) in [
        (score("a", "NUMERIC", json!("0.9")), "expected a number"),
        (score("a", "NUMERIC", Value::Null), "expected a number"),
        (score("a", "BOOLEAN", json!(1)), "expected a bool"),
        (score("a", "BOOLEAN", json!("true")), "expected a bool"),
        (score("a", "SCALE", json!(1)), "unsupported dataType"),
        (score("a", "NUMERIC", json!(1.5)), "0..=1"),
        (score("a", "NUMERIC", json!(-0.1)), "0..=1"),
        (score("", "NUMERIC", json!(1)), "name"),
        (json!({"name": "a", "value": 1}), "dataType"),
        (json!({"name": "a", "value": 1, "dataType": 1}), "dataType"),
        (json!({"name": 1, "value": 1, "dataType": "NUMERIC"}), "name"),
        (json!("score"), "score object"),
    ] {
        let msg = expect_invalid(lfx(vec![item("c", vec![bad.clone()])]));
        assert!(msg.contains(needle), "{bad}: {needle:?} not in {msg}");
        assert!(msg.contains("\"c\""), "names the case: {msg}");
    }
}

#[test]
fn a_score_name_twice_on_one_item_is_invalid() {
    // e.g. a trace-level and an observation-level score with the same name.
    let msg = expect_invalid(lfx(vec![item("c", vec![score("a", "NUMERIC", json!(1)), score("a", "NUMERIC", json!(0))])]));
    assert!(msg.contains("more than once"), "{msg}");
}

#[test]
fn score_names_select_what_counts() {
    let scores = || vec![score("acc", "NUMERIC", json!(0.9)), score("user-feedback", "NUMERIC", json!(4))];
    // Every score counts by default: 4 is out of range.
    let msg = expect_invalid(lfx(vec![item("c", scores())]));
    assert!(msg.contains("user-feedback"), "{msg}");
    let only_acc = ScoreRules { score_names: vec!["acc".into()], ..rules() };
    let run = import(&experiment(1), &page(vec![item("c", scores())]), &only_acc).unwrap();
    assert_eq!(run.cases[0].status, CaseStatus::Pass);
    assert!(!run.cases[0].metrics.contains_key("score.user-feedback"));
    // Unselected scores are not validated, even with a bad type.
    let bad_other = vec![score("acc", "NUMERIC", json!(0.9)), score("x", "NUMERIC", json!("nope"))];
    assert_eq!(import(&experiment(1), &page(vec![item("c", bad_other)]), &only_acc).unwrap().cases[0].status, CaseStatus::Pass);
    // A selected score that is missing: no evidence.
    let acc_and_safety = ScoreRules { score_names: vec!["acc".into(), "safety".into()], ..rules() };
    let run = import(&experiment(1), &page(vec![item("c", scores())]), &acc_and_safety).unwrap();
    assert_eq!(run.cases[0].status, CaseStatus::Error);
}

#[test]
fn threshold_decides_pass_and_fail() {
    let items = || page(vec![item("c", vec![score("s", "NUMERIC", json!(0.7))])]);
    let at = |t: f64| ScoreRules { pass_threshold: t, ..rules() };
    assert_eq!(import(&experiment(1), &items(), &rules()).unwrap().cases[0].status, CaseStatus::Pass);
    assert_eq!(import(&experiment(1), &items(), &at(0.7)).unwrap().cases[0].status, CaseStatus::Pass, ">= passes");
    assert_eq!(import(&experiment(1), &items(), &at(0.71)).unwrap().cases[0].status, CaseStatus::Fail);
    for bad in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
        let msg = expect_invalid(import(&experiment(1), &items(), &at(bad)));
        assert!(msg.contains("threshold"), "{bad}: {msg}");
    }
}

#[test]
fn meta_must_produce_a_valid_run() {
    let m = ImportMeta { covers: vec![], ..meta() };
    let msg = expect_invalid(from_langfuse_experiment(
        &fixture("langfuse_experiment.json"),
        &fixture("langfuse_experiment_items.json"),
        &m,
        &rules(),
    ));
    assert!(msg.contains("covers"), "{msg}");
}

#[test]
fn run_hash_is_reproducible() {
    let a = from_langfuse_experiment(
        &fixture("langfuse_experiment.json"),
        &fixture("langfuse_experiment_items.json"),
        &meta(),
        &rules(),
    )
    .unwrap();
    let b = from_langfuse_experiment(
        &fixture("langfuse_experiment.json"),
        &fixture("langfuse_experiment_items.json"),
        &meta(),
        &rules(),
    )
    .unwrap();
    assert_eq!(a.run_hash(), b.run_hash());
}

proptest! {
    #[test]
    fn never_panics(exp in ".{0,200}", items in ".{0,400}") {
        let _ = from_langfuse_experiment(&exp, &items, &meta(), &rules());
    }

    #[test]
    fn never_panics_on_json_shaped_input(
        count in 0usize..4,
        cursor in proptest::option::of("[a-z]{0,3}"),
        value in prop_oneof![Just(json!(0.5)), Just(json!(true)), Just(json!("x")), Just(Value::Null), Just(json!(9))],
        data_type in prop_oneof![Just("NUMERIC"), Just("BOOLEAN"), Just("TEXT"), Just("WAT")],
    ) {
        let items = json!({"data": [item("a", vec![score("s", data_type, value)])], "meta": {"cursor": cursor}});
        let _ = import(&experiment(count), &items, &rules());
    }
}
