//! Contract tests for `cloakpipe_cert::import` (see the module doc comment).

use cloakpipe_cert::import::{from_json, from_junit, ImportError, ImportMeta};
use cloakpipe_cert::{
    CaseResult, CaseStatus, EvaluationRun, EvaluatorRef, RunSource, SourceKind, SuiteRef, API_VERSION, RUN_KIND,
};
use proptest::prelude::*;
use std::path::Path;

// ── Helpers ─────────────────────────────────────────────────────────────

fn release() -> String {
    format!("sha256:{}", "ae".repeat(32))
}

fn meta() -> ImportMeta {
    ImportMeta {
        run_id: "run-42".into(),
        release: release(),
        suite: SuiteRef { name: "support-critical".into(), version: "23".into() },
        covers: vec!["privacy".into(), "functional".into()],
        dataset: Some("support-golden@2026-09".into()),
        evaluators: vec![EvaluatorRef { name: "llm-judge".into(), version: "4".into() }],
        tool: Some("pytest".into()),
        critical: vec![],
    }
}

fn meta_critical(patterns: &[&str]) -> ImportMeta {
    ImportMeta { critical: patterns.iter().map(|p| p.to_string()).collect(), ..meta() }
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/import").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Wrap `<testcase>` markup in a minimal `<testsuites><testsuite>` document.
fn suite(cases: &str) -> String {
    format!(r#"<?xml version="1.0"?><testsuites><testsuite name="s">{cases}</testsuite></testsuites>"#)
}

fn import(xml: &str) -> EvaluationRun {
    from_junit(xml, &meta()).unwrap_or_else(|e| panic!("import failed: {e}\n{xml}"))
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

fn invalid(xml: &str, meta: &ImportMeta) -> String {
    match from_junit(xml, meta) {
        Err(ImportError::Invalid(issues)) => {
            assert!(!issues.is_empty(), "Invalid must carry at least one issue");
            issues.join("\n")
        }
        other => panic!("expected ImportError::Invalid, got {other:?}"),
    }
}

fn xml_error(xml: &str) -> String {
    match from_junit(xml, &meta()) {
        Err(ImportError::Xml(msg)) => msg,
        other => panic!("expected ImportError::Xml for {xml:?}, got {other:?}"),
    }
}

fn status_of(case_markup: &str) -> CaseStatus {
    import(&suite(case_markup)).cases[0].status
}

fn duration_of(time_attr: &str) -> Option<u64> {
    import(&suite(&format!(r#"<testcase name="t" time="{time_attr}"/>"#))).cases[0].duration_ms
}

// ── Realistic tool output ───────────────────────────────────────────────

#[test]
fn junit_pytest_fixture() {
    let run = from_junit(&fixture("pytest.xml"), &meta()).unwrap();
    assert_eq!(
        ids(&run),
        [
            "evals.test_refunds::test_requires_identity",
            "evals.test_refunds::test_refund_over_limit_escalates",
            "evals.test_privacy::test_no_pii_in_logs[email]",
            "evals.test_privacy::test_no_pii_in_logs[phone]",
            "evals.test_privacy::test_redacts_ssn",
            "evals.test_privacy::test_known_tokenizer_gap",
            "evals.test_trajectory::test_tool_order",
        ],
        "one case per <testcase>, in document order; CDATA markup is not a case"
    );

    let identity = case(&run, "evals.test_refunds::test_requires_identity");
    assert_eq!(identity.status, CaseStatus::Pass);
    assert!(identity.critical);
    assert_eq!(identity.score, Some(0.97));
    assert_eq!(identity.metrics.get("latency_ms"), Some(&412.5));
    assert_eq!(identity.metrics.get("cost_usd"), Some(&0.0031));
    assert_eq!(identity.metrics.len(), 2);
    assert_eq!(identity.duration_ms, Some(412));

    let escalate = case(&run, "evals.test_refunds::test_refund_over_limit_escalates");
    assert_eq!(escalate.status, CaseStatus::Fail);
    assert!(!escalate.critical);
    assert_eq!(escalate.score, None);
    assert_eq!(escalate.duration_ms, Some(1002));

    let email = case(&run, "evals.test_privacy::test_no_pii_in_logs[email]");
    assert_eq!(email.status, CaseStatus::Pass);
    assert_eq!(email.metrics.get("leaked_tokens"), Some(&0.0));
    assert_eq!(email.metrics.len(), 1, "non-cloakpipe properties are ignored");

    assert_eq!(case(&run, "evals.test_privacy::test_no_pii_in_logs[phone]").status, CaseStatus::Error);
    assert_eq!(case(&run, "evals.test_privacy::test_redacts_ssn").status, CaseStatus::Skipped);
    assert_eq!(case(&run, "evals.test_privacy::test_known_tokenizer_gap").status, CaseStatus::Skipped);
    let traj = case(&run, "evals.test_trajectory::test_tool_order");
    assert_eq!(traj.status, CaseStatus::Pass);
    assert_eq!(traj.duration_ms, Some(789));
    assert_eq!(run.validate(), Vec::<String>::new());
}

#[test]
fn junit_jest_fixture() {
    let run = from_junit(&fixture("jest.xml"), &meta()).unwrap();
    assert_eq!(run.cases.len(), 4);
    let id = "refund flow asks for identity before refunding::refund flow asks for identity before refunding";
    assert_eq!(case(&run, id).status, CaseStatus::Pass);
    assert_eq!(case(&run, id).duration_ms, Some(21));
    let twice = "refund flow never refunds twice::refund flow never refunds twice";
    assert_eq!(case(&run, twice).status, CaseStatus::Fail);
    let partial = "refund flow handles partial refunds::refund flow handles partial refunds";
    assert_eq!(case(&run, partial).status, CaseStatus::Skipped);
    assert_eq!(case(&run, partial).duration_ms, Some(0));
    assert_eq!(case(&run, "tone stays polite under abuse::tone stays polite under abuse").status, CaseStatus::Pass);
}

#[test]
fn junit_go_fixture() {
    let run = from_junit(&fixture("go.xml"), &meta()).unwrap();
    let pkg = "github.com/acme/agent/evals";
    assert_eq!(
        ids(&run),
        [
            format!("{pkg}::TestAuthorization"),
            format!("{pkg}::TestAuthorization/denies_cross_tenant"),
            format!("{pkg}::TestAuthorization/allows_owner"),
            format!("{pkg}::TestSideEffects"),
        ]
    );
    assert_eq!(case(&run, &format!("{pkg}::TestAuthorization/allows_owner")).status, CaseStatus::Fail);
    assert_eq!(case(&run, &format!("{pkg}::TestAuthorization/allows_owner")).duration_ms, Some(10));
    assert_eq!(case(&run, &format!("{pkg}::TestSideEffects")).status, CaseStatus::Skipped);
    assert!(
        run.cases.iter().all(|c| !c.critical),
        "suite-level <properties> must not mark cases critical"
    );
}

#[test]
fn junit_nextest_fixture() {
    let run = from_junit(&fixture("nextest.xml"), &meta()).unwrap();
    assert_eq!(
        ids(&run),
        [
            "agent-evals::policy::policy::blocks_wire_transfer",
            "agent-evals::policy::policy::flaky_retry_passes",
            "agent-evals::policy::policy::denies_export",
        ]
    );
    assert_eq!(run.cases[0].status, CaseStatus::Pass);
    assert_eq!(run.cases[1].status, CaseStatus::Pass, "flakyFailure is a pass on retry");
    assert_eq!(run.cases[2].status, CaseStatus::Fail);
    assert_eq!(run.cases[2].duration_ms, Some(100), "0.0995s rounds to 100ms");
}

// ── Run-level fields ────────────────────────────────────────────────────

#[test]
fn junit_run_fields_come_from_meta() {
    let run = import(&suite(r#"<testcase name="t"/>"#));
    assert_eq!(run.api_version, API_VERSION);
    assert_eq!(run.kind, RUN_KIND);
    assert_eq!(run.run_id, "run-42");
    assert_eq!(run.release, release());
    assert_eq!(run.suite, SuiteRef { name: "support-critical".into(), version: "23".into() });
    assert_eq!(run.covers, ["privacy", "functional"]);
    assert_eq!(run.dataset.as_deref(), Some("support-golden@2026-09"));
    assert_eq!(run.evaluators, [EvaluatorRef { name: "llm-judge".into(), version: "4".into() }]);
    assert_eq!(run.source, RunSource { kind: SourceKind::Junit, tool: Some("pytest".into()) });
}

#[test]
fn junit_source_tool_is_optional() {
    let m = ImportMeta { tool: None, dataset: None, evaluators: vec![], ..meta() };
    let run = from_junit(&suite(r#"<testcase name="t"/>"#), &m).unwrap();
    assert_eq!(run.source, RunSource { kind: SourceKind::Junit, tool: None });
    assert_eq!(run.dataset, None);
    assert!(run.evaluators.is_empty());
}

#[test]
fn junit_meta_must_produce_a_valid_run() {
    let m = ImportMeta { release: "support-agent@184".into(), covers: vec!["vibes".into()], ..meta() };
    let issues = invalid(&suite(r#"<testcase name="t"/>"#), &m);
    assert!(issues.contains("release"), "{issues}");
    assert!(issues.contains("unknown assurance suite"), "{issues}");

    let m = ImportMeta { run_id: " ".into(), covers: vec![], ..meta() };
    let issues = invalid(&suite(r#"<testcase name="t"/>"#), &m);
    assert!(issues.contains("runId"), "{issues}");
    assert!(issues.contains("covers"), "{issues}");

    let m = ImportMeta { suite: SuiteRef { name: "".into(), version: "1".into() }, ..meta() };
    assert!(invalid(&suite(""), &m).contains("suite"));
}

#[test]
fn junit_zero_cases_is_allowed() {
    assert!(import(r#"<testsuites/>"#).cases.is_empty());
    assert!(import(r#"<testsuites name="empty"></testsuites>"#).cases.is_empty());
    assert!(import(r#"<testsuite name="s" tests="0"/>"#).cases.is_empty());
}

#[test]
fn junit_run_hash_is_reproducible() {
    let a = from_junit(&fixture("pytest.xml"), &meta()).unwrap();
    let b = from_junit(&fixture("pytest.xml"), &meta()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.run_hash(), b.run_hash());
}

// ── Document shapes ─────────────────────────────────────────────────────

#[test]
fn junit_bare_testsuite_root() {
    let run = import(r#"<testsuite name="s"><testcase classname="c" name="a"/><testcase classname="c" name="b"/></testsuite>"#);
    assert_eq!(ids(&run), ["c::a", "c::b"]);
}

#[test]
fn junit_multiple_testsuites_in_order() {
    let run = import(
        r#"<testsuites>
             <testsuite name="one"><testcase classname="x" name="a"/></testsuite>
             <testsuite name="two"><testcase classname="y" name="b"/><testcase classname="y" name="c"/></testsuite>
           </testsuites>"#,
    );
    assert_eq!(ids(&run), ["x::a", "y::b", "y::c"]);
}

#[test]
fn junit_nested_testsuites_are_walked() {
    let run = import(
        r#"<testsuites>
             <testsuite name="outer">
               <testcase classname="o" name="first"/>
               <testsuite name="inner">
                 <testcase classname="i" name="deep"><failure/></testcase>
                 <testsuite name="innermost"><testcase classname="ii" name="deeper"/></testsuite>
               </testsuite>
               <testcase classname="o" name="last"/>
             </testsuite>
           </testsuites>"#,
    );
    assert_eq!(ids(&run), ["o::first", "i::deep", "ii::deeper", "o::last"]);
    assert_eq!(case(&run, "i::deep").status, CaseStatus::Fail);
}

#[test]
fn junit_nested_testsuite_under_bare_root() {
    let run = import(r#"<testsuite name="a"><testsuite name="b"><testcase name="t"/></testsuite></testsuite>"#);
    assert_eq!(ids(&run), ["t"]);
}

#[test]
fn junit_ignores_unrelated_elements_and_text() {
    let run = import(
        r#"<?xml version="1.0" encoding="UTF-8"?>
           <!-- generated by CI -->
           <?some-processing instruction?>
           <testsuites>
             <testsuite name="s">
               <properties><property name="cloakpipe.critical" value="true"/></properties>
               <system-out>noise &amp; more noise</system-out>
               <testcase classname="c" name="t" file="evals/t.py" line="12" assertions="3">
                 <system-out>ok</system-out>
                 <system-err><![CDATA[warn: <failure/>]]></system-err>
               </testcase>
               <system-err/>
             </testsuite>
           </testsuites>"#,
    );
    assert_eq!(ids(&run), ["c::t"]);
    assert_eq!(run.cases[0].status, CaseStatus::Pass);
    assert!(!run.cases[0].critical);
}

#[test]
fn junit_leading_bom_is_accepted() {
    let run = import(&format!("\u{feff}{}", suite(r#"<testcase name="t"/>"#)));
    assert_eq!(ids(&run), ["t"]);
}

#[test]
fn junit_doctype_is_tolerated() {
    let run = import(r#"<?xml version="1.0"?><!DOCTYPE testsuites><testsuites><testcase name="t"/></testsuites>"#);
    assert_eq!(ids(&run), ["t"]);
}

#[test]
fn junit_rejects_non_junit_root() {
    let issues = invalid(r#"<html><testcase name="t"/></html>"#, &meta());
    assert!(issues.contains("root"), "{issues}");
}

// ── Case identity ───────────────────────────────────────────────────────

#[test]
fn junit_case_id_from_classname_and_name() {
    let run = import(&suite(
        r#"<testcase classname="pkg.mod" name="test_a"/>
           <testcase name="no_class"/>
           <testcase classname="" name="empty_class"/>"#,
    ));
    assert_eq!(ids(&run), ["pkg.mod::test_a", "no_class", "empty_class"]);
}

#[test]
fn junit_case_id_decodes_entities_and_char_refs() {
    let run = import(&suite(
        r#"<testcase classname="a&amp;b" name="x &lt; y &gt; &quot;z&quot; &apos;w&apos; &#233;&#x2603;"/>"#,
    ));
    assert_eq!(ids(&run), ["a&b::x < y > \"z\" 'w' é☃"]);
}

#[test]
fn junit_case_id_preserves_unicode() {
    let run = import(&suite(r#"<testcase classname="évals" name="test_日本語[🦀]"/>"#));
    assert_eq!(ids(&run), ["évals::test_日本語[🦀]"]);
}

#[test]
fn junit_single_quoted_attributes() {
    let run = import(&suite(r#"<testcase classname='c' name='t' time='0.5'/>"#));
    assert_eq!(ids(&run), ["c::t"]);
    assert_eq!(run.cases[0].duration_ms, Some(500));
}

#[test]
fn junit_testcase_without_name_is_invalid() {
    let issues = invalid(&suite(r#"<testcase classname="c"/>"#), &meta());
    assert!(issues.contains("name"), "{issues}");
    let issues = invalid(&suite(r#"<testcase classname="c" name=""/>"#), &meta());
    assert!(issues.contains("name"), "{issues}");
}

#[test]
fn junit_duplicate_case_ids_are_invalid() {
    let issues = invalid(&suite(r#"<testcase classname="c" name="t"/><testcase classname="c" name="t"><failure/></testcase>"#), &meta());
    assert!(issues.contains("duplicate"), "{issues}");
    assert!(issues.contains("c::t"), "{issues}");
}

#[test]
fn junit_duplicate_ids_across_suites_are_invalid() {
    let xml = r#"<testsuites>
                   <testsuite name="a"><testcase name="t"/></testsuite>
                   <testsuite name="b"><testcase name="t"/></testsuite>
                 </testsuites>"#;
    assert!(invalid(xml, &meta()).contains("duplicate"));
}

#[test]
fn junit_same_name_different_classname_is_not_duplicate() {
    let run = import(&suite(r#"<testcase classname="a" name="t"/><testcase classname="b" name="t"/>"#));
    assert_eq!(ids(&run), ["a::t", "b::t"]);
}

#[test]
fn junit_nested_testcase_is_invalid() {
    let issues = invalid(&suite(r#"<testcase name="outer"><testcase name="inner"/></testcase>"#), &meta());
    assert!(issues.contains("testcase"), "{issues}");
}

// ── Status ──────────────────────────────────────────────────────────────

#[test]
fn junit_status_pass_by_default() {
    assert_eq!(status_of(r#"<testcase name="t"/>"#), CaseStatus::Pass);
    assert_eq!(status_of(r#"<testcase name="t"></testcase>"#), CaseStatus::Pass);
    assert_eq!(status_of(r#"<testcase name="t"><system-out>failure</system-out></testcase>"#), CaseStatus::Pass);
}

#[test]
fn junit_status_single_markers() {
    assert_eq!(status_of(r#"<testcase name="t"><failure message="boom">trace</failure></testcase>"#), CaseStatus::Fail);
    assert_eq!(status_of(r#"<testcase name="t"><failure/></testcase>"#), CaseStatus::Fail);
    assert_eq!(status_of(r#"<testcase name="t"><error type="Timeout"/></testcase>"#), CaseStatus::Error);
    assert_eq!(status_of(r#"<testcase name="t"><error>crash</error></testcase>"#), CaseStatus::Error);
    assert_eq!(status_of(r#"<testcase name="t"><skipped/></testcase>"#), CaseStatus::Skipped);
    assert_eq!(status_of(r#"<testcase name="t"><skipped message="later">why</skipped></testcase>"#), CaseStatus::Skipped);
}

#[test]
fn junit_status_precedence_error_over_failure_over_skipped() {
    let cases = [
        ("<failure/><error/>", CaseStatus::Error),
        ("<error/><failure/>", CaseStatus::Error),
        ("<skipped/><error/>", CaseStatus::Error),
        ("<error/><skipped/>", CaseStatus::Error),
        ("<skipped/><failure/><error/>", CaseStatus::Error),
        ("<error/><failure/><skipped/>", CaseStatus::Error),
        ("<skipped/><failure/>", CaseStatus::Fail),
        ("<failure/><skipped/>", CaseStatus::Fail),
        ("<failure/><failure/>", CaseStatus::Fail),
        ("<skipped/><skipped/>", CaseStatus::Skipped),
    ];
    for (children, expected) in cases {
        let markup = format!(r#"<testcase name="t">{children}</testcase>"#);
        assert_eq!(status_of(&markup), expected, "{children}");
    }
}

#[test]
fn junit_status_markers_only_count_as_direct_children() {
    // A <failure> nested inside <system-out> or inside a retry record is not
    // this case's status.
    assert_eq!(
        status_of(r#"<testcase name="t"><flakyFailure><failure/></flakyFailure><rerunError><error/></rerunError></testcase>"#),
        CaseStatus::Pass
    );
    // And markers outside a testcase are ignored.
    let run = import(r#"<testsuites><testsuite name="s"><failure/><error/><testcase name="t"/></testsuite></testsuites>"#);
    assert_eq!(run.cases[0].status, CaseStatus::Pass);
}

// ── Duration ────────────────────────────────────────────────────────────

#[test]
fn junit_time_rounds_to_nearest_ms() {
    assert_eq!(duration_of("0"), Some(0));
    assert_eq!(duration_of("0.000"), Some(0));
    assert_eq!(duration_of("0.0004"), Some(0));
    assert_eq!(duration_of("0.0006"), Some(1));
    assert_eq!(duration_of("0.001"), Some(1));
    assert_eq!(duration_of("1.2344"), Some(1234));
    assert_eq!(duration_of("1.2346"), Some(1235));
    assert_eq!(duration_of("2"), Some(2000));
    assert_eq!(duration_of("12.5"), Some(12500));
    assert_eq!(duration_of("3600.25"), Some(3_600_250));
    assert_eq!(duration_of("1e-3"), Some(1));
    assert_eq!(duration_of(" 0.25 "), Some(250), "surrounding whitespace is tolerated");
}

#[test]
fn junit_time_absent_or_unparseable_is_none() {
    assert_eq!(import(&suite(r#"<testcase name="t"/>"#)).cases[0].duration_ms, None);
    for bad in ["", "abc", "1,234.5", "1.2s", "NaN", "inf", "-inf", "-1", "-0.5", "1e400", "0x10"] {
        assert_eq!(duration_of(bad), None, "time={bad:?}");
    }
}

// ── Properties ──────────────────────────────────────────────────────────

fn with_props(props: &str) -> String {
    suite(&format!(r#"<testcase name="t"><properties>{props}</properties></testcase>"#))
}

#[test]
fn junit_property_critical() {
    let run = import(&with_props(r#"<property name="cloakpipe.critical" value="true"/>"#));
    assert!(run.cases[0].critical);
    let run = import(&with_props(r#"<property name="cloakpipe.critical" value="false"/>"#));
    assert!(!run.cases[0].critical);
}

#[test]
fn junit_property_critical_rejects_other_values() {
    for bad in ["yes", "1", "TRUE", ""] {
        let issues = invalid(&with_props(&format!(r#"<property name="cloakpipe.critical" value="{bad}"/>"#)), &meta());
        assert!(issues.contains("cloakpipe.critical"), "{bad:?}: {issues}");
    }
}

#[test]
fn junit_property_score_and_metrics() {
    let run = import(&with_props(
        r#"<property name="cloakpipe.score" value="0.875"/>
           <property name="cloakpipe.metric.latency_ms" value="1200"/>
           <property name="cloakpipe.metric.tokens.out" value="-3.5e2"/>
           <property name="cloakpipe.metric.Recall@5" value="1"/>"#,
    ));
    let c = &run.cases[0];
    assert_eq!(c.score, Some(0.875));
    assert_eq!(c.metrics.get("latency_ms"), Some(&1200.0));
    assert_eq!(c.metrics.get("tokens.out"), Some(&-350.0), "metric names may contain dots");
    assert_eq!(c.metrics.get("Recall@5"), Some(&1.0));
    assert_eq!(c.metrics.len(), 3);
}

#[test]
fn junit_property_numeric_values_must_be_finite_numbers() {
    for bad in ["NaN", "nan", "inf", "-inf", "infinity", "1e400", "abc", "", "0.5.1", "1,5"] {
        for prop in ["cloakpipe.score", "cloakpipe.metric.latency_ms"] {
            let xml = with_props(&format!(r#"<property name="{prop}" value="{bad}"/>"#));
            let issues = invalid(&xml, &meta());
            assert!(issues.contains(prop), "{prop}={bad:?}: {issues}");
        }
    }
}

#[test]
fn junit_property_without_value_is_invalid_for_cloakpipe_keys() {
    let issues = invalid(&with_props(r#"<property name="cloakpipe.score"/>"#), &meta());
    assert!(issues.contains("cloakpipe.score"), "{issues}");
}

#[test]
fn junit_property_empty_metric_name_is_invalid() {
    let issues = invalid(&with_props(r#"<property name="cloakpipe.metric." value="1"/>"#), &meta());
    assert!(issues.contains("cloakpipe.metric."), "{issues}");
}

#[test]
fn junit_property_duplicates_are_invalid() {
    let issues = invalid(
        &with_props(r#"<property name="cloakpipe.score" value="0.1"/><property name="cloakpipe.score" value="0.9"/>"#),
        &meta(),
    );
    assert!(issues.contains("cloakpipe.score"), "{issues}");
    let issues = invalid(
        &with_props(r#"<property name="cloakpipe.metric.m" value="1"/><property name="cloakpipe.metric.m" value="2"/>"#),
        &meta(),
    );
    assert!(issues.contains("cloakpipe.metric.m"), "{issues}");
}

#[test]
fn junit_property_errors_name_the_case_and_are_all_reported() {
    let xml = suite(
        r#"<testcase classname="c" name="one"><properties><property name="cloakpipe.score" value="x"/></properties></testcase>
           <testcase classname="c" name="two"><properties><property name="cloakpipe.metric.m" value="NaN"/></properties></testcase>"#,
    );
    let issues = invalid(&xml, &meta());
    assert!(issues.contains("c::one"), "{issues}");
    assert!(issues.contains("c::two"), "{issues}");
}

#[test]
fn junit_unknown_properties_are_ignored() {
    let run = import(&with_props(
        r#"<property name="ci.shard" value="3"/>
           <property name="cloakpipe.unknown" value="whatever"/>
           <property name="cloakpipe" value="x"/>
           <property name="cloakpipe.criticality" value="high"/>
           <property name="cloakpipe.scores" value="nope"/>
           <property name="metric.latency" value="NaN"/>
           <property value="no name"/>
           <property name="testrail_id">C1234</property>"#,
    ));
    let c = &run.cases[0];
    assert!(!c.critical);
    assert_eq!(c.score, None);
    assert!(c.metrics.is_empty());
}

#[test]
fn junit_property_values_decode_entities() {
    let run = import(&with_props(r#"<property name="cloakpipe.metric.a&amp;b" value="&#49;.5"/>"#));
    assert_eq!(run.cases[0].metrics.get("a&b"), Some(&1.5));
}

#[test]
fn junit_property_values_tolerate_surrounding_whitespace() {
    let run = import(&with_props(
        r#"<property name="cloakpipe.score" value=" 0.5 "/><property name="cloakpipe.critical" value=" true "/>"#,
    ));
    assert_eq!(run.cases[0].score, Some(0.5));
    assert!(run.cases[0].critical);
}

#[test]
fn junit_properties_outside_case_properties_are_ignored() {
    // A property element that is a direct child of <testcase>, or nested in
    // output, is not a case property.
    let run = import(&suite(
        r#"<testcase name="t">
             <property name="cloakpipe.critical" value="true"/>
             <system-out><properties><property name="cloakpipe.score" value="1"/></properties></system-out>
           </testcase>"#,
    ));
    assert!(!run.cases[0].critical);
    assert_eq!(run.cases[0].score, None);
}

#[test]
fn junit_properties_apply_to_their_own_case_only() {
    let run = import(&suite(
        r#"<testcase name="a"><properties><property name="cloakpipe.critical" value="true"/><property name="cloakpipe.metric.m" value="1"/></properties></testcase>
           <testcase name="b"/>"#,
    ));
    assert!(case(&run, "a").critical);
    assert!(!case(&run, "b").critical);
    assert!(case(&run, "b").metrics.is_empty());
}

#[test]
fn junit_properties_with_status_markers() {
    let run = import(&suite(
        r#"<testcase name="t" time="0.1">
             <failure message="x"/>
             <properties><property name="cloakpipe.score" value="0.2"/></properties>
           </testcase>"#,
    ));
    assert_eq!(run.cases[0].status, CaseStatus::Fail);
    assert_eq!(run.cases[0].score, Some(0.2));
    assert_eq!(run.cases[0].duration_ms, Some(100));
}

// ── Critical patterns ───────────────────────────────────────────────────

#[test]
fn junit_critical_patterns_exact_and_prefix() {
    let xml = suite(
        r#"<testcase classname="refunds" name="requires_identity"/>
           <testcase classname="refunds" name="requires_identity_twice"/>
           <testcase classname="privacy" name="redacts_ssn"/>
           <testcase classname="privacy" name="redacts_email"/>
           <testcase classname="tone" name="polite"/>"#,
    );
    let run = from_junit(&xml, &meta_critical(&["refunds::requires_identity", "privacy::*"])).unwrap();
    assert!(case(&run, "refunds::requires_identity").critical, "exact match");
    assert!(!case(&run, "refunds::requires_identity_twice").critical, "exact is not prefix");
    assert!(case(&run, "privacy::redacts_ssn").critical, "prefix match");
    assert!(case(&run, "privacy::redacts_email").critical, "prefix match");
    assert!(!case(&run, "tone::polite").critical);
}

#[test]
fn junit_critical_star_matches_everything() {
    let run = from_junit(&fixture("pytest.xml"), &meta_critical(&["*"])).unwrap();
    assert!(run.cases.iter().all(|c| c.critical));
}

#[test]
fn junit_critical_pattern_star_only_at_end_is_wildcard() {
    let xml = suite(r#"<testcase name="a*b"/><testcase name="axb"/>"#);
    let run = from_junit(&xml, &meta_critical(&["a*b"])).unwrap();
    assert!(case(&run, "a*b").critical, "inner * is literal");
    assert!(!case(&run, "axb").critical);
}

#[test]
fn junit_critical_pattern_is_case_sensitive_and_unanchored_only_at_end() {
    let xml = suite(r#"<testcase classname="x" name="Refunds"/><testcase classname="pre" name="refunds"/>"#);
    let run = from_junit(&xml, &meta_critical(&["refunds*", "x::refunds"])).unwrap();
    assert!(!case(&run, "x::Refunds").critical);
    assert!(!case(&run, "pre::refunds").critical, "prefix match is anchored at the start");
}

#[test]
fn junit_critical_pattern_or_property() {
    let xml = suite(
        r#"<testcase name="by_pattern"><properties><property name="cloakpipe.critical" value="false"/></properties></testcase>
           <testcase name="by_property"><properties><property name="cloakpipe.critical" value="true"/></properties></testcase>
           <testcase name="neither"/>"#,
    );
    let run = from_junit(&xml, &meta_critical(&["by_pattern"])).unwrap();
    assert!(case(&run, "by_pattern").critical, "a pattern marks critical even if the property says false");
    assert!(case(&run, "by_property").critical);
    assert!(!case(&run, "neither").critical);
}

// ── Malformed XML ───────────────────────────────────────────────────────

#[test]
fn junit_malformed_xml_is_an_xml_error() {
    let bad = [
        "",
        "   ",
        "not xml at all",
        "<testsuites>",
        "<testsuites><testsuite name=\"s\"><testcase name=\"t\"></testsuite></testsuites>",
        "<testsuites></testsuite>",
        "<testsuites><testcase name=\"t\"/></testsuites></testsuites>",
        "<testsuites><testcase name=\"t></testsuites>",
        "<testsuites><testcase name=t/></testsuites>",
        "<testsuites><testcase name=\"a\" name=\"b\"/></testsuites>",
        "<testsuites><testcase name=\"a &bogus; b\"/></testsuites>",
        "<testsuites><testcase name=\"a & b\"/></testsuites>",
        "<testsuites><testcase name=\"a < b\"/></testsuites>",
        "<testsuites/><testsuites/>",
        "<testsuites/>trailing",
        "leading<testsuites/>",
        "<testsuites><![CDATA[unterminated</testsuites>",
        "<testsuites><!-- unterminated </testsuites>",
        "<testsuites><testcase name=\"t\"><failure></testcase></testsuites>",
    ];
    for xml in bad {
        let msg = xml_error(xml);
        assert!(!msg.is_empty(), "{xml:?}");
    }
}

#[test]
fn junit_error_display_is_informative() {
    let err = from_junit("<testsuites>", &meta()).unwrap_err();
    assert!(err.to_string().starts_with("malformed XML:"), "{err}");
    let err = from_junit(&suite(r#"<testcase name="t"/><testcase name="t"/>"#), &meta()).unwrap_err();
    assert!(err.to_string().starts_with("invalid evaluation run:"), "{err}");
}

#[test]
fn junit_entity_expansion_is_not_performed() {
    // Custom DTD entities are not expanded (no billion-laughs); using one in
    // an attribute is an error, never a hang or a panic.
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<testsuites><testcase name="&lol3;"/></testsuites>"#;
    assert!(from_junit(xml, &meta()).is_err());
}

#[test]
fn junit_entities_in_ignored_text_are_harmless() {
    let run = import(&suite(r#"<testcase name="t"><failure>expected &lt;a&gt; &amp; got &#x26;</failure></testcase>"#));
    assert_eq!(run.cases[0].status, CaseStatus::Fail);
}

#[test]
fn junit_cdata_is_opaque() {
    let run = import(&suite(
        r#"<testcase name="t"><system-out><![CDATA[</testcase><testcase name="fake"><failure/>]]></system-out></testcase>"#,
    ));
    assert_eq!(ids(&run), ["t"]);
    assert_eq!(run.cases[0].status, CaseStatus::Pass);
}

#[test]
fn junit_deep_nesting_does_not_panic() {
    let depth = 20_000;
    let xml = format!("<testsuites>{}{}</testsuites>", "<testsuite>".repeat(depth), "</testsuite>".repeat(depth));
    assert!(import(&xml).cases.is_empty());
    let xml = format!("<testsuites>{}", "<testsuite>".repeat(depth));
    let _ = xml_error(&xml);
}

#[test]
fn junit_many_cases() {
    let cases: String = (0..5_000).map(|i| format!(r#"<testcase classname="c" name="t{i}" time="0.001"/>"#)).collect();
    let run = import(&suite(&cases));
    assert_eq!(run.cases.len(), 5_000);
    assert_eq!(run.cases[4_999].id, "c::t4999");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn junit_never_panics_on_arbitrary_input(s in "\\PC*") {
        let _ = from_junit(&s, &meta());
    }

    #[test]
    fn junit_never_panics_on_xmlish_input(
        parts in proptest::collection::vec(
            prop_oneof![
                Just("<testsuites>".to_string()), Just("</testsuites>".to_string()),
                Just("<testsuite name=\"s\">".to_string()), Just("</testsuite>".to_string()),
                Just("<testcase name=\"t\">".to_string()), Just("</testcase>".to_string()),
                Just("<testcase classname=\"c\" name=\"u\" time=\"1e309\"/>".to_string()),
                Just("<failure/>".to_string()), Just("<error/>".to_string()), Just("<skipped/>".to_string()),
                Just("<properties>".to_string()), Just("</properties>".to_string()),
                Just("<property name=\"cloakpipe.score\" value=\"NaN\"/>".to_string()),
                Just("<property name=\"cloakpipe.metric.x\" value=\"1\"/>".to_string()),
                Just("<![CDATA[x]]>".to_string()), Just("&amp;".to_string()), Just("&nope;".to_string()),
                "[a-z<>/=\"& ]{0,8}",
            ],
            0..24,
        )
    ) {
        let _ = from_junit(&parts.concat(), &meta());
    }

    #[test]
    fn junit_time_roundtrips_whole_milliseconds(ms in 0u64..10_000_000) {
        let secs = format!("{}.{:03}", ms / 1000, ms % 1000);
        prop_assert_eq!(duration_of(&secs), Some(ms));
    }

    #[test]
    fn junit_ids_roundtrip_through_escaping(class in "[^\u{0}-\u{1f}]{0,12}", name in "[^\u{0}-\u{1f}]{1,12}") {
        let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('"', "&quot;");
        let xml = suite(&format!(r#"<testcase classname="{}" name="{}"/>"#, esc(&class), esc(&name)));
        // Attribute-value normalisation is the only transformation.
        let run = from_junit(&xml, &meta());
        if name.trim().is_empty() {
            prop_assert!(run.is_err());
        } else {
            let run = run.unwrap();
            let expected = if class.is_empty() { name.clone() } else { format!("{class}::{name}") };
            prop_assert_eq!(&run.cases[0].id, &expected);
        }
    }
}

// ── Native JSON ─────────────────────────────────────────────────────────

#[test]
fn json_fixture_roundtrips() {
    let run = from_json(&fixture("run.json")).unwrap();
    assert_eq!(run.run_id, "support-critical-2026-10-05-1");
    assert_eq!(run.source, RunSource { kind: SourceKind::Native, tool: None });
    assert_eq!(run.cases.len(), 3);
    assert!(run.cases[0].critical);
    assert_eq!(run.cases[0].duration_ms, Some(412));
    assert_eq!(run.cases[2].status, CaseStatus::Skipped);
    let again = from_json(&serde_json::to_string(&run).unwrap()).unwrap();
    assert_eq!(run, again);
    assert_eq!(run.run_hash(), again.run_hash());
}

#[test]
fn json_matches_equivalent_junit_import() {
    let run = from_junit(&fixture("pytest.xml"), &meta()).unwrap();
    let json = serde_json::to_string_pretty(&run).unwrap();
    assert_eq!(from_json(&json).unwrap(), run);
}

#[test]
fn json_rejects_unknown_fields() {
    let mut v: serde_json::Value = serde_json::from_str(&fixture("run.json")).unwrap();
    v["extra"] = serde_json::json!(1);
    assert!(matches!(from_json(&v.to_string()), Err(ImportError::Json(_))));

    let mut v: serde_json::Value = serde_json::from_str(&fixture("run.json")).unwrap();
    v["cases"][0]["weight"] = serde_json::json!(2);
    assert!(matches!(from_json(&v.to_string()), Err(ImportError::Json(_))));
}

#[test]
fn json_rejects_snake_case_fields() {
    let json = fixture("run.json").replace("\"runId\"", "\"run_id\"");
    assert!(matches!(from_json(&json), Err(ImportError::Json(_))));
}

#[test]
fn json_malformed_is_a_json_error() {
    for bad in ["", "{", "[]", "null", "{\"apiVersion\": 1}", "not json"] {
        assert!(matches!(from_json(bad), Err(ImportError::Json(_))), "{bad:?}");
    }
    let err = from_json("{").unwrap_err();
    assert!(err.to_string().starts_with("malformed JSON:"), "{err}");
}

#[test]
fn json_rejects_unknown_status() {
    let json = fixture("run.json").replace("\"fail\"", "\"flaky\"");
    assert!(matches!(from_json(&json), Err(ImportError::Json(_))));
}

#[test]
fn json_structurally_invalid_run_is_invalid() {
    let mut v: serde_json::Value = serde_json::from_str(&fixture("run.json")).unwrap();
    v["apiVersion"] = serde_json::json!("cloakpipe.dev/v0");
    v["release"] = serde_json::json!("support-agent@184");
    v["covers"] = serde_json::json!(["vibes"]);
    v["cases"][1]["id"] = serde_json::json!("refunds::requires_identity");
    match from_json(&v.to_string()) {
        Err(ImportError::Invalid(issues)) => {
            let all = issues.join("\n");
            assert!(all.contains("apiVersion"), "{all}");
            assert!(all.contains("release"), "{all}");
            assert!(all.contains("unknown assurance suite"), "{all}");
            assert!(all.contains("duplicate case id"), "{all}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn json_zero_cases_is_allowed() {
    let mut v: serde_json::Value = serde_json::from_str(&fixture("run.json")).unwrap();
    v["cases"] = serde_json::json!([]);
    assert!(from_json(&v.to_string()).unwrap().cases.is_empty());
}

#[test]
fn json_keeps_source_as_given() {
    let mut v: serde_json::Value = serde_json::from_str(&fixture("run.json")).unwrap();
    v["source"] = serde_json::json!({"kind": "braintrust", "tool": "braintrust-cli"});
    let run = from_json(&v.to_string()).unwrap();
    assert_eq!(run.source, RunSource { kind: SourceKind::Braintrust, tool: Some("braintrust-cli".into()) });
}

proptest! {
    #[test]
    fn json_never_panics(s in "\\PC*") {
        let _ = from_json(&s);
    }
}
