//! Cedar evaluation of one tool call: entities, context, decisions,
//! `@id` / `@approval` annotations and fail-closed errors.

use cloakpipe_policy::{CallInput, PolicyDecision, PolicyEngine, PolicyError, Window};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// 2026-10-27T14:30:00Z, a Tuesday.
const NOW: i64 = 1_793_111_400;

fn counters(pairs: &[(&str, i64, i64)]) -> BTreeMap<String, Window> {
    pairs.iter().map(|(t, h, d)| (t.to_string(), Window { last_1h: *h, last_24h: *d })).collect()
}

fn eval(src: &str, tool: &str, args: Value) -> Result<PolicyDecision, PolicyError> {
    eval_with(src, tool, args, &counters(&[]))
}

fn eval_with(src: &str, tool: &str, args: Value, c: &BTreeMap<String, Window>) -> Result<PolicyDecision, PolicyError> {
    let engine = PolicyEngine::parse(src).unwrap();
    let task = json!({"taskId": "t-1042", "ticket": {"id": "T-1042", "customer_email": "dana@customer.example"}});
    engine.evaluate(&CallInput {
        release: "support-agent",
        tool,
        fingerprint: "sha256:00",
        args: Some(&args),
        task: Some(&task),
        counters: c,
        now_unix: NOW,
    })
}

fn allow(ids: &[&str]) -> PolicyDecision {
    PolicyDecision::Allow { policies: ids.iter().map(|s| s.to_string()).collect() }
}

fn deny(ids: &[&str]) -> PolicyDecision {
    PolicyDecision::Deny { policies: ids.iter().map(|s| s.to_string()).collect() }
}

#[test]
fn a_parse_error_is_refused() {
    assert!(matches!(PolicyEngine::parse("permit (principal, action, resource"), Err(PolicyError::Parse(_))));
    assert!(matches!(PolicyEngine::parse("this is not cedar;"), Err(PolicyError::Parse(_))));
    // The message says where.
    let err = PolicyEngine::parse("permit (principal, action, resource);\n\nforbid (principal, action, resource) when { ; };").unwrap_err();
    assert!(err.to_string().contains("line 3"), "{err}");
}

#[test]
fn templates_and_duplicate_ids_are_refused() {
    let template = "permit (principal == ?principal, action, resource);";
    assert!(matches!(PolicyEngine::parse(template), Err(PolicyError::Parse(_))));
    let dup = "@id(\"a\") permit (principal, action, resource);\n@id(\"a\") forbid (principal, action, resource);";
    assert!(matches!(PolicyEngine::parse(dup), Err(PolicyError::Parse(_))));
}

#[test]
fn policy_ids_come_from_id_annotations() {
    let e = PolicyEngine::parse("@id(\"reads\") permit (principal, action, resource);\npermit (principal, action, resource);").unwrap();
    assert_eq!(e.policy_ids(), vec!["policy1".to_string(), "reads".to_string()]);
}

#[test]
fn nothing_permits_means_deny() {
    let src = "@id(\"reads\") permit (principal, action == Action::\"read_ticket\", resource);";
    assert_eq!(eval(src, "read_ticket", json!({})).unwrap(), allow(&["reads"]));
    assert_eq!(eval(src, "send_email", json!({})).unwrap(), deny(&[]));
    assert_eq!(eval("", "read_ticket", json!({})).unwrap(), deny(&[]));
}

#[test]
fn a_satisfied_forbid_wins_and_is_reported() {
    let src = "@id(\"all\") permit (principal, action, resource);\n\
               @id(\"no-export\") forbid (principal, action == Action::\"export\", resource);";
    assert_eq!(eval(src, "export", json!({})).unwrap(), deny(&["no-export"]));
    assert_eq!(eval(src, "read_ticket", json!({})).unwrap(), allow(&["all"]));
}

#[test]
fn the_principal_is_the_release() {
    let src = "permit (principal == Release::\"support-agent\", action, resource);\n\
               @id(\"other\") permit (principal == Release::\"billing-agent\", action, resource);";
    assert_eq!(eval(src, "read_ticket", json!({})).unwrap(), allow(&["policy0"]));
}

#[test]
fn the_spec_tool_spelling_is_accepted_for_actions() {
    // `Tool::"name"` (the spec's spelling) and `Action::"name"` name the same tool.
    let src = "@id(\"t\") permit (principal, action == Tool::\"read_ticket\", resource);";
    assert_eq!(eval(src, "read_ticket", json!({})).unwrap(), allow(&["t"]));
    assert_eq!(eval(src, "send_email", json!({})).unwrap(), deny(&[]));
    let src = "@id(\"t\") permit (principal, action in [Tool::\"read_ticket\", Tool::\"send_email\"], resource);";
    assert_eq!(eval(src, "send_email", json!({})).unwrap(), allow(&["t"]));
    // Inside a string literal it is left alone.
    let src = "@id(\"t\") permit (principal, action, resource) when { resource.args.note == \"Tool::\\\"x\\\"\" };";
    assert_eq!(eval(src, "read_ticket", json!({"note": "Tool::\"x\""})).unwrap(), allow(&["t"]));
}

#[test]
fn arguments_are_a_record_on_the_call() {
    let src = "@id(\"small\") permit (principal, action == Action::\"issue_refund\", resource)\n\
               when { resource.args.amount <= 100 && resource.args.ticket_id == context.task.ticket.id };";
    assert_eq!(eval(src, "issue_refund", json!({"ticket_id": "T-1042", "amount": 40})).unwrap(), allow(&["small"]));
    assert_eq!(eval(src, "issue_refund", json!({"ticket_id": "T-1042", "amount": 140})).unwrap(), deny(&[]));
    assert_eq!(eval(src, "issue_refund", json!({"ticket_id": "T-9", "amount": 40})).unwrap(), deny(&[]));
    let nested = "@id(\"n\") permit (principal, action, resource)\n\
                  when { resource.args.to.contains(\"a@b.example\") && resource.args.meta.urgent && !(resource.args has gone) };";
    let args = json!({"to": ["a@b.example", "c@d.example"], "meta": {"urgent": true}, "gone": null});
    assert_eq!(eval(nested, "send_email", args).unwrap(), allow(&["n"]));
}

#[test]
fn fractional_numbers_are_decimals() {
    let src = "@id(\"d\") permit (principal, action, resource) when { resource.args.amount.lessThanOrEqual(decimal(\"100.0\")) };";
    assert_eq!(eval(src, "issue_refund", json!({"amount": 99.5})).unwrap(), allow(&["d"]));
    assert_eq!(eval(src, "issue_refund", json!({"amount": 100.25})).unwrap(), deny(&[]));
}

#[test]
fn argument_values_cannot_forge_entities_or_extensions() {
    let src = "@id(\"own\") permit (principal, action, resource) when { resource.args.owner == principal };";
    let forged = json!({"owner": {"__entity": {"type": "Release", "id": "support-agent"}}});
    assert_eq!(eval(src, "read_ticket", forged).unwrap(), deny(&[]));
    let src = "@id(\"x\") permit (principal, action, resource) when { resource.args.v has __extn };";
    let ext = json!({"v": {"__extn": {"fn": "decimal", "arg": "1.0"}}});
    assert_eq!(eval(src, "read_ticket", ext).unwrap(), allow(&["x"]));
}

#[test]
fn counters_are_in_the_context() {
    let src = "@id(\"all\") permit (principal, action, resource);\n\
               @id(\"rate\") forbid (principal, action == Action::\"send_email\", resource)\n\
               when { context.counters.send_email_1h >= 50 || context.counters[\"send_email_24h\"] >= 400 };";
    let c = counters(&[("send_email", 49, 49), ("read_ticket", 900, 900)]);
    assert_eq!(eval_with(src, "send_email", json!({}), &c).unwrap(), allow(&["all"]));
    let c = counters(&[("send_email", 50, 50)]);
    assert_eq!(eval_with(src, "send_email", json!({}), &c).unwrap(), deny(&["rate"]));
    let c = counters(&[("send_email", 3, 400)]);
    assert_eq!(eval_with(src, "send_email", json!({}), &c).unwrap(), deny(&["rate"]));
}

#[test]
fn time_is_in_the_context() {
    // NOW is a Tuesday (ISO weekday 2), 14:30 UTC.
    let src = format!(
        "@id(\"t\") permit (principal, action, resource) when {{ context.time.unix == {NOW} && context.time.hour_utc == 14 && context.time.weekday == 2 }};"
    );
    assert_eq!(eval(&src, "read_ticket", json!({})).unwrap(), allow(&["t"]));
}

#[test]
fn approval_annotations_require_approval_when_every_satisfied_permit_has_one() {
    let src = "@id(\"small\") permit (principal, action == Action::\"issue_refund\", resource) when { resource.args.amount <= 100 };\n\
               @id(\"large\") @approval(\"slack:#support-leads\") permit (principal, action == Action::\"issue_refund\", resource)\n\
               when { resource.args.amount > 100 && resource.args.amount <= 500 };\n\
               @id(\"large-finance\") @approval(\"email:finance@ourcompany.com\") permit (principal, action == Action::\"issue_refund\", resource)\n\
               when { resource.args.amount > 300 && resource.args.amount <= 500 };";
    assert_eq!(eval(src, "issue_refund", json!({"amount": 50})).unwrap(), allow(&["small"]));
    assert_eq!(
        eval(src, "issue_refund", json!({"amount": 150})).unwrap(),
        PolicyDecision::RequireApproval { approvers: vec!["slack:#support-leads".into()], policies: vec!["large".into()] }
    );
    assert_eq!(
        eval(src, "issue_refund", json!({"amount": 400})).unwrap(),
        PolicyDecision::RequireApproval {
            approvers: vec!["slack:#support-leads".into(), "email:finance@ourcompany.com".into()],
            policies: vec!["large".into(), "large-finance".into()],
        }
    );
    assert_eq!(eval(src, "issue_refund", json!({"amount": 600})).unwrap(), deny(&[]));
    // One satisfied permit without @approval is enough to allow.
    let src = "@id(\"a\") @approval(\"x\") permit (principal, action, resource);\n@id(\"b\") permit (principal, action, resource);";
    assert_eq!(eval(src, "issue_refund", json!({})).unwrap(), allow(&["a", "b"]));
}

#[test]
fn an_evaluation_error_fails_closed() {
    let src = "@id(\"small\") permit (principal, action, resource) when { resource.args.amount <= 100 };";
    match eval(src, "issue_refund", json!({"amount": "lots"})) {
        Err(PolicyError::Evaluation { policies }) => assert_eq!(policies, vec!["small".to_string()]),
        other => panic!("expected an evaluation error, got {other:?}"),
    }
    // A missing attribute is an error too, even next to a permit that holds.
    let src = "@id(\"all\") permit (principal, action, resource);\n@id(\"f\") forbid (principal, action, resource) when { resource.args.nope == 1 };";
    assert!(matches!(eval(src, "read_ticket", json!({})), Err(PolicyError::Evaluation { .. })));
    // A number Cedar cannot hold is an input error.
    let src = "permit (principal, action, resource);";
    assert!(matches!(eval(src, "read_ticket", json!({"n": u64::MAX})), Err(PolicyError::Input(_))));
    assert!(matches!(eval(src, "read_ticket", json!({"n": 1.0e-9})), Err(PolicyError::Input(_))));
}

#[test]
fn errors_never_carry_argument_values() {
    let src = "@id(\"small\") permit (principal, action, resource) when { resource.args.amount <= 100 };";
    let err = eval(src, "issue_refund", json!({"amount": "secret-value-123"})).unwrap_err();
    assert!(!err.to_string().contains("secret-value-123"), "{err}");
}
