//! The tool gate with a Cedar policy (`policy:` in a v1 manifest): decision
//! order contract -> Cedar -> approval, `policy_denied` with the determining
//! policies, `@approval`, fail-closed errors and persistent counters.

use cloakpipe_mcp::operations::OperationStore;
use cloakpipe_mcp::{ApprovalRequest, Counters, Denial, GateConfigError, GateMode, ToolGate};
use cloakpipe_receipt::approval::{sign_approval, Approval};
use cloakpipe_receipt::dsse::TrustedKey;
use cloakpipe_release::action::fingerprint;
use cloakpipe_release::v1::Manifest;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::path::Path;

const NOW: &str = "2026-10-27T12:00:00Z";

const MANIFEST: &str = r#"
release: support-agent
version: 2026.10.3
policy: ./support.cedar
tools:
  read_ticket:
    args:
      ticket_id: { type: string, required: true }
  send_email:
    args:
      to: { type: string, required: true }
      body: { type: string, max_len: 4000 }
  issue_refund:
    args:
      ticket_id: { type: string, required: true }
      amount: { type: number, min: 0, max: 1000, required: true }
    side_effect: true
    approval:
      when: "amount > 400"
      approvers: ["slack:#finance"]
  export_customers: {}
"#;

const POLICY: &str = r#"
@id("reads")
permit (principal == Release::"support-agent", action == Action::"read_ticket", resource);

@id("email")
permit (principal, action == Tool::"send_email", resource);

@id("email-rate")
forbid (principal, action == Action::"send_email", resource)
when { context.counters.send_email_1h >= 3 };

@id("refund-small")
permit (principal, action == Action::"issue_refund", resource)
when { resource.args.amount <= 100 && resource.args.ticket_id == context.task.ticket.id };

@id("refund-large")
@approval("slack:#support-leads")
permit (principal, action == Action::"issue_refund", resource)
when { resource.args.amount > 100 && resource.args.amount <= 500 };

@id("no-big-refunds")
forbid (principal, action == Action::"issue_refund", resource)
when { resource.args.amount > 500 };
"#;

fn task() -> Value {
    json!({"taskId": "t-1042", "ticket": {"id": "T-1042"}})
}

/// Write the manifest and `policy` into `dir` and load it.
fn manifest_in(dir: &Path, policy: &str) -> Manifest {
    std::fs::write(dir.join("support.cedar"), policy).unwrap();
    std::fs::write(dir.join("cloakpipe.manifest.yaml"), MANIFEST).unwrap();
    Manifest::parse_path(&dir.join("cloakpipe.manifest.yaml")).unwrap()
}

/// A ready gate on `dir`'s manifest with counters in `dir/state.db`.
fn gate_in(dir: &Path, policy: &str) -> ToolGate {
    let m = manifest_in(dir, policy);
    let g = ToolGate::from_manifest(GateMode::Enforce, &m)
        .with_task_context(Some(task()))
        .unwrap()
        .with_operations(OperationStore::open(dir.join("ops.db")).unwrap())
        .unwrap()
        .with_policy(Counters::open(dir.join("state.db")).unwrap())
        .unwrap();
    g.ready().unwrap();
    g
}

fn refund(amount: u64) -> Value {
    json!({"ticket_id": "T-1042", "amount": amount})
}

fn email() -> Value {
    json!({"to": "dana@customer.example", "body": "hi"})
}

fn denied(ids: &[&str]) -> Result<(), Denial> {
    Err(Denial::PolicyDenied { policies: ids.iter().map(|s| s.to_string()).collect() })
}

#[test]
fn a_manifest_policy_must_be_loaded_before_the_gate_runs() {
    let dir = tempfile::tempdir().unwrap();
    let m = manifest_in(dir.path(), POLICY);
    let g = ToolGate::from_manifest(GateMode::Enforce, &m)
        .with_operations(OperationStore::open(dir.path().join("ops.db")).unwrap())
        .unwrap();
    assert!(g.has_policy());
    assert_eq!(g.ready(), Err(GateConfigError::PolicyNotLoaded));
    // Even unchecked, a gate whose policy is not loaded refuses every call.
    assert_eq!(g.check("read_ticket", Some(&json!({"ticket_id": "T-1"})), NOW), Err(Denial::FailClosed));
    assert_eq!(Denial::FailClosed.code(), "fail_closed");
}

#[test]
fn an_invalid_policy_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let m = manifest_in(dir.path(), "permit (principal, action, resource");
    let err = ToolGate::from_manifest(GateMode::Enforce, &m).with_policy(Counters::in_memory().unwrap()).err();
    assert!(matches!(err, Some(GateConfigError::Policy(_))), "{err:?}");
    assert!(err.unwrap().to_string().contains("support.cedar"));
}

#[test]
fn without_a_policy_cedar_is_skipped() {
    let m = Manifest::parse_str("release: r\nversion: \"1\"\ntools:\n  ping: {}\n", Path::new(".")).unwrap();
    let g = ToolGate::from_manifest(GateMode::Enforce, &m);
    assert!(!g.has_policy());
    assert_eq!(g.ready(), Ok(()));
    assert_eq!(g.check("ping", None, NOW), Ok(()));
    // Loading counters for a manifest without a policy changes nothing.
    let g = g.with_policy(Counters::in_memory().unwrap()).unwrap();
    assert_eq!(g.check("ping", None, NOW), Ok(()));
}

#[test]
fn the_policy_ids_are_exposed() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate_in(dir.path(), POLICY);
    assert_eq!(
        g.policy_ids(),
        ["email", "email-rate", "no-big-refunds", "reads", "refund-large", "refund-small"].map(String::from).to_vec()
    );
}

#[test]
fn the_contract_is_checked_before_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate_in(dir.path(), "@id(\"nothing\") forbid (principal, action, resource);");
    assert_eq!(g.check("nope", None, NOW), Err(Denial::UndeclaredTool));
    assert_eq!(
        g.check("read_ticket", Some(&json!({"ticket_id": "T-1", "x": 1})), NOW),
        Err(Denial::UndeclaredArgument { path: None })
    );
    assert_eq!(g.check("read_ticket", Some(&json!({})), NOW), Err(Denial::ArgumentMissing { path: Some("/ticket_id".into()) }));
    assert_eq!(g.check("read_ticket", Some(&json!({"ticket_id": "T-1"})), NOW), denied(&["nothing"]));
}

#[test]
fn cedar_denies_with_the_determining_policies() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate_in(dir.path(), POLICY);
    assert_eq!(g.check("read_ticket", Some(&json!({"ticket_id": "T-1"})), NOW), Ok(()));
    // Declared, but no policy permits it.
    assert_eq!(g.check("export_customers", None, NOW), denied(&[]));
    // A forbid that holds wins over the contract's own approval rule.
    assert_eq!(g.check("issue_refund", Some(&refund(700)), NOW), denied(&["no-big-refunds"]));
    // The permit binds the refund to the ticket being worked.
    assert_eq!(g.check("issue_refund", Some(&json!({"ticket_id": "T-9", "amount": 50})), NOW), denied(&[]));
    assert_eq!(g.check("issue_refund", Some(&refund(50)), NOW), Ok(()));
    let d = Denial::PolicyDenied { policies: vec!["no-big-refunds".into()] };
    assert_eq!(d.code(), "policy_denied");
    assert_eq!(d.policies(), Some(&["no-big-refunds".to_string()][..]));
}

#[test]
fn an_evaluation_error_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate_in(dir.path(), "permit (principal, action, resource) when { resource.args.ticket_id > 3 };");
    assert_eq!(g.check("read_ticket", Some(&json!({"ticket_id": "T-1"})), NOW), Err(Denial::FailClosed));
}

// ── @approval ────────────────────────────────────────────────────────────

fn approver() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn approve(dir: &Path, release: &str, args: &Value) {
    let fp = fingerprint(&release.parse().unwrap(), "issue_refund", args);
    let a = Approval {
        release: release.into(),
        tool: "issue_refund".into(),
        task_id: "t-1042".into(),
        operation_id: "op-refund-1".into(),
        approver: "approver-1".into(),
        approved_at: "2026-10-27T11:55:00Z".into(),
        not_after: "2026-10-27T12:10:00Z".into(),
    };
    let env = sign_approval(&fp, &a, &approver(), "approver-1");
    std::fs::write(dir.join(format!("{}.approval.json", fp.hex())), serde_json::to_vec(&env).unwrap()).unwrap();
}

#[test]
fn an_approval_annotation_requires_a_receipt() {
    let (dir, receipts) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let keys = vec![TrustedKey { keyid: "approver-1".into(), public_key: approver().verifying_key().to_bytes() }];
    let g = gate_in(dir.path(), POLICY).with_approvals(receipts.path(), keys);
    // 150: only the @approval permit holds; the manifest's own rule (> 400) does not.
    assert_eq!(g.check("issue_refund", Some(&refund(150)), NOW), Err(Denial::ApprovalRequired));
    let fp = fingerprint(&g.release().parse().unwrap(), "issue_refund", &refund(150)).to_string();
    assert_eq!(
        g.approval_request("issue_refund", Some(&refund(150))),
        Some(ApprovalRequest { approvers: vec!["slack:#support-leads".into()], fingerprint: fp })
    );
    // 450: both require it; the routes are merged, the manifest's first.
    let req = g.approval_request("issue_refund", Some(&refund(450))).unwrap();
    assert_eq!(req.approvers, vec!["slack:#finance".to_string(), "slack:#support-leads".to_string()]);
    // 50: the plain permit holds, nothing requires approval.
    assert_eq!(g.approval_request("issue_refund", Some(&refund(50))), None);
    // A receipt for the exact call lets it through.
    approve(receipts.path(), g.release(), &refund(150));
    let auth = g.authorize("issue_refund", Some(&refund(150)), NOW).unwrap();
    assert_eq!(auth.approval.unwrap().operation_id, "op-refund-1");
}

// ── counters ─────────────────────────────────────────────────────────────

#[test]
fn the_counter_forbid_holds_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let g = gate_in(dir.path(), POLICY);
        for _ in 0..3 {
            assert_eq!(g.check("send_email", Some(&email()), NOW), Ok(()));
            g.record_forwarded("send_email", NOW).unwrap();
        }
        assert_eq!(g.check("send_email", Some(&email()), NOW), denied(&["email-rate"]));
        // Other tools are counted apart.
        assert_eq!(g.check("read_ticket", Some(&json!({"ticket_id": "T-1"})), NOW), Ok(()));
    }
    // A new process on the same state database still sees the three calls.
    let g = gate_in(dir.path(), POLICY);
    assert_eq!(g.check("send_email", Some(&email()), NOW), denied(&["email-rate"]));
    // An hour later the window has slid past them.
    assert_eq!(g.check("send_email", Some(&email()), "2026-10-27T13:00:01Z"), Ok(()));
}

#[test]
fn a_withdrawn_call_is_not_counted() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate_in(dir.path(), POLICY);
    for _ in 0..2 {
        g.record_forwarded("send_email", NOW).unwrap();
    }
    let id = g.record_forwarded("send_email", NOW).unwrap().expect("counted");
    assert_eq!(g.check("send_email", Some(&email()), NOW), denied(&["email-rate"]));
    g.forget_forwarded(id);
    assert_eq!(g.check("send_email", Some(&email()), NOW), Ok(()));
}

#[test]
fn without_a_policy_nothing_is_counted() {
    let m = Manifest::parse_str("release: r\nversion: \"1\"\ntools:\n  ping: {}\n", Path::new(".")).unwrap();
    let g = ToolGate::from_manifest(GateMode::Enforce, &m);
    assert_eq!(g.record_forwarded("ping", NOW), Ok(None));
}
