//! The tool gate on a single-file v1 manifest ([`ToolGate::from_manifest`]):
//! closed by default, `one_of_context`, idempotency key templates and
//! conditional approval with a ttl.

use cloakpipe_mcp::operations::OperationStore;
use cloakpipe_mcp::{ApprovalRequest, Denial, GateConfigError, GateMode, ToolGate};
use cloakpipe_receipt::approval::{sign_approval, Approval};
use cloakpipe_receipt::dsse::TrustedKey;
use cloakpipe_release::action::{derive_idempotent_operation_id, derive_operation_id, fingerprint};
use cloakpipe_release::v1::Manifest;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const NOW: &str = "2026-10-27T12:00:00Z";

fn manifest() -> Manifest {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../cloakpipe-release/testdata/v1/support.manifest.yaml");
    Manifest::parse_path(&p).unwrap()
}

fn task() -> Value {
    json!({"taskId": "t-1042", "ticket": {"id": "T-1042", "customer_email": "dana@customer.example"}})
}

fn store(dir: &Path) -> OperationStore {
    OperationStore::open(dir.join("ops.db")).unwrap()
}

/// A gate with the task context and an operations store in `dir`.
fn gate(dir: &Path) -> ToolGate {
    ToolGate::from_manifest(GateMode::Enforce, &manifest())
        .with_task_context(Some(task()))
        .unwrap()
        .with_operations(store(dir))
        .unwrap()
}

fn email(to: &str, body: &str) -> Value {
    json!({"ticket_id": "T-1042", "to": to, "body": body})
}

#[test]
fn the_gate_exposes_the_manifest_identity() {
    let m = manifest();
    let g = ToolGate::from_manifest(GateMode::Enforce, &m);
    assert_eq!(g.release(), m.digest().to_string());
    assert_eq!(g.manifest_digest(), m.digest().to_string());
    assert_eq!(g.policy_digest(), m.policy_digest().map(|d| d.to_string()));
    assert!(g.policy_digest().is_some());
    assert_eq!(g.release_name(), "support-agent");
    assert_eq!(g.version(), "2026.10.3");
    assert_eq!(g.release_bytes(), m.digest().0);
}

#[test]
fn undeclared_tools_and_arguments_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate(dir.path());
    assert_eq!(g.check("export_customers", Some(&json!({})), NOW), Err(Denial::UndeclaredTool));
    assert_eq!(g.check("read_ticket", Some(&json!({"ticket_id": "T-1042"})), NOW), Ok(()));
    assert_eq!(
        g.check("read_ticket", Some(&json!({"ticket_id": "T-1042", "include_pii": true})), NOW),
        Err(Denial::UndeclaredArgument { path: None })
    );
    assert_eq!(Denial::UndeclaredArgument { path: None }.code(), "undeclared_argument");
    assert_eq!(
        g.check("read_ticket", Some(&json!({"ticket_id": "1042"})), NOW),
        Err(Denial::ArgumentInvalid { path: Some("/ticket_id".into()) })
    );
}

#[test]
fn a_declared_tool_without_args_takes_no_arguments() {
    let m = Manifest::parse_str("release: r\nversion: \"1\"\ntools:\n  ping: {}\n", Path::new(".")).unwrap();
    let g = ToolGate::from_manifest(GateMode::Enforce, &m);
    assert_eq!(g.check("ping", None, NOW), Ok(()));
    assert_eq!(g.check("ping", Some(&json!({})), NOW), Ok(()));
    assert_eq!(g.check("ping", Some(&json!({"x": 1})), NOW), Err(Denial::UndeclaredArgument { path: None }));
}

#[test]
fn one_of_context_and_or_pattern() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate(dir.path());
    assert_eq!(g.check("send_email", Some(&email("dana@customer.example", "hi")), NOW), Ok(()));
    assert_eq!(g.check("send_email", Some(&email("lead@ourcompany.com", "hi")), NOW), Ok(()));
    assert_eq!(
        g.check("send_email", Some(&email("attacker@evil.example", "hi")), NOW),
        Err(Denial::ScopeMismatch { path: Some("/to".into()) })
    );
    // Without a task context the binding cannot be checked.
    drop(g);
    let g = ToolGate::from_manifest(GateMode::Enforce, &manifest()).with_operations(store(dir.path())).unwrap();
    assert_eq!(
        g.check("send_email", Some(&email("dana@customer.example", "hi")), NOW),
        Err(Denial::TaskContextMissing { path: Some("/to".into()) })
    );
}

#[test]
fn the_task_context_must_be_an_object() {
    let r = ToolGate::from_manifest(GateMode::Enforce, &manifest()).with_task_context(Some(json!([1])));
    assert_eq!(r.err(), Some(GateConfigError::TaskContextNotObject));
}

#[test]
fn side_effect_tools_need_an_operations_store() {
    let g = ToolGate::from_manifest(GateMode::Enforce, &manifest()).with_task_context(Some(task())).unwrap();
    assert!(matches!(g.ready(), Err(GateConfigError::OperationsRequired { .. })));
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(gate(dir.path()).ready(), Ok(()));
    let read_only = Manifest::parse_str("release: r\nversion: \"1\"\ntools:\n  ping: {}\n", Path::new(".")).unwrap();
    assert_eq!(ToolGate::from_manifest(GateMode::Enforce, &read_only).ready(), Ok(()));
}

#[test]
fn the_idempotency_key_template_names_the_operation() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate(dir.path());
    let a = email("dana@customer.example", "Your refund is on its way.");
    let op = g.authorize("send_email", Some(&a), NOW).unwrap().operation.expect("an operation");
    // The id is keyed by the store: HMAC over release, tool and the rendered key.
    drop(g);
    let store_key = store(dir.path()).operation_id_key().unwrap();
    let rendered = format!("T-1042:{}", hex::encode(Sha256::digest(b"Your refund is on its way.")));
    assert_eq!(op.operation_id, derive_idempotent_operation_id(&store_key, "support-agent", "send_email", &rendered));
    assert_eq!(op.fingerprint, fingerprint(&manifest().digest(), "send_email", &a));
    let legacy = derive_operation_id(&store_key, "t-1042", &op.fingerprint);
    assert_ne!(op.operation_id, legacy, "the template replaces the task + fingerprint derivation");

    let g = gate(dir.path());
    // Same ticket and body to another allowed recipient: the same operation.
    let other = email("lead@ourcompany.com", "Your refund is on its way.");
    assert_eq!(g.authorize("send_email", Some(&other), NOW).unwrap().operation.unwrap().operation_id, op.operation_id);
    // Another body: another operation.
    let changed = email("dana@customer.example", "Second notice.");
    assert_ne!(g.authorize("send_email", Some(&changed), NOW).unwrap().operation.unwrap().operation_id, op.operation_id);
}

#[test]
fn without_a_template_the_operation_is_derived_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate(dir.path());
    let a = json!({"ticket_id": "T-1042", "amount": 50});
    let op = g.authorize("issue_refund", Some(&a), NOW).unwrap().operation.expect("an operation");
    drop(g);
    let store_key = store(dir.path()).operation_id_key().unwrap();
    let fp = fingerprint(&manifest().digest(), "issue_refund", &a);
    assert_eq!(op.operation_id, derive_operation_id(&store_key, "t-1042", &fp));
}

// ── conditional approval ─────────────────────────────────────────────────

fn approver() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn approvers() -> Vec<TrustedKey> {
    vec![TrustedKey { keyid: "approver-1".into(), public_key: approver().verifying_key().to_bytes() }]
}

fn refund(amount: u64) -> Value {
    json!({"ticket_id": "T-1042", "amount": amount})
}

/// File a receipt for `refund(amount)` valid from `approved_at` to `not_after`.
fn approve(dir: &Path, amount: u64, approved_at: &str, not_after: &str) {
    let fp = fingerprint(&manifest().digest(), "issue_refund", &refund(amount));
    let a = Approval {
        release: manifest().digest().to_string(),
        tool: "issue_refund".into(),
        task_id: "t-1042".into(),
        operation_id: "op-refund-1".into(),
        approver: "approver-1".into(),
        approved_at: approved_at.into(),
        not_after: not_after.into(),
    };
    let env = sign_approval(&fp, &a, &approver(), "approver-1");
    std::fs::write(dir.join(format!("{}.approval.json", fp.hex())), serde_json::to_vec(&env).unwrap()).unwrap();
}

fn approval_gate(ops: &Path, receipts: &Path) -> ToolGate {
    gate(ops).with_approvals(receipts, approvers())
}

#[test]
fn approval_is_required_only_when_the_condition_holds() {
    let (ops, receipts) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let g = approval_gate(ops.path(), receipts.path());
    let small = g.authorize("issue_refund", Some(&refund(50)), NOW).unwrap();
    assert_eq!(small.approval, None, "50 <= 100: no approval needed");
    assert_eq!(g.check("issue_refund", Some(&refund(350)), NOW), Err(Denial::ApprovalRequired));
    // Arguments are still checked first: 600 is over the contract's max.
    assert_eq!(
        g.check("issue_refund", Some(&refund(600)), NOW),
        Err(Denial::ArgumentInvalid { path: Some("/amount".into()) })
    );
}

#[test]
fn an_approval_request_names_the_routes_and_the_call() {
    let (ops, receipts) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let g = approval_gate(ops.path(), receipts.path());
    let req = g.approval_request("issue_refund", Some(&refund(350))).expect("a request");
    assert_eq!(
        req,
        ApprovalRequest {
            approvers: vec!["slack:#support-leads".into()],
            fingerprint: fingerprint(&manifest().digest(), "issue_refund", &refund(350)).to_string(),
        }
    );
    assert_eq!(g.approval_request("read_ticket", Some(&json!({"ticket_id": "T-1042"}))), None);
    assert_eq!(g.approval_request("nope", None), None);
}

#[test]
fn a_receipt_within_the_ttl_approves_the_call() {
    let (ops, receipts) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    approve(receipts.path(), 350, "2026-10-27T11:55:00Z", "2026-10-27T12:10:00Z");
    let g = approval_gate(ops.path(), receipts.path());
    let auth = g.authorize("issue_refund", Some(&refund(350)), NOW).unwrap();
    assert_eq!(auth.approval.expect("approved").operation_id, "op-refund-1");
    // The receipt covers this exact call only: another amount needs its own.
    assert_eq!(g.check("issue_refund", Some(&refund(351)), NOW), Err(Denial::ApprovalRequired));
}

#[test]
fn a_receipt_longer_than_the_ttl_is_invalid() {
    let (ops, receipts) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // 30 minutes of validity against a 15m ttl.
    approve(receipts.path(), 350, "2026-10-27T11:55:00Z", "2026-10-27T12:25:00Z");
    let g = approval_gate(ops.path(), receipts.path());
    assert_eq!(g.check("issue_refund", Some(&refund(350)), NOW), Err(Denial::ApprovalInvalid));
    // Exactly the ttl is accepted.
    let (ops, receipts) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    approve(receipts.path(), 350, "2026-10-27T11:55:00Z", "2026-10-27T12:10:00Z");
    assert_eq!(approval_gate(ops.path(), receipts.path()).check("issue_refund", Some(&refund(350)), NOW), Ok(()));
}

#[test]
fn the_legacy_gate_exposes_its_identity_too() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../cloakpipe-release/testdata/support-agent-184.json");
    let m: cloakpipe_release::AgentRelease = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    let g = ToolGate::new(GateMode::Enforce, &m);
    assert_eq!(g.manifest_digest(), m.manifest_hash().to_string());
    assert_eq!(g.release_name(), m.metadata.agent);
    assert_eq!(g.version(), m.metadata.version);
    assert_eq!(g.policy_digest(), None);
}
