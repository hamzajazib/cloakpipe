//! Contract tests for `cloakpipe_mcp::gate` (see the module doc comment).

use cloakpipe_cert::statement::{sign, statement, Certification, Envelope, TrustedKey, VerifyContext};
use cloakpipe_mcp::{Denial, GateMode, ToolGate};
use cloakpipe_release::AgentRelease;
use ed25519_dalek::SigningKey;
use serde_json::json;

const NOW: &str = "2026-10-06T12:00:00Z";

fn manifest() -> AgentRelease {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cloakpipe-release/testdata/support-agent-184.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn release() -> String {
    manifest().manifest_hash().to_string()
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn cert_for(release: &str, outcome: &str, environment: &str) -> Certification {
    serde_json::from_value(json!({
        "id": "cert-0001",
        "release": release,
        "agent": "support-agent",
        "environment": environment,
        "decision": {
            "outcome": outcome,
            "release": release,
            "policy": {"name": "support-prod", "version": "11", "hash": format!("sha256:{}", "cd".repeat(32))},
            "requiredSuites": [],
            "runs": [{"runId": "run-1", "suite": "support-critical", "hash": format!("sha256:{}", "11".repeat(32))}],
            "baselineRuns": [],
            "summaries": [],
            "reasons": if outcome == "blocked" {
                json!([{"code": "pass_rate_below_minimum", "message": "pass rate 0.8 < 0.95"}])
            } else { json!([]) }
        },
        "issuedAt": "2026-10-01T00:00:00Z",
        "validUntil": "2026-10-31T00:00:00Z",
        "issuer": "ci:acme/support"
    }))
    .unwrap()
}

fn envelope(c: &Certification) -> Envelope {
    sign(&statement(c), &key(), "k1")
}

fn trust() -> VerifyContext {
    VerifyContext {
        trusted: vec![TrustedKey { keyid: "k1".into(), public_key: key().verifying_key().to_bytes() }],
        ..Default::default()
    }
}

fn gate(cert: Option<Envelope>) -> ToolGate {
    ToolGate::new(GateMode::Enforce, &manifest(), "production", cert, trust())
}

fn certified() -> ToolGate {
    gate(Some(envelope(&cert_for(&release(), "certified", "production"))))
}

#[test]
fn a_certified_release_may_call_its_declared_tools() {
    let g = certified();
    assert_eq!(g.release(), release());
    assert_eq!(g.check("refund", NOW), Ok(()));
    assert_eq!(g.check("lookup-customer", NOW), Ok(()));
}

#[test]
fn undeclared_tools_are_refused() {
    let g = certified();
    for tool in ["delete_customer", "refund@4", "tool:refund", "", "REFUND"] {
        assert_eq!(g.check(tool, NOW), Err(Denial::UndeclaredTool), "{tool:?}");
    }
}

#[test]
fn without_a_certification_every_call_is_refused() {
    assert_eq!(gate(None).check("refund", NOW), Err(Denial::Uncertified));
}

#[test]
fn the_certification_must_verify_now() {
    let g = certified();
    assert_eq!(g.check("refund", "2026-10-31T00:00:00Z"), Err(Denial::NotCertified("expired".into())));
    assert_eq!(g.check("refund", "2026-09-30T00:00:00Z"), Err(Denial::NotCertified("invalid".into())), "not yet valid is INVALID in the verify contract");
    assert_eq!(g.check("refund", "not a time"), Err(Denial::NotCertified("invalid".into())));
}

#[test]
fn revoked_untrusted_and_foreign_certifications_are_refused() {
    let c = cert_for(&release(), "certified", "production");
    let env = envelope(&c);

    let mut revoked = trust();
    let digest = {
        use base64::prelude::*;
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(BASE64_STANDARD.decode(&env.payload).unwrap()))
    };
    revoked.revoked_statements.insert(digest);
    let g = ToolGate::new(GateMode::Enforce, &manifest(), "production", Some(env.clone()), revoked);
    assert_eq!(g.check("refund", NOW), Err(Denial::NotCertified("revoked".into())));

    let untrusted = ToolGate::new(GateMode::Enforce, &manifest(), "production", Some(env), VerifyContext::default());
    assert_eq!(untrusted.check("refund", NOW), Err(Denial::NotCertified("invalid".into())));

    // A valid certification of another release.
    let other = format!("sha256:{}", "ab".repeat(32));
    let g = gate(Some(envelope(&cert_for(&other, "certified", "production"))));
    assert_eq!(g.check("refund", NOW), Err(Denial::NotCertified("invalid".into())));
}

#[test]
fn a_blocked_decision_does_not_certify() {
    let g = gate(Some(envelope(&cert_for(&release(), "blocked", "production"))));
    assert_eq!(g.check("refund", NOW), Err(Denial::NotCertified("blocked".into())));
}

#[test]
fn the_certification_must_cover_the_environment() {
    let g = gate(Some(envelope(&cert_for(&release(), "certified", "staging"))));
    assert_eq!(g.check("refund", NOW), Err(Denial::WrongEnvironment("staging".into())));
}

#[test]
fn undeclared_is_checked_before_certification() {
    // An undeclared tool is refused for that reason even without a certification.
    assert_eq!(gate(None).check("delete_customer", NOW), Err(Denial::UndeclaredTool));
}

#[test]
fn denial_codes_are_stable() {
    assert_eq!(Denial::UndeclaredTool.code(), "undeclared_tool");
    assert_eq!(Denial::Uncertified.code(), "uncertified");
    assert_eq!(Denial::NotCertified("revoked".into()).code(), "revoked");
    assert_eq!(Denial::WrongEnvironment("staging".into()).code(), "wrong_environment");
}
