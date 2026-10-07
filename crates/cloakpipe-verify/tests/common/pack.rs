//! Fixtures shared by the release audit pack tests: a real manifest, an
//! evaluation run, a signed certification and a ledger export produced by
//! the real producer crates, assembled with `PackBuilder`.

use base64::prelude::*;
use chrono::{DateTime, Utc};
use cloakpipe_cert::statement::{self, Certification, Envelope};
use cloakpipe_cert::EvaluationRun;
use cloakpipe_ledger::export::export_bundle;
use cloakpipe_ledger::{Ed25519Signer, Hop, LedgerStore, RecordBuilder};
use cloakpipe_release::AgentRelease;
use cloakpipe_verify::bundle::Bundle;
use cloakpipe_verify::pack::{
    digest_of, keyid, signing_input, GovernanceEvent, PackBuilder, ReleaseAuditPack, TrustedKey, VerifyOptions,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::path::PathBuf;

pub const NOW: &str = "2026-10-07T00:00:00Z";
pub const CREATED_AT: &str = "2026-10-06T00:00:00Z";
pub const ISSUED_AT: &str = "2026-10-01T00:00:00Z";
pub const VALID_UNTIL: &str = "2026-10-31T00:00:00Z";

pub const EXPORTER_SEED: u8 = 3;
pub const CERT_SEED: u8 = 7;
pub const LEDGER_SEED: u8 = 5;

pub fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../cloakpipe-release/testdata/support-agent-184.yaml")
}

pub fn manifest() -> AgentRelease {
    cloakpipe_release::parse_path(&manifest_path()).unwrap()
}

pub fn release() -> String {
    manifest().manifest_hash().to_string()
}

pub fn release_bytes() -> [u8; 32] {
    manifest().manifest_hash().0
}

pub fn other_release() -> String {
    format!("sha256:{}", "ab".repeat(32))
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn trusted(seed: u8) -> TrustedKey {
    let public = key(seed).verifying_key().to_bytes();
    TrustedKey { keyid: keyid(&public), public_key: public }
}

pub fn now() -> DateTime<Utc> {
    NOW.parse().unwrap()
}

/// One trusted key per role: exporter, ledger signer, certification issuer.
pub fn options() -> VerifyOptions {
    VerifyOptions {
        trusted: vec![trusted(EXPORTER_SEED)],
        ledger_trusted: vec![trusted(LEDGER_SEED)],
        cert_trusted: vec![trusted(CERT_SEED)],
        now: now(),
    }
}

pub fn run_for(release: &str) -> EvaluationRun {
    serde_json::from_value(json!({
        "apiVersion": "cloakpipe.dev/v1alpha1",
        "kind": "EvaluationRun",
        "runId": "support-critical@23",
        "release": release,
        "suite": {"name": "support-critical", "version": "23"},
        "covers": ["privacy", "functional"],
        "source": {"kind": "junit", "tool": "pytest"},
        "cases": [
            {"id": "privacy::no_pan", "critical": true, "status": "pass"},
            {"id": "refunds::identity", "status": "pass"}
        ]
    }))
    .unwrap()
}

pub fn run() -> EvaluationRun {
    run_for(&release())
}

pub fn certification_with(id: &str, environment: &str, outcome: &str, issued: &str, until: &str) -> Certification {
    let r = run();
    serde_json::from_value(json!({
        "id": id,
        "release": release(),
        "agent": "support-agent",
        "environment": environment,
        "decision": {
            "outcome": outcome,
            "release": release(),
            "policy": {"name": "support-prod", "version": "11", "hash": format!("sha256:{}", "cd".repeat(32))},
            "requiredSuites": ["privacy"],
            "runs": [{"runId": r.run_id, "suite": "support-critical", "hash": r.run_hash()}],
            "baselineRuns": [],
            "summaries": [],
            "reasons": []
        },
        "issuedAt": issued,
        "validUntil": until,
        "issuer": "ci:acme/support"
    }))
    .unwrap()
}

pub fn certification() -> Certification {
    certification_with("cert-0001", "production", "certified", ISSUED_AT, VALID_UNTIL)
}

pub fn sign_cert(c: &Certification, seed: u8) -> Envelope {
    let k = key(seed);
    statement::sign(&statement::statement(c), &k, &keyid(&k.verifying_key().to_bytes()))
}

pub fn envelope() -> Envelope {
    sign_cert(&certification(), CERT_SEED)
}

/// sha256 hex of an envelope's decoded payload (the revocation key).
pub fn statement_digest(e: &Envelope) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(BASE64_STANDARD.decode(&e.payload).unwrap()))
}

/// A real v4 ledger export: `bound` hops bound to this release, then
/// `unbound` hops bound to nothing.
pub fn ledger_with(bound: u64, unbound: u64, seed: u8) -> Bundle {
    let mut store = LedgerStore::open(":memory:").unwrap();
    let tenant = uuid::Uuid::from_u128(42);
    let ts: DateTime<Utc> = "2026-10-03T10:00:00Z".parse().unwrap();
    for seq in 0..bound + unbound {
        let mut b = RecordBuilder::new().seq(seq).tenant(tenant).ts(ts).hop(if seq % 2 == 0 {
            Hop::McpToolCall
        } else {
            Hop::McpToolResult
        });
        if seq < bound {
            b = b.release(release_bytes());
        }
        let mut r = b.build().unwrap();
        store.append(&tenant, &mut r).unwrap();
    }
    to_verify_bundle(export_bundle(&store, &tenant, &Ed25519Signer::from_bytes(&[seed; 32])).unwrap())
}

pub fn to_verify_bundle(b: impl serde::Serialize) -> Bundle {
    serde_json::from_value(serde_json::to_value(b).unwrap()).unwrap()
}

pub fn ledger() -> Bundle {
    ledger_with(4, 2, LEDGER_SEED)
}

pub fn registered() -> GovernanceEvent {
    GovernanceEvent::ReleaseRegistered {
        at: "2026-09-30T09:00:00Z".into(),
        actor: "ci:acme/support".into(),
        agent: "support-agent".into(),
        version: "184".into(),
    }
}

pub fn promoted(environment: &str, at: &str, break_glass: bool, reason: Option<&str>) -> GovernanceEvent {
    GovernanceEvent::ReleasePromoted {
        at: at.into(),
        actor: "alice@acme".into(),
        environment: environment.into(),
        from_release: Some(other_release()),
        break_glass,
        reason: reason.map(str::to_string),
    }
}

pub fn events() -> Vec<GovernanceEvent> {
    vec![
        registered(),
        promoted("staging", "2026-09-30T12:00:00Z", false, None),
        promoted("production", "2026-10-02T00:00:00Z", false, None),
    ]
}

pub fn builder_with(events: Vec<GovernanceEvent>) -> PackBuilder {
    let mut b = PackBuilder::new(manifest(), "cloakpipe-cloud:acme", CREATED_AT)
        .run(run())
        .certification(envelope())
        .ledger_export(ledger());
    for e in events {
        b = b.event(e);
    }
    b
}

pub fn pack_with(events: Vec<GovernanceEvent>) -> ReleaseAuditPack {
    builder_with(events).build(&key(EXPORTER_SEED)).unwrap()
}

pub fn pack() -> ReleaseAuditPack {
    pack_with(events())
}

pub fn pack_value() -> Value {
    serde_json::to_value(pack()).unwrap()
}

/// Re-sign a (tampered) pack document as the trusted exporter would: a
/// malicious or buggy exporter, so only the semantic checks can catch it.
pub fn resign(mut doc: Value, seed: u8) -> Value {
    let input = signing_input(&doc["apiVersion"], &doc["kind"], &doc["spec"]).unwrap();
    let k = key(seed);
    doc["digest"] = json!(digest_of(&input));
    doc["signature"] = json!({
        "keyid": keyid(&k.verifying_key().to_bytes()),
        "sig": BASE64_STANDARD.encode(k.sign(&input).to_bytes()),
    });
    doc
}

pub fn to_bytes(doc: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(doc).unwrap()
}
