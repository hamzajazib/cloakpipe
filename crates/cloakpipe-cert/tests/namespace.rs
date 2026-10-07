//! Certification objects are written in the `cloakpipe.co` namespace; runs,
//! policies and attestations issued before the rename (`cloakpipe.dev`) keep
//! verifying with their original hashes and signatures.
//!
//! The legacy fixtures were produced by CloakPipe 0.10 (before the rename);
//! see `crates/cloakpipe-verify/tests/fixtures/README.md`.

use cloakpipe_cert::import::from_json;
use cloakpipe_cert::statement::{self, sign, verify, Certification, Envelope, Status, TrustedKey, VerifyContext};
use cloakpipe_cert::{CertificationPolicy, EvaluationRun};
use cloakpipe_release::namespace;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Hashes recorded in the legacy certification's decision.
const LEGACY_RELEASE: &str = "sha256:ae7bc9e404c194c9fcf80d95cafe4c322e4e9f69595c693ffb48441647d03c32";
const LEGACY_RUN_HASH: &str = "sha256:13370c86cbd2cb372fadf1576900f46d453b5e88c3294df6db4938c82336f9a8";
const LEGACY_POLICY_HASH: &str = "sha256:ff742b6b96732a407e299ed2a7686fbc376c7184f363e088f5001fed6a7174c5";

fn legacy(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../cloakpipe-verify/tests/fixtures/legacy-cloakpipe-dev").join(name);
    std::fs::read_to_string(p).unwrap()
}

fn legacy_run() -> EvaluationRun {
    from_json(&legacy("run.json")).unwrap()
}

/// `legacy-cloakpipe-dev/policy.yaml`, as JSON.
fn policy_json(api_version: &str) -> Value {
    json!({
        "apiVersion": api_version,
        "kind": "CertificationPolicy",
        "name": "support-prod",
        "version": "11",
        "validityDays": 30,
        "rules": {
            "maxNewCriticalFailures": 0,
            "blockPersistingCriticalFailures": true,
            "minPassRate": 0.95,
            "minCoverage": 1.0,
            "metrics": [{"metric": "latency_ms", "aggregate": "p95", "op": "lte", "value": 2000}]
        }
    })
}

fn policy(api_version: &str) -> CertificationPolicy {
    serde_json::from_value(policy_json(api_version)).unwrap()
}

fn legacy_envelope() -> Envelope {
    serde_json::from_str(&legacy("cert.dsse.json")).unwrap()
}

fn legacy_issuer() -> TrustedKey {
    let k: Value = serde_json::from_str(&legacy("cert.pub.json")).unwrap();
    let mut public_key = [0u8; 32];
    hex::decode_to_slice(k["publicKey"].as_str().unwrap(), &mut public_key).unwrap();
    TrustedKey { keyid: k["keyid"].as_str().unwrap().into(), public_key }
}

fn legacy_ctx() -> VerifyContext {
    VerifyContext {
        trusted: vec![legacy_issuer()],
        now: "2026-10-02T00:00:00Z".into(),
        expected_release: Some(LEGACY_RELEASE.into()),
        required_runs: Some(vec![LEGACY_RUN_HASH.into()]),
        ..Default::default()
    }
}

fn payload(env: &Envelope) -> Value {
    use base64::prelude::*;
    serde_json::from_slice(&BASE64_STANDARD.decode(&env.payload).unwrap()).unwrap()
}

#[test]
fn writers_emit_the_cloakpipe_co_namespace() {
    assert_eq!(cloakpipe_cert::API_VERSION, "cloakpipe.co/v1alpha1");
    assert_eq!(cloakpipe_cert::RUN_HASH_DOMAIN, "cloakpipe.co/evaluation-run/v1");
    assert_eq!(cloakpipe_cert::POLICY_HASH_DOMAIN, "cloakpipe.co/certification-policy/v1");
    assert_eq!(statement::PREDICATE_TYPE, "https://cloakpipe.co/attestations/certification/v1alpha1");
}

#[test]
fn legacy_run_validates_and_keeps_its_issued_hash() {
    let run = legacy_run();
    assert_eq!(run.api_version, namespace::LEGACY_API_VERSION, "never rewritten on read");
    assert_eq!(run.validate(), Vec::<String>::new());
    assert_eq!(run.run_hash(), LEGACY_RUN_HASH);
}

#[test]
fn a_run_in_the_current_namespace_is_a_different_object() {
    let mut run = legacy_run();
    run.api_version = namespace::API_VERSION.into();
    assert_eq!(run.validate(), Vec::<String>::new());
    assert_ne!(run.run_hash(), LEGACY_RUN_HASH);
}

#[test]
fn legacy_policy_validates_and_keeps_its_issued_hash() {
    let p = policy(namespace::LEGACY_API_VERSION);
    assert_eq!(p.validate(), Vec::<String>::new());
    assert_eq!(p.policy_hash(), LEGACY_POLICY_HASH);

    let current = policy(namespace::API_VERSION);
    assert_eq!(current.validate(), Vec::<String>::new());
    assert_ne!(current.policy_hash(), LEGACY_POLICY_HASH);
}

#[test]
fn unsupported_versions_in_either_namespace_are_rejected() {
    for bad in ["cloakpipe.co/v2", "cloakpipe.dev/v2", "cloakpipe.co/v0", "cloakpipe.com/v1alpha1", ""] {
        let mut run = legacy_run();
        run.api_version = bad.into();
        assert!(run.validate().iter().any(|i| i.contains("apiVersion")), "run {bad:?}");

        let p = policy(bad);
        assert!(p.validate().iter().any(|i| i.contains("apiVersion")), "policy {bad:?}");
    }
}

#[test]
fn legacy_certification_verifies_with_its_original_signature() {
    let env = legacy_envelope();
    assert_eq!(payload(&env)["predicateType"], namespace::LEGACY_CERTIFICATION_PREDICATE_TYPE);
    let r = verify(&env, &legacy_ctx());
    assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
    assert!(r.certified);
    assert_eq!(r.release.as_deref(), Some(LEGACY_RELEASE));
}

#[test]
fn legacy_certification_still_fails_closed_on_tampering() {
    let mut env = legacy_envelope();
    let mut s = payload(&env);
    s["predicate"]["certification"]["environment"] = json!("staging");
    use base64::prelude::*;
    env.payload = BASE64_STANDARD.encode(serde_json::to_vec(&s).unwrap());
    assert_eq!(verify(&env, &legacy_ctx()).status, Status::Invalid);
}

fn signed_with_predicate_type(predicate_type: &str) -> (Envelope, VerifyContext) {
    let c: Certification = serde_json::from_value(payload(&legacy_envelope())["predicate"]["certification"].clone()).unwrap();
    let mut s = statement::statement(&c);
    assert_eq!(s["predicateType"], namespace::CERTIFICATION_PREDICATE_TYPE, "writers emit the current namespace");
    s["predicateType"] = json!(predicate_type);
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let ctx = VerifyContext {
        trusted: vec![TrustedKey { keyid: "k".into(), public_key: key.verifying_key().to_bytes() }],
        ..legacy_ctx()
    };
    (sign(&s, &key, "k"), ctx)
}

#[test]
fn both_predicate_type_namespaces_verify() {
    for ok in [namespace::CERTIFICATION_PREDICATE_TYPE, namespace::LEGACY_CERTIFICATION_PREDICATE_TYPE] {
        let (env, ctx) = signed_with_predicate_type(ok);
        let r = verify(&env, &ctx);
        assert_eq!(r.status, Status::Valid, "{ok}: {:?}", r.reasons);
    }
}

#[test]
fn unsupported_predicate_types_fail_closed() {
    for bad in [
        "https://cloakpipe.co/attestations/certification/v2",
        "https://cloakpipe.dev/attestations/certification/v2",
        "https://cloakpipe.com/attestations/certification/v1alpha1",
        namespace::AGENT_RELEASE_PREDICATE_TYPE,
    ] {
        let (env, ctx) = signed_with_predicate_type(bad);
        let r = verify(&env, &ctx);
        assert_eq!(r.status, Status::Invalid, "{bad}");
        assert!(r.reasons.iter().any(|x| x.contains("predicateType")), "{bad}: {:?}", r.reasons);
    }
}
