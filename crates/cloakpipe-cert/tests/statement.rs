//! Contract tests for `cloakpipe_cert::statement` (see the module doc comment).

use base64::prelude::*;
use cloakpipe_cert::statement::*;
use cloakpipe_cert::Outcome;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use proptest::prelude::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ── Fixtures ────────────────────────────────────────────────────────────

const RELEASE_HEX: &str = "abababababababababababababababababababababababababababababababab";
const RUN_HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_RUN_HASH: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const NOW: &str = "2026-10-06T12:00:00Z";
const ISSUED_AT: &str = "2026-10-01T00:00:00Z";
const VALID_UNTIL: &str = "2026-10-31T00:00:00Z";

fn release() -> String {
    format!("sha256:{RELEASE_HEX}")
}

fn cert_json() -> Value {
    json!({
        "id": "cert-0001",
        "release": release(),
        "agent": "support-agent",
        "environment": "production",
        "decision": {
            "outcome": "certified",
            "release": release(),
            "policy": {"name": "support-prod", "version": "11", "hash": format!("sha256:{}", "cd".repeat(32))},
            "requiredSuites": ["privacy"],
            "runs": [{"runId": "run-1", "suite": "support-critical", "hash": RUN_HASH}],
            "baselineRuns": [],
            "summaries": [{
                "suite": "support-critical", "cases": 2, "passed": 2, "failed": 0,
                "errored": 0, "skipped": 0, "passRate": 1.0, "coverage": 1.0
            }],
            "reasons": []
        },
        "issuedAt": ISSUED_AT,
        "validUntil": VALID_UNTIL,
        "issuer": "cloakpipe-cloud"
    })
}

fn cert() -> Certification {
    serde_json::from_value(cert_json()).expect("fixture certification")
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn trusted(keyid: &str, k: &SigningKey) -> TrustedKey {
    TrustedKey { keyid: keyid.into(), public_key: k.verifying_key().to_bytes() }
}

fn ctx() -> VerifyContext {
    VerifyContext { trusted: vec![trusted("k1", &key())], now: NOW.into(), ..Default::default() }
}

fn ctx_at(now: &str) -> VerifyContext {
    VerifyContext { now: now.into(), ..ctx() }
}

fn envelope(c: &Certification) -> Envelope {
    sign(&statement(c), &key(), "k1")
}

/// DSSE PAE built independently of the implementation, from the spec text.
fn spec_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Sign arbitrary payload bytes with the trusted key, bypassing `sign`, so
/// tests can produce correctly signed envelopes around malformed statements.
fn sign_raw(payload: &[u8]) -> Envelope {
    let sig = key().sign(&spec_pae(PAYLOAD_TYPE, payload));
    Envelope {
        payload_type: PAYLOAD_TYPE.into(),
        payload: BASE64_STANDARD.encode(payload),
        signatures: vec![Signature { keyid: "k1".into(), sig: BASE64_STANDARD.encode(sig.to_bytes()) }],
    }
}

/// Sign an arbitrary (possibly malformed) statement value, canonicalised.
fn sign_value(v: &Value) -> Envelope {
    sign_raw(&serde_json_canonicalizer::to_vec(v).unwrap())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn payload_bytes(env: &Envelope) -> Vec<u8> {
    BASE64_STANDARD.decode(&env.payload).unwrap()
}

fn assert_status(report: &Report, status: Status, needle: &str) {
    assert_eq!(report.status, status, "reasons: {:?}", report.reasons);
    if !needle.is_empty() {
        assert!(
            report.reasons.iter().any(|r| r.contains(needle)),
            "expected a reason containing {needle:?}, got {:?}",
            report.reasons
        );
    }
    if status > Status::ValidWithLimitations {
        assert!(!report.certified, "a {status:?} attestation must not be certified");
    }
}

// ── Statement shape ─────────────────────────────────────────────────────

#[test]
fn statement_has_in_toto_v1_shape() {
    let s = statement(&cert());
    assert_eq!(s["_type"], STATEMENT_TYPE);
    assert_eq!(STATEMENT_TYPE, "https://in-toto.io/Statement/v1");
    assert_eq!(s["predicateType"], PREDICATE_TYPE);
    assert_eq!(PREDICATE_TYPE, "https://cloakpipe.co/attestations/certification/v1alpha1");
    assert_eq!(
        s["subject"],
        json!([{ "name": "agent-release:support-agent", "digest": { "sha256": RELEASE_HEX } }])
    );
    let obj = s.as_object().unwrap();
    assert_eq!(obj.len(), 4, "only _type, subject, predicateType, predicate: {s}");
    let predicate = s["predicate"].as_object().unwrap();
    assert_eq!(predicate.len(), 1, "predicate holds only `certification`");
}

#[test]
fn statement_predicate_is_camel_case_certification() {
    let s = statement(&cert());
    let c = &s["predicate"]["certification"];
    assert_eq!(c, &cert_json(), "round-trips exactly as camelCase JSON");
    assert!(c.get("limitations").is_none(), "empty limitations are omitted");
    let back: Certification = serde_json::from_value(c.clone()).unwrap();
    assert_eq!(back, cert());
}

#[test]
fn statement_subject_name_defaults_to_unknown() {
    let mut c = cert();
    c.agent = None;
    let s = statement(&c);
    assert_eq!(s["subject"][0]["name"], "agent-release:unknown");
    assert!(s["predicate"]["certification"].get("agent").is_none());
}

// ── DSSE ────────────────────────────────────────────────────────────────

#[test]
fn pae_matches_dsse_spec_example() {
    // https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#test-vectors
    assert_eq!(
        pae("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
    );
}

#[test]
fn pae_counts_raw_bytes_not_chars() {
    let payload = "é€".as_bytes(); // 2 chars, 5 bytes
    assert_eq!(pae("t/é", payload), b"DSSEv1 4 t/\xc3\xa9 5 \xc3\xa9\xe2\x82\xac".to_vec());
    assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
}

#[test]
fn sign_produces_dsse_envelope_with_canonical_payload() {
    let s = statement(&cert());
    let env = sign(&s, &key(), "k1");
    assert_eq!(env.payload_type, "application/vnd.in-toto+json");
    assert_eq!(env.payload_type, PAYLOAD_TYPE);
    assert_eq!(env.signatures.len(), 1);
    assert_eq!(env.signatures[0].keyid, "k1");
    let bytes = BASE64_STANDARD.decode(&env.payload).expect("standard base64 payload");
    assert_eq!(bytes, serde_json_canonicalizer::to_vec(&s).unwrap(), "RFC 8785 canonical bytes");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with(r#"{"_type":"https://in-toto.io/Statement/v1","predicate":"#), "{text}");
    assert_eq!(BASE64_STANDARD.decode(&env.signatures[0].sig).unwrap().len(), 64);
}

#[test]
fn signature_is_ed25519_over_the_pae() {
    let env = envelope(&cert());
    let payload = payload_bytes(&env);
    let sig_bytes: [u8; 64] = BASE64_STANDARD.decode(&env.signatures[0].sig).unwrap().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    key().verifying_key().verify(&spec_pae(PAYLOAD_TYPE, &payload), &sig).expect("signature over PAE");
    assert!(key().verifying_key().verify(&payload, &sig).is_err(), "not over the bare payload");
}

#[test]
fn sign_is_deterministic_and_keyid_is_verbatim() {
    let s = statement(&cert());
    assert_eq!(sign(&s, &key(), "k1"), sign(&s, &key(), "k1"));
    let env = sign(&s, &key(), "  odd keyid/ä ");
    assert_eq!(env.signatures[0].keyid, "  odd keyid/ä ");
}

#[test]
fn sign_and_verify_round_trip_arbitrary_statement_value() {
    let env = sign(&json!({"hello": [1, 2.5, "x"]}), &key(), "k1");
    // Signature is good, so the only problems are statement-level.
    let r = verify(&env, &ctx());
    assert_status(&r, Status::Invalid, "_type");
    assert!(!r.reasons.iter().any(|x| x.contains("signature")), "{:?}", r.reasons);
}

// ── Valid statuses and the certified flag ───────────────────────────────

#[test]
fn valid_certified_attestation() {
    let env = envelope(&cert());
    let r = verify(&env, &ctx());
    assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
    assert!(r.reasons.is_empty(), "{:?}", r.reasons);
    assert_eq!(r.statement_digest, Some(sha256_hex(&payload_bytes(&env))));
    assert_eq!(r.release, Some(release()));
    assert_eq!(r.outcome, Some(Outcome::Certified));
    assert!(r.certified);
}

#[test]
fn blocked_decision_is_a_valid_attestation_but_not_certified() {
    let mut c = cert();
    c.decision.outcome = Outcome::Blocked;
    let r = verify(&envelope(&c), &ctx());
    assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
    assert_eq!(r.outcome, Some(Outcome::Blocked));
    assert!(!r.certified);
}

#[test]
fn limitations_yield_valid_with_limitations_and_still_certified() {
    let mut c = cert();
    c.limitations = vec!["locale en only".into()];
    let r = verify(&envelope(&c), &ctx());
    assert_status(&r, Status::ValidWithLimitations, "locale en only");
    assert!(r.certified);
}

#[test]
fn blocked_with_limitations_is_not_certified() {
    let mut c = cert();
    c.limitations = vec!["locale en only".into()];
    c.decision.outcome = Outcome::Blocked;
    let r = verify(&envelope(&c), &ctx());
    assert_eq!(r.status, Status::ValidWithLimitations);
    assert!(!r.certified);
}

#[test]
fn expected_release_matching_subject_is_valid() {
    let r = verify(&envelope(&cert()), &VerifyContext { expected_release: Some(release()), ..ctx() });
    assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
    assert!(r.certified);
}

#[test]
fn status_serialises_screaming_snake_case() {
    let all = [
        (Status::Valid, "VALID"),
        (Status::ValidWithLimitations, "VALID_WITH_LIMITATIONS"),
        (Status::Incomplete, "INCOMPLETE"),
        (Status::Expired, "EXPIRED"),
        (Status::Revoked, "REVOKED"),
        (Status::Invalid, "INVALID"),
    ];
    for (s, name) in all {
        assert_eq!(serde_json::to_value(s).unwrap(), json!(name));
    }
}

// ── Invalid: envelope ───────────────────────────────────────────────────

#[test]
fn wrong_payload_type_is_invalid() {
    let mut env = envelope(&cert());
    env.payload_type = "application/json".into();
    let r = verify(&env, &ctx());
    assert_status(&r, Status::Invalid, "payloadType");
}

#[test]
fn wrong_payload_type_signed_consistently_is_still_invalid() {
    let payload = payload_bytes(&envelope(&cert()));
    let sig = key().sign(&spec_pae("application/json", &payload));
    let env = Envelope {
        payload_type: "application/json".into(),
        payload: BASE64_STANDARD.encode(&payload),
        signatures: vec![Signature { keyid: "k1".into(), sig: BASE64_STANDARD.encode(sig.to_bytes()) }],
    };
    assert_status(&verify(&env, &ctx()), Status::Invalid, "payloadType");
}

#[test]
fn undecodable_payload_base64_is_invalid() {
    for bad in ["!!!not base64!!!", "eyJ", "eyJ9-_", " e30="] {
        let mut env = envelope(&cert());
        env.payload = bad.into();
        let r = verify(&env, &ctx());
        assert_status(&r, Status::Invalid, "payload");
        assert_eq!(r.statement_digest, None, "{bad}");
        assert_eq!(r.release, None);
        assert_eq!(r.outcome, None);
    }
}

#[test]
fn undecodable_signature_base64_is_invalid() {
    let mut env = envelope(&cert());
    env.signatures[0].sig = "%%%".into();
    assert_status(&verify(&env, &ctx()), Status::Invalid, "signature");
}

#[test]
fn signature_of_wrong_length_is_invalid() {
    let mut env = envelope(&cert());
    env.signatures[0].sig = BASE64_STANDARD.encode([1u8; 63]);
    assert_status(&verify(&env, &ctx()), Status::Invalid, "signature");
}

#[test]
fn no_signatures_is_invalid() {
    let mut env = envelope(&cert());
    env.signatures.clear();
    assert_status(&verify(&env, &ctx()), Status::Invalid, "signature");
}

#[test]
fn non_json_payload_is_invalid_with_digest() {
    let env = sign_raw(b"this is not json");
    let r = verify(&env, &ctx());
    assert_status(&r, Status::Invalid, "JSON");
    assert_eq!(r.statement_digest, Some(sha256_hex(b"this is not json")));
}

#[test]
fn non_object_json_is_invalid() {
    for v in [json!(null), json!([]), json!("x"), json!(1)] {
        assert_status(&verify(&sign_value(&v), &ctx()), Status::Invalid, "");
    }
}

#[test]
fn tampered_payload_is_invalid() {
    let mut c = cert();
    let env = envelope(&c);
    c.environment = "staging".into();
    let forged = envelope(&c);
    let tampered = Envelope { payload: forged.payload, ..env };
    assert_status(&verify(&tampered, &ctx()), Status::Invalid, "signature");
}

#[test]
fn tampered_signature_is_invalid() {
    let mut env = envelope(&cert());
    let mut sig = BASE64_STANDARD.decode(&env.signatures[0].sig).unwrap();
    sig[10] ^= 0x01;
    env.signatures[0].sig = BASE64_STANDARD.encode(sig);
    assert_status(&verify(&env, &ctx()), Status::Invalid, "signature");
}

#[test]
fn signature_by_untrusted_key_is_invalid() {
    let env = sign(&statement(&cert()), &other_key(), "k1");
    assert_status(&verify(&env, &ctx()), Status::Invalid, "signature");
    let env = sign(&statement(&cert()), &other_key(), "other");
    assert_status(&verify(&env, &ctx()), Status::Invalid, "signature");
}

#[test]
fn trusted_key_under_mismatched_keyid_is_invalid() {
    let env = sign(&statement(&cert()), &key(), "k2");
    assert_status(&verify(&env, &ctx()), Status::Invalid, "signature");
}

#[test]
fn no_trusted_keys_is_invalid() {
    let r = verify(&envelope(&cert()), &VerifyContext { trusted: vec![], ..ctx() });
    assert_status(&r, Status::Invalid, "signature");
}

#[test]
fn invalid_trusted_public_key_is_skipped_not_panicking() {
    // Not a valid curve point encoding for many byte patterns; must not panic.
    let ctx = VerifyContext {
        trusted: vec![TrustedKey { keyid: "k1".into(), public_key: [0xff; 32] }, trusted("k1", &key())],
        ..ctx()
    };
    assert_eq!(verify(&envelope(&cert()), &ctx).status, Status::Valid);
}

#[test]
fn any_one_trusted_signature_suffices() {
    let s = statement(&cert());
    let good = sign(&s, &key(), "k1");
    let bad = sign(&s, &other_key(), "rogue");
    let env = Envelope {
        signatures: vec![bad.signatures[0].clone(), good.signatures[0].clone()],
        ..good
    };
    let r = verify(&env, &ctx());
    assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
    assert!(r.reasons.is_empty(), "{:?}", r.reasons);
}

#[test]
fn second_trusted_key_verifies() {
    let ctx = VerifyContext { trusted: vec![trusted("k1", &key()), trusted("k2", &other_key())], ..ctx() };
    let env = sign(&statement(&cert()), &other_key(), "k2");
    assert_eq!(verify(&env, &ctx).status, Status::Valid);
}

// ── Invalid: statement ──────────────────────────────────────────────────

#[test]
fn wrong_statement_type_is_invalid() {
    let mut s = statement(&cert());
    s["_type"] = json!("https://in-toto.io/Statement/v0.1");
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "_type");
}

#[test]
fn wrong_predicate_type_is_invalid() {
    let mut s = statement(&cert());
    s["predicateType"] = json!("https://slsa.dev/provenance/v1");
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "predicateType");
}

#[test]
fn missing_type_fields_are_invalid() {
    let mut s = statement(&cert());
    s.as_object_mut().unwrap().remove("_type");
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "_type");
    let mut s = statement(&cert());
    s.as_object_mut().unwrap().remove("predicateType");
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "predicateType");
}

#[test]
fn malformed_predicate_is_invalid() {
    let mut s = statement(&cert());
    s["predicate"]["certification"]["surprise"] = json!(true);
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "predicate");

    let mut s = statement(&cert());
    s["predicate"] = json!({});
    let r = verify(&sign_value(&s), &ctx());
    assert_status(&r, Status::Invalid, "predicate");
    assert_eq!(r.outcome, None);

    let mut s = statement(&cert());
    s["predicate"]["certification"]["decision"]["outcome"] = json!("maybe");
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "predicate");

    let mut s = statement(&cert());
    s.as_object_mut().unwrap().remove("predicate");
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "predicate");
}

#[test]
fn malformed_subject_is_invalid() {
    for subject in [json!(null), json!([]), json!([{"name": "x"}]), json!([{"name": "x", "digest": {"sha256": 5}}])] {
        let mut s = statement(&cert());
        s["subject"] = subject.clone();
        let r = verify(&sign_value(&s), &ctx());
        assert_status(&r, Status::Invalid, "subject");
        assert_eq!(r.release, None, "{subject}");
    }
}

#[test]
fn subject_digest_not_matching_certification_release_is_invalid() {
    let mut s = statement(&cert());
    s["subject"][0]["digest"]["sha256"] = json!("cd".repeat(32));
    let r = verify(&sign_value(&s), &ctx());
    assert_status(&r, Status::Invalid, "subject");
    assert_eq!(r.release, Some(format!("sha256:{}", "cd".repeat(32))), "reports the subject");
}

#[test]
fn subject_digest_must_be_lowercase_hex() {
    let mut s = statement(&cert());
    s["subject"][0]["digest"]["sha256"] = json!(RELEASE_HEX.to_uppercase());
    assert_status(&verify(&sign_value(&s), &ctx()), Status::Invalid, "subject");
}

#[test]
fn decision_release_mismatch_is_invalid() {
    let mut c = cert();
    c.decision.release = format!("sha256:{}", "cd".repeat(32));
    assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, "decision.release");
}

#[test]
fn certification_release_not_a_hash_is_invalid() {
    let mut c = cert();
    c.release = "support-agent@184".into();
    c.decision.release = c.release.clone();
    assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, "release");
}

#[test]
fn expected_release_mismatch_is_invalid() {
    let other = format!("sha256:{}", "cd".repeat(32));
    let r = verify(&envelope(&cert()), &VerifyContext { expected_release: Some(other), ..ctx() });
    assert_status(&r, Status::Invalid, "expected");
    let r = verify(&envelope(&cert()), &VerifyContext { expected_release: Some("garbage".into()), ..ctx() });
    assert_status(&r, Status::Invalid, "expected");
}

#[test]
fn non_rfc3339_times_are_invalid() {
    let mut c = cert();
    c.issued_at = "2026-10-01".into();
    assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, "issuedAt");
    let mut c = cert();
    c.valid_until = "next tuesday".into();
    assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, "validUntil");
}

#[test]
fn unparseable_now_is_invalid() {
    assert_status(&verify(&envelope(&cert()), &ctx_at("now")), Status::Invalid, "now");
}

#[test]
fn valid_until_not_after_issued_at_is_invalid() {
    let mut c = cert();
    c.valid_until = c.issued_at.clone();
    assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, "validUntil");
    let mut c = cert();
    c.valid_until = "2026-09-30T00:00:00Z".into();
    assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, "validUntil");
}

#[test]
fn not_yet_valid_is_invalid() {
    let r = verify(&envelope(&cert()), &ctx_at("2026-09-30T23:59:59Z"));
    assert_status(&r, Status::Invalid, "issuedAt");
}

#[test]
fn now_equal_to_issued_at_is_valid() {
    assert_eq!(verify(&envelope(&cert()), &ctx_at(ISSUED_AT)).status, Status::Valid);
}

#[test]
fn time_window_boundaries() {
    let env = envelope(&cert());
    assert_eq!(verify(&env, &ctx_at("2026-10-30T23:59:59.999Z")).status, Status::Valid);
    let at = verify(&env, &ctx_at(VALID_UNTIL));
    assert_status(&at, Status::Expired, "validUntil");
    assert_eq!(at.outcome, Some(Outcome::Certified));
    assert!(!at.certified);
    assert_status(&verify(&env, &ctx_at("2027-01-01T00:00:00Z")), Status::Expired, "");
}

#[test]
fn time_comparisons_use_instants_not_strings() {
    let env = envelope(&cert());
    // Same instant as validUntil, different offset: expired.
    assert_eq!(verify(&env, &ctx_at("2026-10-31T02:00:00+02:00")).status, Status::Expired);
    // Lexically "after" validUntil but one hour before it as an instant.
    assert_eq!(verify(&env, &ctx_at("2026-10-31T00:00:00+01:00")).status, Status::Valid);
}

// ── Revoked ─────────────────────────────────────────────────────────────

#[test]
fn revoked_by_statement_digest() {
    let env = envelope(&cert());
    let digest = sha256_hex(&payload_bytes(&env));
    let r = verify(&env, &VerifyContext { revoked_statements: [digest].into(), ..ctx() });
    assert_status(&r, Status::Revoked, "revoked");
    assert!(!r.certified);
}

#[test]
fn revoking_another_statement_has_no_effect() {
    let env = envelope(&cert());
    let r = verify(&env, &VerifyContext { revoked_statements: ["00".repeat(32)].into(), ..ctx() });
    assert_eq!(r.status, Status::Valid);
}

#[test]
fn revoked_by_keyid() {
    let r = verify(&envelope(&cert()), &VerifyContext { revoked_keys: ["k1".to_string()].into(), ..ctx() });
    assert_status(&r, Status::Revoked, "k1");
    assert!(!r.certified);
}

#[test]
fn revoked_keyid_of_a_non_verifying_signature_has_no_effect() {
    let s = statement(&cert());
    let good = sign(&s, &key(), "k1");
    let rogue = sign(&s, &other_key(), "rogue");
    let env = Envelope { signatures: vec![rogue.signatures[0].clone(), good.signatures[0].clone()], ..good };
    let r = verify(&env, &VerifyContext { revoked_keys: ["rogue".to_string()].into(), ..ctx() });
    assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
}

// ── Incomplete ──────────────────────────────────────────────────────────

#[test]
fn incomplete_when_a_required_run_is_not_cited() {
    let ctx = VerifyContext { required_runs: Some(vec![RUN_HASH.into(), OTHER_RUN_HASH.into()]), ..ctx() };
    let r = verify(&envelope(&cert()), &ctx);
    assert_status(&r, Status::Incomplete, OTHER_RUN_HASH);
    assert!(!r.reasons.iter().any(|x| x.contains(RUN_HASH)), "{:?}", r.reasons);
    assert!(!r.certified);
}

#[test]
fn complete_when_all_required_runs_are_cited() {
    for required in [vec![], vec![RUN_HASH.to_string()]] {
        let r = verify(&envelope(&cert()), &VerifyContext { required_runs: Some(required), ..ctx() });
        assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
    }
}

#[test]
fn baseline_runs_do_not_satisfy_required_runs() {
    let mut c = cert();
    c.decision.baseline_runs = vec![cloakpipe_cert::RunRef {
        run_id: "base".into(),
        suite: "support-critical".into(),
        hash: OTHER_RUN_HASH.into(),
    }];
    let r = verify(&envelope(&c), &VerifyContext { required_runs: Some(vec![OTHER_RUN_HASH.into()]), ..ctx() });
    assert_eq!(r.status, Status::Incomplete);
}

// ── Precedence ──────────────────────────────────────────────────────────

/// A certification that trips every non-Invalid status at once.
fn everything_wrong_ctx(env: &Envelope) -> VerifyContext {
    VerifyContext {
        revoked_statements: [sha256_hex(&payload_bytes(env))].into(),
        revoked_keys: ["k1".to_string()].into(),
        now: "2027-01-01T00:00:00Z".into(),
        required_runs: Some(vec![OTHER_RUN_HASH.into()]),
        ..ctx()
    }
}

fn limited() -> Certification {
    let mut c = cert();
    c.limitations = vec!["locale en only".into()];
    c
}

#[test]
fn precedence_invalid_over_everything_and_all_reasons_reported() {
    let env = envelope(&limited());
    let ctx = VerifyContext {
        expected_release: Some(format!("sha256:{}", "cd".repeat(32))),
        ..everything_wrong_ctx(&env)
    };
    let r = verify(&env, &ctx);
    assert_status(&r, Status::Invalid, "expected");
    let all = r.reasons.join("\n");
    assert!(all.contains("revoked"), "{all}");
    assert!(all.contains("validUntil"), "{all}");
    assert!(all.contains(OTHER_RUN_HASH), "{all}");
    assert!(all.contains("locale en only"), "{all}");
}

#[test]
fn precedence_revoked_over_expired_incomplete_limitations() {
    let env = envelope(&limited());
    let r = verify(&env, &everything_wrong_ctx(&env));
    assert_status(&r, Status::Revoked, "revoked");
    assert!(r.reasons.len() >= 4, "{:?}", r.reasons);
}

#[test]
fn precedence_expired_over_incomplete_and_limitations() {
    let env = envelope(&limited());
    let ctx = VerifyContext { revoked_statements: Default::default(), revoked_keys: Default::default(), ..everything_wrong_ctx(&env) };
    assert_status(&verify(&env, &ctx), Status::Expired, OTHER_RUN_HASH);
}

#[test]
fn precedence_incomplete_over_limitations() {
    let env = envelope(&limited());
    let ctx = VerifyContext { required_runs: Some(vec![OTHER_RUN_HASH.into()]), ..ctx() };
    assert_status(&verify(&env, &ctx), Status::Incomplete, "locale en only");
}

#[test]
fn status_order_matches_precedence() {
    use Status::*;
    let mut v = vec![Invalid, Valid, Expired, ValidWithLimitations, Revoked, Incomplete];
    v.sort();
    assert_eq!(v, vec![Valid, ValidWithLimitations, Incomplete, Expired, Revoked, Invalid]);
}

// ── Never panics ────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn verify_never_panics_on_arbitrary_envelopes(
        payload_type in ".{0,40}",
        payload in ".{0,200}",
        keyid in ".{0,10}",
        sig in ".{0,100}",
        now in ".{0,30}",
    ) {
        let env = Envelope { payload_type, payload, signatures: vec![Signature { keyid, sig }] };
        let r = verify(&env, &ctx_at(&now));
        prop_assert_eq!(r.status, Status::Invalid);
        prop_assert!(!r.certified);
    }

    #[test]
    fn verify_never_panics_on_signed_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let r = verify(&sign_raw(&bytes), &ctx());
        prop_assert_eq!(r.status, Status::Invalid);
        prop_assert_eq!(r.statement_digest, Some(sha256_hex(&bytes)));
    }

    #[test]
    fn verify_never_panics_on_signed_mutated_statements(
        field in prop::sample::select(vec!["release", "agent", "environment", "issuedAt", "validUntil", "issuer", "limitations", "decision"]),
        replacement in prop_oneof![
            Just(json!(null)), Just(json!(1e308)), Just(json!(-1)), Just(json!("")),
            Just(json!([])), Just(json!({})), ".{0,30}".prop_map(Value::from),
        ],
    ) {
        let mut s = statement(&cert());
        s["predicate"]["certification"][field] = replacement;
        let _ = verify(&sign_value(&s), &ctx());
    }

    #[test]
    fn sign_verify_round_trip_for_any_agent_and_environment(agent in ".{0,20}", env in ".{0,20}") {
        let mut c = cert();
        c.agent = Some(agent.clone());
        c.environment = env;
        let e = envelope(&c);
        let st = statement(&c);
        let name = format!("agent-release:{agent}");
        prop_assert_eq!(st["subject"][0]["name"].as_str(), Some(name.as_str()));
        let r = verify(&e, &ctx());
        prop_assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
        prop_assert!(r.certified);
    }
}

// ── Review findings ─────────────────────────────────────────────────────

#[test]
fn revoked_verifying_key_is_revoked_even_when_another_trusted_key_signed() {
    let s = statement(&cert());
    let a = sign(&s, &key(), "k1");
    let b = sign(&s, &other_key(), "k2");
    let env = Envelope { signatures: vec![a.signatures[0].clone(), b.signatures[0].clone()], ..a };
    let ctx = VerifyContext {
        trusted: vec![trusted("k1", &key()), trusted("k2", &other_key())],
        revoked_keys: ["k1".to_string()].into(),
        ..ctx()
    };
    assert_status(&verify(&env, &ctx), Status::Revoked, "k1");
}

#[test]
fn space_separated_timestamps_are_not_rfc3339() {
    for (field, value) in [("issuedAt", "2026-10-01 00:00:00Z"), ("validUntil", "2026-10-31 00:00:00Z")] {
        let mut v = cert_json();
        v[field] = json!(value);
        let c: Certification = serde_json::from_value(v).unwrap();
        assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, field);
    }
    assert_status(&verify(&envelope(&cert()), &ctx_at("2026-10-06 12:00:00Z")), Status::Invalid, "now");
}

#[test]
fn lowercase_t_and_z_timestamps_are_rfc3339() {
    let mut v = cert_json();
    v["issuedAt"] = json!("2026-10-01t00:00:00z");
    let c: Certification = serde_json::from_value(v).unwrap();
    assert_eq!(verify(&envelope(&c), &ctx()).status, Status::Valid);
}

#[test]
fn subject_name_mismatch_is_not_in_the_invalid_list() {
    let mut s = statement(&cert());
    s["subject"][0]["name"] = json!("agent-release:other-agent");
    let r = verify(&sign_value(&s), &ctx());
    assert_eq!(r.status, Status::Valid, "{:?}", r.reasons);
}

#[test]
fn non_finite_float_certification_is_invalid_not_panicking() {
    // JSON cannot represent NaN; the statement carries `null`, which is a
    // malformed certification. Documented, not a round-trip.
    let mut c = cert();
    c.decision.summaries[0].pass_rate = f64::NAN;
    assert_status(&verify(&envelope(&c), &ctx()), Status::Invalid, "predicate");
}

#[test]
fn duplicate_keys_in_signed_payload_are_invalid() {
    let canon = String::from_utf8(serde_json_canonicalizer::to_vec(&statement(&cert())).unwrap()).unwrap();
    let top = canon.replacen('{', "{\"_type\":\"evil\",", 1);
    assert_status(&verify(&sign_raw(top.as_bytes()), &ctx()), Status::Invalid, "duplicate");
    let nested = canon.replacen("\"issuer\":", "\"issuer\":\"evil\",\"issuer\":", 1);
    assert_status(&verify(&sign_raw(nested.as_bytes()), &ctx()), Status::Invalid, "duplicate");
}


// ── Certification identity ──────────────────────────────────────────────

#[test]
fn certifications_differing_only_by_id_have_distinct_digests_and_revoke_independently() {
    // Two otherwise identical issuances (same release, decision, second and
    // issuer) must not share a statement digest, or revoking one would revoke
    // the other, including across tenants.
    let a = envelope(&cert());
    let mut other = cert();
    other.id = "cert-0002".into();
    let b = envelope(&other);
    let (da, db) = (sha256_hex(&payload_bytes(&a)), sha256_hex(&payload_bytes(&b)));
    assert_ne!(da, db);

    let revoke_a = VerifyContext { revoked_statements: [da].into(), ..ctx() };
    assert_eq!(verify(&a, &revoke_a).status, Status::Revoked);
    assert_eq!(verify(&b, &revoke_a).status, Status::Valid);
}

#[test]
fn a_certification_without_an_id_is_invalid() {
    let mut c = cert();
    c.id = "  ".into();
    let r = verify(&envelope(&c), &ctx());
    assert_eq!(r.status, Status::Invalid, "{:?}", r.reasons);
    assert!(r.reasons.iter().any(|x| x.contains("id")), "{:?}", r.reasons);
}

#[test]
fn the_certification_id_is_required_in_json() {
    let mut v = cert_json();
    v.as_object_mut().unwrap().remove("id");
    assert!(serde_json::from_value::<Certification>(v).is_err());
}
