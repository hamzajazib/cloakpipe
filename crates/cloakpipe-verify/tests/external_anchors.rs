//! External anchoring against RECORDED real responses.
//!
//! The fixtures in `tests/fixtures/anchoring/` are real RFC 3161 responses
//! from freetsa.org and DigiCert and real Rekor entries from
//! rekor.sigstore.dev, captured by `tools/capture_anchor_fixtures.sh` over
//! the batch heads built in `common`. Everything here runs offline.

mod common;

use base64::Engine;
use cloakpipe_verify::anchor::{verify_anchors, verify_anchors_with_trust, AnchorTrust, AnchorVerifyError};
use cloakpipe_verify::bundle::{AnchorReceiptRef, Bundle, Record};
use cloakpipe_verify::rekor::{verify_rekor_entry, RekorError, RekorKey};
use cloakpipe_verify::rfc3161::{verify_timestamp_response, Rfc3161Error, TrustedRoots};
use common::*;
use sha2::{Digest, Sha256};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn nonce(name: &str) -> Vec<u8> {
    hex::decode(String::from_utf8(fixture(&format!("{name}.nonce"))).unwrap().trim()).unwrap()
}

fn freetsa_roots() -> TrustedRoots {
    TrustedRoots::from_pem(&fixture("freetsa-root.pem")).unwrap()
}

fn digicert_roots() -> TrustedRoots {
    TrustedRoots::from_pem(&fixture("digicert-trusted-root-g4.pem")).unwrap()
}

fn rekor_key() -> RekorKey {
    RekorKey::from_pem(&fixture("rekor.pub")).unwrap()
}

fn operator_pub() -> [u8; 32] {
    operator_key().verifying_key().to_bytes()
}

/// (uuid, entry) from a recorded `POST /api/v1/log/entries` response.
fn rekor_entry(name: &str) -> (String, serde_json::Value) {
    let v: serde_json::Value = serde_json::from_slice(&fixture(&format!("{name}.json"))).unwrap();
    let (uuid, entry) = v.as_object().unwrap().iter().next().unwrap();
    (uuid.clone(), entry.clone())
}

fn tsa_receipt(s: &Scenario, name: &str, url: &str) -> AnchorReceiptRef {
    AnchorReceiptRef::Rfc3161 {
        batch_id: s.batch_id.into(),
        subject_hash: hex_lower(&sha256(&head_bytes(s))),
        tsa_url: url.into(),
        nonce: hex_lower(&nonce(name)),
        tsr: B64.encode(fixture(&format!("{name}.tsr"))),
    }
}

fn rekor_receipt(s: &Scenario, name: &str) -> AnchorReceiptRef {
    let (entry_uuid, entry) = rekor_entry(name);
    AnchorReceiptRef::Rekor {
        batch_id: s.batch_id.into(),
        subject_hash: hex_lower(&sha256(&head_bytes(s))),
        rekor_url: "https://rekor.sigstore.dev".into(),
        entry_uuid,
        entry,
    }
}

fn anchored(s: &Scenario, tsa: &str, rekor: &str) -> Bundle {
    let mut b = bundle_for(s);
    b.anchor_receipts = vec![tsa_receipt(s, tsa, "https://freetsa.org/tsr"), rekor_receipt(s, rekor)];
    b
}

fn full_trust() -> AnchorTrust {
    AnchorTrust { tsa_roots: Some(freetsa_roots()), rekor_key: Some(rekor_key()) }
}

// ── RFC 3161 ────────────────────────────────────────────────────────────

#[test]
fn freetsa_token_verifies_offline() {
    let ts = verify_timestamp_response(
        &fixture("freetsa-honest.tsr"),
        &sha256(&head_bytes(&HONEST)),
        &nonce("freetsa-honest"),
        &freetsa_roots(),
    )
    .expect("freetsa token verifies");
    assert_eq!(ts.gen_time, "2026-10-07T11:58:53Z");
    assert!(ts.tsa_subject.contains("freetsa.org"), "{}", ts.tsa_subject);
}

#[test]
fn digicert_token_verifies_through_an_intermediate() {
    let ts = verify_timestamp_response(
        &fixture("digicert-honest.tsr"),
        &sha256(&head_bytes(&HONEST)),
        &nonce("digicert-honest"),
        &digicert_roots(),
    )
    .expect("digicert token verifies");
    assert_eq!(ts.gen_time, "2026-10-07T11:58:55Z");
    assert!(ts.tsa_subject.contains("DigiCert"), "{}", ts.tsa_subject);
}

#[test]
fn token_does_not_chain_to_another_root() {
    let honest = sha256(&head_bytes(&HONEST));
    let e = verify_timestamp_response(
        &fixture("freetsa-honest.tsr"),
        &honest,
        &nonce("freetsa-honest"),
        &digicert_roots(),
    )
    .unwrap_err();
    assert!(matches!(e, Rfc3161Error::UntrustedChain(_)), "{e}");
    let e = verify_timestamp_response(
        &fixture("digicert-honest.tsr"),
        &honest,
        &nonce("digicert-honest"),
        &freetsa_roots(),
    )
    .unwrap_err();
    assert!(matches!(e, Rfc3161Error::UntrustedChain(_)), "{e}");
}

#[test]
fn token_for_another_hash_is_rejected() {
    let e = verify_timestamp_response(
        &fixture("freetsa-honest.tsr"),
        &sha256(&head_bytes(&FUTURE)),
        &nonce("freetsa-honest"),
        &freetsa_roots(),
    )
    .unwrap_err();
    assert!(matches!(e, Rfc3161Error::ImprintMismatch), "{e}");
}

#[test]
fn nonce_must_echo() {
    let mut n = nonce("freetsa-honest");
    *n.last_mut().unwrap() ^= 1;
    let e =
        verify_timestamp_response(&fixture("freetsa-honest.tsr"), &sha256(&head_bytes(&HONEST)), &n, &freetsa_roots())
            .unwrap_err();
    assert!(matches!(e, Rfc3161Error::NonceMismatch), "{e}");
}

#[test]
fn rejection_status_is_not_a_timestamp() {
    // TimeStampResp { status: { status: rejection(2) } } with no token.
    let rejected = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
    let e = verify_timestamp_response(&rejected, &[0; 32], &[1], &freetsa_roots()).unwrap_err();
    assert!(matches!(e, Rfc3161Error::NotGranted(2)), "{e}");
}

#[test]
fn garbage_and_truncation_are_rejected() {
    let tsr = fixture("freetsa-honest.tsr");
    let roots = freetsa_roots();
    let honest = sha256(&head_bytes(&HONEST));
    let n = nonce("freetsa-honest");
    assert!(verify_timestamp_response(&[], &honest, &n, &roots).is_err());
    assert!(verify_timestamp_response(b"not der", &honest, &n, &roots).is_err());
    assert!(verify_timestamp_response(&tsr[..tsr.len() - 1], &honest, &n, &roots).is_err());
    let mut trailing = tsr.clone();
    trailing.push(0);
    assert!(verify_timestamp_response(&trailing, &honest, &n, &roots).is_err());
}

/// Byte offset of `needle` inside `hay` (the first occurrence).
fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).position(|w| w == needle).expect("needle present")
}

/// DER of every certificate carried in the token that is on the path to
/// the root: copies of the root (self-signed or cross-signed, i.e. any cert
/// with the root's subject) are never used, the anchor comes from the
/// caller's PEM.
fn embedded_certs(tsr: &[u8], root_pem: &[u8]) -> Vec<Vec<u8>> {
    use der::{Decode, DecodePem, Encode};
    #[derive(der::Sequence)]
    struct Resp {
        status: der::Any,
        token: cms::content_info::ContentInfo,
    }
    let root = x509_cert::Certificate::from_pem(root_pem).unwrap();
    let r = Resp::from_der(tsr).unwrap();
    let sd: cms::signed_data::SignedData = r.token.content.decode_as().unwrap();
    sd.certificates
        .unwrap()
        .0
        .iter()
        .filter_map(|c| match c {
            cms::cert::CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .filter(|c| c.tbs_certificate.subject != root.tbs_certificate.subject)
        .map(|c| c.to_der().unwrap())
        .collect()
}

#[test]
fn flipping_a_byte_in_any_signed_region_fails() {
    for (name, root) in [("freetsa-honest", "freetsa-root.pem"), ("digicert-honest", "digicert-trusted-root-g4.pem")] {
        let roots = TrustedRoots::from_pem(&fixture(root)).unwrap();
        let tsr = fixture(&format!("{name}.tsr"));
        let honest = sha256(&head_bytes(&HONEST));
        let n = nonce(name);
        // The message imprint (inside TSTInfo), the nonce, the TSA's
        // signature (last bytes of the response) and the middle of every
        // certificate on the path to the root.
        let mut targets = vec![
            ("imprint".to_string(), find(&tsr, &honest) + 5),
            ("nonce".to_string(), find(&tsr, &n) + n.len() - 1),
            ("signature".to_string(), tsr.len() - 3),
        ];
        let certs = embedded_certs(&tsr, &fixture(root));
        assert!(!certs.is_empty());
        for (i, c) in certs.iter().enumerate() {
            let at = find(&tsr, c);
            targets.push((format!("certificate {i} (tbs)"), at + c.len() / 3));
            targets.push((format!("certificate {i} (signature)"), at + c.len() - 2));
        }
        for (what, at) in targets {
            let mut t = tsr.clone();
            t[at] ^= 0x01;
            let r = verify_timestamp_response(&t, &honest, &n, &roots);
            assert!(r.is_err(), "{name}: flipped {what} byte at {at} still verified");
        }
    }
}

#[test]
fn no_single_byte_flip_changes_the_attested_time() {
    // Sweep: any flip either fails or (in an unsigned, unused byte) leaves
    // the verified facts identical. Never a different time.
    let tsr = fixture("freetsa-honest.tsr");
    let honest = sha256(&head_bytes(&HONEST));
    let n = nonce("freetsa-honest");
    let roots = freetsa_roots();
    let want = verify_timestamp_response(&tsr, &honest, &n, &roots).unwrap();
    for at in (0..tsr.len()).step_by(17) {
        let mut t = tsr.clone();
        t[at] ^= 0x80;
        if let Ok(got) = verify_timestamp_response(&t, &honest, &n, &roots) {
            assert_eq!(got, want, "flip at {at} changed the verified timestamp");
        }
    }
}

#[test]
fn trusted_roots_reject_bad_pem() {
    assert!(TrustedRoots::from_pem(b"").is_err());
    assert!(TrustedRoots::from_pem(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err());
    assert!(TrustedRoots::from_pem(&fixture("rekor.pub")).is_err());
}

// ── Rekor ───────────────────────────────────────────────────────────────

#[test]
fn rekor_entry_verifies_offline() {
    let (uuid, entry) = rekor_entry("rekor-honest");
    let v = verify_rekor_entry(&uuid, &entry, &rekor_key(), &head_bytes(&HONEST), &operator_pub())
        .expect("rekor entry verifies");
    assert_eq!(v.integrated_time, entry["integratedTime"].as_i64().unwrap());
    assert_eq!(v.log_index, entry["logIndex"].as_u64().unwrap());
}

#[test]
fn rekor_entry_for_another_head_is_rejected() {
    let (uuid, entry) = rekor_entry("rekor-honest");
    let e = verify_rekor_entry(&uuid, &entry, &rekor_key(), &head_bytes(&FUTURE), &operator_pub()).unwrap_err();
    assert!(matches!(e, RekorError::ArtifactHashMismatch), "{e}");
}

#[test]
fn rekor_entry_signed_by_another_key_is_rejected() {
    let (uuid, entry) = rekor_entry("rekor-honest");
    let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let e = verify_rekor_entry(&uuid, &entry, &rekor_key(), &head_bytes(&HONEST), &other).unwrap_err();
    assert!(matches!(e, RekorError::SignerKeyMismatch), "{e}");
}

#[test]
fn rekor_entry_under_another_log_key_is_rejected() {
    let (uuid, entry) = rekor_entry("rekor-honest");
    // A well-formed P-256 key that is not Rekor's.
    let other = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEofsPhdK8DgRBO5whe6X2NpTrvuAE\n\
cLsnl2Di9aop3lhqr3wFUmrqeizU5m39DIDwt0tzydccly1cxgABu6XRfA==\n\
-----END PUBLIC KEY-----\n";
    let key = RekorKey::from_pem(other.as_bytes()).unwrap();
    let e = verify_rekor_entry(&uuid, &entry, &key, &head_bytes(&HONEST), &operator_pub()).unwrap_err();
    assert!(matches!(e, RekorError::LogIdMismatch), "{e}");
}

fn rekor_tamper(f: impl FnOnce(&mut serde_json::Value, &mut String)) -> RekorError {
    let (mut uuid, mut entry) = rekor_entry("rekor-honest");
    f(&mut entry, &mut uuid);
    verify_rekor_entry(&uuid, &entry, &rekor_key(), &head_bytes(&HONEST), &operator_pub()).unwrap_err()
}

fn flip_hex(s: &str, at: usize) -> String {
    let mut c: Vec<char> = s.chars().collect();
    c[at] = if c[at] == '0' { '1' } else { '0' };
    c.into_iter().collect()
}

#[test]
fn rekor_body_tamper_fails() {
    let e = rekor_tamper(|e, _| {
        let mut body = B64.decode(e["body"].as_str().unwrap()).unwrap();
        let at = body.len() / 2;
        body[at] ^= 0x01;
        e["body"] = B64.encode(body).into();
    });
    assert!(matches!(e, RekorError::SetInvalid | RekorError::BadBody(_)), "{e}");
}

#[test]
fn rekor_set_covers_integrated_time_and_index() {
    let e = rekor_tamper(|e, _| e["integratedTime"] = (e["integratedTime"].as_i64().unwrap() - 86_400).into());
    assert!(matches!(e, RekorError::SetInvalid), "{e}");
    let e = rekor_tamper(|e, _| e["logIndex"] = (e["logIndex"].as_u64().unwrap() + 1).into());
    assert!(matches!(e, RekorError::SetInvalid), "{e}");
    let e = rekor_tamper(|e, _| {
        let set = B64.decode(e["verification"]["signedEntryTimestamp"].as_str().unwrap()).unwrap();
        let mut set = set.clone();
        let at = set.len() - 2;
        set[at] ^= 0x01;
        e["verification"]["signedEntryTimestamp"] = B64.encode(set).into();
    });
    assert!(matches!(e, RekorError::SetInvalid | RekorError::Malformed(_)), "{e}");
}

#[test]
fn rekor_inclusion_proof_tamper_fails() {
    let e = rekor_tamper(|e, _| {
        let h = e["verification"]["inclusionProof"]["hashes"][3].as_str().unwrap().to_string();
        e["verification"]["inclusionProof"]["hashes"][3] = flip_hex(&h, 10).into();
    });
    assert!(matches!(e, RekorError::InclusionProofInvalid), "{e}");
    let e = rekor_tamper(|e, _| {
        let i = e["verification"]["inclusionProof"]["logIndex"].as_u64().unwrap();
        e["verification"]["inclusionProof"]["logIndex"] = (i ^ 1).into();
    });
    assert!(matches!(e, RekorError::InclusionProofInvalid), "{e}");
    let e = rekor_tamper(|e, _| {
        e["verification"]["inclusionProof"]["hashes"].as_array_mut().unwrap().pop();
    });
    assert!(matches!(e, RekorError::InclusionProofInvalid), "{e}");
}

#[test]
fn rekor_checkpoint_must_be_signed_and_match_the_proof() {
    let e = rekor_tamper(|e, _| {
        let r = e["verification"]["inclusionProof"]["rootHash"].as_str().unwrap().to_string();
        e["verification"]["inclusionProof"]["rootHash"] = flip_hex(&r, 0).into();
    });
    assert!(matches!(e, RekorError::InclusionProofInvalid | RekorError::CheckpointMismatch), "{e}");
    let e = rekor_tamper(|e, _| {
        let cp = e["verification"]["inclusionProof"]["checkpoint"].as_str().unwrap().to_string();
        // Change the tree size line: the checkpoint signature breaks.
        let mut lines: Vec<String> = cp.split('\n').map(str::to_string).collect();
        lines[1] = (lines[1].parse::<u64>().unwrap() + 1).to_string();
        e["verification"]["inclusionProof"]["checkpoint"] = lines.join("\n").into();
    });
    assert!(matches!(e, RekorError::CheckpointInvalid | RekorError::CheckpointMismatch), "{e}");
    let e = rekor_tamper(|e, _| {
        let cp = e["verification"]["inclusionProof"]["checkpoint"].as_str().unwrap();
        let (text, _) = cp.split_once("\n\n").unwrap();
        e["verification"]["inclusionProof"]["checkpoint"] = format!("{text}\n\n").into();
    });
    assert!(matches!(e, RekorError::CheckpointInvalid), "{e}");
}

#[test]
fn rekor_uuid_must_name_this_leaf() {
    let e = rekor_tamper(|_, u| *u = flip_hex(u, u.len() - 1));
    assert!(matches!(e, RekorError::UuidMismatch), "{e}");
}

#[test]
fn rekor_missing_fields_fail_closed() {
    for field in ["body", "integratedTime", "logID", "logIndex", "verification"] {
        let e = rekor_tamper(|e, _| {
            e.as_object_mut().unwrap().remove(field);
        });
        assert!(matches!(e, RekorError::Malformed(_)), "{field}: {e}");
    }
    let e = rekor_tamper(|e, _| {
        e["verification"].as_object_mut().unwrap().remove("inclusionProof");
    });
    assert!(matches!(e, RekorError::Malformed(_)), "{e}");
}

#[test]
fn rekor_key_rejects_non_p256() {
    assert!(RekorKey::from_pem(b"").is_err());
    assert!(RekorKey::from_pem(&fixture("operator.pub.pem")).is_err());
    assert!(RekorKey::from_pem(&fixture("freetsa-root.pem")).is_err());
}

// ── Bundles ─────────────────────────────────────────────────────────────

#[test]
fn anchored_bundle_verifies_with_both_trust_inputs() {
    let b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    let n = verify_anchors_with_trust(&b, &full_trust()).expect("anchors verify");
    assert_eq!(n, 2);
}

#[test]
fn digicert_receipt_verifies_with_digicert_root() {
    let mut b = bundle_for(&HONEST);
    b.anchor_receipts = vec![tsa_receipt(&HONEST, "digicert-honest", "http://timestamp.digicert.com")];
    let trust = AnchorTrust { tsa_roots: Some(digicert_roots()), rekor_key: None };
    assert_eq!(verify_anchors_with_trust(&b, &trust).unwrap(), 1);
}

#[test]
fn external_receipts_without_trust_input_fail() {
    let b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    let e = verify_anchors(&b).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::MissingTrust { .. }), "{e}");
    let tsa_only = AnchorTrust { tsa_roots: Some(freetsa_roots()), rekor_key: None };
    let e = verify_anchors_with_trust(&b, &tsa_only).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::MissingTrust { ref kind, .. } if kind == "rekor"), "{e}");
    let rekor_only = AnchorTrust { tsa_roots: None, rekor_key: Some(rekor_key()) };
    let e = verify_anchors_with_trust(&b, &rekor_only).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::MissingTrust { ref kind, .. } if kind == "rfc3161"), "{e}");
}

#[test]
fn trust_input_without_matching_receipts_fails() {
    // --rekor-key was given, but nothing in the bundle is in Rekor.
    let mut b = bundle_for(&HONEST);
    b.anchor_receipts = vec![tsa_receipt(&HONEST, "freetsa-honest", "https://freetsa.org/tsr")];
    let e = verify_anchors_with_trust(&b, &full_trust()).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::HeadNotAnchored { ref kind, .. } if kind == "rekor"), "{e}");
    // An unanchored bundle with trust inputs is not "verified".
    let e = verify_anchors_with_trust(&bundle_for(&HONEST), &full_trust()).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::HeadNotAnchored { .. }), "{e}");
}

#[test]
fn back_dated_records_are_detected() {
    // Records and seal time claim 2027; the TSA and Rekor prove the head
    // existed on 2026-10-07.
    let b = anchored(&FUTURE, "freetsa-future", "rekor-future");
    let e = verify_anchors_with_trust(&b, &full_trust()).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::BackDating { .. }), "{e}");
    for receipt in b.anchor_receipts.clone() {
        let mut one = b.clone();
        let trust = match receipt {
            AnchorReceiptRef::Rfc3161 { .. } => AnchorTrust { tsa_roots: Some(freetsa_roots()), rekor_key: None },
            _ => AnchorTrust { tsa_roots: None, rekor_key: Some(rekor_key()) },
        };
        one.anchor_receipts = vec![receipt];
        let e = verify_anchors_with_trust(&one, &trust).unwrap_err();
        assert!(matches!(e, AnchorVerifyError::BackDating { .. }), "{e}");
    }
}

#[test]
fn a_record_stamped_after_the_anchor_is_detected() {
    // Only the head's signed_time is honest; one record claims a later
    // time than the anchor. Re-sealing is impossible without a new anchor,
    // so build the record set first and keep the honest head: the record
    // hash then no longer matches the head's Merkle root -> rejected, and
    // the time check fires before any other check would hide it.
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    let r = &mut b.records[2];
    r.canonical_bytes = r.canonical_bytes.replace("2026-10-07T10:00:00Z", "2026-10-08T00:00:00Z");
    let e = verify_anchors_with_trust(&b, &full_trust()).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::BackDating { .. }), "{e}");
}

#[test]
fn a_head_without_an_anchor_fails() {
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    let mut extra = b.batch_heads[0].clone();
    extra.batch_id = "batch-unanchored".into();
    b.batch_heads.push(extra);
    let e = verify_anchors_with_trust(&b, &full_trust()).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::HeadNotAnchored { ref batch_id, .. } if batch_id == "batch-unanchored"), "{e}");
}

#[test]
fn a_record_outside_every_anchored_head_fails() {
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    let last = b.records.last().unwrap().clone();
    let canonical = format!("seq=5\nts=2026-10-07T10:00:00Z\ntenant_id={TENANT}\nhop=llm_prompt");
    b.records.push(Record {
        seq: 5,
        tenant_id: TENANT.into(),
        record_hash: hex_lower(&sha256(canonical.as_bytes())),
        canonical_bytes: canonical,
        prev_hash: last.record_hash,
    });
    b.inclusion_proofs.push(None);
    cloakpipe_verify::verify::verify_chain(&b).expect("chain still links");
    let e = verify_anchors_with_trust(&b, &full_trust()).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::RecordNotAnchored { seq: 5 }), "{e}");
}

#[test]
fn receipt_for_a_different_head_fails() {
    let mut b = bundle_for(&HONEST);
    // FUTURE's receipts, relabelled with HONEST's batch id.
    let mut r = tsa_receipt(&FUTURE, "freetsa-future", "https://freetsa.org/tsr");
    if let AnchorReceiptRef::Rfc3161 { batch_id, subject_hash, .. } = &mut r {
        *batch_id = HONEST.batch_id.into();
        *subject_hash = hex_lower(&sha256(&head_bytes(&HONEST)));
    }
    b.anchor_receipts = vec![r];
    let trust = AnchorTrust { tsa_roots: Some(freetsa_roots()), rekor_key: None };
    let e = verify_anchors_with_trust(&b, &trust).unwrap_err();
    assert!(matches!(e, AnchorVerifyError::Rfc3161 { .. }), "{e}");
}

#[test]
fn tampered_receipt_fields_fail_in_the_bundle() {
    let trust = full_trust();
    // Token bytes.
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    if let AnchorReceiptRef::Rfc3161 { tsr, .. } = &mut b.anchor_receipts[0] {
        let mut der = B64.decode(&*tsr).unwrap();
        let at = der.len() - 5;
        der[at] ^= 1;
        *tsr = B64.encode(der);
    }
    assert!(verify_anchors_with_trust(&b, &trust).is_err());
    // Not base64.
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    if let AnchorReceiptRef::Rfc3161 { tsr, .. } = &mut b.anchor_receipts[0] {
        tsr.insert(0, '!');
    }
    assert!(verify_anchors_with_trust(&b, &trust).is_err());
    // Nonce.
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    if let AnchorReceiptRef::Rfc3161 { nonce, .. } = &mut b.anchor_receipts[0] {
        *nonce = flip_hex(nonce, 3);
    }
    assert!(verify_anchors_with_trust(&b, &trust).is_err());
    // Rekor proof.
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    if let AnchorReceiptRef::Rekor { entry, .. } = &mut b.anchor_receipts[1] {
        let h = entry["verification"]["inclusionProof"]["hashes"][0].as_str().unwrap().to_string();
        entry["verification"]["inclusionProof"]["hashes"][0] = flip_hex(&h, 5).into();
    }
    assert!(verify_anchors_with_trust(&b, &trust).is_err());
    // Head bytes: the batch head's merkle root changes -> subject changes.
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    b.batch_heads[0].signed_time = Some("2026-10-07T10:05:01Z".into());
    assert!(matches!(
        verify_anchors_with_trust(&b, &trust).unwrap_err(),
        AnchorVerifyError::SubjectHashMismatch { .. }
    ));
}

#[test]
fn receipts_round_trip_through_bundle_json() {
    let b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    let j = serde_json::to_string(&b).unwrap();
    assert!(j.contains("\"kind\":\"rfc3161\"") && j.contains("\"kind\":\"rekor\""));
    let back: Bundle = serde_json::from_str(&j).unwrap();
    assert_eq!(verify_anchors_with_trust(&back, &full_trust()).unwrap(), 2);
}
