//! RFC 3161 and Rekor clients against a local server replaying the real
//! responses recorded from freetsa.org and rekor.sigstore.dev. Offline.

mod common;

use base64::Engine;
use cloakpipe_anchor::anchor::rekor::{hashedrekord_request, RekorClient};
use cloakpipe_anchor::anchor::rfc3161::{fresh_nonce, timestamp_request, TsaClient};
use cloakpipe_anchor::anchor::AnchorError;
use cloakpipe_anchor::batch::SignedBatchHead;
use cloakpipe_anchor::receipt::ExternalReceipt;
use cloakpipe_verify::rekor::RekorKey;
use cloakpipe_verify::rfc3161::TrustedRoots;
use common::*;
use sha2::{Digest, Sha256};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn operator() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
}

fn honest_head() -> SignedBatchHead {
    serde_json::from_slice(&fixture("head-honest.json")).unwrap()
}

fn recorded_nonce(name: &str) -> Vec<u8> {
    hex::decode(String::from_utf8(fixture(&format!("{name}.nonce"))).unwrap()).unwrap()
}

fn freetsa_roots() -> TrustedRoots {
    TrustedRoots::from_pem(&fixture("freetsa-root.pem")).unwrap()
}

fn rekor_key() -> RekorKey {
    RekorKey::from_pem(&fixture("rekor.pub")).unwrap()
}

// ── Request encoding ────────────────────────────────────────────────────

#[test]
fn timestamp_request_is_exact_der() {
    let req = timestamp_request(&[0x11; 32], &[0x01, 0x02]);
    let mut want = hex::decode("303d020101303130 0d060960864801650304020105000420".replace(' ', "")).unwrap();
    want.extend([0x11; 32]);
    want.extend([0x02, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff]);
    assert_eq!(hex::encode(&req), hex::encode(&want));
}

#[test]
fn timestamp_request_pads_and_strips_the_nonce_integer() {
    let tail = |r: Vec<u8>| r[2 + 3 + 51..].to_vec();
    assert_eq!(tail(timestamp_request(&[0; 32], &[0x80, 0x01])), [0x02, 0x03, 0x00, 0x80, 0x01, 0x01, 0x01, 0xff]);
    assert_eq!(tail(timestamp_request(&[0; 32], &[0x00, 0x00, 0x05])), [0x02, 0x01, 0x05, 0x01, 0x01, 0xff]);
}

#[test]
#[should_panic]
fn timestamp_request_rejects_a_zero_nonce() {
    timestamp_request(&[0; 32], &[0, 0]);
}

#[test]
fn nonces_are_positive_minimal_and_fresh() {
    let a = fresh_nonce();
    let b = fresh_nonce();
    assert_ne!(a, b);
    for n in [a, b] {
        assert_eq!(n.len(), 16);
        assert!(n[0] != 0 && n[0] & 0x80 == 0, "{n:?}");
    }
}

#[test]
fn head_bytes_match_the_verifier_serialization() {
    // The anchored subject is the head's JSON as the verifier re-serializes it.
    assert_eq!(serde_json::to_vec(&honest_head()).unwrap(), fixture("head-honest.json"));
}

#[test]
fn hashedrekord_request_matches_what_rekor_recorded() {
    // Ed25519 is deterministic: our request must be byte-for-byte the body
    // Rekor stored for the OpenSSL-built submission of the same head.
    let req = hashedrekord_request(&fixture("head-honest.json"), &operator());
    let v: serde_json::Value = serde_json::from_slice(&fixture("rekor-honest.json")).unwrap();
    let body = B64.decode(v.as_object().unwrap().values().next().unwrap()["body"].as_str().unwrap()).unwrap();
    assert_eq!(req, String::from_utf8(body).unwrap());
}

// ── TSA client ──────────────────────────────────────────────────────────

#[test]
fn tsa_client_posts_a_timestamp_query_and_verifies_the_reply() {
    let (url, seen) = serve(vec![Reply::new(200, "application/timestamp-reply", fixture("freetsa-honest.tsr"))]);
    let client = TsaClient::new(format!("{url}/tsr"), freetsa_roots());
    let head = honest_head();
    let nonce = recorded_nonce("freetsa-honest");
    let r = client.anchor_head_with_nonce(&head, &nonce).expect("timestamp");
    let req = seen.recv().unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/tsr");
    assert_eq!(req.content_type.as_deref(), Some("application/timestamp-query"));
    let subject: [u8; 32] = Sha256::digest(fixture("head-honest.json")).into();
    assert_eq!(req.body, timestamp_request(&subject, &nonce));
    match r {
        ExternalReceipt::Rfc3161 { batch_id, subject_hash, tsa_url, nonce: n, tsr } => {
            assert_eq!(batch_id, head.batch_id);
            assert_eq!(subject_hash, hex::encode(subject));
            assert_eq!(tsa_url, format!("{url}/tsr"));
            assert_eq!(n, hex::encode(&nonce));
            assert_eq!(B64.decode(tsr).unwrap(), fixture("freetsa-honest.tsr"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn tsa_client_refuses_a_reply_it_cannot_verify() {
    let head = honest_head();
    let nonce = recorded_nonce("freetsa-honest");
    // Fresh nonce: the recorded reply cannot echo it.
    let (url, _) = serve(vec![Reply::new(200, "application/timestamp-reply", fixture("freetsa-honest.tsr"))]);
    let e = TsaClient::new(url, freetsa_roots()).anchor_head(&head).unwrap_err();
    assert!(matches!(e, AnchorError::Rejected(_)), "{e}");
    // Wrong roots.
    let (url, _) = serve(vec![Reply::new(200, "application/timestamp-reply", fixture("freetsa-honest.tsr"))]);
    let digicert = TrustedRoots::from_pem(&fixture("digicert-trusted-root-g4.pem")).unwrap();
    let e = TsaClient::new(url, digicert).anchor_head_with_nonce(&head, &nonce).unwrap_err();
    assert!(matches!(e, AnchorError::Rejected(_)), "{e}");
    // HTTP error, wrong content type.
    let (url, _) = serve(vec![Reply::new(500, "text/plain", b"down".to_vec())]);
    let e = TsaClient::new(url, freetsa_roots()).anchor_head_with_nonce(&head, &nonce).unwrap_err();
    assert!(matches!(e, AnchorError::Submit(_)), "{e}");
    let (url, _) = serve(vec![Reply::new(200, "text/html", fixture("freetsa-honest.tsr"))]);
    let e = TsaClient::new(url, freetsa_roots()).anchor_head_with_nonce(&head, &nonce).unwrap_err();
    assert!(matches!(e, AnchorError::Submit(_)), "{e}");
}

#[test]
fn tsa_client_reports_an_unreachable_tsa() {
    let e = TsaClient::new("http://127.0.0.1:9/tsr".to_string(), freetsa_roots())
        .anchor_head(&honest_head())
        .unwrap_err();
    assert!(matches!(e, AnchorError::Unavailable(_)), "{e}");
}

// ── Rekor client ────────────────────────────────────────────────────────

#[test]
fn rekor_client_submits_and_verifies_the_entry() {
    let (url, seen) = serve(vec![Reply::new(201, "application/json", fixture("rekor-honest.json"))]);
    let client = RekorClient::new(url.clone(), rekor_key());
    let head = honest_head();
    let r = client.anchor_head(&head, &operator()).expect("rekor entry");
    let req = seen.recv().unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/v1/log/entries");
    assert_eq!(req.content_type.as_deref(), Some("application/json"));
    assert_eq!(String::from_utf8(req.body).unwrap(), hashedrekord_request(&fixture("head-honest.json"), &operator()));
    let recorded: serde_json::Value = serde_json::from_slice(&fixture("rekor-honest.json")).unwrap();
    let (uuid, entry) = recorded.as_object().unwrap().iter().next().unwrap();
    match r {
        ExternalReceipt::Rekor { batch_id, rekor_url, entry_uuid, entry: got, .. } => {
            assert_eq!(batch_id, head.batch_id);
            assert_eq!(rekor_url, url);
            assert_eq!(&entry_uuid, uuid);
            assert_eq!(&got, entry);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn rekor_client_fetches_an_existing_entry_on_conflict() {
    let recorded: serde_json::Value = serde_json::from_slice(&fixture("rekor-honest.json")).unwrap();
    let uuid = recorded.as_object().unwrap().keys().next().unwrap().clone();
    let mut conflict = Reply::new(409, "application/json", br#"{"code":409,"message":"exists"}"#.to_vec());
    conflict.headers.push(("Location".into(), format!("/api/v1/log/entries/{uuid}")));
    let (url, seen) = serve(vec![conflict, Reply::new(200, "application/json", fixture("rekor-honest.json"))]);
    let r = RekorClient::new(url, rekor_key()).anchor_head(&honest_head(), &operator()).expect("existing entry");
    assert_eq!(seen.recv().unwrap().method, "POST");
    let get = seen.recv().unwrap();
    assert_eq!((get.method.as_str(), get.path), ("GET", format!("/api/v1/log/entries/{uuid}")));
    assert!(matches!(r, ExternalReceipt::Rekor { .. }));
}

#[test]
fn rekor_client_refuses_entries_it_cannot_verify() {
    let head = honest_head();
    // An entry for a different head.
    let (url, _) = serve(vec![Reply::new(201, "application/json", fixture("rekor-future.json"))]);
    let e = RekorClient::new(url, rekor_key()).anchor_head(&head, &operator()).unwrap_err();
    assert!(matches!(e, AnchorError::Rejected(_)), "{e}");
    // Signed with a key other than the one we submitted with.
    let (url, _) = serve(vec![Reply::new(201, "application/json", fixture("rekor-honest.json"))]);
    let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let e = RekorClient::new(url, rekor_key()).anchor_head(&head, &other).unwrap_err();
    assert!(matches!(e, AnchorError::Rejected(_)), "{e}");
    // More than one entry, or none.
    let (url, _) = serve(vec![Reply::new(201, "application/json", b"{}".to_vec())]);
    let e = RekorClient::new(url, rekor_key()).anchor_head(&head, &operator()).unwrap_err();
    assert!(matches!(e, AnchorError::Rejected(_)), "{e}");
    let (url, _) = serve(vec![Reply::new(400, "application/json", br#"{"code":400}"#.to_vec())]);
    let e = RekorClient::new(url, rekor_key()).anchor_head(&head, &operator()).unwrap_err();
    assert!(matches!(e, AnchorError::Submit(_)), "{e}");
}
