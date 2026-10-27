//! The anchor clients timestamp and log arbitrary bytes (ledger epoch
//! heads), and the local test authorities (`cloakpipe_anchor::testkit`)
//! answer in a form this verifier accepts offline, exactly as it accepts
//! the recorded freetsa.org and rekor.sigstore.dev answers.

use base64::Engine;
use cloakpipe_anchor::anchor::rekor::RekorClient;
use cloakpipe_anchor::anchor::rfc3161::TsaClient;
use cloakpipe_anchor::receipt::ExternalReceipt;
use cloakpipe_anchor::testkit::{MockRekor, MockTsa};
use cloakpipe_verify::rekor::{verify_rekor_entry, RekorError, RekorKey};
use cloakpipe_verify::rfc3161::{verify_timestamp_response, Rfc3161Error, TrustedRoots};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn tsa_parts(r: &ExternalReceipt) -> (Vec<u8>, Vec<u8>) {
    match r {
        ExternalReceipt::Rfc3161 { tsr, nonce, .. } => (B64.decode(tsr).unwrap(), hex::decode(nonce).unwrap()),
        other => panic!("not a TSA receipt: {other:?}"),
    }
}

#[test]
fn a_mock_tsa_timestamp_for_any_artifact_verifies_offline() {
    let tsa = MockTsa::start();
    let roots = TrustedRoots::from_pem(&tsa.root_pem()).unwrap();
    let client = TsaClient::new(tsa.url(), roots.clone());
    let artifact = br#"{"kind":"cloakpipe.epoch/v1","epoch":0}"#;
    let receipt = client.anchor_artifact("epoch-0", artifact).expect("anchored");
    assert_eq!(receipt.batch_id(), "epoch-0");
    let (tsr, nonce) = tsa_parts(&receipt);
    let subject: [u8; 32] = Sha256::digest(artifact).into();
    let t = verify_timestamp_response(&tsr, &subject, &nonce, &roots).expect("verifies");
    assert!((t.gen_time_unix - chrono::Utc::now().timestamp()).abs() < 60);

    // Bound to the artifact, the nonce and the pinned root.
    let other: [u8; 32] = Sha256::digest(b"other").into();
    assert_eq!(verify_timestamp_response(&tsr, &other, &nonce, &roots), Err(Rfc3161Error::ImprintMismatch));
    assert_eq!(verify_timestamp_response(&tsr, &subject, &[9; 16], &roots), Err(Rfc3161Error::NonceMismatch));
    let stranger = TrustedRoots::from_pem(&MockTsa::start().root_pem()).unwrap();
    assert!(verify_timestamp_response(&tsr, &subject, &nonce, &stranger).is_err());
}

#[test]
fn a_mock_tsa_can_fail_and_run_its_clock_off() {
    let tsa = MockTsa::start();
    let roots = TrustedRoots::from_pem(&tsa.root_pem()).unwrap();
    let client = TsaClient::new(tsa.url(), roots.clone());
    tsa.set_failing(true);
    assert!(client.anchor_artifact("e", b"x").is_err());
    tsa.set_failing(false);
    tsa.set_clock_offset(-3600);
    let receipt = client.anchor_artifact("e", b"x").unwrap();
    let (tsr, nonce) = tsa_parts(&receipt);
    let t = verify_timestamp_response(&tsr, &Sha256::digest(b"x").into(), &nonce, &roots).unwrap();
    assert!((t.gen_time_unix - (chrono::Utc::now().timestamp() - 3600)).abs() < 60);
    assert_eq!((tsa.requests(), tsa.issued()), (2, 1));
}

#[test]
fn a_mock_rekor_entry_for_any_artifact_verifies_offline() {
    let rekor = MockRekor::start();
    let key = RekorKey::from_pem(&rekor.key_pem()).unwrap();
    let client = RekorClient::new(rekor.url(), key.clone());
    let signer = SigningKey::from_bytes(&[5; 32]);
    let mut receipts = Vec::new();
    // Several entries, so inclusion proofs have real paths.
    for i in 0..5u8 {
        let artifact = format!("epoch head {i}").into_bytes();
        receipts.push((artifact.clone(), client.anchor_artifact(&format!("epoch-{i}"), &artifact, &signer).expect("logged")));
    }
    assert_eq!(rekor.entries(), 5);
    for (artifact, r) in &receipts {
        let ExternalReceipt::Rekor { entry_uuid, entry, .. } = r else { panic!("not a Rekor receipt") };
        let v = verify_rekor_entry(entry_uuid, entry, &key, artifact, &signer.verifying_key().to_bytes()).expect("verifies");
        assert!((v.integrated_time - chrono::Utc::now().timestamp()).abs() < 60);
        assert_eq!(
            verify_rekor_entry(entry_uuid, entry, &key, b"another head", &signer.verifying_key().to_bytes()),
            Err(RekorError::ArtifactHashMismatch)
        );
    }
    let stranger = RekorKey::from_pem(&MockRekor::start().key_pem()).unwrap();
    let (artifact, ExternalReceipt::Rekor { entry_uuid, entry, .. }) = &receipts[0] else { panic!() };
    assert_eq!(
        verify_rekor_entry(entry_uuid, entry, &stranger, artifact, &signer.verifying_key().to_bytes()),
        Err(RekorError::LogIdMismatch)
    );
    rekor.set_failing(true);
    assert!(client.anchor_artifact("x", b"x", &signer).is_err());
}
