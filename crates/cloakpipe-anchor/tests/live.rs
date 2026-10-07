//! Live anchoring against freetsa.org, DigiCert and rekor.sigstore.dev.
//!
//! Skipped unless `CLOAKPIPE_LIVE_ANCHOR=1` (the `live-anchor` CI job sets
//! it). Each run writes a new, permanent, public Rekor entry containing only
//! a hash, a signature and a throwaway public key.
//!
//! Endpoints and trust inputs can be overridden with
//! `CLOAKPIPE_TSA_URL` / `CLOAKPIPE_REKOR_URL`; the default trust inputs are
//! the committed fixtures.

mod common;

use cloakpipe_anchor::anchor::rekor::{RekorClient, DEFAULT_REKOR_URL};
use cloakpipe_anchor::anchor::rfc3161::{TsaClient, DEFAULT_TSA_URL, DIGICERT_TSA_URL};
use cloakpipe_anchor::batch::SignedBatchHead;
use cloakpipe_anchor::merkle::MerkleTree;
use cloakpipe_anchor::receipt::ExternalReceipt;
use cloakpipe_verify::anchor::{verify_anchors_with_trust, AnchorTrust};
use cloakpipe_verify::bundle::{
    AnchorReceiptRef, BatchHead, Bundle, InclusionProofRef, Record, SignerKey, BUNDLE_FORMAT_VERSION, BUNDLE_MAGIC,
};
use cloakpipe_verify::rekor::RekorKey;
use cloakpipe_verify::rfc3161::TrustedRoots;
use common::fixture;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn live() -> bool {
    let on = std::env::var("CLOAKPIPE_LIVE_ANCHOR").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set CLOAKPIPE_LIVE_ANCHOR=1 to anchor against the live services");
    }
    on
}

/// A one-record bundle whose head is signed now by a fresh key.
fn fresh() -> (Bundle, SignedBatchHead, SigningKey) {
    let key = SigningKey::from_bytes(&rand::random());
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let canonical = format!("seq=0\nts={now}\ntenant_id=00000000-0000-4000-8000-000000000000\nhop=llm_prompt");
    let hash: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
    let root = MerkleTree::from_hashed_leaves(vec![hash]).root();
    let batch_id = format!("live-{}", uuid::Uuid::new_v4());
    #[derive(serde::Serialize)]
    struct Unsigned<'a> {
        batch_id: &'a str,
        first_seq: u64,
        last_seq: u64,
        merkle_root: &'a str,
        algorithm: &'a str,
        signed_time: &'a Option<String>,
    }
    let signed_time = Some(now);
    let root_hex = hex::encode(root);
    let payload =
        serde_json::to_vec(&Unsigned { batch_id: &batch_id, first_seq: 0, last_seq: 0, merkle_root: &root_hex, algorithm: "ed25519", signed_time: &signed_time })
            .unwrap();
    let head = cloakpipe_anchor::batch::build_signed_batch_head(
        batch_id.clone(),
        0,
        0,
        root_hex.as_str(),
        "ed25519",
        signed_time,
        "default",
        "ed25519",
        hex::encode(key.sign(&payload).to_bytes()),
    );
    let verifier_head: BatchHead = serde_json::from_slice(&serde_json::to_vec(&head).unwrap()).unwrap();
    let bundle = Bundle {
        format: BUNDLE_MAGIC.into(),
        format_version: BUNDLE_FORMAT_VERSION,
        tenant_id: "00000000-0000-4000-8000-000000000000".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        range_start: None,
        range_end: None,
        records: vec![Record {
            seq: 0,
            tenant_id: "00000000-0000-4000-8000-000000000000".into(),
            canonical_bytes: canonical,
            record_hash: hex::encode(hash),
            prev_hash: "0".repeat(64),
        }],
        inclusion_proofs: vec![Some(InclusionProofRef { batch_id, leaf_index: 0, total_leaves: 1, steps: vec![] })],
        batch_heads: vec![verifier_head],
        signer_public_keys: vec![SignerKey {
            key_id: "default".into(),
            algorithm: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
        }],
        anchor_receipts: vec![],
        manifest: None,
        policy_packs: vec![],
    };
    (bundle, head, key)
}

fn to_ref(r: &ExternalReceipt) -> AnchorReceiptRef {
    serde_json::from_value(serde_json::to_value(r).unwrap()).unwrap()
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

#[test]
fn live_freetsa_and_rekor_anchor_a_fresh_head() {
    if !live() {
        return;
    }
    let (mut bundle, head, key) = fresh();
    let tsa = TsaClient::new(env_or("CLOAKPIPE_TSA_URL", DEFAULT_TSA_URL), roots("freetsa-root.pem"));
    let rekor = RekorClient::new(env_or("CLOAKPIPE_REKOR_URL", DEFAULT_REKOR_URL), rekor_key());
    let t = tsa.anchor_head(&head).expect("freetsa timestamp");
    let r = rekor.anchor_head(&head, &key).expect("rekor entry");
    bundle.anchor_receipts = vec![to_ref(&t), to_ref(&r)];
    let trust = AnchorTrust { tsa_roots: Some(roots("freetsa-root.pem")), rekor_key: Some(rekor_key()) };
    assert_eq!(verify_anchors_with_trust(&bundle, &trust).expect("verifies offline"), 2);
    // Re-submitting the same head is idempotent (409 -> existing entry; the
    // proof may be against a newer tree, the entry itself is the same).
    let again = rekor.anchor_head(&head, &key).expect("existing entry");
    match (&again, &r) {
        (ExternalReceipt::Rekor { entry_uuid: u1, entry: e1, .. }, ExternalReceipt::Rekor { entry_uuid: u2, entry: e2, .. }) => {
            assert_eq!(u1, u2);
            for f in ["body", "integratedTime", "logIndex", "logID"] {
                assert_eq!(e1[f], e2[f], "{f}");
            }
        }
        _ => panic!("expected Rekor receipts"),
    }
}

#[test]
fn live_digicert_timestamps_a_fresh_head() {
    if !live() {
        return;
    }
    let (mut bundle, head, _) = fresh();
    let tsa = TsaClient::new(DIGICERT_TSA_URL, roots("digicert-trusted-root-g4.pem"));
    bundle.anchor_receipts = vec![to_ref(&tsa.anchor_head(&head).expect("digicert timestamp"))];
    let trust = AnchorTrust { tsa_roots: Some(roots("digicert-trusted-root-g4.pem")), rekor_key: None };
    assert_eq!(verify_anchors_with_trust(&bundle, &trust).expect("verifies offline"), 1);
}

#[test]
fn live_rekor_serves_the_committed_public_key() {
    if !live() {
        return;
    }
    let url = format!("{}/api/v1/log/publicKey", env_or("CLOAKPIPE_REKOR_URL", DEFAULT_REKOR_URL));
    let served = reqwest::blocking::get(&url).and_then(|r| r.bytes()).expect("fetch Rekor key");
    assert_eq!(
        RekorKey::from_pem(&served).unwrap().log_id_hex(),
        rekor_key().log_id_hex(),
        "rekor.sigstore.dev rotated its key: re-run tools/capture_anchor_fixtures.sh"
    );
}

fn roots(name: &str) -> TrustedRoots {
    TrustedRoots::from_pem(&fixture(name)).unwrap()
}

fn rekor_key() -> RekorKey {
    RekorKey::from_pem(&fixture("rekor.pub")).unwrap()
}
