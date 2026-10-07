//! Deterministic bundles for the external-anchoring tests.
//!
//! The recorded TSA tokens and Rekor entries under
//! `tests/fixtures/anchoring/` were captured over the exact batch-head bytes
//! these builders produce, so every field here is fixed: record timestamps,
//! the operator's signing seed, the batch id and the seal time. Changing any
//! of them changes the head and invalidates the recordings.

#![allow(dead_code)]

use cloakpipe_anchor::merkle::{MerkleTree, ProofPosition};
use cloakpipe_verify::bundle::{
    BatchHead, Bundle, InclusionProofRef, ProofStepRef, Record, SignedBatchHead, SignerKey, BUNDLE_FORMAT_VERSION,
    BUNDLE_MAGIC,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const TENANT: &str = "550e8400-e29b-41d4-a716-446655440000";
pub const OPERATOR_KEY_ID: &str = "default";
/// The operator's Ed25519 seed. Test-only; it signs the batch heads and the
/// Rekor hashedrekord entries in the fixtures.
pub const OPERATOR_SEED: [u8; 32] = [0x42; 32];

/// One fixed scenario: records stamped `record_ts`, sealed at `signed_time`.
pub struct Scenario {
    pub batch_id: &'static str,
    pub record_ts: &'static str,
    pub signed_time: &'static str,
}

/// Records and seal time that precede the recorded anchors (captured
/// 2026-10-07): verification must pass.
pub const HONEST: Scenario =
    Scenario { batch_id: "batch-honest-001", record_ts: "2026-10-07T10:00:00Z", signed_time: "2026-10-07T10:05:00Z" };

/// Records and seal time claimed for 2027 while the anchors prove the head
/// existed in 2026: back-dating, verification must fail.
pub const FUTURE: Scenario =
    Scenario { batch_id: "batch-future-001", record_ts: "2027-01-01T00:00:00Z", signed_time: "2027-01-01T00:05:00Z" };

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/anchoring")
}

pub fn fixture(name: &str) -> Vec<u8> {
    let p = fixtures_dir().join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

pub fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn operator_key() -> SigningKey {
    SigningKey::from_bytes(&OPERATOR_SEED)
}

/// A v4 bundle with five chained records, one signed batch head over all of
/// them and per-record inclusion proofs. No anchor receipts and no manifest.
pub fn bundle_for(s: &Scenario) -> Bundle {
    let mut records = Vec::new();
    let mut hashes = Vec::new();
    let mut prev = [0u8; 32];
    for seq in 0..5u64 {
        let canonical = format!("seq={seq}\nts={}\ntenant_id={TENANT}\nhop=llm_prompt", s.record_ts);
        let hash: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        records.push(Record {
            seq,
            tenant_id: TENANT.into(),
            canonical_bytes: canonical,
            record_hash: hex_lower(&hash),
            prev_hash: hex_lower(&prev),
        });
        hashes.push(hash);
        prev = hash;
    }
    let tree = MerkleTree::from_hashed_leaves(hashes);
    let mut head = BatchHead {
        batch_id: s.batch_id.into(),
        first_seq: 0,
        last_seq: 4,
        merkle_root: hex_lower(&tree.root()),
        algorithm: "ed25519".into(),
        signed_time: Some(s.signed_time.into()),
        signature: SignedBatchHead { key_id: OPERATOR_KEY_ID.into(), algorithm: "ed25519".into(), value: String::new() },
    };
    // The head signature covers the unsigned fields, in declaration order.
    #[derive(serde::Serialize)]
    struct Unsigned<'a> {
        batch_id: &'a str,
        first_seq: u64,
        last_seq: u64,
        merkle_root: &'a str,
        algorithm: &'a str,
        signed_time: &'a Option<String>,
    }
    let unsigned = Unsigned {
        batch_id: &head.batch_id,
        first_seq: head.first_seq,
        last_seq: head.last_seq,
        merkle_root: &head.merkle_root,
        algorithm: &head.algorithm,
        signed_time: &head.signed_time,
    };
    let payload = serde_json::to_vec(&unsigned).unwrap();
    head.signature.value = hex_lower(&operator_key().sign(&payload).to_bytes());

    let inclusion_proofs = (0..5)
        .map(|i| {
            let p = tree.inclusion_proof(i);
            Some(InclusionProofRef {
                batch_id: s.batch_id.into(),
                leaf_index: i as u64,
                total_leaves: 5,
                steps: p
                    .steps
                    .into_iter()
                    .map(|st| ProofStepRef {
                        position: match st.position {
                            ProofPosition::Left => "left".into(),
                            ProofPosition::Right => "right".into(),
                        },
                        hash: hex_lower(&st.hash),
                    })
                    .collect(),
            })
        })
        .collect();

    Bundle {
        format: BUNDLE_MAGIC.into(),
        format_version: BUNDLE_FORMAT_VERSION,
        tenant_id: TENANT.into(),
        created_at: "2026-10-07T10:06:00Z".into(),
        range_start: None,
        range_end: None,
        records,
        inclusion_proofs,
        batch_heads: vec![head],
        signer_public_keys: vec![SignerKey {
            key_id: OPERATOR_KEY_ID.into(),
            algorithm: "ed25519".into(),
            public_key: hex_lower(&operator_key().verifying_key().to_bytes()),
        }],
        anchor_receipts: vec![],
        manifest: None,
        policy_packs: vec![],
    }
}

/// The exact bytes an anchor commits to for this scenario's batch head.
pub fn head_bytes(s: &Scenario) -> Vec<u8> {
    serde_json::to_vec(&bundle_for(s).batch_heads[0]).unwrap()
}

/// Append `n` records stamped `ts`, chained to the bundle's last record,
/// sealed under a new operator-signed head `batch_id` (signed at
/// `signed_time`) with per-record inclusion proofs. No anchor is added:
/// this is what an operator holding the key can forge after the fact.
pub fn append_batch(b: &mut Bundle, batch_id: &str, n: u64, ts: &str, signed_time: &str) {
    let first = b.records.last().map_or(0, |r| r.seq + 1);
    let mut prev = b.records.last().map(|r| r.record_hash.clone()).unwrap_or_else(|| "0".repeat(64));
    let mut hashes = Vec::new();
    for seq in first..first + n {
        let canonical = format!("seq={seq}\nts={ts}\ntenant_id={TENANT}\nhop=llm_prompt");
        let hash: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        b.records.push(Record {
            seq,
            tenant_id: TENANT.into(),
            canonical_bytes: canonical,
            record_hash: hex_lower(&hash),
            prev_hash: prev,
        });
        prev = hex_lower(&hash);
        hashes.push(hash);
    }
    let tree = MerkleTree::from_hashed_leaves(hashes);
    let mut head = BatchHead {
        batch_id: batch_id.into(),
        first_seq: first,
        last_seq: first + n - 1,
        merkle_root: hex_lower(&tree.root()),
        algorithm: "ed25519".into(),
        signed_time: Some(signed_time.into()),
        signature: SignedBatchHead { key_id: OPERATOR_KEY_ID.into(), algorithm: "ed25519".into(), value: String::new() },
    };
    #[derive(serde::Serialize)]
    struct Unsigned<'a> {
        batch_id: &'a str,
        first_seq: u64,
        last_seq: u64,
        merkle_root: &'a str,
        algorithm: &'a str,
        signed_time: &'a Option<String>,
    }
    let payload = serde_json::to_vec(&Unsigned {
        batch_id: &head.batch_id,
        first_seq: head.first_seq,
        last_seq: head.last_seq,
        merkle_root: &head.merkle_root,
        algorithm: &head.algorithm,
        signed_time: &head.signed_time,
    })
    .unwrap();
    head.signature.value = hex_lower(&operator_key().sign(&payload).to_bytes());
    for i in 0..n as usize {
        let p = tree.inclusion_proof(i);
        b.inclusion_proofs.push(Some(InclusionProofRef {
            batch_id: batch_id.into(),
            leaf_index: i as u64,
            total_leaves: n,
            steps: p
                .steps
                .into_iter()
                .map(|st| ProofStepRef {
                    position: match st.position {
                        ProofPosition::Left => "left".into(),
                        ProofPosition::Right => "right".into(),
                    },
                    hash: hex_lower(&st.hash),
                })
                .collect(),
        }));
    }
    b.batch_heads.push(head);
}
