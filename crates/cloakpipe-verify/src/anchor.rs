//! Anchor verification (M3.6).
//!
//! Pure functions over the bundle's `anchor_receipts` and
//! `inclusion_proofs`. Mirrors the wire-format types from
//! `cloakpipe-anchor` — same architecture as the chain verifier:
//! the verifier defines its own types and they must remain
//! byte-compatible with the producer.
//!
//! ## Checks performed
//!
//! 1. **TSA receipt**: the TSA's Ed25519 signature over the canonical
//!    signed payload is valid, given the included TSA public key.
//!    The message imprint in the token matches the subject hash.
//! 2. **Log receipt**: the log's Ed25519 signature on the STH is
//!    valid. The STH's root matches what the inclusion proof
//!    reconstructs from (subject_hash, leaf_index, proof steps).
//! 3. **Subject hash**: the receipt's subject_hash equals the SHA-256
//!    of the canonical bytes of the referenced batch head.
//! 4. **Back-dating**: the receipt's claimed_time is not before the
//!    batch head's signed_time (the operator's claim about when the
//!    batch was sealed).
//!
//! All checks return errors that callers pattern-match on; nothing
//! is logged or printed.

use crate::bundle::{
    AnchorReceiptRef, BatchHead, Bundle, InclusionProofRef, Manifest,
    PolicyPackRef, ProofStepRef,
};
use base64::Engine;
use ed25519_dalek::{Signature as DalekSig, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnchorVerifyError {
    #[error("anchor receipt for batch `{0}` references unknown key id (not a TSA nor log pubkey in the bundle)")]
    UnknownKey(String),
    #[error("TSA signature invalid for batch `{0}`")]
    TsaSignatureInvalid(String),
    #[error("log STH signature invalid for batch `{0}`")]
    LogSthSignatureInvalid(String),
    #[error("log inclusion proof invalid for batch `{0}`")]
    LogInclusionProofInvalid(String),
    #[error("inclusion proof invalid for record #{seq} against batch `{batch_id}`")]
    InclusionProofInvalid { seq: u64, batch_id: String },
    #[error("inclusion proof missing for record #{seq} but batch `{batch_id}` is anchored")]
    InclusionProofMissing { seq: u64, batch_id: String },
    #[error("inclusion proof references unknown batch `{0}` (not declared in bundle.batch_heads)")]
    UnknownBatch(String),
    #[error("subject hash mismatch for batch `{batch_id}` — receipt `{got}`, expected `{expected}`")]
    SubjectHashMismatch {
        batch_id: String,
        got: String,
        expected: String,
    },
    #[error("back-dating detected for batch `{batch_id}` — signed_time `{claimed}`, anchor time `{anchor}`")]
    BackDating {
        batch_id: String,
        claimed: String,
        anchor: String,
    },
    #[error("invalid hex in anchor field for batch `{batch_id}`: {field}")]
    BadHex { batch_id: String, field: String },
    #[error("invalid RFC3339 timestamp in anchor for batch `{batch_id}`: {value}")]
    BadTimestamp { batch_id: String, value: String },
    #[error("bundle carries `{kind}` receipts but no trust input was given for them ({flag})")]
    MissingTrust { kind: String, flag: String },
    #[error("batch `{batch_id}` has no verified `{kind}` anchor")]
    HeadNotAnchored { batch_id: String, kind: String },
    #[error("record #{seq} is not covered by any anchored batch head")]
    RecordNotAnchored { seq: u64 },
    #[error("RFC 3161 receipt for batch `{batch_id}`: {error}")]
    Rfc3161 { batch_id: String, error: crate::rfc3161::Rfc3161Error },
    #[error("Rekor receipt for batch `{batch_id}`: {error}")]
    Rekor { batch_id: String, error: crate::rekor::RekorError },
    #[error("batch id `{0}` is used by more than one batch head")]
    DuplicateBatchId(String),
    #[error("batch head `{batch_id}` has an empty or inverted range {first_seq}..={last_seq}")]
    BadBatchRange { batch_id: String, first_seq: u64, last_seq: u64 },
    #[error("batch heads `{a}` and `{b}` cover overlapping record ranges")]
    OverlappingBatches { a: String, b: String },
}

/// Trust inputs for external anchors. Each is supplied by the verifying
/// party, never read from the bundle.
#[derive(Debug, Clone, Default)]
pub struct AnchorTrust {
    /// Roots an RFC 3161 TSA certificate must chain to (`--tsa-root`).
    pub tsa_roots: Option<crate::rfc3161::TrustedRoots>,
    /// The Rekor log's public key (`--rekor-key`).
    pub rekor_key: Option<crate::rekor::RekorKey>,
}

impl AnchorTrust {
    fn is_empty(&self) -> bool {
        self.tsa_roots.is_none() && self.rekor_key.is_none()
    }
}

const KIND_RFC3161: &str = "rfc3161";
const KIND_REKOR: &str = "rekor";

/// Mirror of `cloakpipe-anchor::receipt::SignedTreeHead`.
/// Byte-compatible with the JSON wire format; the verifier defines
/// its own type to stay standalone.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct SthRef {
    log_id: String,
    tree_size: u64,
    root_hash: String,
    claimed_time: String,
    signature: String,
    pubkey: String,
}

/// Unsigned view of a manifest. The producer signs over the
/// deterministic JSON of this struct; the verifier re-serializes
/// and re-hashes.
#[derive(Debug, Clone, Serialize)]
struct UnsignedManifest<'a> {
    bundle_id: &'a str,
    range_start: &'a str,
    range_end: &'a str,
    record_count: u64,
    first_seq: u64,
    last_seq: u64,
    batch_head_ids: &'a [String],
    anchor_receipt_refs: &'a [String],
    policy_pack_versions: &'a [String],
    operator: &'a str,
    created_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_tip: &'a Option<String>,
}

impl<'a> From<&'a Manifest> for UnsignedManifest<'a> {
    fn from(m: &'a Manifest) -> Self {
        Self {
            bundle_id: &m.bundle_id,
            range_start: &m.range_start,
            range_end: &m.range_end,
            record_count: m.record_count,
            first_seq: m.first_seq,
            last_seq: m.last_seq,
            batch_head_ids: &m.batch_head_ids,
            anchor_receipt_refs: &m.anchor_receipt_refs,
            policy_pack_versions: &m.policy_pack_versions,
            operator: &m.operator,
            created_at: &m.created_at,
            chain_tip: &m.chain_tip,
        }
    }
}/// Compute the canonical subject hash for a batch head — the bytes
/// the anchor backend signed over (and the verifier re-hashes).
///
/// This MUST match `cloakpipe-anchor::receipt::subject_hash_for` —
/// i.e. `SHA-256(serde_json::to_vec(producer_signed_head))` where
/// `producer_signed_head` has the same field shape as the bundle's
/// `BatchHead`. The producer's `SignedBatchHead` is defined with
/// the same field set and order so the two serializations match
/// byte-for-byte.
fn subject_hash_for_batch(head: &BatchHead) -> [u8; 32] {
    let bytes = serde_json::to_vec(head).expect("serialize batch head");
    let mut h = Sha256::new();
    h.update(&bytes);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// Domain-separated leaf hash, same as cloakpipe-anchor::merkle.
fn leaf_hash(value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(value);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// Domain-separated internal node hash.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn decode_hex_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Verify a Merkle inclusion proof against `expected_root`.
///
/// `leaf_value` is treated as **already-hashed** (the input to
/// `MerkleTree::from_hashed_leaves`). The producer's per-record
/// inclusion proof uses raw record-hash bytes; the log-side proof
/// uses domain-prefixed `leaf_hash(subject)`. Callers must use the
/// right form — this function does NOT apply any prefix.
fn verify_merkle_proof(
    leaf_value: &[u8],
    proof: &InclusionProofRef,
    expected_root: &[u8; 32],
) -> bool {
    if leaf_value.len() != 32 {
        return false;
    }
    let mut cur: [u8; 32] = leaf_value.try_into().unwrap();
    for step in &proof.steps {
        let sib = match decode_hex_32(&step.hash) {
            Some(h) => h,
            None => return false,
        };
        cur = match step.position.as_str() {
            "left" => node_hash(&sib, &cur),
            "right" => node_hash(&cur, &sib),
            _ => return false,
        };
    }
    &cur == expected_root
}

/// Walk a log inclusion proof against an STH's root hash, where the
/// leaf value is `subject_hash` (re-hashed with the leaf prefix
/// by the producer when adding to the log).
fn verify_log_inclusion(
    subject_hash: &[u8; 32],
    proof: &[ProofStepRef],
    expected_root: &[u8; 32],
) -> bool {
    let mut cur = leaf_hash(subject_hash);
    for step in proof {
        let sib = match decode_hex_32(&step.hash) {
            Some(h) => h,
            None => return false,
        };
        cur = match step.position.as_str() {
            "left" => node_hash(&sib, &cur),
            "right" => node_hash(&cur, &sib),
            _ => return false,
        };
    }
    &cur == expected_root
}

/// Verify every anchor receipt with no external trust inputs. Bundles
/// that carry RFC 3161 or Rekor receipts fail with
/// [`AnchorVerifyError::MissingTrust`]; use [`verify_anchors_with_trust`].
pub fn verify_anchors(bundle: &Bundle) -> Result<usize, AnchorVerifyError> {
    verify_anchors_with_trust(bundle, &AnchorTrust::default())
}

/// Verify every anchor receipt in the bundle against the corresponding
/// batch head and the bundle's records. On success, returns the count of
/// verified receipts.
///
/// External receipts (`rfc3161`, `rekor`) are checked against `trust`
/// only; a receipt kind without its trust input is an error, not a skip.
/// Once anything is externally anchored (or a trust input is given):
///
/// - every batch head must carry a verified receipt of every such kind;
/// - every record must fall inside a batch head and carry a valid Merkle
///   inclusion proof into it;
/// - no record time and no head `signed_time` may be later than the
///   anchored time (`genTime` / `integratedTime`, whole seconds):
///   anything claimed after the anchor was written after the fact.
pub fn verify_anchors_with_trust(bundle: &Bundle, trust: &AnchorTrust) -> Result<usize, AnchorVerifyError> {
    if bundle.format_version < 2 && bundle.anchor_receipts.is_empty() && trust.is_empty() {
        // v1 bundles don't carry anchor receipts.
        return Ok(0);
    }
    // (batch_id, kind) pairs with a verified external anchor.
    let mut anchored: std::collections::BTreeSet<(String, &'static str)> = Default::default();
    let mut external_kinds: std::collections::BTreeSet<&'static str> = Default::default();
    if trust.tsa_roots.is_some() {
        external_kinds.insert(KIND_RFC3161);
    }
    if trust.rekor_key.is_some() {
        external_kinds.insert(KIND_REKOR);
    }

    let mut verified = 0usize;

    // Unique ids and disjoint ranges: a receipt names exactly one head and
    // every record is covered by at most one, so a second head cannot reuse
    // an anchored id to cover records the anchor never saw.
    check_head_structure(bundle)?;

    // Build a quick lookup: batch_id -> BatchHead.
    let heads_by_id: std::collections::HashMap<&str, &BatchHead> = bundle
        .batch_heads
        .iter()
        .map(|h| (h.batch_id.as_str(), h))
        .collect();

    for receipt in &bundle.anchor_receipts {
        let batch_id = receipt.batch_id().to_string();
        let head = heads_by_id
            .get(batch_id.as_str())
            .ok_or_else(|| AnchorVerifyError::UnknownBatch(batch_id.clone()))?;
        let expected_subject = subject_hash_for_batch(head);

        match receipt {
            AnchorReceiptRef::Tsa {
                claimed_time,
                subject_hash,
                token_der,
                tsa_pubkey,
                ..
            } => {
                let subj_hex = hex_lower(&expected_subject);
                if subject_hash != &subj_hex {
                    return Err(AnchorVerifyError::SubjectHashMismatch {
                        batch_id: batch_id.clone(),
                        got: subject_hash.clone(),
                        expected: subj_hex,
                    });
                }
                // The token_der field on the wire is the hex-encoded
                // TsaToken JSON (see AnchorReceipt::Tsa in
                // cloakpipe-anchor). Parse it as TsaTokenRef.
                let token: TsaTokenRef = serde_json::from_str(
                    &hex_to_string(token_der).map_err(|_| AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "token_der".into(),
                    })?,
                )
                .map_err(|_| AnchorVerifyError::BadHex {
                    batch_id: batch_id.clone(),
                    field: "token_der".into(),
                })?;

                // Verify the TSA signature offline.
                let pk_bytes = decode_hex_32(tsa_pubkey).ok_or_else(|| {
                    AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "tsa_pubkey".into(),
                    }
                })?;
                let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| {
                    AnchorVerifyError::TsaSignatureInvalid(batch_id.clone())
                })?;
                let imprint = decode_hex_32(&token.message_imprint).ok_or_else(|| {
                    AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "message_imprint".into(),
                    }
                })?;
                let sig_bytes = decode_hex_64(&token.signature).ok_or_else(|| {
                    AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "signature".into(),
                    }
                })?;
                let sig = DalekSig::from_bytes(&sig_bytes);
                let payload = tsa_signed_payload(
                    token.serial,
                    &token.algorithm,
                    &token.claimed_time,
                    &imprint,
                    &token.tsa_identity,
                );
                vk.verify(&payload, &sig)
                    .map_err(|_| AnchorVerifyError::TsaSignatureInvalid(batch_id.clone()))?;

                check_no_back_dating(&batch_id, head, claimed_time)?;
            }
            AnchorReceiptRef::Log {
                claimed_time,
                subject_hash,
                log_index: _,
                sth_bytes,
                inclusion_proof,
                log_pubkey,
                ..
            } => {
                let subj_hex = hex_lower(&expected_subject);
                if subject_hash != &subj_hex {
                    return Err(AnchorVerifyError::SubjectHashMismatch {
                        batch_id: batch_id.clone(),
                        got: subject_hash.clone(),
                        expected: subj_hex,
                    });
                }
                // Parse the STH from its hex-encoded JSON form.
                let sth: SthRef = serde_json::from_str(
                    &hex_to_string(sth_bytes).map_err(|_| AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "sth_bytes".into(),
                    })?,
                )
                .map_err(|_| AnchorVerifyError::BadHex {
                    batch_id: batch_id.clone(),
                    field: "sth_bytes".into(),
                })?;

                // Verify the log's signature on the STH.
                let pk_bytes = decode_hex_32(log_pubkey).ok_or_else(|| {
                    AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "log_pubkey".into(),
                    }
                })?;
                let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| {
                    AnchorVerifyError::LogSthSignatureInvalid(batch_id.clone())
                })?;
                let sth_root = decode_hex_32(&sth.root_hash).ok_or_else(|| {
                    AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "sth_root_hash".into(),
                    }
                })?;
                let sth_sig = decode_hex_64(&sth.signature).ok_or_else(|| {
                    AnchorVerifyError::BadHex {
                        batch_id: batch_id.clone(),
                        field: "sth_signature".into(),
                    }
                })?;
                let payload = sth_signed_payload(&sth.log_id, sth.tree_size, &sth_root, &sth.claimed_time);
                let sig = DalekSig::from_bytes(&sth_sig);
                vk.verify(&payload, &sig)
                    .map_err(|_| AnchorVerifyError::LogSthSignatureInvalid(batch_id.clone()))?;

                // Verify the inclusion proof: leaf = subject_hash,
                // root = sth.root_hash.
                if !verify_log_inclusion(&expected_subject, inclusion_proof, &sth_root) {
                    return Err(AnchorVerifyError::LogInclusionProofInvalid(batch_id));
                }

                check_no_back_dating(&batch_id, head, claimed_time)?;
            }
            AnchorReceiptRef::Rfc3161 { subject_hash, nonce, tsr, .. } => {
                external_kinds.insert(KIND_RFC3161);
                let roots = trust.tsa_roots.as_ref().ok_or_else(|| AnchorVerifyError::MissingTrust {
                    kind: KIND_RFC3161.into(),
                    flag: "--tsa-root".into(),
                })?;
                check_subject(&batch_id, subject_hash, &expected_subject)?;
                let bad = |field: &str| AnchorVerifyError::BadHex { batch_id: batch_id.clone(), field: field.into() };
                let tsr = base64::engine::general_purpose::STANDARD.decode(tsr).map_err(|_| bad("tsr"))?;
                let nonce = hex::decode(nonce).map_err(|_| bad("nonce"))?;
                let ts = crate::rfc3161::verify_timestamp_response(&tsr, &expected_subject, &nonce, roots)
                    .map_err(|error| AnchorVerifyError::Rfc3161 { batch_id: batch_id.clone(), error })?;
                check_anchor_time(bundle, head, ts.gen_time_unix)?;
                anchored.insert((batch_id.clone(), KIND_RFC3161));
            }
            AnchorReceiptRef::Rekor { subject_hash, entry_uuid, entry, .. } => {
                external_kinds.insert(KIND_REKOR);
                let key = trust.rekor_key.as_ref().ok_or_else(|| AnchorVerifyError::MissingTrust {
                    kind: KIND_REKOR.into(),
                    flag: "--rekor-key".into(),
                })?;
                check_subject(&batch_id, subject_hash, &expected_subject)?;
                let signer = head_signer_key(bundle, head)?;
                let head_bytes = serde_json::to_vec(head).expect("serialize batch head");
                let v = crate::rekor::verify_rekor_entry(entry_uuid, entry, key, &head_bytes, &signer)
                    .map_err(|error| AnchorVerifyError::Rekor { batch_id: batch_id.clone(), error })?;
                check_anchor_time(bundle, head, v.integrated_time)?;
                anchored.insert((batch_id.clone(), KIND_REKOR));
            }
        }

        verified += 1;
    }

    if !external_kinds.is_empty() {
        check_coverage(bundle, &anchored, &external_kinds)?;
    }

    Ok(verified)
}

/// Batch ids are unique, every head's range is non-empty and no two heads
/// cover the same sequence number.
fn check_head_structure(bundle: &Bundle) -> Result<(), AnchorVerifyError> {
    let mut ids = std::collections::BTreeSet::new();
    let mut ranges: Vec<&BatchHead> = Vec::with_capacity(bundle.batch_heads.len());
    for h in &bundle.batch_heads {
        if !ids.insert(h.batch_id.as_str()) {
            return Err(AnchorVerifyError::DuplicateBatchId(h.batch_id.clone()));
        }
        if h.first_seq > h.last_seq {
            return Err(AnchorVerifyError::BadBatchRange {
                batch_id: h.batch_id.clone(),
                first_seq: h.first_seq,
                last_seq: h.last_seq,
            });
        }
        ranges.push(h);
    }
    ranges.sort_by_key(|h| h.first_seq);
    for w in ranges.windows(2) {
        if w[1].first_seq <= w[0].last_seq {
            return Err(AnchorVerifyError::OverlappingBatches { a: w[0].batch_id.clone(), b: w[1].batch_id.clone() });
        }
    }
    Ok(())
}

fn check_subject(batch_id: &str, got: &str, expected: &[u8; 32]) -> Result<(), AnchorVerifyError> {
    let expected = hex_lower(expected);
    if got != expected {
        return Err(AnchorVerifyError::SubjectHashMismatch { batch_id: batch_id.into(), got: got.into(), expected });
    }
    Ok(())
}

/// The head signer's Ed25519 key, from `signer_public_keys`.
fn head_signer_key(bundle: &Bundle, head: &BatchHead) -> Result<[u8; 32], AnchorVerifyError> {
    let unknown = || AnchorVerifyError::UnknownKey(head.batch_id.clone());
    let k = bundle.signer_public_keys.iter().find(|k| k.key_id == head.signature.key_id).ok_or_else(unknown)?;
    if k.algorithm != "ed25519" || head.signature.algorithm != "ed25519" {
        return Err(unknown());
    }
    decode_hex_32(&k.public_key).ok_or_else(unknown)
}

/// Nothing covered by `head` may claim a time after `anchor_time`.
fn check_anchor_time(bundle: &Bundle, head: &BatchHead, anchor_time: i64) -> Result<(), AnchorVerifyError> {
    let anchor = crate::time::rfc3339_from_unix(anchor_time);
    let check = |claimed: &str| -> Result<(), AnchorVerifyError> {
        let t = crate::time::parse_rfc3339_secs(claimed).ok_or_else(|| AnchorVerifyError::BadTimestamp {
            batch_id: head.batch_id.clone(),
            value: claimed.to_string(),
        })?;
        if t > anchor_time {
            return Err(AnchorVerifyError::BackDating {
                batch_id: head.batch_id.clone(),
                claimed: claimed.to_string(),
                anchor: anchor.clone(),
            });
        }
        Ok(())
    };
    if let Some(st) = &head.signed_time {
        check(st)?;
    }
    for r in bundle.records.iter().filter(|r| head.first_seq <= r.seq && r.seq <= head.last_seq) {
        let ts = record_time(&r.canonical_bytes).ok_or_else(|| AnchorVerifyError::BadTimestamp {
            batch_id: head.batch_id.clone(),
            value: format!("record #{} has no ts", r.seq),
        })?;
        check(ts)?;
    }
    Ok(())
}

/// The record's `ts=` line; exactly one is required.
fn record_time(canonical: &str) -> Option<&str> {
    let mut it = canonical.lines().filter_map(|l| l.strip_prefix("ts="));
    let ts = it.next()?;
    it.next().is_none().then_some(ts)
}

/// Every head anchored by every external kind in play, every record
/// inside an anchored head with a valid inclusion proof.
fn check_coverage(
    bundle: &Bundle,
    anchored: &std::collections::BTreeSet<(String, &'static str)>,
    kinds: &std::collections::BTreeSet<&'static str>,
) -> Result<(), AnchorVerifyError> {
    if bundle.batch_heads.is_empty() {
        let kind = kinds.iter().next().copied().unwrap_or(KIND_RFC3161);
        return Err(AnchorVerifyError::HeadNotAnchored { batch_id: "(no batch heads)".into(), kind: kind.into() });
    }
    for head in &bundle.batch_heads {
        for kind in kinds {
            if !anchored.contains(&(head.batch_id.clone(), *kind)) {
                return Err(AnchorVerifyError::HeadNotAnchored { batch_id: head.batch_id.clone(), kind: (*kind).into() });
            }
        }
    }
    for (i, r) in bundle.records.iter().enumerate() {
        let head = bundle
            .batch_heads
            .iter()
            .find(|h| h.first_seq <= r.seq && r.seq <= h.last_seq)
            .ok_or(AnchorVerifyError::RecordNotAnchored { seq: r.seq })?;
        let proof = bundle.inclusion_proofs.get(i).and_then(Option::as_ref).ok_or_else(|| {
            AnchorVerifyError::InclusionProofMissing { seq: r.seq, batch_id: head.batch_id.clone() }
        })?;
        let invalid = || AnchorVerifyError::InclusionProofInvalid { seq: r.seq, batch_id: head.batch_id.clone() };
        if proof.batch_id != head.batch_id || proof.leaf_index != r.seq - head.first_seq {
            return Err(invalid());
        }
        let root = decode_hex_32(&head.merkle_root).ok_or_else(invalid)?;
        let leaf = decode_hex_32(&r.record_hash).ok_or_else(invalid)?;
        if !verify_merkle_proof(&leaf, proof, &root) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Verify every per-record inclusion proof in the bundle. Each
/// `inclusion_proofs[i]`, if present, must reconstruct the merkle
/// root of the batch head whose range covers record `i`.
pub fn verify_inclusion_proofs(bundle: &Bundle) -> Result<usize, AnchorVerifyError> {
    if bundle.format_version < 2 {
        return Ok(0);
    }
    check_head_structure(bundle)?;
    let mut verified = 0usize;
    // Build a lookup of batch heads by their seq range.
    let mut heads_by_first: std::collections::BTreeMap<u64, &BatchHead> =
        std::collections::BTreeMap::new();
    for h in &bundle.batch_heads {
        heads_by_first.insert(h.first_seq, h);
    }

    for (i, proof_opt) in bundle.inclusion_proofs.iter().enumerate() {
        let Some(proof) = proof_opt else { continue };
        let head = heads_by_first
            .values()
            .find(|h| h.first_seq <= i as u64 && i as u64 <= h.last_seq)
            .ok_or_else(|| AnchorVerifyError::UnknownBatch(proof.batch_id.clone()))?;
        if head.batch_id != proof.batch_id {
            return Err(AnchorVerifyError::InclusionProofInvalid {
                seq: i as u64,
                batch_id: proof.batch_id.clone(),
            });
        }
        let root = decode_hex_32(&head.merkle_root).ok_or_else(|| {
            AnchorVerifyError::BadHex {
                batch_id: head.batch_id.clone(),
                field: "merkle_root".into(),
            }
        })?;
        // The leaf value is the record's record_hash (hex bytes).
        let rec = &bundle.records[i];
        let leaf = decode_hex_32(&rec.record_hash).ok_or_else(|| {
            AnchorVerifyError::BadHex {
                batch_id: head.batch_id.clone(),
                field: "record_hash".into(),
            }
        })?;
        if !verify_merkle_proof(&leaf, proof, &root) {
            return Err(AnchorVerifyError::InclusionProofInvalid {
                seq: i as u64,
                batch_id: proof.batch_id.clone(),
            });
        }
        verified += 1;
    }

    Ok(verified)
}

fn check_no_back_dating(
    batch_id: &str,
    head: &BatchHead,
    anchor_time: &str,
) -> Result<(), AnchorVerifyError> {
    let anchor_t = parse_rfc3339(anchor_time).map_err(|_| AnchorVerifyError::BadTimestamp {
        batch_id: batch_id.to_string(),
        value: anchor_time.to_string(),
    })?;
    if let Some(claimed) = &head.signed_time {
        let claimed_t = parse_rfc3339(claimed).map_err(|_| AnchorVerifyError::BadTimestamp {
            batch_id: batch_id.to_string(),
            value: claimed.clone(),
        })?;
        if claimed_t > anchor_t {
            return Err(AnchorVerifyError::BackDating {
                batch_id: batch_id.to_string(),
                claimed: claimed.clone(),
                anchor: anchor_time.to_string(),
            });
        }
    }
    Ok(())
}

/// Minimal RFC3339 parser. Accepts `YYYY-MM-DDTHH:MM:SSZ` and
/// `YYYY-MM-DDTHH:MM:SS+HH:MM` (or `-HH:MM`). Returns a unix
/// timestamp in seconds. No subsecond precision.
fn parse_rfc3339(s: &str) -> Result<i64, ()> {
    // Byte offsets below assume ASCII; anything else is not RFC 3339.
    if !s.is_ascii() {
        return Err(());
    }
    // Accept "...Z" as the trailing byte.
    let (datetime, offset_secs) = if let Some(rest) = s.strip_suffix('Z') {
        (rest, 0i64)
    } else if s.len() > 6 {
        // Try offset suffix.
        let (dt_part, off_part) = s.split_at(s.len() - 6);
        if off_part.chars().nth(3) == Some(':')
            && (off_part.starts_with('+') || off_part.starts_with('-'))
        {
            let sign = if off_part.starts_with('+') { 1 } else { -1 };
            let hh: i64 = off_part[1..3].parse().map_err(|_| ())?;
            let mm: i64 = off_part[4..6].parse().map_err(|_| ())?;
            (dt_part, sign * (hh * 3600 + mm * 60))
        } else {
            return Err(());
        }
    } else {
        return Err(());
    };

    // datetime is "YYYY-MM-DDTHH:MM:SS"
    let b = datetime.as_bytes();
    if b.len() != 19 || b[4] != b'/' /* placeholder */
    {
        // Just check structure.
    }
    if b.len() != 19 || b[4] != b'-' || b[10] != b'T' {
        return Err(());
    }
    let year: i64 = std::str::from_utf8(&b[0..4]).map_err(|_| ())?.parse().map_err(|_| ())?;
    let mon: i64 = std::str::from_utf8(&b[5..7]).map_err(|_| ())?.parse().map_err(|_| ())?;
    let day: i64 = std::str::from_utf8(&b[8..10]).map_err(|_| ())?.parse().map_err(|_| ())?;
    let hh: i64 = std::str::from_utf8(&b[11..13]).map_err(|_| ())?.parse().map_err(|_| ())?;
    let mm: i64 = std::str::from_utf8(&b[14..16]).map_err(|_| ())?.parse().map_err(|_| ())?;
    let ss: i64 = std::str::from_utf8(&b[17..19]).map_err(|_| ())?.parse().map_err(|_| ())?;

    days_from_civil(year, mon, day)
        .and_then(|days| {
            days.checked_mul(86400)
                .and_then(|s| s.checked_add(hh * 3600 + mm * 60 + ss - offset_secs))
        })
        .ok_or(())
}

/// Howard Hinnant's `days_from_civil` — converts a (y,m,d) proleptic
/// Gregorian date to days since unix epoch. Public domain.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

fn hex_to_string(s: &str) -> Result<String, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| ())?;
    String::from_utf8(bytes).map_err(|_| ())
}

/// Mirror of `cloakpipe-anchor::tsa::TsaToken`. The verifier defines
/// its own type to stay standalone.
#[derive(Debug, Clone, Deserialize)]
struct TsaTokenRef {
    serial: u64,
    algorithm: String,
    claimed_time: String,
    message_imprint: String,
    tsa_identity: String,
    signature: String,
}

/// Reconstruct the TSA's signed payload. Must match
/// `cloakpipe-anchor::tsa::TsaToken::signed_payload` byte-for-byte.
fn tsa_signed_payload(
    serial: u64,
    algorithm: &str,
    claimed_time: &str,
    message_imprint: &[u8; 32],
    tsa_identity: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 16 + 32 + 64);
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.extend_from_slice(algorithm.as_bytes());
    buf.push(0xff);
    buf.extend_from_slice(claimed_time.as_bytes());
    buf.push(0xff);
    buf.extend_from_slice(message_imprint);
    buf.push(0xff);
    buf.extend_from_slice(tsa_identity.as_bytes());
    buf
}

/// Reconstruct the log's signed STH payload. Must match
/// `cloakpipe-anchor::receipt::SignedTreeHead::signed_payload`.
fn sth_signed_payload(
    log_id: &str,
    tree_size: u64,
    root_hash: &[u8; 32],
    claimed_time: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + 32);
    buf.extend_from_slice(log_id.as_bytes());
    buf.push(0xff);
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.push(0xff);
    buf.extend_from_slice(root_hash);
    buf.push(0xff);
    buf.extend_from_slice(claimed_time.as_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BatchHead, SignedBatchHead};

    fn h32() -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"test");
        let out = h.finalize();
        let mut out32 = [0u8; 32];
        out32.copy_from_slice(&out);
        out32
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        assert_eq!(leaf_hash(b"x"), leaf_hash(b"x"));
        assert_ne!(leaf_hash(b"x"), leaf_hash(b"y"));
    }

    #[test]
    fn node_hash_changes_with_inputs() {
        let a = h32();
        let b = [1u8; 32];
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }

    #[test]
    fn domain_separation_blocks_leaf_as_node() {
        let l = leaf_hash(b"x");
        let n = node_hash(&h32(), &[0u8; 32]);
        assert_ne!(l, n);
    }

    #[test]
    fn parse_rfc3339_accepts_zulu() {
        let t = parse_rfc3339("2026-07-02T12:00:00Z").expect("parse");
        assert_eq!(t, 1782993600);
    }

    #[test]
    fn parse_rfc3339_accepts_offset() {
        let t = parse_rfc3339("2026-07-02T12:00:00+00:00").expect("parse");
        assert_eq!(t, 1782993600);
    }

    #[test]
    fn parse_rfc3339_offset_shifts_time() {
        // 12:00:00+05:00 == 07:00:00Z
        let plus5 = parse_rfc3339("2026-07-02T12:00:00+05:00").expect("parse");
        let utc7 = parse_rfc3339("2026-07-02T07:00:00Z").expect("parse");
        assert_eq!(plus5, utc7);
    }

    #[test]
    fn parse_rfc3339_rejects_garbage() {
        assert!(parse_rfc3339("not-a-date").is_err());
    }

    #[test]
    fn parse_rfc3339_rejects_non_ascii_without_panicking() {
        // A multibyte char straddling the offset split must not panic.
        assert!(parse_rfc3339("2026-07-02T12:00:00+0é:00").is_err());
        assert!(parse_rfc3339("2026-07-02T12:00:00é+0:00").is_err());
    }

    #[test]
    fn parse_rfc3339_compares_correctly() {
        let a = parse_rfc3339("2026-07-02T12:00:00Z").unwrap();
        let b = parse_rfc3339("2026-07-02T12:01:00Z").unwrap();
        assert!(a < b);
    }

    #[test]
    fn subject_hash_for_batch_is_deterministic() {
        let h = BatchHead {
            batch_id: "b1".into(),
            first_seq: 0,
            last_seq: 9,
            merkle_root: hex_lower(&[7u8; 32]),
            algorithm: "ed25519".into(),
            signed_time: Some("2026-07-02T12:00:00Z".into()),
            signature: SignedBatchHead {
                key_id: "k1".into(),
                algorithm: "ed25519".into(),
                value: hex_lower(&[0u8; 64]),
            },
        };
        assert_eq!(subject_hash_for_batch(&h), subject_hash_for_batch(&h));
    }

    #[test]
    fn back_dating_detected() {
        // anchor time < signed_time => back-dating.
        let head = BatchHead {
            batch_id: "b".into(),
            first_seq: 0,
            last_seq: 0,
            merkle_root: hex_lower(&[0u8; 32]),
            algorithm: "ed25519".into(),
            signed_time: Some("2026-07-02T13:00:00Z".into()),
            signature: SignedBatchHead {
                key_id: "k".into(),
                algorithm: "ed25519".into(),
                value: hex_lower(&[0u8; 64]),
            },
        };
        let err = check_no_back_dating("b", &head, "2026-07-02T12:00:00Z").unwrap_err();
        assert!(matches!(err, AnchorVerifyError::BackDating { .. }));
    }

    #[test]
    fn no_back_dating_when_anchor_after_signed_time() {
        let head = BatchHead {
            batch_id: "b".into(),
            first_seq: 0,
            last_seq: 0,
            merkle_root: hex_lower(&[0u8; 32]),
            algorithm: "ed25519".into(),
            signed_time: Some("2026-07-02T12:00:00Z".into()),
            signature: SignedBatchHead {
                key_id: "k".into(),
                algorithm: "ed25519".into(),
                value: hex_lower(&[0u8; 64]),
            },
        };
        check_no_back_dating("b", &head, "2026-07-02T12:01:00Z").unwrap();
    }

    #[test]
    fn signed_payload_format_is_stable() {
        let payload = tsa_signed_payload(42, "ed25519", "2026-07-02T12:00:00Z", &[0u8; 32], "tsa-1");
        // serial || algorithm || 0xff || time || 0xff || imprint || 0xff || identity
        let mut expected = Vec::new();
        expected.extend_from_slice(&42u64.to_be_bytes());
        expected.extend_from_slice(b"ed25519");
        expected.push(0xff);
        expected.extend_from_slice(b"2026-07-02T12:00:00Z");
        expected.push(0xff);
        expected.extend_from_slice(&[0u8; 32]);
        expected.push(0xff);
        expected.extend_from_slice(b"tsa-1");
        assert_eq!(payload, expected);
    }
}

/// Verify the manifest: signature, declared counts, batch/anchor
/// references, and policy pack coverage of every record.
pub fn verify_manifest(bundle: &Bundle) -> Result<(), ManifestError> {
    if bundle.format_version < crate::bundle::MIN_BUNDLE_VERSION_FOR_MANIFEST {
        return Ok(());
    }
    let m = bundle
        .manifest
        .as_ref()
        .ok_or(ManifestError::Missing)?;
    // 1. Look up the operator's public key in the bundle.
    let pk_hex = bundle
        .signer_public_keys
        .iter()
        .find(|k| k.key_id == m.signature.key_id)
        .map(|k| k.public_key.clone())
        .ok_or_else(|| ManifestError::UnknownKey(m.signature.key_id.clone()))?;
    let pk_bytes = decode_hex_32(&pk_hex)
        .ok_or_else(|| ManifestError::BadHex(m.signature.key_id.clone()))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| ManifestError::BadKey(m.signature.key_id.clone()))?;
    // 2. Re-serialize the unsigned view and verify the signature.
    let unsigned = UnsignedManifest::from(m);
    let payload = serde_json::to_vec(&unsigned)
        .map_err(|_| ManifestError::SerializationFailed)?;
    let sig_bytes = decode_hex_64(&m.signature.value)
        .ok_or_else(|| ManifestError::BadHex("signature".into()))?;
    let sig = DalekSig::from_bytes(&sig_bytes);
    vk.verify(&payload, &sig)
        .map_err(|_| ManifestError::SignatureInvalid)?;
    // 3. Counts and seq range match the bundle.
    let actual_count = bundle.records.len() as u64;
    if m.record_count != actual_count {
        return Err(ManifestError::RecordCountMismatch {
            got: m.record_count,
            expected: actual_count,
        });
    }
    let first_seq = bundle.records.first().map(|r| r.seq).unwrap_or(0);
    let last_seq = bundle.records.last().map(|r| r.seq).unwrap_or(0);
    if m.first_seq != first_seq {
        return Err(ManifestError::FirstSeqMismatch {
            got: m.first_seq,
            expected: first_seq,
        });
    }
    if m.last_seq != last_seq {
        return Err(ManifestError::LastSeqMismatch {
            got: m.last_seq,
            expected: last_seq,
        });
    }
    // 3b. v4+: the signed chain tip must be the tip of these records, so a
    // different (even internally consistent) chain cannot reuse the signature.
    if bundle.format_version >= crate::bundle::MIN_BUNDLE_VERSION_FOR_CHAIN_TIP {
        let signed = m.chain_tip.as_deref().ok_or(ManifestError::MissingChainTip)?;
        let actual = bundle
            .records
            .last()
            .map(|r| r.record_hash.to_ascii_lowercase())
            .unwrap_or_else(|| "0".repeat(64));
        if signed != actual {
            return Err(ManifestError::ChainTipMismatch { signed: signed.to_string(), actual });
        }
    }
    // 4. Manifest batch_head_ids must all exist in the bundle.
    let known_heads: std::collections::BTreeSet<&str> = bundle
        .batch_heads
        .iter()
        .map(|h| h.batch_id.as_str())
        .collect();
    for bh in &m.batch_head_ids {
        if !known_heads.contains(bh.as_str()) {
            return Err(ManifestError::UnknownBatch(bh.clone()));
        }
    }
    // 5. Manifest anchor_receipt_refs (e.g. "tsa:bid:tsa:42") must
    //    exist as receipts in the bundle. We match by prefix
    //    (kind:batch_id).
    for ar in &m.anchor_receipt_refs {
        let mut parts = ar.splitn(3, ':');
        let kind = parts.next().unwrap_or("");
        let bid = parts.next().unwrap_or("");
        let found = bundle.anchor_receipts.iter().any(|r| r.kind() == kind && r.batch_id() == bid);
        if !found {
            return Err(ManifestError::UnknownAnchor(ar.clone()));
        }
    }
    // 6. Every record's policy.pack_version must appear in the
    //    bundle's policy_packs list (if any record references one).
    let known_versions: std::collections::BTreeSet<&str> = bundle
        .policy_packs
        .iter()
        .map(|p: &PolicyPackRef| p.pack_version.as_str())
        .collect();
    for rec in &bundle.records {
        let v = extract_policy_pack_version(&rec.canonical_bytes);
        if let Some(v) = v {
            if !known_versions.is_empty() && !known_versions.contains(v.as_str()) {
                return Err(ManifestError::UnknownPolicyPack {
                    seq: rec.seq,
                    version: v,
                });
            }
        }
    }
    Ok(())
}

/// Extract `policy.pack_version` from a record's canonical bytes.
/// Returns None if the field is not present.
fn extract_policy_pack_version(canonical: &str) -> Option<String> {
    // The canonical encoding puts policy fields in parentheses:
    //   policy=(<pack_id>|<pack_version>|<rule_id>|<decision>)
    let line = canonical.lines().find(|l| l.starts_with("policy="))?;
    let inner = line.trim_start_matches("policy=").trim_matches('(').trim_matches(')');
    let mut parts = inner.splitn(4, '|');
    parts.next()?; // pack_id
    Some(parts.next()?.to_string())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("manifest missing on v3 bundle (required for auditor packs)")]
    Missing,
    #[error("manifest signature is invalid")]
    SignatureInvalid,
    #[error("manifest signature serialization failed")]
    SerializationFailed,
    #[error("manifest key id `{0}` not in `signer_public_keys`")]
    UnknownKey(String),
    #[error("signer key `{0}` is not a valid Ed25519 public key")]
    BadKey(String),
    #[error("invalid hex in manifest field: {0}")]
    BadHex(String),
    #[error("manifest record count `{got}` does not match bundle (`{expected}`)")]
    RecordCountMismatch { got: u64, expected: u64 },
    #[error("manifest first_seq `{got}` does not match bundle (`{expected}`)")]
    FirstSeqMismatch { got: u64, expected: u64 },
    #[error("manifest last_seq `{got}` does not match bundle (`{expected}`)")]
    LastSeqMismatch { got: u64, expected: u64 },
    #[error("manifest references unknown batch head `{0}`")]
    UnknownBatch(String),
    #[error("manifest references unknown anchor receipt `{0}`")]
    UnknownAnchor(String),
    #[error("record #{seq} references policy pack version `{version}` not in manifest")]
    UnknownPolicyPack { seq: u64, version: String },
    #[error("v4+ manifest does not sign the chain tip")]
    MissingChainTip,
    #[error("signed chain tip `{signed}` does not match the records' tip `{actual}`")]
    ChainTipMismatch { signed: String, actual: String },
    #[error("signer `{0}` is not a trusted key")]
    UntrustedSigner(String),
}

/// Pin the signer: the manifest's key id must be in `trusted` and the bundle's
/// declared public key for it must be that trusted key. Without this, a
/// bundle verifies under whatever key it carries.
pub fn check_trusted_signer(
    bundle: &Bundle,
    trusted: &std::collections::BTreeMap<String, [u8; 32]>,
) -> Result<(), ManifestError> {
    let m = bundle.manifest.as_ref().ok_or(ManifestError::Missing)?;
    let key_id = &m.signature.key_id;
    let expected = trusted.get(key_id).ok_or_else(|| ManifestError::UntrustedSigner(key_id.clone()))?;
    let declared = bundle
        .signer_public_keys
        .iter()
        .find(|k| &k.key_id == key_id)
        .and_then(|k| decode_hex_32(&k.public_key))
        .ok_or_else(|| ManifestError::UnknownKey(key_id.clone()))?;
    if &declared != expected {
        return Err(ManifestError::UntrustedSigner(key_id.clone()));
    }
    Ok(())
}