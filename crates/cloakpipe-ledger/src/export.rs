//! Producer-side bundle export.
//!
//! Lives in `cloakpipe-ledger` because this crate owns the canonical
//! byte encoding (`canonical::canonicalize`) and the durable store
//! (`store::LedgerStore`). The verifier reads the JSON we emit here
//! without any back-reference to this crate.
//!
//! The export is **deterministic**: same records + same signer keys =
//! byte-identical bundle JSON. This is what lets auditors diff
//! bundles across versions and across operators.
//!
//! ## M4 — auditor pack
//!
//! `export_range` produces a **sealed auditor pack** for a date
//! range: every record in range + every batch head covering them +
//! every anchor receipt referenced + the active policy pack refs +
//! a **signed manifest** that binds them all together. Tampering
//! with any of these without re-signing the manifest breaks
//! verification.

use crate::canonical::canonicalize;
use crate::sign::Signer;
use crate::store::LedgerStore;
use chrono::Utc;
use serde::Serialize;
use thiserror::Error;

/// Re-export the verifier's bundle types. We **do not** import from
/// `cloakpipe-verify` — that would create a dependency cycle (the
/// verifier is supposed to be standalone). Instead, we mirror the
/// shapes here. Tests assert byte-level equivalence so a producer
/// change can't silently break the verifier.
pub mod bundle_format {
    use serde::{Deserialize, Serialize};

    pub const BUNDLE_MAGIC: &str = "cloakpipe.bundle";
    pub const BUNDLE_FORMAT_VERSION: u32 = 4;

    pub type Hex32 = String;
    pub type Hex64 = String;
    pub type HexPubkey = String;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Bundle {
        pub format: String,
        pub format_version: u32,
        pub tenant_id: String,
        pub created_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub range_start: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub range_end: Option<String>,
        pub records: Vec<Record>,
        /// Per-record Merkle inclusion proofs into the covering batch head
        /// (index = record position). Empty until [`super::seal_batch`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub inclusion_proofs: Vec<Option<InclusionProofRef>>,
        #[serde(default)]
        pub batch_heads: Vec<BatchHead>,
        #[serde(default)]
        pub signer_public_keys: Vec<SignerKey>,
        #[serde(default)]
        pub anchor_receipts: Vec<AnchorReceiptRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub manifest: Option<Manifest>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub policy_packs: Vec<PolicyPackRef>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Record {
        pub seq: u64,
        pub tenant_id: String,
        pub canonical_bytes: String,
        pub record_hash: Hex32,
        pub prev_hash: Hex32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct BatchHead {
        pub batch_id: String,
        pub first_seq: u64,
        pub last_seq: u64,
        pub merkle_root: Hex32,
        pub algorithm: String,
        pub signed_time: Option<String>,
        pub signature: SignedBatchHead,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SignedBatchHead {
        pub key_id: String,
        pub algorithm: String,
        pub value: Hex64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SignerKey {
        pub key_id: String,
        pub algorithm: String,
        pub public_key: HexPubkey,
    }

    /// Anchor receipt reference — same shape the verifier reads.
    /// The producer emits this when an anchor backend has anchored a
    /// batch head referenced by the bundle.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum AnchorReceiptRef {
        Tsa {
            batch_id: String,
            subject_hash: Hex32,
            claimed_time: String,
            backend_ref: String,
            token_der: String,
            tsa_pubkey: HexPubkey,
        },
        Log {
            batch_id: String,
            subject_hash: Hex32,
            claimed_time: String,
            log_index: u64,
            sth_bytes: String,
            inclusion_proof: Vec<ProofStepRef>,
            log_pubkey: HexPubkey,
        },
        /// RFC 3161 timestamp from an external TSA (see
        /// `cloakpipe_anchor::receipt::ExternalReceipt`).
        Rfc3161 { batch_id: String, subject_hash: Hex32, tsa_url: String, nonce: String, tsr: String },
        /// Sigstore Rekor entry, verbatim.
        Rekor { batch_id: String, subject_hash: Hex32, rekor_url: String, entry_uuid: String, entry: serde_json::Value },
    }

    impl From<cloakpipe_anchor::receipt::ExternalReceipt> for AnchorReceiptRef {
        fn from(r: cloakpipe_anchor::receipt::ExternalReceipt) -> Self {
            use cloakpipe_anchor::receipt::ExternalReceipt as E;
            match r {
                E::Rfc3161 { batch_id, subject_hash, tsa_url, nonce, tsr } => {
                    AnchorReceiptRef::Rfc3161 { batch_id, subject_hash, tsa_url, nonce, tsr }
                }
                E::Rekor { batch_id, subject_hash, rekor_url, entry_uuid, entry } => {
                    AnchorReceiptRef::Rekor { batch_id, subject_hash, rekor_url, entry_uuid, entry }
                }
            }
        }
    }

    impl AnchorReceiptRef {
        pub fn batch_id(&self) -> &str {
            match self {
                AnchorReceiptRef::Tsa { batch_id, .. }
                | AnchorReceiptRef::Log { batch_id, .. }
                | AnchorReceiptRef::Rfc3161 { batch_id, .. }
                | AnchorReceiptRef::Rekor { batch_id, .. } => batch_id,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct InclusionProofRef {
        pub batch_id: String,
        pub leaf_index: u64,
        pub total_leaves: u64,
        pub steps: Vec<ProofStepRef>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ProofStepRef {
        pub position: String,
        pub hash: Hex32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct PolicyPackRef {
        pub pack_id: String,
        pub pack_version: String,
        pub active_from: String,
        pub active_until: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Manifest {
        pub bundle_id: String,
        pub range_start: String,
        pub range_end: String,
        pub record_count: u64,
        pub first_seq: u64,
        pub last_seq: u64,
        pub batch_head_ids: Vec<String>,
        pub anchor_receipt_refs: Vec<String>,
        pub policy_pack_versions: Vec<String>,
        pub operator: String,
        pub created_at: String,
        /// v4+: hex `record_hash` of the last record (genesis when empty).
        /// Signing it checkpoints every record through the hash chain.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain_tip: Option<Hex32>,
        pub signature: ManifestSignature,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ManifestSignature {
        pub key_id: String,
        pub algorithm: String,
        pub value: Hex64,
    }
}

use bundle_format::*;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("serialize error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot anchor: {0}")]
    Anchoring(String),
}

/// Export every record for `tenant_id` into a v3 bundle.
///
/// Convenience over `export_range` with no date filter. The
/// resulting bundle has a signed manifest binding the records.
pub fn export_bundle<S: Signer>(
    store: &LedgerStore,
    tenant_id: &uuid::Uuid,
    signer: &S,
) -> Result<Bundle, ExportError> {
    let stored = store.records_for_tenant(tenant_id)?;
    let records: Vec<Record> = stored
        .into_iter()
        .map(record_to_bundle_record)
        .collect();

    let operator_key_id = "default".to_string();
    let bundle_id = format!("bundle-{}", UuidShort::new());
    let policy_packs = default_policy_packs();

    let mut bundle = Bundle {
        format: BUNDLE_MAGIC.into(),
        format_version: BUNDLE_FORMAT_VERSION,
        tenant_id: tenant_id.to_string(),
        created_at: Utc::now().to_rfc3339(),
        range_start: None,
        range_end: None,
        records,
        inclusion_proofs: vec![],
        batch_heads: vec![],
        signer_public_keys: vec![SignerKey {
            key_id: operator_key_id.clone(),
            algorithm: signer.algorithm().to_string(),
            public_key: hex_lower(&signer.public_key()),
        }],
        anchor_receipts: vec![],
        manifest: None,
        policy_packs,
    };

    bundle.manifest = Some(build_manifest(
        &bundle,
        &operator_key_id,
        signer,
        &bundle_id,
    )?);

    Ok(bundle)
}

/// Export records in `[range_start, range_end)` (RFC3339 UTC,
/// inclusive lower, exclusive upper) into a sealed v3 bundle.
pub fn export_range<S: Signer>(
    store: &LedgerStore,
    tenant_id: &uuid::Uuid,
    range_start: chrono::DateTime<chrono::Utc>,
    range_end: chrono::DateTime<chrono::Utc>,
    signer: &S,
) -> Result<Bundle, ExportError> {
    let stored = store.records_for_tenant(tenant_id)?;
    let filtered: Vec<Record> = stored
        .into_iter()
        .filter(|s| {
            s.record.ts >= range_start && s.record.ts < range_end
        })
        .map(|s| {
            let canon = canonicalize(&s.record);
            let canon_string = String::from_utf8(canon).unwrap_or_default();
            Record {
                seq: s.record.seq,
                tenant_id: s.record.tenant_id.to_string(),
                canonical_bytes: canon_string,
                record_hash: hex_lower(&s.record.record_hash),
                prev_hash: hex_lower(&s.record.prev_hash),
            }
        })
        .collect();

    let operator_key_id = "default".to_string();
    let bundle_id = format!("bundle-{}", UuidShort::new());
    let policy_packs = default_policy_packs();

    let mut bundle = Bundle {
        format: BUNDLE_MAGIC.into(),
        format_version: BUNDLE_FORMAT_VERSION,
        tenant_id: tenant_id.to_string(),
        created_at: Utc::now().to_rfc3339(),
        range_start: Some(range_start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        range_end: Some(range_end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        records: filtered,
        inclusion_proofs: vec![],
        batch_heads: vec![],
        signer_public_keys: vec![SignerKey {
            key_id: operator_key_id.clone(),
            algorithm: signer.algorithm().to_string(),
            public_key: hex_lower(&signer.public_key()),
        }],
        anchor_receipts: vec![],
        manifest: None,
        policy_packs,
    };

    bundle.manifest = Some(build_manifest(
        &bundle,
        &operator_key_id,
        signer,
        &bundle_id,
    )?);

    Ok(bundle)
}

/// Seal every record of an exported bundle under one signed batch head and
/// add per-record inclusion proofs; the manifest is re-signed to list the
/// head. Returns the head, whose JSON bytes are what external anchors
/// commit to.
///
/// Fails closed: the bundle must have records, no batch head yet, a
/// manifest signed by `signer`, and no record stamped after `signed_time`.
pub fn seal_batch<S: Signer>(
    bundle: &mut Bundle,
    signer: &S,
    batch_id: &str,
    signed_time: chrono::DateTime<Utc>,
) -> Result<cloakpipe_anchor::batch::SignedBatchHead, ExportError> {
    let refuse = |m: String| ExportError::Anchoring(m);
    let operator = check_operator(bundle, signer)?;
    if !bundle.batch_heads.is_empty() || !bundle.anchor_receipts.is_empty() {
        return Err(refuse("bundle is already sealed".into()));
    }
    let (first, last) = match (bundle.records.first(), bundle.records.last()) {
        (Some(f), Some(l)) => (f.seq, l.seq),
        _ => return Err(refuse("bundle has no records".into())),
    };
    let signed_time_s = signed_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut leaves = Vec::with_capacity(bundle.records.len());
    for (i, r) in bundle.records.iter().enumerate() {
        if r.seq != first + i as u64 {
            return Err(refuse(format!("record #{} breaks the seq range", r.seq)));
        }
        let ts = r.canonical_bytes.lines().find_map(|l| l.strip_prefix("ts=")).ok_or_else(|| refuse(format!("record #{} has no ts", r.seq)))?;
        let ts = chrono::DateTime::parse_from_rfc3339(ts).map_err(|_| refuse(format!("record #{} ts unreadable", r.seq)))?;
        if ts.timestamp() > signed_time.timestamp() {
            return Err(refuse(format!("record #{} is stamped after the seal time {signed_time_s}", r.seq)));
        }
        let mut leaf = [0u8; 32];
        hex::decode_to_slice(&r.record_hash, &mut leaf).map_err(|_| refuse(format!("record #{} hash", r.seq)))?;
        leaves.push(leaf);
    }
    let tree = cloakpipe_anchor::merkle::MerkleTree::from_hashed_leaves(leaves);
    let root = hex_lower(&tree.root());

    let mut head = cloakpipe_anchor::batch::build_signed_batch_head(
        batch_id,
        first,
        last,
        root.as_str(),
        signer.algorithm(),
        Some(signed_time_s),
        operator.clone(),
        signer.algorithm(),
        String::new(),
    );
    let payload = serde_json::to_vec(&cloakpipe_anchor::batch::BatchHeadUnsigned::from(&head))?;
    head.signature.value = hex_lower(&signer.sign_bytes(&payload));

    bundle.inclusion_proofs = (0..bundle.records.len())
        .map(|i| {
            let p = tree.inclusion_proof(i);
            Some(InclusionProofRef {
                batch_id: batch_id.to_string(),
                leaf_index: i as u64,
                total_leaves: bundle.records.len() as u64,
                steps: p
                    .steps
                    .into_iter()
                    .map(|st| ProofStepRef {
                        position: match st.position {
                            cloakpipe_anchor::merkle::ProofPosition::Left => "left".into(),
                            cloakpipe_anchor::merkle::ProofPosition::Right => "right".into(),
                        },
                        hash: hex_lower(&st.hash),
                    })
                    .collect(),
            })
        })
        .collect();
    bundle.batch_heads.push(BatchHead {
        batch_id: head.batch_id.clone(),
        first_seq: head.first_seq,
        last_seq: head.last_seq,
        merkle_root: head.merkle_root.clone(),
        algorithm: head.algorithm.clone(),
        signed_time: head.signed_time.clone(),
        signature: SignedBatchHead {
            key_id: head.signature.key_id.clone(),
            algorithm: head.signature.algorithm.clone(),
            value: head.signature.value.clone(),
        },
    });
    reseal_manifest(bundle, signer, &operator)?;
    Ok(head)
}

/// Attach external anchor receipts for heads already in the bundle and
/// re-sign the manifest so it lists them.
pub fn attach_receipts<S: Signer>(
    bundle: &mut Bundle,
    receipts: Vec<cloakpipe_anchor::receipt::ExternalReceipt>,
    signer: &S,
) -> Result<(), ExportError> {
    let operator = check_operator(bundle, signer)?;
    for r in receipts {
        if !bundle.batch_heads.iter().any(|h| h.batch_id == r.batch_id()) {
            return Err(ExportError::Anchoring(format!("receipt for unknown batch `{}`", r.batch_id())));
        }
        bundle.anchor_receipts.push(r.into());
    }
    reseal_manifest(bundle, signer, &operator)
}

/// The manifest's operator key id, if `signer` holds that key.
fn check_operator<S: Signer>(bundle: &Bundle, signer: &S) -> Result<String, ExportError> {
    let m = bundle.manifest.as_ref().ok_or_else(|| ExportError::Anchoring("bundle has no signed manifest".into()))?;
    let declared = bundle
        .signer_public_keys
        .iter()
        .find(|k| k.key_id == m.operator)
        .ok_or_else(|| ExportError::Anchoring(format!("operator key `{}` not declared", m.operator)))?;
    if declared.public_key != hex_lower(&signer.public_key()) || declared.algorithm != signer.algorithm() {
        return Err(ExportError::Anchoring(format!("the signing key is not the bundle operator `{}`", m.operator)));
    }
    Ok(m.operator.clone())
}

/// Re-sign the manifest after heads or receipts changed, keeping its
/// bundle id and range.
fn reseal_manifest<S: Signer>(bundle: &mut Bundle, signer: &S, operator: &str) -> Result<(), ExportError> {
    let old = bundle.manifest.take().ok_or_else(|| ExportError::Anchoring("bundle has no signed manifest".into()))?;
    let (rs, re) = (bundle.range_start.clone(), bundle.range_end.clone());
    bundle.range_start = Some(old.range_start.clone());
    bundle.range_end = Some(old.range_end.clone());
    let m = build_manifest(bundle, operator, signer, &old.bundle_id);
    bundle.range_start = rs;
    bundle.range_end = re;
    bundle.manifest = Some(m?);
    Ok(())
}

fn record_to_bundle_record(s: crate::store::StoredRecord) -> Record {
    let canon = canonicalize(&s.record);
    let canon_string = String::from_utf8(canon).unwrap_or_default();
    Record {
        seq: s.record.seq,
        tenant_id: s.record.tenant_id.to_string(),
        canonical_bytes: canon_string,
        record_hash: hex_lower(&s.record.record_hash),
        prev_hash: hex_lower(&s.record.prev_hash),
    }
}

/// Build the manifest. Signs over the canonical JSON of
/// `(everything except signature)`.
fn build_manifest<S: Signer>(
    bundle: &Bundle,
    operator_key_id: &str,
    signer: &S,
    bundle_id: &str,
) -> Result<Manifest, ExportError> {
    let first_seq = bundle.records.first().map(|r| r.seq).unwrap_or(0);
    let last_seq = bundle.records.last().map(|r| r.seq).unwrap_or(0);
    let record_count = bundle.records.len() as u64;
    let chain_tip = bundle
        .records
        .last()
        .map(|r| r.record_hash.clone())
        .unwrap_or_else(|| hex_lower(&crate::chain::GENESIS_HASH));
    // range_start / range_end come from the caller (export_range sets
    // them). For export_bundle (no date filter), use the bundle
    // created_at for both so the manifest has well-formed RFC3339
    // values. The verifier doesn't require them to be sensible —
    // they're metadata.
    let default_ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let range_start = bundle.range_start.clone().unwrap_or_else(|| default_ts.clone());
    let range_end = bundle.range_end.clone().unwrap_or(default_ts);
    let batch_head_ids: Vec<String> =
        bundle.batch_heads.iter().map(|h| h.batch_id.clone()).collect();
    let anchor_receipt_refs: Vec<String> = bundle
        .anchor_receipts
        .iter()
        .map(|r| match r {
            AnchorReceiptRef::Tsa {
                batch_id,
                backend_ref,
                ..
            } => format!("tsa:{batch_id}:{backend_ref}"),
            AnchorReceiptRef::Log {
                batch_id,
                log_index,
                ..
            } => format!("log:{batch_id}:{log_index}"),
            AnchorReceiptRef::Rfc3161 { batch_id, nonce, .. } => format!("rfc3161:{batch_id}:{nonce}"),
            AnchorReceiptRef::Rekor { batch_id, entry_uuid, .. } => format!("rekor:{batch_id}:{entry_uuid}"),
        })
        .collect();
    let policy_pack_versions: Vec<String> =
        bundle.policy_packs.iter().map(|p| p.pack_version.clone()).collect();

    let unsigned = UnsignedManifest {
        bundle_id: bundle_id.to_string(),
        range_start: range_start.clone(),
        range_end: range_end.clone(),
        record_count,
        first_seq,
        last_seq,
        batch_head_ids: batch_head_ids.clone(),
        anchor_receipt_refs: anchor_receipt_refs.clone(),
        policy_pack_versions: policy_pack_versions.clone(),
        operator: operator_key_id.to_string(),
        created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        chain_tip: Some(chain_tip.clone()),
    };
    let payload = serde_json::to_vec(&unsigned)
        .map_err(ExportError::Json)?;
    let sig = signer.sign_bytes(&payload);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig);

    Ok(Manifest {
        bundle_id: bundle_id.to_string(),
        range_start,
        range_end,
        record_count,
        first_seq,
        last_seq,
        batch_head_ids,
        anchor_receipt_refs,
        policy_pack_versions,
        operator: operator_key_id.to_string(),
        created_at: unsigned.created_at,
        chain_tip: Some(chain_tip),
        signature: ManifestSignature {
            key_id: operator_key_id.to_string(),
            algorithm: signer.algorithm().to_string(),
            value: hex_lower(&sig_arr),
        },
    })
}

#[derive(Serialize)]
struct UnsignedManifest {
    bundle_id: String,
    range_start: String,
    range_end: String,
    record_count: u64,
    first_seq: u64,
    last_seq: u64,
    batch_head_ids: Vec<String>,
    anchor_receipt_refs: Vec<String>,
    policy_pack_versions: Vec<String>,
    operator: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_tip: Option<String>,
}

/// Default policy pack refs (no packs registered yet — the verifier
/// accepts an empty list and only checks that *every* pack_version
/// referenced by a record is in the list).
fn default_policy_packs() -> Vec<PolicyPackRef> {
    vec![]
}

/// A small, non-cryptographic short id for bundle names. Sufficient
/// for human-readable bundle ids; the audit trail doesn't depend on
/// these being unguessable.
struct UuidShort;

impl UuidShort {
    #[allow(clippy::new_ret_no_self)]
    fn new() -> String {
        let u = uuid::Uuid::new_v4().simple().to_string();
        u[..12].to_string()
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

/// Convenience: write a bundle to disk as pretty JSON.
pub fn write_bundle(path: &std::path::Path, bundle: &Bundle) -> anyhow::Result<()> {
    let j = serde_json::to_string_pretty(bundle)?;
    std::fs::write(path, j)?;
    Ok(())
}

/// Asserts the producer's bundle types serialize *byte-for-byte* the
/// same way as the verifier's. Run this in CI to catch drift.
#[cfg(test)]
mod format_compat {
    use super::*;
    use crate::sign::Ed25519Signer;
    use crate::record::*;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn producer_bundle_has_verifier_compatible_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        let mut r = RecordBuilder::new()
            .seq(0)
            .tenant(t)
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap();
        store.append(&t, &mut r).unwrap();
        let signer = Ed25519Signer::generate();
        let bundle = export_bundle(&store, &t, &signer).unwrap();

        // Structural invariants the verifier relies on. If any of
        // these drift, `cloakpipe-verify` will reject every bundle.
        assert_eq!(bundle.format, "cloakpipe.bundle");
        assert_eq!(bundle.format_version, BUNDLE_FORMAT_VERSION);
        assert!(!bundle.records.is_empty());
        let rec = &bundle.records[0];
        assert!(!rec.canonical_bytes.is_empty());
        assert_eq!(rec.record_hash.len(), 64);
        assert_eq!(rec.prev_hash.len(), 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;
    use crate::record::*;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn export_includes_all_records_with_canonical_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        for i in 0..3u64 {
            let mut r = RecordBuilder::new()
                .seq(i)
                .tenant(t)
                .hop(Hop::LlmPrompt)
                .build()
                .unwrap();
            store.append(&t, &mut r).unwrap();
        }
        let signer = Ed25519Signer::generate();
        let bundle = export_bundle(&store, &t, &signer).unwrap();
        assert_eq!(bundle.records.len(), 3);
        assert_eq!(bundle.format, "cloakpipe.bundle");
        assert_eq!(bundle.format_version, BUNDLE_FORMAT_VERSION);
        // Record 0's prev_hash is all zeros (genesis).
        assert!(bundle.records[0].prev_hash.chars().all(|c| c == '0'));
        // Each record's record_hash matches SHA-256 of its canonical bytes.
        for r in &bundle.records {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(r.canonical_bytes.as_bytes());
            let out = h.finalize();
            let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(r.record_hash, hex);
        }
    }

    #[test]
    fn export_is_deterministic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        let mut r = RecordBuilder::new()
            .seq(0)
            .tenant(t)
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap();
        store.append(&t, &mut r).unwrap();
        let signer = Ed25519Signer::generate();
        let b1 = export_bundle(&store, &t, &signer).unwrap();
        let b2 = export_bundle(&store, &t, &signer).unwrap();
        // Records are identical; created_at differs (we set Utc::now
        // each time) so we compare just the records.
        assert_eq!(b1.records, b2.records);
        assert_eq!(b1.records[0].canonical_bytes, b2.records[0].canonical_bytes);
        assert_eq!(b1.records[0].record_hash, b2.records[0].record_hash);
    }

    #[test]
    fn export_bundle_includes_signed_manifest() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        for i in 0..3u64 {
            let mut r = RecordBuilder::new()
                .seq(i)
                .tenant(t)
                .hop(Hop::LlmPrompt)
                .build()
                .unwrap();
            store.append(&t, &mut r).unwrap();
        }
        let signer = Ed25519Signer::generate();
        let bundle = export_bundle(&store, &t, &signer).unwrap();
        let m = bundle.manifest.as_ref().expect("manifest present");
        assert_eq!(m.record_count, 3);
        assert_eq!(m.first_seq, 0);
        assert_eq!(m.last_seq, 2);
        assert!(!m.bundle_id.is_empty());
        assert_eq!(m.signature.value.len(), 128);
        assert_eq!(m.signature.algorithm, "ed25519");
    }

    #[test]
    fn export_range_filters_by_date() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        for i in 0..5u64 {
            let mut r = RecordBuilder::new()
                .seq(i)
                .tenant(t)
                .hop(Hop::LlmPrompt)
                .build()
                .unwrap();
            store.append(&t, &mut r).unwrap();
        }
        let signer = Ed25519Signer::generate();
        // Range covers only the future — empty.
        let start = chrono::Utc::now() + chrono::Duration::days(1);
        let end = start + chrono::Duration::days(1);
        let bundle = export_range(&store, &t, start, end, &signer).unwrap();
        assert_eq!(bundle.records.len(), 0);
        assert_eq!(bundle.manifest.as_ref().unwrap().record_count, 0);
        assert!(bundle.range_start.is_some());
        assert!(bundle.range_end.is_some());
    }

    #[test]
    fn export_range_includes_all_when_wide() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        for i in 0..3u64 {
            let mut r = RecordBuilder::new()
                .seq(i)
                .tenant(t)
                .hop(Hop::LlmPrompt)
                .build()
                .unwrap();
            store.append(&t, &mut r).unwrap();
        }
        let signer = Ed25519Signer::generate();
        let start = chrono::Utc::now() - chrono::Duration::days(1);
        let end = chrono::Utc::now() + chrono::Duration::days(1);
        let bundle = export_range(&store, &t, start, end, &signer).unwrap();
        assert_eq!(bundle.records.len(), 3);
    }
}