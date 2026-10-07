//! Sigstore Rekor (v1 API) entry verification, fully offline.
//!
//! The receipt is the log's own response entry, kept verbatim. Given the
//! log's public key (supplied by the verifying party), the batch-head bytes
//! and the head signer's Ed25519 key, every check below must pass:
//!
//! 1. `logID` is SHA-256 of the log key (DER SubjectPublicKeyInfo).
//! 2. The SignedEntryTimestamp is the log's ECDSA P-256 / SHA-256
//!    signature over the canonical JSON
//!    `{"body":…,"integratedTime":…,"logID":…,"logIndex":…}`: the log
//!    commits to *this* body at *this* time and index.
//! 3. The body is a `hashedrekord` v0.0.1 whose SHA-512 is that of the
//!    head bytes, whose public key is the head signer's Ed25519 key, and
//!    whose signature is a valid Ed25519ph signature over the head bytes.
//! 4. The entry UUID ends with the RFC 6962 leaf hash of the body.
//! 5. The RFC 6962 inclusion proof reconstructs `rootHash` from that leaf,
//!    and the checkpoint carried with the proof is signed by the log key
//!    and commits to the same tree size and root.

use base64::Engine;
use der::{Decode, Encode};
use p256::ecdsa::signature::Verifier;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RekorError {
    #[error("malformed Rekor entry: {0}")]
    Malformed(String),
    #[error("entry body is not an acceptable hashedrekord: {0}")]
    BadBody(String),
    #[error("signed entry timestamp does not verify under the Rekor key")]
    SetInvalid,
    #[error("entry logID is not the supplied Rekor key")]
    LogIdMismatch,
    #[error("entry does not commit to the batch head (artifact hash differs)")]
    ArtifactHashMismatch,
    #[error("entry is not signed by the batch head's signing key")]
    SignerKeyMismatch,
    #[error("hashedrekord signature does not verify over the batch head")]
    ArtifactSignatureInvalid,
    #[error("inclusion proof does not reconstruct the root hash")]
    InclusionProofInvalid,
    #[error("checkpoint is not signed by the Rekor key")]
    CheckpointInvalid,
    #[error("checkpoint does not match the inclusion proof")]
    CheckpointMismatch,
    #[error("entry UUID does not name this entry's leaf")]
    UuidMismatch,
    #[error("Rekor key: {0}")]
    BadTrustInput(String),
}

type Result<T> = std::result::Result<T, RekorError>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const OID_EC_PUBLIC_KEY: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ED25519: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");

/// A Rekor log's ECDSA P-256 public key, supplied by the verifying party.
#[derive(Debug, Clone)]
pub struct RekorKey {
    key: p256::ecdsa::VerifyingKey,
    /// SHA-256 of the DER SubjectPublicKeyInfo: the log ID.
    log_id: [u8; 32],
}

impl RekorKey {
    /// Parse a PEM `PUBLIC KEY` (as served by `/api/v1/log/publicKey`).
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let bad = |m: String| RekorError::BadTrustInput(m);
        let (label, der_bytes) = der::pem::decode_vec(pem).map_err(|e| bad(format!("PEM: {e}")))?;
        if label != "PUBLIC KEY" {
            return Err(bad(format!("expected PUBLIC KEY, found {label}")));
        }
        Self::from_spki_der(&der_bytes)
    }

    fn from_spki_der(der_bytes: &[u8]) -> Result<Self> {
        let bad = |m: String| RekorError::BadTrustInput(m);
        let spki = spki::SubjectPublicKeyInfoOwned::from_der(der_bytes).map_err(|e| bad(e.to_string()))?;
        let curve: Option<der::asn1::ObjectIdentifier> =
            spki.algorithm.parameters.as_ref().and_then(|p| p.decode_as().ok());
        if spki.algorithm.oid != OID_EC_PUBLIC_KEY || curve != Some(OID_P256) {
            return Err(bad("only ECDSA P-256 Rekor keys are supported".into()));
        }
        let point = spki.subject_public_key.as_bytes().ok_or_else(|| bad("bad key bits".into()))?;
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| bad(e.to_string()))?;
        // Hash the canonical re-encoding, not the input, so the ID matches
        // what the log computes.
        let canonical = spki.to_der().map_err(|e| bad(e.to_string()))?;
        Ok(Self { key, log_id: Sha256::digest(canonical).into() })
    }

    /// Hex log ID, as Rekor reports it.
    pub fn log_id_hex(&self) -> String {
        hex::encode(self.log_id)
    }
}

/// What a verified entry attests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRekorEntry {
    /// Unix seconds at which the log integrated the entry (signed by the
    /// SET).
    pub integrated_time: i64,
    /// Global log index (signed by the SET).
    pub log_index: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    body: String,
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: String,
    log_index: u64,
    verification: Verification,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Verification {
    signed_entry_timestamp: String,
    inclusion_proof: InclusionProof,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionProof {
    checkpoint: String,
    hashes: Vec<String>,
    log_index: u64,
    root_hash: String,
    tree_size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    spec: Spec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    data: Data,
    signature: Sig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    hash: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sig {
    content: String,
    #[serde(rename = "publicKey")]
    public_key: PublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    content: String,
}

fn malformed(m: impl std::fmt::Display) -> RekorError {
    RekorError::Malformed(m.to_string())
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    // Lowercase only: the log emits lowercase and the SET signs the exact
    // string.
    if s.len() != 64 || s.bytes().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Verify one Rekor entry offline. `artifact` is the batch-head bytes the
/// entry must commit to; `signer` is the head signer's Ed25519 key.
pub fn verify_rekor_entry(
    uuid: &str,
    entry: &serde_json::Value,
    key: &RekorKey,
    artifact: &[u8],
    signer: &[u8; 32],
) -> Result<VerifiedRekorEntry> {
    let e: Entry = serde_json::from_value(entry.clone()).map_err(malformed)?;

    // 1. The entry names the supplied log.
    if hex32(&e.log_id).ok_or_else(|| malformed("logID is not 32-byte lowercase hex"))? != key.log_id {
        return Err(RekorError::LogIdMismatch);
    }

    // 2. SignedEntryTimestamp over the canonical entry. The body is
    //    base64 and the log ID hex, so neither needs JSON escaping; reject
    //    anything else rather than guess at canonicalization.
    if !e.body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=') {
        return Err(malformed("body is not base64"));
    }
    let canonical = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        e.body, e.integrated_time, e.log_id, e.log_index
    );
    let set = B64.decode(&e.verification.signed_entry_timestamp).map_err(|_| malformed("SET is not base64"))?;
    let set = p256::ecdsa::Signature::from_der(&set).map_err(|_| RekorError::SetInvalid)?;
    key.key.verify(canonical.as_bytes(), &set).map_err(|_| RekorError::SetInvalid)?;

    // 3. The body commits to the batch head, signed by its key.
    let body_bytes = B64.decode(&e.body).map_err(|_| malformed("body is not base64"))?;
    check_body(&body_bytes, artifact, signer)?;

    // 4. The UUID names this leaf: [16 hex tree ID] + 64 hex leaf hash.
    let leaf = leaf_hash(&body_bytes);
    // ASCII first: the UUID is not covered by the SET, and slicing a
    // multibyte character would panic.
    if !uuid.is_ascii() {
        return Err(RekorError::UuidMismatch);
    }
    let uuid_leaf = match uuid.len() {
        64 => uuid,
        80 if uuid[..16].bytes().all(|c| c.is_ascii_hexdigit()) => &uuid[16..],
        _ => return Err(RekorError::UuidMismatch),
    };
    if hex32(uuid_leaf) != Some(leaf) {
        return Err(RekorError::UuidMismatch);
    }

    // 5. Inclusion in a tree whose root the log signed.
    let p = &e.verification.inclusion_proof;
    let root = hex32(&p.root_hash).ok_or_else(|| malformed("rootHash is not 32-byte hex"))?;
    let path = p
        .hashes
        .iter()
        .map(|h| hex32(h).ok_or_else(|| malformed("proof hash is not 32-byte hex")))
        .collect::<Result<Vec<_>>>()?;
    if !verify_inclusion(p.log_index, p.tree_size, &leaf, &path, &root) {
        return Err(RekorError::InclusionProofInvalid);
    }
    verify_checkpoint(&p.checkpoint, key, p.tree_size, &root)?;

    Ok(VerifiedRekorEntry { integrated_time: e.integrated_time, log_index: e.log_index })
}

fn check_body(body: &[u8], artifact: &[u8], signer: &[u8; 32]) -> Result<()> {
    let bad = |m: &str| RekorError::BadBody(m.into());
    let b: Body = serde_json::from_slice(body).map_err(|e| RekorError::BadBody(e.to_string()))?;
    if b.api_version != "0.0.1" || b.kind != "hashedrekord" {
        return Err(bad("expected hashedrekord 0.0.1"));
    }
    // Rekor accepts Ed25519 only with a SHA-512 prehash (Ed25519ph).
    if b.spec.data.hash.algorithm != "sha512" {
        return Err(bad("hash algorithm must be sha512"));
    }
    let want = Sha512::digest(artifact);
    if b.spec.data.hash.value != hex::encode(want) {
        return Err(RekorError::ArtifactHashMismatch);
    }
    let pem = B64.decode(&b.spec.signature.public_key.content).map_err(|_| bad("public key is not base64"))?;
    let (label, spki_der) = der::pem::decode_vec(&pem).map_err(|_| bad("public key is not PEM"))?;
    if label != "PUBLIC KEY" {
        return Err(bad("public key is not a PUBLIC KEY"));
    }
    let spki = spki::SubjectPublicKeyInfoRef::from_der(&spki_der).map_err(|_| bad("public key unreadable"))?;
    if spki.algorithm.oid != OID_ED25519 || spki.algorithm.parameters.is_some() {
        return Err(RekorError::SignerKeyMismatch);
    }
    if spki.subject_public_key.as_bytes() != Some(signer.as_slice()) {
        return Err(RekorError::SignerKeyMismatch);
    }
    let sig = B64.decode(&b.spec.signature.content).map_err(|_| bad("signature is not base64"))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| RekorError::ArtifactSignatureInvalid)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(signer).map_err(|_| RekorError::SignerKeyMismatch)?;
    let mut prehash = Sha512::new();
    prehash.update(artifact);
    vk.verify_prehashed_strict(prehash, None, &sig).map_err(|_| RekorError::ArtifactSignatureInvalid)?;
    Ok(())
}

/// RFC 6962 leaf hash: `SHA-256(0x00 || entry)`.
pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(entry);
    h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// RFC 9162 §2.1.3.2 inclusion-proof verification.
fn verify_inclusion(index: u64, size: u64, leaf: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &r == root
}

/// Verify a signed-note checkpoint:
///
/// ```text
/// <origin>\n<tree size>\n<base64 root hash>\n[other lines\n]
/// \n
/// — <name> <base64(4-byte key hint || DER ECDSA signature)>\n
/// ```
///
/// The signed message is everything before the blank line (with its
/// trailing newline). A signature line counts only if its key hint is the
/// first four bytes of the log ID and it verifies under the log key.
fn verify_checkpoint(note: &str, key: &RekorKey, tree_size: u64, root: &[u8; 32]) -> Result<()> {
    let (text, sigs) = note.split_once("\n\n").ok_or(RekorError::CheckpointInvalid)?;
    let text = format!("{text}\n");
    let mut lines = text.lines();
    let _origin = lines.next().filter(|l| !l.is_empty()).ok_or(RekorError::CheckpointInvalid)?;
    let size: u64 = lines
        .next()
        .filter(|l| !l.is_empty() && l.bytes().all(|c| c.is_ascii_digit()))
        .and_then(|l| l.parse().ok())
        .ok_or(RekorError::CheckpointInvalid)?;
    let cp_root = lines.next().and_then(|l| B64.decode(l).ok()).ok_or(RekorError::CheckpointInvalid)?;

    let mut signed = false;
    for line in sigs.lines().filter(|l| !l.is_empty()) {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            return Err(RekorError::CheckpointInvalid);
        };
        let Some((_name, b64)) = rest.rsplit_once(' ') else {
            return Err(RekorError::CheckpointInvalid);
        };
        let Ok(raw) = B64.decode(b64) else {
            return Err(RekorError::CheckpointInvalid);
        };
        if raw.len() < 5 || raw[..4] != key.log_id[..4] {
            continue; // another signer (e.g. a witness)
        }
        let Ok(sig) = p256::ecdsa::Signature::from_der(&raw[4..]) else {
            return Err(RekorError::CheckpointInvalid);
        };
        if key.key.verify(text.as_bytes(), &sig).is_err() {
            return Err(RekorError::CheckpointInvalid);
        }
        signed = true;
    }
    if !signed {
        return Err(RekorError::CheckpointInvalid);
    }
    if size != tree_size || cp_root.as_slice() != root.as_slice() {
        return Err(RekorError::CheckpointMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6962 tree over leaves 0..n built the reference way.
    fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let k = leaves.len().next_power_of_two() / 2;
        node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
    }

    fn path(leaves: &[[u8; 32]], i: usize) -> Vec<[u8; 32]> {
        if leaves.len() == 1 {
            return vec![];
        }
        let k = leaves.len().next_power_of_two() / 2;
        if i < k {
            let mut p = path(&leaves[..k], i);
            p.push(mth(&leaves[k..]));
            p
        } else {
            let mut p = path(&leaves[k..], i - k);
            p.push(mth(&leaves[..k]));
            p
        }
    }

    #[test]
    fn inclusion_matches_reference_tree_for_all_shapes() {
        for n in 1..=33usize {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| leaf_hash(&[i as u8])).collect();
            let root = mth(&leaves);
            for i in 0..n {
                let p = path(&leaves, i);
                assert!(verify_inclusion(i as u64, n as u64, &leaves[i], &p, &root), "n={n} i={i}");
                if !p.is_empty() {
                    let mut bad = p.clone();
                    bad[0][0] ^= 1;
                    assert!(!verify_inclusion(i as u64, n as u64, &leaves[i], &bad, &root));
                    assert!(!verify_inclusion(i as u64, n as u64, &leaves[i], &p[..p.len() - 1], &root));
                }
            }
            assert!(!verify_inclusion(n as u64, n as u64, &leaves[0], &[], &root));
        }
    }
}
