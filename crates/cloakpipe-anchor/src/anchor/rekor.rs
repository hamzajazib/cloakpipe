//! Sigstore Rekor client (v1 API, `hashedrekord`).
//!
//! The batch head's JSON bytes are the artifact. The head's own Ed25519
//! signing key signs them Ed25519ph (Rekor accepts Ed25519 only over a
//! SHA-512 prehash) and the entry records SHA-512 of the bytes, the
//! signature and the key (PKIX PEM). The log's response is verified offline
//! (SET, body, UUID, inclusion proof, signed checkpoint) before it is
//! returned, and is kept verbatim as the receipt.

use crate::anchor::rfc3161::{http, read_reply};
use crate::anchor::AnchorError;
use crate::batch::SignedBatchHead;
use crate::receipt::ExternalReceipt;
use base64::Engine;
use cloakpipe_verify::rekor::{verify_rekor_entry, RekorKey};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256, Sha512};
use std::time::Duration;

/// The public-good Sigstore instance.
pub const DEFAULT_REKOR_URL: &str = "https://rekor.sigstore.dev";
const ENTRIES_PATH: &str = "/api/v1/log/entries";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// PKIX PEM of an Ed25519 public key.
pub fn ed25519_public_pem(key: &ed25519_dalek::VerifyingKey) -> String {
    // SubjectPublicKeyInfo { AlgorithmIdentifier { id-Ed25519 }, BIT STRING }.
    let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    der.extend(key.to_bytes());
    format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", B64.encode(der))
}

/// The proposed entry, in the canonical form Rekor stores as the body.
pub fn hashedrekord_request(artifact: &[u8], key: &SigningKey) -> String {
    let mut prehash = Sha512::new();
    prehash.update(artifact);
    let sig = key.sign_prehashed(prehash, None).expect("Ed25519ph without context cannot fail");
    format!(
        r#"{{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{{"data":{{"hash":{{"algorithm":"sha512","value":"{}"}}}},"signature":{{"content":"{}","publicKey":{{"content":"{}"}}}}}}}}"#,
        hex::encode(Sha512::digest(artifact)),
        B64.encode(sig.to_bytes()),
        B64.encode(ed25519_public_pem(&key.verifying_key())),
    )
}

/// A configured Rekor log: where to submit and the key its answers must
/// verify under.
pub struct RekorClient {
    url: String,
    key: RekorKey,
    timeout: Duration,
}

impl RekorClient {
    pub fn new(url: impl Into<String>, key: RekorKey) -> Self {
        Self { url: url.into().trim_end_matches('/').to_string(), key, timeout: DEFAULT_TIMEOUT }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Submit the head, signed by `signer` (the head's signing key). An
    /// entry that already exists (HTTP 409) is fetched instead.
    pub fn anchor_head(&self, head: &SignedBatchHead, signer: &SigningKey) -> Result<ExternalReceipt, AnchorError> {
        let artifact = serde_json::to_vec(head).map_err(|e| AnchorError::Submit(e.to_string()))?;
        let url = format!("{}{ENTRIES_PATH}", self.url);
        let client = http(self.timeout)?;
        let resp = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(hashedrekord_request(&artifact, signer))
            .send()
            .map_err(|e| AnchorError::Unavailable(format!("{url}: {e}")))?;
        let body = if resp.status() == reqwest::StatusCode::CONFLICT {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AnchorError::Submit(format!("{url}: 409 without Location")))?;
            let existing = self.entry_url(location)?;
            let resp = client.get(&existing).send().map_err(|e| AnchorError::Unavailable(format!("{existing}: {e}")))?;
            read_reply(&existing, resp, "application/json")?
        } else {
            read_reply(&url, resp, "application/json")?
        };

        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| AnchorError::Rejected(format!("{url}: not JSON: {e}")))?;
        let obj = v.as_object().ok_or_else(|| AnchorError::Rejected(format!("{url}: entry is not an object")))?;
        let (uuid, entry) = match obj.iter().collect::<Vec<_>>().as_slice() {
            [(u, e)] => ((*u).clone(), (*e).clone()),
            _ => return Err(AnchorError::Rejected(format!("{url}: expected exactly one entry"))),
        };
        verify_rekor_entry(&uuid, &entry, &self.key, &artifact, &signer.verifying_key().to_bytes())
            .map_err(|e| AnchorError::Rejected(format!("{url}: {e}")))?;
        Ok(ExternalReceipt::Rekor {
            batch_id: head.batch_id.clone(),
            subject_hash: hex::encode(Sha256::digest(&artifact)),
            rekor_url: self.url.clone(),
            entry_uuid: uuid,
            entry,
        })
    }

    /// Resolve a 409 `Location` against this log only.
    fn entry_url(&self, location: &str) -> Result<String, AnchorError> {
        let ok = |p: &str| p.starts_with(ENTRIES_PATH) && !p.contains("..");
        if location.starts_with('/') && ok(location) {
            return Ok(format!("{}{location}", self.url));
        }
        match location.strip_prefix(&self.url) {
            Some(p) if ok(p) => Ok(location.to_string()),
            _ => Err(AnchorError::Submit(format!("unexpected entry location `{location}`"))),
        }
    }
}
