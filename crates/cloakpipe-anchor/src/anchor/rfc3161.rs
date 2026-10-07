//! RFC 3161 client for a real, external timestamp authority.
//!
//! Builds a DER `TimeStampReq` (SHA-256 imprint, 128-bit nonce,
//! `certReq = TRUE`), POSTs it as `application/timestamp-query`, and
//! returns a receipt only after the reply verifies offline (status, CMS
//! signature, imprint, nonce, ESS binding, path to the configured roots)
//! with the same code `cloakpipe-verify` runs. The receipt keeps the full
//! DER reply, so later verification never needs the network.

use crate::anchor::AnchorError;
use crate::batch::SignedBatchHead;
use crate::receipt::ExternalReceipt;
use base64::Engine;
use cloakpipe_verify::rfc3161::{verify_timestamp_response, TrustedRoots};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// freetsa.org: free, RSA-4096 root, ECDSA P-384 signer.
pub const DEFAULT_TSA_URL: &str = "https://freetsa.org/tsr";
/// DigiCert's public RFC 3161 endpoint (root: DigiCert Trusted Root G4).
pub const DIGICERT_TSA_URL: &str = "http://timestamp.digicert.com";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// DER `TimeStampReq`:
///
/// ```text
/// SEQUENCE { version INTEGER 1,
///            messageImprint SEQUENCE { SEQUENCE { sha256, NULL }, OCTET STRING },
///            nonce INTEGER, certReq BOOLEAN TRUE }
/// ```
///
/// `nonce` is an unsigned big-endian integer (leading zeros ignored); it
/// must be non-zero and at most 64 bytes.
pub fn timestamp_request(sha256: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    let magnitude = &nonce[nonce.iter().take_while(|&&b| b == 0).count()..];
    assert!(!magnitude.is_empty() && magnitude.len() <= 64, "nonce must be non-zero and at most 64 bytes");
    // DER INTEGER: minimal, positive (a 0x00 pad when the top bit is set).
    let mut nonce_int = Vec::with_capacity(magnitude.len() + 1);
    if magnitude[0] & 0x80 != 0 {
        nonce_int.push(0);
    }
    nonce_int.extend(magnitude);
    const SHA256_ALG: [u8; 15] = [0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00];
    let mut imprint = vec![0x30, (SHA256_ALG.len() + 34) as u8];
    imprint.extend(SHA256_ALG);
    imprint.extend([0x04, 0x20]);
    imprint.extend(sha256);
    let mut body = vec![0x02, 0x01, 0x01];
    body.extend(imprint);
    body.extend([0x02, nonce_int.len() as u8]);
    body.extend(nonce_int);
    body.extend([0x01, 0x01, 0xff]);
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

/// 128 random bits, top bit clear and first byte non-zero, so the DER
/// encoding is exactly these 16 bytes.
pub fn fresh_nonce() -> [u8; 16] {
    let mut n: [u8; 16] = rand::random();
    n[0] = (n[0] & 0x7f) | 0x01;
    n
}

/// A configured TSA: where to ask and which roots its answer must chain to.
pub struct TsaClient {
    url: String,
    roots: TrustedRoots,
    timeout: Duration,
}

impl TsaClient {
    pub fn new(url: impl Into<String>, roots: TrustedRoots) -> Self {
        Self { url: url.into(), roots, timeout: DEFAULT_TIMEOUT }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Timestamp SHA-256 of the head's JSON bytes with a fresh nonce.
    pub fn anchor_head(&self, head: &SignedBatchHead) -> Result<ExternalReceipt, AnchorError> {
        self.anchor_head_with_nonce(head, &fresh_nonce())
    }

    /// As [`Self::anchor_head`] with a caller-chosen nonce (tests replay
    /// recorded replies). Never reuse a nonce against a live TSA.
    pub fn anchor_head_with_nonce(&self, head: &SignedBatchHead, nonce: &[u8]) -> Result<ExternalReceipt, AnchorError> {
        let head_bytes = serde_json::to_vec(head).map_err(|e| AnchorError::Submit(e.to_string()))?;
        let subject: [u8; 32] = Sha256::digest(&head_bytes).into();
        let req = timestamp_request(&subject, nonce);
        let tsr = post(&self.url, self.timeout, "application/timestamp-query", req, "application/timestamp-reply")?;
        verify_timestamp_response(&tsr, &subject, nonce, &self.roots)
            .map_err(|e| AnchorError::Rejected(format!("{}: {e}", self.url)))?;
        Ok(ExternalReceipt::Rfc3161 {
            batch_id: head.batch_id.clone(),
            subject_hash: hex::encode(subject),
            tsa_url: self.url.clone(),
            nonce: hex::encode(nonce),
            tsr: base64::engine::general_purpose::STANDARD.encode(tsr),
        })
    }
}

/// POST `body`; the reply must be 2xx with `want_type`.
pub(crate) fn post(
    url: &str,
    timeout: Duration,
    content_type: &str,
    body: Vec<u8>,
    want_type: &str,
) -> Result<Vec<u8>, AnchorError> {
    let client = http(timeout)?;
    let resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(body)
        .send()
        .map_err(|e| AnchorError::Unavailable(format!("{url}: {e}")))?;
    read_reply(url, resp, want_type)
}

pub(crate) fn http(timeout: Duration) -> Result<reqwest::blocking::Client, AnchorError> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("cloakpipe-anchor/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AnchorError::Unavailable(e.to_string()))
}

pub(crate) fn read_reply(
    url: &str,
    resp: reqwest::blocking::Response,
    want_type: &str,
) -> Result<Vec<u8>, AnchorError> {
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    let bytes = resp.bytes().map_err(|e| AnchorError::Unavailable(format!("{url}: {e}")))?;
    if !status.is_success() {
        let snippet = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).into_owned();
        return Err(AnchorError::Submit(format!("{url}: HTTP {status}: {snippet}")));
    }
    if ctype != want_type {
        return Err(AnchorError::Submit(format!("{url}: expected {want_type}, got `{ctype}`")));
    }
    Ok(bytes.to_vec())
}
