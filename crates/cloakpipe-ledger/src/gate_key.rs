//! The gate signing key: an Ed25519 key that signs every decision entry.
//!
//! The key file is the `cloakpipe release keygen` format, a JSON object
//! `{"keyid", "publicKey", "privateKey"}` (hex), so an operator can make one
//! with `release keygen --out` and hand auditors only the public part.
//! [`GateKey::load_or_create`] makes one (owner-only, never overwriting)
//! when none exists yet.

use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Domain separator of the key that keys argument fingerprints.
pub const ARGS_FINGERPRINT_DOMAIN: &str = "cloakpipe.args-fingerprint.v1";

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0}: not a signing key file: {1}")]
    Invalid(PathBuf, String),
}

/// The key file format of `cloakpipe release keygen`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

/// An Ed25519 gate signing key.
#[derive(Clone)]
pub struct GateKey {
    key: SigningKey,
}

impl GateKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: SigningKey::from_bytes(&seed) }
    }

    pub fn generate() -> Self {
        Self::from_seed(rand::random())
    }

    /// Read a key file. Its `publicKey` and `keyid`, when present, must
    /// match the private key.
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let bad = |msg: &str| KeyError::Invalid(path.to_path_buf(), msg.to_string());
        let src = std::fs::read(path).map_err(|e| KeyError::Io(path.to_path_buf(), e))?;
        let file: KeyFile = serde_json::from_slice(&src).map_err(|e| bad(&e.to_string()))?;
        let seed = file.private_key.as_deref().and_then(hex32).ok_or_else(|| bad("privateKey must be a 32-byte hex Ed25519 seed"))?;
        let key = Self::from_seed(seed);
        if file.public_key.as_deref().is_some_and(|p| hex32(p) != Some(key.public_key())) {
            return Err(bad("publicKey does not match privateKey"));
        }
        if file.keyid.as_deref().is_some_and(|k| k != key.keyid()) {
            return Err(bad("keyid does not match the key"));
        }
        Ok(key)
    }

    /// [`Self::load`], or, when `path` does not exist, generate a key and
    /// write it there (parent directories created, the file readable by the
    /// owner only). `true` when the key was created now.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool), KeyError> {
        if path.exists() {
            return Self::load(path).map(|k| (k, false));
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            create_private_dir(dir).map_err(|e| KeyError::Io(dir.to_path_buf(), e))?;
        }
        let key = Self::generate();
        let file = KeyFile {
            keyid: Some(key.keyid()),
            public_key: Some(key.public_hex()),
            private_key: Some(hex::encode(key.key.to_bytes())),
        };
        let body = format!("{}\n", serde_json::to_string_pretty(&file).expect("a key file serializes"));
        match write_private(path, &body) {
            Ok(()) => Ok((key, true)),
            // Another process made it first: use theirs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Self::load(path).map(|k| (k, false)),
            Err(e) => Err(KeyError::Io(path.to_path_buf(), e)),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// `ed25519:` + the first 16 hex chars of SHA-256(public key), as
    /// `release keygen` names keys.
    pub fn keyid(&self) -> String {
        format!("ed25519:{}", &hex::encode(Sha256::digest(self.public_key()))[..16])
    }

    /// The key itself, for signers that need it whole (a Rekor
    /// `hashedrekord` entry is signed Ed25519ph).
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    /// The ledger form of a tool-call fingerprint: `hmac-sha256:<hex>`,
    /// HMAC-SHA256 under a key derived from this signing key. The raw
    /// fingerprint is a plain hash of the arguments, so a low-entropy value
    /// (an amount, a status) could be recovered from it by guessing; keyed,
    /// only the key holder can link an entry to a call.
    pub fn args_fingerprint(&self, fingerprint: &[u8; 32]) -> String {
        let mut derived = Sha256::new();
        derived.update(ARGS_FINGERPRINT_DOMAIN.as_bytes());
        derived.update(b"\n");
        derived.update(self.key.to_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&derived.finalize()).expect("HMAC takes any key length");
        mac.update(fingerprint);
        format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out).ok()?;
    Some(out)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Create `path` (never overwriting) readable only by the owner.
fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()
}
