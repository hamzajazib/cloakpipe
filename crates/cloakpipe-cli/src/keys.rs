//! Shared CLI plumbing: exit-code helpers, `--now` parsing and the Ed25519
//! key files written by `cloakpipe release keygen` (approver keys, exporter
//! keys, anchoring keys). Nothing here depends on certification.

use crate::release::{EXIT_INVALID, EXIT_IO, EXIT_OK};
use chrono::{DateTime, SecondsFormat, Utc};
use cloakpipe_receipt::dsse::TrustedKey;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Exit early with a code.
pub(crate) type Res<T> = Result<T, i32>;

pub(crate) fn usage(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    EXIT_IO
}

pub(crate) fn invalid(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    EXIT_INVALID
}

pub(crate) fn read(path: &Path) -> Res<String> {
    std::fs::read_to_string(path).map_err(|e| usage(format_args!("cannot read {}: {e}", path.display())))
}

pub(crate) fn pretty(v: &impl Serialize) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).expect("serialisable"))
}

pub(crate) fn finish(code: Res<i32>) -> i32 {
    code.unwrap_or_else(|c| c)
}

/// `--now`: RFC 3339, normalised to UTC with second precision; defaults to
/// the current time.
pub(crate) fn now_arg(now: Option<&str>) -> Res<DateTime<Utc>> {
    match now {
        None => Ok(Utc::now()),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| usage(format_args!("--now {s:?} is not RFC 3339: {e}"))),
    }
}

pub(crate) fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ── Keys ────────────────────────────────────────────────────────────────

/// `ed25519:` + first 16 hex chars of SHA-256(public key).
pub fn keyid(public: &[u8; 32]) -> String {
    format!("ed25519:{}", &hex::encode(Sha256::digest(public))[..16])
}

/// The `keygen` file format. Trust files may omit `privateKey`.
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

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out).ok()?;
    Some(out)
}

fn read_key_file(path: &Path) -> Res<KeyFile> {
    let src = read(path)?;
    serde_json::from_str(&src).map_err(|e| invalid(format_args!("{}: not a key file: {e}", path.display())))
}

/// Check that the file's declared `keyid` / `publicKey` match `public`.
fn check_declared(path: &Path, file: &KeyFile, public: &[u8; 32]) -> Res<String> {
    let id = keyid(public);
    if file.public_key.as_deref().is_some_and(|p| hex32(p) != Some(*public)) {
        return Err(invalid(format_args!("{}: publicKey does not match privateKey", path.display())));
    }
    if file.keyid.as_deref().is_some_and(|k| k != id) {
        return Err(invalid(format_args!("{}: keyid does not match the key (expected {id})", path.display())));
    }
    Ok(id)
}

pub(crate) fn signing_key(path: &Path) -> Res<(SigningKey, String)> {
    let file = read_key_file(path)?;
    let Some(seed) = file.private_key.as_deref().and_then(hex32) else {
        return Err(invalid(format_args!("{}: privateKey must be a 32-byte hex Ed25519 seed", path.display())));
    };
    let key = SigningKey::from_bytes(&seed);
    let id = check_declared(path, &file, &key.verifying_key().to_bytes())?;
    Ok((key, id))
}

/// A trust file: only the public part is used (derived from `privateKey`
/// when `publicKey` is absent).
pub(crate) fn trusted_key(path: &Path) -> Res<TrustedKey> {
    let file = read_key_file(path)?;
    let public = match (&file.public_key, &file.private_key) {
        (Some(p), _) => hex32(p),
        (None, Some(s)) => hex32(s).map(|s| SigningKey::from_bytes(&s).verifying_key().to_bytes()),
        (None, None) => None,
    };
    let Some(public) = public else {
        return Err(invalid(format_args!("{}: publicKey must be a 32-byte hex Ed25519 key", path.display())));
    };
    let id = check_declared(path, &KeyFile { private_key: None, ..file }, &public)?;
    Ok(TrustedKey { keyid: id, public_key: public })
}

#[cfg(feature = "certification")]
pub(crate) fn inline_key(arg: &str) -> Res<TrustedKey> {
    let (id, public) = arg.split_once('=').ok_or_else(|| usage("--trust-key expects KEYID=PUBHEX"))?;
    let public = hex32(public).ok_or_else(|| usage(format_args!("--trust-key {id}: public key must be 64 hex chars")))?;
    Ok(TrustedKey { keyid: id.to_string(), public_key: public })
}

pub fn keygen(out: Option<&Path>) -> i32 {
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let public = key.verifying_key().to_bytes();
    let mut file = KeyFile {
        keyid: Some(keyid(&public)),
        public_key: Some(hex::encode(public)),
        private_key: Some(hex::encode(key.to_bytes())),
    };
    let Some(out) = out else {
        print!("{}", pretty(&file));
        return EXIT_OK;
    };
    if let Err(e) = write_private(out, &pretty(&file)) {
        return usage(format_args!("cannot write {}: {e}", out.display()));
    }
    file.private_key = None;
    print!("{}", pretty(&file));
    EXIT_OK
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
    opts.open(path)?.write_all(content.as_bytes())
}
