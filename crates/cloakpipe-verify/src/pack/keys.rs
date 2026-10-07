//! Key ids and trust files (the `cloakpipe release keygen` format).

use super::TrustedKey;
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// `ed25519:` + first 16 hex chars of SHA-256(public key), as
/// `cloakpipe release keygen` prints it.
pub fn keyid(public: &[u8; 32]) -> String {
    format!("ed25519:{}", &hex::encode(Sha256::digest(public))[..16])
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyFile {
    keyid: Option<String>,
    public_key: Option<String>,
    private_key: Option<String>,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// A trust anchor from a key file: `{"keyid"?, "publicKey"?, "privateKey"?}`.
/// Only the public part is used (derived from `privateKey` when `publicKey`
/// is absent); a declared `keyid` or `publicKey` must match the key.
pub fn trusted_key_from_json(src: &str) -> Result<TrustedKey, String> {
    let file: KeyFile = serde_json::from_str(src).map_err(|e| format!("not a key file: {e}"))?;
    let from_private = match &file.private_key {
        Some(s) => Some(hex32(s).ok_or("privateKey must be a 32-byte hex Ed25519 seed")?)
            .map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes()),
        None => None,
    };
    let declared = match &file.public_key {
        Some(p) => Some(hex32(p).ok_or("publicKey must be a 32-byte hex Ed25519 key")?),
        None => None,
    };
    let public = match (declared, from_private) {
        (Some(d), Some(p)) if d != p => return Err("publicKey does not match privateKey".into()),
        (Some(d), _) => d,
        (None, Some(p)) => p,
        (None, None) => return Err("no publicKey or privateKey".into()),
    };
    if ed25519_dalek::VerifyingKey::from_bytes(&public).is_err() {
        return Err("publicKey is not a valid Ed25519 point".into());
    }
    let id = keyid(&public);
    if file.keyid.as_deref().is_some_and(|k| k != id) {
        return Err(format!("keyid does not match the key (expected {id})"));
    }
    Ok(TrustedKey { keyid: id, public_key: public })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_files() {
        let k = SigningKey::from_bytes(&[1; 32]);
        let public = hex::encode(k.verifying_key().to_bytes());
        let private = hex::encode(k.to_bytes());
        let id = keyid(&k.verifying_key().to_bytes());
        let t = trusted_key_from_json(&format!(r#"{{"keyid":"{id}","publicKey":"{public}"}}"#)).unwrap();
        assert_eq!(t.keyid, id);
        assert_eq!(trusted_key_from_json(&format!(r#"{{"privateKey":"{private}"}}"#)).unwrap(), t);
        assert!(trusted_key_from_json(&format!(r#"{{"keyid":"ed25519:00","publicKey":"{public}"}}"#)).is_err());
        let other = hex::encode([9u8; 32]);
        assert!(trusted_key_from_json(&format!(r#"{{"publicKey":"{other}","privateKey":"{private}"}}"#)).is_err());
        assert!(trusted_key_from_json("{}").is_err());
        assert!(trusted_key_from_json(r#"{"publicKey":"zz"}"#).is_err());
    }
}
