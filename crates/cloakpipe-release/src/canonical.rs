//! Canonical encoding and the manifest hash.
//!
//! The hash covers `apiVersion`, `kind`, `metadata.agent` and the whole `spec`,
//! but not `metadata.version` or `metadata.labels`: re-registering identical
//! behaviour under a new release number yields the same hash.
//!
//! Normalisation before encoding:
//! - every string (keys included) is Unicode NFC;
//! - unordered collections (tools, MCP servers, policies, dependencies) are
//!   sorted; prompt order is semantic and kept;
//! - an absent `retrieval` is an explicit `null`; empty collections are kept.
//!
//! The normalised view is encoded with RFC 8785 (JSON Canonicalization Scheme)
//! and hashed as `SHA-256(HASH_DOMAIN || "\n" || jcs_bytes)`.

use crate::manifest::{AgentRelease, ArtifactRef};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Domain-separation prefix for the manifest hash. Bump only together with a
/// deliberate change to the canonical view.
pub const HASH_DOMAIN: &str = "cloakpipe.dev/agent-release/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReleaseHash(pub [u8; 32]);

impl ReleaseHash {
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected `sha256:<64 lowercase hex>`, got {0:?}")]
pub struct ReleaseHashParseError(pub String);

impl std::str::FromStr for ReleaseHash {
    type Err = ReleaseHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ReleaseHashParseError(s.to_string());
        let hex = s.strip_prefix("sha256:").ok_or_else(err)?;
        if !crate::reference::is_lower_hex(hex, 64..=64) {
            return Err(err());
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex, &mut out).map_err(|_| err())?;
        Ok(ReleaseHash(out))
    }
}

impl std::fmt::Display for ReleaseHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

impl AgentRelease {
    /// The normalised, hash-relevant view of this manifest.
    pub fn canonical_view(&self) -> Value {
        let s = &self.spec;
        let refs = |v: &[ArtifactRef]| -> Vec<String> { v.iter().map(|r| r.reference.clone()).collect() };
        let sorted = |v: &[ArtifactRef]| -> Vec<String> {
            let mut out = refs(v);
            out.sort();
            out
        };
        let mut deps = s.dependencies.clone();
        deps.sort();

        let view = json!({
            "apiVersion": self.api_version,
            "kind": self.kind,
            "agent": self.metadata.agent,
            "spec": {
                "code": { "repository": s.code.repository, "commit": s.code.commit },
                "prompts": refs(&s.prompts),
                "model": s.model.reference,
                "parameters": s.parameters,
                "tools": sorted(&s.tools),
                "mcpServers": sorted(&s.mcp_servers),
                "retrieval": s.retrieval.as_ref().map(|r| r.reference.clone()),
                "policies": sorted(&s.policies),
                "runtime": { "image": s.runtime.image, "region": s.runtime.region },
                "dependencies": deps,
                "featureFlags": s.feature_flags,
            }
        });
        nfc(view)
    }

    /// RFC 8785 encoding of [`Self::canonical_view`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&self.canonical_view())
            .expect("canonical view contains only JSON-representable values")
    }

    pub fn manifest_hash(&self) -> ReleaseHash {
        let mut h = Sha256::new();
        h.update(HASH_DOMAIN.as_bytes());
        h.update(b"\n");
        h.update(self.canonical_bytes());
        ReleaseHash(h.finalize().into())
    }
}

fn nfc(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(s.nfc().collect()),
        Value::Array(a) => Value::Array(a.into_iter().map(nfc).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k.nfc().collect(), nfc(v))).collect::<Map<_, _>>()),
        other => other,
    }
}
