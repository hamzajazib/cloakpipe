//! Release audit packs: everything a security reviewer needs about one Agent
//! Release, in one signed JSON document that verifies offline.
//!
//! The contract is `docs/AUDIT_PACK.md`; this doc comment is its summary.
//!
//! ```text
//! {
//!   "apiVersion": "cloakpipe.co/v1alpha1",
//!   "kind": "ReleaseAuditPack",
//!   "spec": {
//!     "createdAt": RFC 3339, "exporter": "<who assembled the pack>",
//!     "release": { "hash": "sha256:<hex>", "manifest": <AgentRelease> },
//!     "evaluationRuns": [<EvaluationRun>],
//!     "certifications": [<DSSE envelope>],
//!     "governance": { "attestedBy": "exporter", "events": [<GovernanceEvent>] },
//!     "ledgerExports": [<cloakpipe.bundle v4>],
//!     "limitations": ["<text>"]
//!   },
//!   "digest": "sha256:<hex>",
//!   "signature": { "keyid": "ed25519:<16 hex>", "sig": "<base64>" }
//! }
//! ```
//!
//! **Signing input** = `"cloakpipe.co/release-audit-pack/v1alpha1" || "\n" ||
//! JCS({apiVersion, kind, spec})` (RFC 8785). A pack issued under the legacy
//! `cloakpipe.dev/v1alpha1` apiVersion is signed under the legacy domain
//! `cloakpipe.dev/release-audit-pack/v1alpha1` and still verifies. `digest` is `sha256:` + hex of
//! SHA-256(signing input); `signature.sig` is standard base64 of the Ed25519
//! signature over the signing input, by the key named `keyid`
//! (`ed25519:` + first 16 hex of SHA-256(public key), as `release keygen`).
//!
//! Governance events are attested by the exporter's signature only: nobody
//! else signed them. The pack says so (`governance.attestedBy: "exporter"`)
//! and the verifier repeats it as a limitation of every report.
//!
//! - [`PackBuilder`] assembles and signs a pack (producers: the CLI,
//!   CloakPipe Cloud).
//! - [`verify_pack_bytes`] checks one, offline and deterministically given
//!   `now`, and returns a [`PackReport`] with a status timeline.

mod build;
mod check;
mod keys;
mod strict;

pub use build::{BuildError, PackBuilder};
pub use check::{
    verify_pack, verify_pack_bytes, CertSummary, EnvironmentStatus, LedgerSummary, PackReport, RunSummary,
    TimelineEntry, VerifyOptions,
};
pub use cloakpipe_cert::statement::TrustedKey;
pub use keys::{keyid, trusted_key_from_json};

use crate::bundle::Bundle;
use cloakpipe_cert::statement::Envelope;
use cloakpipe_cert::EvaluationRun;
use cloakpipe_release::namespace::{self, Namespace};
use cloakpipe_release::AgentRelease;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `apiVersion` the builder writes; the verifier also accepts the legacy
/// `cloakpipe.dev/v1alpha1` (see [`cloakpipe_release::namespace`]).
pub const PACK_API_VERSION: &str = namespace::API_VERSION;
/// `kind` of a pack.
pub const PACK_KIND: &str = "ReleaseAuditPack";
/// Domain separator of the signing input of a current-namespace pack.
pub const PACK_SIGNING_DOMAIN: &str = namespace::RELEASE_AUDIT_PACK_SIGNING_DOMAIN;
/// The only `governance.attestedBy` this version defines.
pub const ATTESTED_BY_EXPORTER: &str = "exporter";
/// The one environment a promotion into requires a valid certification (or
/// a break-glass override).
pub const CERTIFIED_ENVIRONMENT: &str = "production";
/// The environments an event may name, spelled exactly (CloakPipe Cloud's
/// environment pointers). Anything else, including a near-miss such as
/// `Production` or `prod`, fails verification rather than being treated as
/// an environment that needs no certification.
pub const KNOWN_ENVIRONMENTS: [&str; 5] = ["draft", "candidate", "staging", CERTIFIED_ENVIRONMENT, "rollback"];
/// The largest pack file `cloakpipe-verify release-pack` reads (256 MiB).
pub const MAX_PACK_BYTES: u64 = 256 * 1024 * 1024;
/// Stated in every pack the builder makes and in every report.
pub const GOVERNANCE_LIMITATION: &str = "Governance events (registration, promotions, revocations, sentinel \
     breaches) are attested only by the exporter's pack signature; they are not signed by the actors they name.";

/// A signed release audit pack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuditPack {
    pub api_version: String,
    pub kind: String,
    pub spec: PackSpec,
    /// `sha256:<hex>` of the signing input.
    pub digest: String,
    pub signature: PackSignature,
}

/// The signed body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackSpec {
    /// RFC 3339; not before any governance event.
    pub created_at: String,
    /// Who assembled the pack, e.g. `cloakpipe-cloud:acme`.
    pub exporter: String,
    pub release: ReleaseSection,
    pub evaluation_runs: Vec<EvaluationRun>,
    pub certifications: Vec<Envelope>,
    pub governance: Governance,
    pub ledger_exports: Vec<Bundle>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseSection {
    /// `sha256:<hex>` manifest hash; must recompute from `manifest`.
    pub hash: String,
    pub manifest: AgentRelease,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Governance {
    /// Always [`ATTESTED_BY_EXPORTER`] in this version.
    pub attested_by: String,
    /// In non-decreasing `at` order.
    pub events: Vec<GovernanceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSignature {
    pub keyid: String,
    /// Standard base64 Ed25519 signature over the signing input.
    pub sig: String,
}

/// A control-plane event about the pack's release. `at` is RFC 3339 and
/// `actor` a non-empty identity (a user, `ci:<repo>`, `sentinel:<name>`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum GovernanceEvent {
    /// The manifest was registered; `agent`/`version` must match it. Exactly
    /// one, and it is the first event.
    ReleaseRegistered { at: String, actor: String, agent: String, version: String },
    /// An environment pointer moved to this release. Into
    /// [`CERTIFIED_ENVIRONMENT`] it needs a certification valid at `at`, or
    /// `breakGlass` with a non-empty `reason`.
    ReleasePromoted {
        at: String,
        actor: String,
        environment: String,
        /// The release the pointer moved from (`sha256:<hex>`), if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_release: Option<String>,
        #[serde(default)]
        break_glass: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// An environment pointer moved away from this release to `toRelease`.
    ReleaseSuperseded { at: String, actor: String, environment: String, to_release: String },
    /// A certification in the pack (by statement digest) was revoked.
    CertificationRevoked { at: String, actor: String, statement_digest: String, reason: String },
    /// A production sentinel breached for this release.
    SentinelBreach {
        at: String,
        actor: String,
        sentinel: String,
        environment: String,
        metric: String,
        op: SentinelOp,
        threshold: f64,
        value: f64,
        calls: u64,
        action: SentinelAction,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelOp {
    Gt,
    Lt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelAction {
    Alert,
    Revoke,
}

impl GovernanceEvent {
    pub fn at(&self) -> &str {
        match self {
            GovernanceEvent::ReleaseRegistered { at, .. }
            | GovernanceEvent::ReleasePromoted { at, .. }
            | GovernanceEvent::ReleaseSuperseded { at, .. }
            | GovernanceEvent::CertificationRevoked { at, .. }
            | GovernanceEvent::SentinelBreach { at, .. } => at,
        }
    }

    pub fn actor(&self) -> &str {
        match self {
            GovernanceEvent::ReleaseRegistered { actor, .. }
            | GovernanceEvent::ReleasePromoted { actor, .. }
            | GovernanceEvent::ReleaseSuperseded { actor, .. }
            | GovernanceEvent::CertificationRevoked { actor, .. }
            | GovernanceEvent::SentinelBreach { actor, .. } => actor,
        }
    }

    /// The wire `type`.
    pub fn kind(&self) -> &'static str {
        match self {
            GovernanceEvent::ReleaseRegistered { .. } => "release_registered",
            GovernanceEvent::ReleasePromoted { .. } => "release_promoted",
            GovernanceEvent::ReleaseSuperseded { .. } => "release_superseded",
            GovernanceEvent::CertificationRevoked { .. } => "certification_revoked",
            GovernanceEvent::SentinelBreach { .. } => "sentinel_breach",
        }
    }
}

impl ReleaseAuditPack {
    /// Pretty JSON, newline-terminated.
    pub fn to_json_pretty(&self) -> String {
        // Every map key is a string; non-finite floats serialise as null.
        format!("{}\n", serde_json::to_string_pretty(self).unwrap_or_default())
    }
}

/// The signing input of a pack document: the domain, a newline and the
/// RFC 8785 form of `{apiVersion, kind, spec}` taken from `doc` as is. The
/// domain follows `apiVersion`: a legacy `cloakpipe.dev` pack keeps the
/// legacy domain it was signed under.
pub fn signing_input(api_version: &Value, kind: &Value, spec: &Value) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({ "apiVersion": api_version, "kind": kind, "spec": spec });
    let jcs = serde_json_canonicalizer::to_vec(&body).map_err(|e| format!("not canonicalisable: {e}"))?;
    let domain = Namespace::for_hashing(api_version.as_str().unwrap_or_default()).release_audit_pack_signing_domain();
    let mut out = Vec::with_capacity(domain.len() + 1 + jcs.len());
    out.extend_from_slice(domain.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&jcs);
    Ok(out)
}

/// `sha256:<hex>` of a signing input.
pub fn digest_of(signing_input: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(signing_input)))
}
