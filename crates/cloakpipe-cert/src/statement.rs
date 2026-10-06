//! Signed certification attestations and offline verification.
//!
//! Contract (see docs/CERTIFICATION.md §Attestation):
//!
//! **Statement** (`statement`): an in-toto v1 Statement
//! ```json
//! { "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [{ "name": "agent-release:<agent or 'unknown'>",
//!                 "digest": { "sha256": "<release hex>" } }],
//!   "predicateType": "https://cloakpipe.dev/attestations/certification/v1alpha1",
//!   "predicate": { "certification": <Certification as camelCase JSON> } }
//! ```
//! `Certification.decision.release` must equal `Certification.release`.
//!
//! **Envelope** (`sign`): a DSSE envelope, payloadType
//! `application/vnd.in-toto+json`, payload = standard base64 of the
//! RFC 8785 canonical bytes of the statement, one Ed25519 signature over the
//! DSSE PAE: `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`
//! (lengths are ASCII decimal byte counts of the *raw* type and payload
//! bytes). `sig` is standard base64; `keyid` as given.
//!
//! **Verification** (`verify`) is offline and deterministic (the caller
//! supplies `now`). It returns the *most severe* applicable status, in
//! precedence order Invalid > Revoked > Expired > Incomplete >
//! ValidWithLimitations > Valid, plus every reason found:
//! - **Invalid**: wrong payloadType; undecodable base64/JSON; no signature
//!   that verifies under a *trusted* key whose `keyid` matches; wrong
//!   `_type`/`predicateType`; malformed predicate; subject digest ≠
//!   `certification.release` hex or ≠ `decision.release`; `expected_release`
//!   given and ≠ subject; `issuedAt`/`validUntil` not RFC 3339, or
//!   `validUntil` ≤ `issuedAt`; `now` < `issuedAt` (not yet valid).
//! - **Revoked**: the statement digest (sha256 hex of the decoded payload
//!   bytes) is in `revoked_statements`, or the verifying signature's keyid is
//!   in `revoked_keys`.
//! - **Expired**: `now` ≥ `validUntil`.
//! - **Incomplete**: `required_runs` given and some hash in it is not among
//!   `decision.runs[].hash`.
//! - **ValidWithLimitations**: `certification.limitations` is non-empty.
//! - **Valid**: none of the above.
//! A Blocked decision can still be a Valid attestation (of a block);
//! `Report.certified` is true only when status is Valid or
//! ValidWithLimitations *and* the decision outcome is Certified.
//! Never panics on any input.

use crate::model::{Decision, Outcome};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://cloakpipe.dev/attestations/certification/v1alpha1";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Certification {
    /// `sha256:<hex>` manifest hash of the certified release.
    pub release: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Scope, e.g. `production`.
    pub environment: String,
    pub decision: Decision,
    /// RFC 3339.
    pub issued_at: String,
    /// RFC 3339; `issued_at + policy validity`.
    pub valid_until: String,
    /// Issuer identity, e.g. `cloakpipe-cloud` or a CI workload.
    pub issuer: String,
    /// Declared scope exclusions or caveats (e.g. "locale en only").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: String,
    pub sig: String,
}

/// DSSE envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub keyid: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct VerifyContext {
    pub trusted: Vec<TrustedKey>,
    /// sha256 hex of revoked statement payloads.
    pub revoked_statements: BTreeSet<String>,
    pub revoked_keys: BTreeSet<String>,
    /// RFC 3339 "current" time supplied by the caller.
    pub now: String,
    /// `sha256:<hex>` the attestation must be about, if known.
    pub expected_release: Option<String>,
    /// Run hashes that must be cited by the decision (evidence completeness).
    pub required_runs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Valid,
    ValidWithLimitations,
    Incomplete,
    Expired,
    Revoked,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub status: Status,
    pub reasons: Vec<String>,
    /// sha256 hex of the decoded payload, when decodable.
    pub statement_digest: Option<String>,
    /// `sha256:<hex>` subject, when parseable.
    pub release: Option<String>,
    pub outcome: Option<Outcome>,
    pub certified: bool,
}

/// Build the in-toto Statement for a certification.
pub fn statement(_c: &Certification) -> serde_json::Value {
    todo!("implement per the module contract")
}

/// Sign a statement into a DSSE envelope.
pub fn sign(_statement: &serde_json::Value, _key: &ed25519_dalek::SigningKey, _keyid: &str) -> Envelope {
    todo!("implement per the module contract")
}

/// Verify an envelope offline.
pub fn verify(_envelope: &Envelope, _ctx: &VerifyContext) -> Report {
    todo!("implement per the module contract")
}
