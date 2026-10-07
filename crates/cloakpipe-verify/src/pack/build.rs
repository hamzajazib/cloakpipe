//! Producer side: assemble and sign a pack.
//!
//! The builder refuses inputs that could never verify (a run or
//! certification about another release, an uncertifiable manifest, a
//! timestamp that is not RFC 3339, a ledger export with no hop for this
//! release or overlapping another, no `release_registered` event), sorts governance events by time and always states
//! [`GOVERNANCE_LIMITATION`]. It does not check certification signatures or
//! promotion consistency: those need the verifier's trust anchors.

use super::check::{overlap, parse_time, release_binding_count, subject_release};
use super::*;
use base64::prelude::*;
use ed25519_dalek::{Signer, SigningKey};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BuildError {
    #[error("exporter must not be empty")]
    EmptyExporter,
    #[error("manifest is not certifiable: {}", .0.join("; "))]
    InvalidManifest(Vec<String>),
    #[error("evaluation run {run_id:?} is about release {release}, not this one")]
    RunNotForRelease { run_id: String, release: String },
    #[error("evaluation run {run_id:?} is invalid: {}", .issues.join("; "))]
    InvalidRun { run_id: String, issues: Vec<String> },
    #[error("certifications[{index}]: {problem}")]
    CertificationNotForRelease { index: usize, problem: String },
    #[error("{field}: {value:?} is not an RFC 3339 timestamp")]
    BadTimestamp { field: String, value: String },
    #[error("ledgerExports[{index}]: {problem}")]
    Ledger { index: usize, problem: String },
    #[error("pack cannot be serialised canonically: {0}")]
    Serialization(String),
    #[error("governance events must include the release_registered event")]
    MissingRegistration,
}

/// Assembles a [`ReleaseAuditPack`]; see the module docs.
///
/// ```ignore
/// let pack = PackBuilder::new(manifest, "cloakpipe-cloud:acme", "2026-10-07T12:00:00Z")
///     .run(run)
///     .certification(envelope)
///     .event(GovernanceEvent::ReleaseRegistered { at, actor, agent, version })
///     .ledger_export_json(bundle_json)?
///     .build(&signing_key)?;
/// std::fs::write("release.audit-pack.json", pack.to_json_pretty())?;
/// ```
#[derive(Debug, Clone)]
pub struct PackBuilder {
    manifest: AgentRelease,
    exporter: String,
    created_at: String,
    runs: Vec<EvaluationRun>,
    certifications: Vec<Envelope>,
    events: Vec<GovernanceEvent>,
    ledger_exports: Vec<Bundle>,
    limitations: Vec<String>,
}

impl PackBuilder {
    /// `created_at` is RFC 3339 and must not be before any event.
    pub fn new(manifest: AgentRelease, exporter: impl Into<String>, created_at: impl Into<String>) -> Self {
        PackBuilder {
            manifest,
            exporter: exporter.into(),
            created_at: created_at.into(),
            runs: Vec::new(),
            certifications: Vec::new(),
            events: Vec::new(),
            ledger_exports: Vec::new(),
            limitations: Vec::new(),
        }
    }

    pub fn run(mut self, run: EvaluationRun) -> Self {
        self.runs.push(run);
        self
    }

    pub fn runs(mut self, runs: impl IntoIterator<Item = EvaluationRun>) -> Self {
        self.runs.extend(runs);
        self
    }

    /// A DSSE certification envelope (blocked decisions too).
    pub fn certification(mut self, envelope: Envelope) -> Self {
        self.certifications.push(envelope);
        self
    }

    pub fn certifications(mut self, envelopes: impl IntoIterator<Item = Envelope>) -> Self {
        self.certifications.extend(envelopes);
        self
    }

    pub fn event(mut self, event: GovernanceEvent) -> Self {
        self.events.push(event);
        self
    }

    pub fn events(mut self, events: impl IntoIterator<Item = GovernanceEvent>) -> Self {
        self.events.extend(events);
        self
    }

    /// A signed ledger export (`cloakpipe.bundle` v4) as this crate reads it.
    pub fn ledger_export(mut self, bundle: Bundle) -> Self {
        self.ledger_exports.push(bundle);
        self
    }

    /// A ledger export as JSON, e.g. `serde_json::to_value` of
    /// `cloakpipe_ledger::export::Bundle`.
    pub fn ledger_export_json(mut self, bundle: Value) -> Result<Self, BuildError> {
        let index = self.ledger_exports.len();
        let bundle = serde_json::from_value(bundle)
            .map_err(|e| BuildError::Ledger { index, problem: format!("not a ledger export: {e}") })?;
        self.ledger_exports.push(bundle);
        Ok(self)
    }

    /// An exporter-declared caveat, shown to the reviewer.
    pub fn limitation(mut self, text: impl Into<String>) -> Self {
        self.limitations.push(text.into());
        self
    }

    /// Check, sort and sign with the exporter's Ed25519 key.
    pub fn build(self, key: &SigningKey) -> Result<ReleaseAuditPack, BuildError> {
        if self.exporter.trim().is_empty() {
            return Err(BuildError::EmptyExporter);
        }
        let created_at = parse_time(&self.created_at)
            .ok_or_else(|| BuildError::BadTimestamp { field: "createdAt".into(), value: self.created_at.clone() })?;
        let issues: Vec<String> = self.manifest.validate().iter().map(ToString::to_string).collect();
        if !issues.is_empty() {
            return Err(BuildError::InvalidManifest(issues));
        }
        let hash = self.manifest.manifest_hash().to_string();

        for run in &self.runs {
            if run.release != hash {
                return Err(BuildError::RunNotForRelease { run_id: run.run_id.clone(), release: run.release.clone() });
            }
            let issues = run.validate();
            if !issues.is_empty() {
                return Err(BuildError::InvalidRun { run_id: run.run_id.clone(), issues });
            }
        }
        for (index, envelope) in self.certifications.iter().enumerate() {
            match subject_release(envelope) {
                Ok(release) if release == hash => {}
                Ok(release) => {
                    return Err(BuildError::CertificationNotForRelease {
                        index,
                        problem: format!("certifies {release}, not this release"),
                    })
                }
                Err(problem) => return Err(BuildError::CertificationNotForRelease { index, problem }),
            }
        }

        let mut events = Vec::with_capacity(self.events.len());
        for (i, event) in self.events.into_iter().enumerate() {
            let at = parse_time(event.at()).ok_or_else(|| BuildError::BadTimestamp {
                field: format!("governance.events[{i}].at"),
                value: event.at().to_string(),
            })?;
            if at > created_at {
                return Err(BuildError::BadTimestamp {
                    field: format!("governance.events[{i}].at (after createdAt)"),
                    value: event.at().to_string(),
                });
            }
            events.push((at, event));
        }
        events.sort_by_key(|(at, _)| *at); // stable: equal times keep their order

        let mut seen = std::collections::BTreeMap::new();
        for (index, bundle) in self.ledger_exports.iter().enumerate() {
            match release_binding_count(bundle, &hash) {
                Ok(0) => {
                    return Err(BuildError::Ledger { index, problem: "contains no hop bound to this release".into() })
                }
                Ok(_) => {}
                Err(problem) => return Err(BuildError::Ledger { index, problem }),
            }
            if let Some(problem) = overlap(&mut seen, index, bundle) {
                return Err(BuildError::Ledger { index, problem });
            }
        }
        if !events.iter().any(|(_, e)| matches!(e, GovernanceEvent::ReleaseRegistered { .. })) {
            return Err(BuildError::MissingRegistration);
        }

        let mut limitations = vec![GOVERNANCE_LIMITATION.to_string()];
        for l in self.limitations {
            if !limitations.contains(&l) {
                limitations.push(l);
            }
        }

        let spec = PackSpec {
            created_at: self.created_at,
            exporter: self.exporter,
            release: ReleaseSection { hash, manifest: self.manifest },
            evaluation_runs: self.runs,
            certifications: self.certifications,
            governance: Governance {
                attested_by: ATTESTED_BY_EXPORTER.into(),
                events: events.into_iter().map(|(_, e)| e).collect(),
            },
            ledger_exports: self.ledger_exports,
            limitations,
        };
        let spec_value = serde_json::to_value(&spec).map_err(|e| BuildError::Serialization(e.to_string()))?;
        super::strict::check_numbers(&spec_value).map_err(BuildError::Serialization)?;
        let input = signing_input(&Value::from(PACK_API_VERSION), &Value::from(PACK_KIND), &spec_value)
            .map_err(BuildError::Serialization)?;
        let signature = key.sign(&input);
        Ok(ReleaseAuditPack {
            api_version: PACK_API_VERSION.into(),
            kind: PACK_KIND.into(),
            spec,
            digest: digest_of(&input),
            signature: PackSignature {
                keyid: keyid(&key.verifying_key().to_bytes()),
                sig: BASE64_STANDARD.encode(signature.to_bytes()),
            },
        })
    }
}
