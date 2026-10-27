//! The single-file v1 manifest, `cloakpipe.manifest.yaml`.
//!
//! ```yaml
//! release: support-agent
//! version: 2026.10.3
//! policy: ./policies/support.cedar      # optional
//! tools:
//!   send_email:
//!     args:
//!       to:   { type: string, one_of_context: ["ticket.customer_email"], or_pattern: "@ourcompany\\.com$", required: true }
//!       body: { type: string, max_len: 4000 }
//!     side_effect: true
//!     idempotency_key: "{ticket_id}:{sha256(body)}"
//!   issue_refund:
//!     args:
//!       amount: { type: number, min: 0, max: 500, required: true }
//!     side_effect: true
//!     approval: { when: "amount > 100", approvers: ["slack:#support-leads"], ttl: 15m }
//! ```
//!
//! The manifest compiles into the same [`ToolRule`]s a legacy
//! `ToolContract` does, so one tested checker serves both formats. It is
//! closed by default: a declared tool accepts only the arguments under its
//! `args` (none when `args` is absent), each optional unless `required: true`,
//! and a tool that is not declared is not callable.
//!
//! The **manifest digest** is `sha256:` over the RFC 8785 (JCS) encoding of
//! the parsed document; formatting, comments and key order do not change it.
//! A referenced policy file (resolved against the manifest's directory) is
//! read at load and digested separately, over its bytes, as the **policy
//! digest**.
//!
//! Every rule is checked at load: unknown keys, duplicate keys, bad
//! patterns, malformed templates or conditions, and references to arguments
//! the tool does not declare are errors, so the gate fails closed at start-up.

use crate::canonical::ReleaseHash;
use crate::contract::{child, present, Constraint, JsonType, Strict, ToolRule};
use serde::Deserialize;
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use crate::rules::{parse_duration, ApprovalRule, Condition, Effect, IdempotencyKey};

/// The conventional file name.
pub const FILE_NAME: &str = "cloakpipe.manifest.yaml";

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
    #[error("invalid manifest: {0}")]
    Syntax(String),
    #[error("invalid manifest: {0}")]
    Invalid(String),
}

/// Which manifest format a document is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    /// A top-level `release` key: this format.
    V1,
    /// A top-level `apiVersion` key: the legacy AgentRelease (+ ToolContract).
    Legacy,
}

/// Tell the formats apart by their top-level keys (JSON or YAML).
pub fn detect(src: &str) -> Result<ManifestKind, String> {
    let v: Value = serde_yaml::from_str(src).map_err(|e| format!("not a YAML or JSON document: {e}"))?;
    let Value::Object(o) = v else { return Err("the manifest must be a mapping".into()) };
    match (o.contains_key("release"), o.contains_key("apiVersion")) {
        (true, false) => Ok(ManifestKind::V1),
        (false, true) => Ok(ManifestKind::Legacy),
        (true, true) => Err("both `release` (v1 manifest) and `apiVersion` (legacy AgentRelease) at the top level".into()),
        (false, false) => Err("neither `release` (v1 manifest) nor `apiVersion` (legacy AgentRelease) at the top level".into()),
    }
}

/// A loaded v1 manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub release: String,
    pub version: String,
    pub policy: Option<Policy>,
    tools: BTreeMap<String, ToolRule>,
    digest: ReleaseHash,
}

/// The policy file a manifest references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The `policy:` value as written.
    pub declared: String,
    /// Resolved against the manifest's directory.
    pub path: PathBuf,
    /// The file's bytes, as digested.
    pub source: Vec<u8>,
    /// `sha256:` over [`Self::source`].
    pub digest: ReleaseHash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    release: String,
    version: Value,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    tools: Option<BTreeMap<String, RawTool>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    #[serde(default)]
    args: BTreeMap<String, ArgSpec>,
    side_effect: Option<bool>,
    effect: Option<Effect>,
    idempotency_key: Option<String>,
    approval: Option<RawApproval>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApproval {
    when: Option<String>,
    #[serde(default)]
    approvers: Vec<String>,
    ttl: Option<String>,
}

/// One argument's constraint, as written in a v1 manifest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgSpec {
    #[serde(rename = "type")]
    ty: Option<JsonType>,
    pattern: Option<String>,
    #[serde(rename = "enum")]
    one_of: Option<Vec<Value>>,
    #[serde(rename = "const", default, deserialize_with = "present")]
    constant: Option<Value>,
    min_len: Option<u64>,
    max_len: Option<u64>,
    min: Option<Number>,
    max: Option<Number>,
    items: Option<Box<ArgSpec>>,
    properties: Option<BTreeMap<String, ArgSpec>>,
    #[serde(default)]
    required: bool,
    one_of_context: Option<Vec<String>>,
    or_pattern: Option<String>,
}

impl ArgSpec {
    /// The equivalent internal constraint (not yet validated).
    fn compile(self, path: &str) -> Result<Constraint, String> {
        if self.ty == Some(JsonType::Null) {
            return Err(format!("{path}: type must be string, number, integer, boolean, object or array"));
        }
        let array = self.ty == Some(JsonType::Array);
        let (min_length, max_length, min_items, max_items) =
            if array { (None, None, self.min_len, self.max_len) } else { (self.min_len, self.max_len, None, None) };
        let (properties, required) = match self.properties {
            Some(props) => {
                let required = props.iter().filter(|(_, a)| a.required).map(|(k, _)| k.clone()).collect();
                let mut out = BTreeMap::new();
                for (name, spec) in props {
                    let p = child(path, &name);
                    out.insert(name, spec.compile(&p)?);
                }
                (Some(out), Some(required))
            }
            None => (None, None),
        };
        let items = match self.items {
            Some(i) => Some(Box::new(i.compile(&format!("{path}/items"))?)),
            None => None,
        };
        Ok(Constraint {
            ty: self.ty,
            one_of: self.one_of,
            constant: self.constant,
            min_length,
            max_length,
            pattern: self.pattern,
            minimum: self.min,
            maximum: self.max,
            properties,
            required,
            additional_properties: None,
            min_properties: None,
            max_properties: None,
            items,
            min_items,
            max_items,
            bind_to: None,
            one_of_context: self.one_of_context,
            or_pattern: self.or_pattern,
            regex: None,
            or_regex: None,
        })
    }
}

impl RawTool {
    fn compile(self, tool: &str) -> Result<ToolRule, String> {
        let effect = match (self.side_effect, self.effect) {
            (Some(true), Some(Effect::Read)) | (Some(false), Some(Effect::Write | Effect::Irreversible)) => {
                return Err(format!("{tool}: side_effect and effect disagree"));
            }
            (_, Some(e)) => Some(e),
            (Some(true), None) => Some(Effect::Write),
            (Some(false), None) => Some(Effect::Read),
            (None, None) => None,
        };
        let side_effect = effect.is_some_and(Effect::is_side_effect);
        let required = self.args.iter().filter(|(_, a)| a.required).map(|(k, _)| k.clone()).collect();
        let mut arguments = BTreeMap::new();
        for (name, spec) in self.args {
            let path = child("", &name);
            let mut c = spec.compile(&path).map_err(|e| format!("{tool}: {e}"))?;
            c.validate(&path).map_err(|e| format!("{tool}: {e}"))?;
            arguments.insert(name, c);
        }
        let idempotency_key = match self.idempotency_key {
            Some(src) => {
                if !side_effect {
                    return Err(format!("{tool}: idempotency_key applies only to a side-effecting tool (side_effect: true)"));
                }
                let key = IdempotencyKey::parse(&src).map_err(|e| format!("{tool}: {e}"))?;
                if let Some(root) = key.argument_roots().find(|r| !arguments.contains_key(*r)) {
                    return Err(format!("{tool}: idempotency_key uses {root:?}, which is not a declared argument"));
                }
                Some(key)
            }
            None => None,
        };
        let approval = match self.approval {
            Some(a) => {
                let when = match a.when {
                    Some(src) => {
                        let c = Condition::parse(&src).map_err(|e| format!("{tool}: approval.when: {e}"))?;
                        if let Some(root) = c.argument_roots().into_iter().find(|r| !arguments.contains_key(*r)) {
                            return Err(format!("{tool}: approval.when uses {root:?}, which is not a declared argument"));
                        }
                        Some(c)
                    }
                    None => None,
                };
                if a.approvers.iter().any(|r| r.trim().is_empty()) {
                    return Err(format!("{tool}: approval.approvers has an empty entry"));
                }
                let ttl_secs = match a.ttl {
                    Some(t) => Some(parse_duration(&t).map_err(|e| format!("{tool}: approval.ttl: {e}"))?),
                    None => None,
                };
                Some(ApprovalRule { when, approvers: a.approvers, ttl_secs })
            }
            None => None,
        };
        Ok(ToolRule {
            side_effect,
            requires_approval: approval.is_some(),
            arguments,
            required,
            effect,
            idempotency_key,
            approval,
        })
    }
}

impl Manifest {
    /// Parse a manifest (YAML, or JSON as YAML's subset). A `policy:` path is
    /// resolved against `base`, the manifest's directory.
    pub fn parse_str(src: &str, base: &Path) -> Result<Self, ManifestError> {
        let syntax = |e: &dyn std::fmt::Display| ManifestError::Syntax(e.to_string());
        let invalid = ManifestError::Invalid;
        // Duplicate keys are refused: they could mean different things to
        // different readers.
        let Strict(raw) = serde_yaml::from_str(src).map_err(|e| syntax(&e))?;
        let parsed: RawManifest = serde_json::from_value(raw.clone()).map_err(|e| syntax(&e))?;
        if parsed.release.trim().is_empty() {
            return Err(invalid("release is empty".into()));
        }
        let version = match &parsed.version {
            Value::String(s) if !s.trim().is_empty() => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => return Err(invalid("version must be a non-empty string".into())),
        };
        let policy = match parsed.policy {
            Some(declared) => {
                if declared.trim().is_empty() {
                    return Err(invalid("policy is empty".into()));
                }
                let path = base.join(&declared);
                let source = std::fs::read(&path)
                    .map_err(|e| invalid(format!("policy {declared:?} ({}): {e}", path.display())))?;
                let digest = ReleaseHash(Sha256::digest(&source).into());
                Some(Policy { declared, path, source, digest })
            }
            None => None,
        };
        let mut tools = BTreeMap::new();
        for (name, tool) in parsed.tools.unwrap_or_default() {
            if name.is_empty() {
                return Err(invalid("tools has an empty tool name".into()));
            }
            let rule = tool.compile(&name).map_err(invalid)?;
            tools.insert(name, rule);
        }
        let jcs = serde_json_canonicalizer::to_vec(&raw).expect("a parsed JSON value encodes");
        let digest = ReleaseHash(Sha256::digest(&jcs).into());
        Ok(Manifest { release: parsed.release, version, policy, tools, digest })
    }

    /// Parse a manifest file; a `policy:` path is relative to its directory.
    pub fn parse_path(path: &Path) -> Result<Self, ManifestError> {
        let src = std::fs::read_to_string(path).map_err(|e| ManifestError::Io(path.display().to_string(), e))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse_str(&src, base)
    }

    /// The manifest digest (`sha256:` over the JCS form): the release
    /// identity that fingerprints, approvals and the ledger bind to.
    pub fn digest(&self) -> ReleaseHash {
        self.digest
    }

    /// The policy file's digest, when the manifest references one.
    pub fn policy_digest(&self) -> Option<ReleaseHash> {
        self.policy.as_ref().map(|p| p.digest)
    }

    /// The declared tools and their compiled rules.
    pub fn tools(&self) -> &BTreeMap<String, ToolRule> {
        &self.tools
    }

    /// The rules for `tool`; `None`: the tool is not declared.
    pub fn rule(&self, tool: &str) -> Option<&ToolRule> {
        self.tools.get(tool)
    }
}
