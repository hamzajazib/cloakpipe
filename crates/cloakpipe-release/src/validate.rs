//! Certifiability checks. An empty result means the manifest pins every
//! behaviour-affecting component to an immutable identity.

use crate::manifest::{AgentRelease, ArtifactRef, API_VERSION, KIND};
use crate::reference::{is_lower_hex, is_valid_name, RefError, RefKind, Reference};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueCode {
    UnsupportedApiVersion,
    UnsupportedKind,
    MalformedReference,
    MutableReference,
    WrongReferenceKind,
    DuplicateEntry,
    InvalidCommit,
    UnpinnedImage,
    EmptyField,
    InvalidName,
}

impl IssueCode {
    /// Stable machine-readable name for API responses.
    pub fn as_str(self) -> &'static str {
        match self {
            IssueCode::UnsupportedApiVersion => "unsupported_api_version",
            IssueCode::UnsupportedKind => "unsupported_kind",
            IssueCode::MalformedReference => "malformed_reference",
            IssueCode::MutableReference => "mutable_reference",
            IssueCode::WrongReferenceKind => "wrong_reference_kind",
            IssueCode::DuplicateEntry => "duplicate_entry",
            IssueCode::InvalidCommit => "invalid_commit",
            IssueCode::UnpinnedImage => "unpinned_image",
            IssueCode::EmptyField => "empty_field",
            IssueCode::InvalidName => "invalid_name",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub code: IssueCode,
    /// Dotted path to the offending field, e.g. `spec.tools[1].ref`.
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl AgentRelease {
    pub fn validate(&self) -> Vec<Issue> {
        let mut v = Validator::default();
        let s = &self.spec;

        if self.api_version != API_VERSION {
            v.push(IssueCode::UnsupportedApiVersion, "apiVersion", format!("expected {API_VERSION}, got {:?}", self.api_version));
        }
        if self.kind != KIND {
            v.push(IssueCode::UnsupportedKind, "kind", format!("expected {KIND}, got {:?}", self.kind));
        }
        if !is_valid_name(&self.metadata.agent) {
            v.push(IssueCode::InvalidName, "metadata.agent", "must be lowercase [a-z0-9._/-]".into());
        }

        if s.code.repository.trim().is_empty() {
            v.push(IssueCode::EmptyField, "spec.code.repository", "must not be empty".into());
        }
        if !is_lower_hex(&s.code.commit, 7..=40) {
            v.push(IssueCode::InvalidCommit, "spec.code.commit", format!("{:?} is not a 7-40 char lowercase hex commit", s.code.commit));
        }

        if s.prompts.is_empty() {
            v.push(IssueCode::EmptyField, "spec.prompts", "at least one prompt is required".into());
        }
        for (i, r) in s.prompts.iter().enumerate() {
            v.reference(&format!("spec.prompts[{i}].ref"), r, RefKind::Prompt);
        }
        v.reference("spec.model.ref", &s.model, RefKind::Model);
        v.set("spec.tools", &s.tools, RefKind::Tool);
        v.set("spec.mcpServers", &s.mcp_servers, RefKind::Mcp);
        if let Some(r) = &s.retrieval {
            v.reference("spec.retrieval.ref", r, RefKind::Retrieval);
        }
        v.set("spec.policies", &s.policies, RefKind::Policy);

        let pinned = s
            .runtime
            .image
            .rsplit_once("@sha256:")
            .is_some_and(|(repo, hex)| !repo.is_empty() && is_lower_hex(hex, 64..=64));
        if !pinned {
            v.push(IssueCode::UnpinnedImage, "spec.runtime.image", "must be pinned by digest (<image>@sha256:<64 hex>)".into());
        }
        if s.runtime.region.trim().is_empty() {
            v.push(IssueCode::EmptyField, "spec.runtime.region", "must not be empty".into());
        }

        let mut seen = BTreeSet::new();
        for (i, d) in s.dependencies.iter().enumerate() {
            if d.name.trim().is_empty() || d.version.trim().is_empty() {
                v.push(IssueCode::EmptyField, &format!("spec.dependencies[{i}]"), "name and version are required".into());
            }
            if !seen.insert(d.name.as_str()) {
                v.push(IssueCode::DuplicateEntry, &format!("spec.dependencies[{i}].name"), format!("dependency {:?} listed twice", d.name));
            }
        }

        v.issues
    }
}

#[derive(Default)]
struct Validator {
    issues: Vec<Issue>,
}

impl Validator {
    fn push(&mut self, code: IssueCode, path: &str, message: String) {
        self.issues.push(Issue { code, path: path.to_string(), message });
    }

    fn reference(&mut self, path: &str, r: &ArtifactRef, expected: RefKind) -> Option<Reference> {
        match Reference::parse(&r.reference) {
            Ok(parsed) if parsed.kind != expected => {
                self.push(IssueCode::WrongReferenceKind, path, format!("expected a `{}:` reference, got {:?}", expected.as_str(), r.reference));
                None
            }
            Ok(parsed) => Some(parsed),
            Err(RefError::Mutable) => {
                self.push(IssueCode::MutableReference, path, format!("{:?} is not pinned to an immutable version", r.reference));
                None
            }
            Err(RefError::Malformed) => {
                self.push(IssueCode::MalformedReference, path, format!("{:?} is not `<kind>:<name>@<version>`", r.reference));
                None
            }
        }
    }

    fn set(&mut self, field: &str, refs: &[ArtifactRef], kind: RefKind) {
        let mut seen = BTreeSet::new();
        for (i, r) in refs.iter().enumerate() {
            let path = format!("{field}[{i}].ref");
            if let Some(parsed) = self.reference(&path, r, kind) {
                if !seen.insert(parsed.key()) {
                    self.push(IssueCode::DuplicateEntry, &path, format!("{} listed more than once", parsed.key()));
                }
            }
        }
    }
}
