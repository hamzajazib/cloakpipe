//! Artifact reference grammar: `<kind>:<name>@<version>`.
//!
//! `name` is lowercase `[a-z0-9][a-z0-9._/-]*`. `version` is either a content
//! digest (`sha256:<64 hex>`) or an immutable version token such as `31`,
//! `2.4.1` or `2026-08-01`. Environment-style aliases (`latest`, `production`,
//! ...) and unversioned references are mutable and cannot be certified.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefKind {
    Prompt,
    Model,
    Tool,
    Mcp,
    Retrieval,
    Policy,
}

impl RefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RefKind::Prompt => "prompt",
            RefKind::Model => "model",
            RefKind::Tool => "tool",
            RefKind::Mcp => "mcp",
            RefKind::Retrieval => "retrieval",
            RefKind::Policy => "policy",
        }
    }

    fn parse(s: &str) -> Option<RefKind> {
        Some(match s {
            "prompt" => RefKind::Prompt,
            "model" => RefKind::Model,
            "tool" => RefKind::Tool,
            "mcp" => RefKind::Mcp,
            "retrieval" => RefKind::Retrieval,
            "policy" => RefKind::Policy,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub kind: RefKind,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefError {
    Malformed,
    Mutable,
}

/// Labels that resolve to different versions over time.
const MUTABLE_ALIASES: &[&str] = &[
    "latest", "production", "prod", "staging", "candidate", "draft", "dev", "development", "main",
    "master", "head", "stable", "current", "rollback", "next", "canary",
];

impl Reference {
    pub fn parse(s: &str) -> Result<Reference, RefError> {
        let (kind, rest) = s.split_once(':').ok_or(RefError::Malformed)?;
        let kind = RefKind::parse(kind).ok_or(RefError::Malformed)?;
        let Some((name, version)) = rest.split_once('@') else {
            // Well-formed name with no version: resolvable only through a moving pointer.
            return Err(if is_valid_name(rest) { RefError::Mutable } else { RefError::Malformed });
        };
        if !is_valid_name(name) || !is_valid_version(version) {
            return Err(RefError::Malformed);
        }
        if MUTABLE_ALIASES.contains(&version.to_ascii_lowercase().as_str()) {
            return Err(RefError::Mutable);
        }
        Ok(Reference { kind, name: name.to_string(), version: version.to_string() })
    }

    /// `kind:name` without the version — the identity used to match a
    /// component across two releases.
    pub fn key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.name)
    }
}

pub(crate) fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-'))
}

fn is_valid_version(s: &str) -> bool {
    if let Some(hex) = s.strip_prefix("sha256:") {
        return is_lower_hex(hex, 64..=64);
    }
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

pub(crate) fn is_lower_hex(s: &str, len: std::ops::RangeInclusive<usize>) -> bool {
    len.contains(&s.len()) && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Matching key for a raw reference string, falling back to the whole string
/// when it does not parse (so malformed entries still diff sensibly).
pub(crate) fn key_of(raw: &str) -> String {
    match raw.split_once('@') {
        Some((k, _)) => k.to_string(),
        None => raw.to_string(),
    }
}
