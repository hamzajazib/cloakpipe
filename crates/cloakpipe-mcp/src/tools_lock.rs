//! Tool pinning: `cloakpipe.tools.lock`.
//!
//! An MCP server describes its tools in `tools/list`, and the model reads
//! those descriptions as instructions. A server that changes a description
//! or a schema after it was reviewed (tool poisoning, a "rug pull") changes
//! what the agent does without any change to the release. The lock pins
//! each tool's definition when it was reviewed:
//!
//! ```json
//! {
//!   "schema": "cloakpipe.tools-lock/v1",
//!   "digest": "sha256:<hex>",
//!   "servers": { "<server>": { "<tool>": "sha256:<hex>" } }
//! }
//! ```
//!
//! A tool's hash is SHA-256 over the RFC 8785 (JCS) canonical JSON of the
//! object holding its `name`, `description`, `inputSchema` and
//! `annotations` (the members it has; nothing else). The lock `digest` is
//! SHA-256 over the canonical JSON of `{"schema", "servers"}`: an edited
//! lock does not read back ([`LockError::Digest`]); pin again instead.
//!
//! With a lock, the gate hides a tool whose definition does not match its
//! pin (or that has none) from `tools/list` and refuses calls to it as
//! `tool_drift`.

use crate::servers::ServerTools;
use cloakpipe_receipt::dsse::canonical_bytes;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The `schema` member of a lock.
pub const TOOLS_LOCK_SCHEMA: &str = "cloakpipe.tools-lock/v1";

/// The members of a tool definition its hash covers.
const PINNED_MEMBERS: [&str; 4] = ["name", "description", "inputSchema", "annotations"];

/// The pinned hash of one tool definition (an entry of a `tools/list`
/// result): `"sha256:<hex>"`.
pub fn tool_hash(tool: &Value) -> String {
    let mut pinned = Map::new();
    for member in PINNED_MEMBERS {
        if let Some(v) = tool.get(member) {
            pinned.insert(member.to_string(), v.clone());
        }
    }
    sha256(&canonical_bytes(&Value::Object(pinned)))
}

fn sha256(bytes: &[u8]) -> String {
    let digest: String = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{digest}")
}

/// Why a lock file does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Not JSON, or not shaped like a lock.
    Syntax(String),
    /// Another `schema`.
    Schema(String),
    /// The digest does not match the pins: the file was edited.
    Digest { recorded: String, computed: String },
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Syntax(e) => write!(f, "not a tools lock: {e}"),
            LockError::Schema(s) => write!(f, "unsupported tools lock schema {s:?} (expected {TOOLS_LOCK_SCHEMA})"),
            LockError::Digest { recorded, computed } => write!(
                f,
                "the tools lock digest does not match its content (recorded {recorded:?}, computed {computed}): \
                 it was edited; pin again with `cloakpipe tools pin`"
            ),
        }
    }
}

impl std::error::Error for LockError {}

/// Pinned tool hashes, per server, per tool.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolsLock {
    servers: BTreeMap<String, BTreeMap<String, String>>,
}

/// How a tool differs between two locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeKind {
    /// In the newer lock only.
    Added,
    /// In the older lock only.
    Removed,
    /// In both, with another hash.
    Changed,
}

impl ChangeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Changed => "changed",
        }
    }
}

/// One tool that differs between two locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockChange {
    pub server: String,
    pub tool: String,
    pub kind: ChangeKind,
    /// Its hash in the older lock.
    pub before: Option<String>,
    /// Its hash in the newer lock.
    pub after: Option<String>,
}

impl ToolsLock {
    /// Pin every tool `servers` list now.
    pub fn from_servers(servers: &[ServerTools]) -> Self {
        let mut lock = Self::default();
        for server in servers {
            let tools = lock.servers.entry(server.name.clone()).or_default();
            for tool in &server.tools {
                if let Some(name) = tool.get("name").and_then(Value::as_str) {
                    tools.insert(name.to_string(), tool_hash(tool));
                }
            }
        }
        lock
    }

    /// Read a lock, checking its schema and digest.
    pub fn parse(text: &str) -> Result<Self, LockError> {
        let v: Value = serde_json::from_str(text).map_err(|e| LockError::Syntax(e.to_string()))?;
        let schema = v.get("schema").and_then(Value::as_str).unwrap_or_default();
        if schema != TOOLS_LOCK_SCHEMA {
            return Err(LockError::Schema(schema.to_string()));
        }
        let servers: BTreeMap<String, BTreeMap<String, String>> = serde_json::from_value(v.get("servers").cloned().unwrap_or(Value::Null))
            .map_err(|e| LockError::Syntax(format!("servers: {e}")))?;
        let lock = Self { servers };
        let recorded = v.get("digest").and_then(Value::as_str).unwrap_or_default().to_string();
        let computed = lock.digest();
        if recorded != computed {
            return Err(LockError::Digest { recorded, computed });
        }
        Ok(lock)
    }

    /// The lock digest (`sha256:<hex>`).
    pub fn digest(&self) -> String {
        sha256(&canonical_bytes(&self.body()))
    }

    fn body(&self) -> Value {
        serde_json::json!({ "schema": TOOLS_LOCK_SCHEMA, "servers": self.servers })
    }

    /// The lock file's text (pretty JSON, a trailing newline).
    pub fn to_json_string(&self) -> String {
        let mut v = self.body();
        v["digest"] = Value::String(self.digest());
        let mut text = serde_json::to_string_pretty(&v).unwrap_or_default();
        text.push('\n');
        text
    }

    /// The pinned hash of `tool` on `server`.
    pub fn hash_of(&self, server: &str, tool: &str) -> Option<&str> {
        self.servers.get(server)?.get(tool).map(String::as_str)
    }

    /// Whether the lock pins anything for `server`.
    pub fn has_server(&self, server: &str) -> bool {
        self.servers.contains_key(server)
    }

    /// The servers the lock pins, in name order.
    pub fn servers(&self) -> impl Iterator<Item = &str> {
        self.servers.keys().map(String::as_str)
    }

    /// How many tools it pins.
    pub fn tool_count(&self) -> usize {
        self.servers.values().map(BTreeMap::len).sum()
    }

    /// What changed from this lock to `newer`, by server, then tool.
    pub fn diff(&self, newer: &ToolsLock) -> Vec<LockChange> {
        let empty = BTreeMap::new();
        let mut changes = Vec::new();
        let mut names: Vec<&String> = self.servers.keys().chain(newer.servers.keys()).collect();
        names.sort();
        names.dedup();
        for server in names {
            let before = self.servers.get(server).unwrap_or(&empty);
            let after = newer.servers.get(server).unwrap_or(&empty);
            let mut tools: Vec<&String> = before.keys().chain(after.keys()).collect();
            tools.sort();
            tools.dedup();
            for tool in tools {
                let (b, a) = (before.get(tool), after.get(tool));
                let kind = match (b, a) {
                    (None, Some(_)) => ChangeKind::Added,
                    (Some(_), None) => ChangeKind::Removed,
                    (Some(b), Some(a)) if b != a => ChangeKind::Changed,
                    _ => continue,
                };
                changes.push(LockChange { server: server.clone(), tool: tool.clone(), kind, before: b.cloned(), after: a.cloned() });
            }
        }
        changes
    }
}
