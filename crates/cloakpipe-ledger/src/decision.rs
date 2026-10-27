//! Decision ledger entries (`cloakpipe.decision/v1`): what the tool gate
//! decided, one entry per decision.
//!
//! A separate record kind from the legacy PII hop records
//! ([`crate::record::LedgerRecord`]), kept in its own table of the same
//! ledger database, so neither schema bends to the other.
//!
//! ## Format
//!
//! An entry is a flat JSON object (every field present, `null` when
//! absent):
//!
//! - `kind`: `cloakpipe.decision/v1`; `seq` (from 0, no gaps); `ts` (RFC
//!   3339 UTC, seconds)
//! - `event`: `call` (a tool call was decided), `replay` (a retry of a
//!   completed side effect, answered from the operations store), `outcome`
//!   (a forwarded side effect settled: `committed` / `failed` / `unknown`),
//!   `reconcile` (an operator settled an unknown one)
//! - `release` (`sha256:` manifest digest), `tool`, `args_fingerprint`
//!   (keyed: `hmac-sha256:`, see [`crate::gate_key::GateKey::args_fingerprint`];
//!   never raw values), `task_id`, `operation_id`, `approval` (`sha256:` of
//!   the approval receipt)
//! - `decision` (`allow` / `deny` / `require_approval`), `reason` (a denial
//!   code, `ok`, or `reconciled`), `path` (the contract path of an argument
//!   denial)
//! - `policy_version` (the manifest digest), `policy_digest` (the sha256 of
//!   the manifest's Cedar policy file, null without one)
//! - `mode` (`enforce` / `shadow`: in shadow the decision is what enforce
//!   would have done), `forwarded` (whether the call reached the tool),
//!   `outcome`
//! - `signer` (`ed25519:<keyid>`), `prev_hash`, `entry_hash`, `sig`
//!
//! `entry_hash` = SHA-256(`cloakpipe.decision.v1` `\n` canonical JSON of
//! the entry without `entry_hash` and `sig`), where canonical JSON has
//! sorted keys and no whitespace. Every field, including ones a later
//! version adds, is covered. `prev_hash` is the previous entry's
//! `entry_hash` ([`GENESIS`] for seq 0). `sig` is Ed25519 over the 32 raw
//! bytes of `entry_hash`, by the gate signing key named in `signer`.
//! `cloakpipe-verify` re-derives all of it with its own code.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The `kind` of a decision entry.
pub const DECISION_KIND: &str = "cloakpipe.decision/v1";

/// Domain separator of `entry_hash`.
pub const DECISION_HASH_DOMAIN: &str = "cloakpipe.decision.v1";

/// `prev_hash` of the first entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What the gate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

/// Whether the gate enforced its decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Enforce,
    /// Every call the gate can read is forwarded; the entry records what
    /// enforce mode would have decided.
    Shadow,
}

/// How a forwarded side effect ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Committed,
    Failed,
    Unknown,
}

/// What an entry is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Call,
    Replay,
    Outcome,
    Reconcile,
}

/// An entry before it is chained and signed
/// ([`crate::LedgerStore::append_decision`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionDraft {
    /// Defaults to now.
    pub ts: Option<DateTime<Utc>>,
    pub event: Event,
    pub release: Option<String>,
    pub tool: Option<String>,
    pub args_fingerprint: Option<String>,
    pub decision: Decision,
    pub reason: String,
    pub path: Option<String>,
    /// Defaults to `release` (the manifest digest).
    pub policy_version: Option<String>,
    pub policy_digest: Option<String>,
    pub mode: Option<Mode>,
    pub task_id: Option<String>,
    pub operation_id: Option<String>,
    pub approval: Option<String>,
    pub outcome: Option<Outcome>,
    pub forwarded: bool,
}

impl DecisionDraft {
    fn new(event: Event, reason: &str) -> Self {
        Self {
            ts: None,
            event,
            release: None,
            tool: None,
            args_fingerprint: None,
            decision: Decision::Allow,
            reason: reason.to_string(),
            path: None,
            policy_version: None,
            policy_digest: None,
            mode: None,
            task_id: None,
            operation_id: None,
            approval: None,
            outcome: None,
            forwarded: false,
        }
    }

    /// A tool call decision (`allow`, `ok` until set otherwise).
    pub fn call() -> Self {
        Self::new(Event::Call, "ok")
    }

    /// A settled side effect (set `outcome`).
    pub fn outcome() -> Self {
        Self::new(Event::Outcome, "ok")
    }

    /// An operator's reconciliation (set `outcome`).
    pub fn reconcile() -> Self {
        Self::new(Event::Reconcile, "reconciled")
    }
}

/// A chained, signed decision entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionEntry {
    pub kind: String,
    pub seq: u64,
    pub ts: String,
    pub event: Event,
    pub release: Option<String>,
    pub tool: Option<String>,
    pub args_fingerprint: Option<String>,
    pub decision: Decision,
    pub reason: String,
    pub path: Option<String>,
    pub policy_version: Option<String>,
    pub policy_digest: Option<String>,
    pub mode: Option<Mode>,
    pub task_id: Option<String>,
    pub operation_id: Option<String>,
    pub approval: Option<String>,
    pub outcome: Option<Outcome>,
    pub forwarded: bool,
    pub signer: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub sig: String,
}

impl DecisionEntry {
    /// Chain `draft` after `prev_hash` as entry `seq`, unsigned
    /// (`entry_hash` set, `sig` empty).
    pub(crate) fn link(draft: DecisionDraft, seq: u64, prev_hash: &str, signer: String) -> Self {
        let ts = draft.ts.unwrap_or_else(Utc::now).to_rfc3339_opts(SecondsFormat::Secs, true);
        let policy_version = draft.policy_version.or_else(|| draft.release.clone());
        let mut entry = DecisionEntry {
            kind: DECISION_KIND.to_string(),
            seq,
            ts,
            event: draft.event,
            release: draft.release,
            tool: draft.tool,
            args_fingerprint: draft.args_fingerprint,
            decision: draft.decision,
            reason: draft.reason,
            path: draft.path,
            policy_version,
            policy_digest: draft.policy_digest,
            mode: draft.mode,
            task_id: draft.task_id,
            operation_id: draft.operation_id,
            approval: draft.approval,
            outcome: draft.outcome,
            forwarded: draft.forwarded,
            signer,
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            sig: String::new(),
        };
        entry.entry_hash = entry.compute_hash();
        entry
    }

    /// The `entry_hash` these fields hash to (hex).
    pub fn compute_hash(&self) -> String {
        let value = serde_json::to_value(self).expect("an entry serializes");
        hex::encode(entry_hash_of(&value))
    }

    /// The entry as one line of `entries.jsonl`.
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).expect("an entry serializes")
    }
}

/// `entry_hash` of an entry given as JSON: every member except `entry_hash`
/// and `sig` is covered.
pub fn entry_hash_of(entry: &Value) -> [u8; 32] {
    let mut covered = entry.clone();
    if let Some(o) = covered.as_object_mut() {
        o.remove("entry_hash");
        o.remove("sig");
    }
    let mut bytes = format!("{DECISION_HASH_DOMAIN}\n").into_bytes();
    canonical_json(&covered, &mut bytes);
    Sha256::digest(&bytes).into()
}

/// Sorted keys, no whitespace, serde_json's string escaping.
fn canonical_json(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_string(k).expect("a string serializes").into_bytes());
                out.push(b':');
                canonical_json(&o[k], out);
            }
            out.push(b'}');
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_json(x, out);
            }
            out.push(b']');
        }
        other => out.extend(serde_json::to_string(other).expect("a scalar serializes").into_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_at_every_level() {
        let mut a = Vec::new();
        canonical_json(&serde_json::json!({"b": 1, "a": {"d": null, "c": "x\n"}}), &mut a);
        assert_eq!(String::from_utf8(a).unwrap(), r#"{"a":{"c":"x\n","d":null},"b":1}"#);
    }

    #[test]
    fn the_hash_ignores_entry_hash_and_sig_only() {
        let base = serde_json::json!({"seq": 0, "reason": "ok"});
        let with = serde_json::json!({"seq": 0, "reason": "ok", "entry_hash": "aa", "sig": "bb"});
        assert_eq!(entry_hash_of(&base), entry_hash_of(&with));
        let extra = serde_json::json!({"seq": 0, "reason": "ok", "later_field": 1});
        assert_ne!(entry_hash_of(&base), entry_hash_of(&extra), "a field a later version adds is covered");
    }
}
