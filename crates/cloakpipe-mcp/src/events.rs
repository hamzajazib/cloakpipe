//! Gate events: what a human (or an alerting pipeline) should hear about.
//!
//! The interceptor hands a [`GateEvent`] to every [`EventSink`] in
//! [`ProxyContext::events`](crate::ProxyContext::events) at each decision
//! point that deserves attention: a refused call, an approval request, a
//! receipt that does not match, a would-deny in shadow mode, a side effect
//! replayed or left unknown, an upstream tool whose definition drifted. An
//! allowed call emits nothing.
//!
//! An event is emitted after its decision ledger entry is written, so it
//! names the entry (`ledger_seq`, `entry_hash`). The exception is the
//! `tool.drift` raised when the gate finds a drifted tool, before any call:
//! it has no entry. It carries only what the
//! ledger may: the tool name, the reason code, the contract path, the
//! release, the policy digest, the decision and mode, the operation id and
//! fingerprints, never an argument value, a tool result or a credential.
//!
//! A refusal the gate could not record (`fail_closed`) is still a
//! `decision.deny`, with no `ledger_seq`. A side-effect event's `reason` is
//! its own: `already_committed` (replayed) or `operation_unknown`.
//!
//! Sinks are called on the decision path: [`EventSink::emit`] must return
//! at once (queue the event and deliver it elsewhere). A sink never changes
//! a decision.

use cloakpipe_ledger::decision::{Decision, Mode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The `schema` member of [`GateEvent::to_json`].
pub const EVENT_SCHEMA: &str = "cloakpipe.event/v1";

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum EventKind {
    /// The gate refused a call (enforce mode).
    #[serde(rename = "decision.deny")]
    DecisionDeny,
    /// A call needs an approval receipt and has none (enforce mode).
    #[serde(rename = "approval.requested")]
    ApprovalRequested,
    /// A call came with an approval receipt that does not cover it: bound to
    /// other arguments, another release or tool, or not validly signed.
    /// (An expired receipt is a `decision.deny` with `approval_expired`.)
    #[serde(rename = "approval.mismatch")]
    ApprovalMismatch,
    /// A forwarded side-effecting call has no settled outcome: an operator
    /// must reconcile it.
    #[serde(rename = "side_effect.unknown")]
    SideEffectUnknown,
    /// A retry of a completed side-effecting call was answered with its
    /// stored result instead of running again.
    #[serde(rename = "side_effect.replayed")]
    SideEffectReplayed,
    /// Shadow mode forwarded a call enforce mode would have refused.
    #[serde(rename = "shadow.finding")]
    ShadowFinding,
    /// An upstream tool's definition no longer matches its pin in the tools
    /// lock (or has none), or changed during the session: it is hidden from
    /// the agent and calls to it are refused (`tool_drift`). Emitted when the
    /// gate finds it (no ledger entry) and for each refused call.
    #[serde(rename = "tool.drift")]
    ToolDrift,
    /// Reserved: anchoring the ledger head failed.
    #[serde(rename = "anchor.failed")]
    AnchorFailed,
}

impl EventKind {
    /// The stable name (`decision.deny`, ...).
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::DecisionDeny => "decision.deny",
            EventKind::ApprovalRequested => "approval.requested",
            EventKind::ApprovalMismatch => "approval.mismatch",
            EventKind::SideEffectUnknown => "side_effect.unknown",
            EventKind::SideEffectReplayed => "side_effect.replayed",
            EventKind::ShadowFinding => "shadow.finding",
            EventKind::ToolDrift => "tool.drift",
            EventKind::AnchorFailed => "anchor.failed",
        }
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One gate event. Every member is safe to send off the host: nothing in it
/// comes from a call's argument values or a tool's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateEvent {
    pub kind: EventKind,
    /// [`fingerprint`] of this event: the same failure, the same value.
    pub fingerprint: String,
    /// When (RFC 3339, UTC): the ledger entry's time when there is one.
    pub ts: String,
    /// The release name.
    pub release: Option<String>,
    /// The release manifest digest (`sha256:<hex>`).
    pub release_digest: Option<String>,
    /// The Cedar policy file's digest (`sha256:<hex>`), when the release has one.
    pub policy_version: Option<String>,
    /// The tool, when the call named one the ledger may record.
    pub tool: Option<String>,
    /// The upstream server the event is about (`tool.drift`).
    pub server: Option<String>,
    /// The reason code (`undeclared_tool`, `scope_mismatch`, ...): the rule id.
    pub reason: String,
    /// The contract path of an argument denial (from the contract, never the call).
    pub path: Option<String>,
    pub decision: Option<Decision>,
    pub mode: Option<Mode>,
    pub operation_id: Option<String>,
    /// The decision ledger entry this event follows (`None` without a ledger,
    /// or when the entry could not be written).
    pub ledger_seq: Option<u64>,
    pub entry_hash: Option<String>,
}

impl GateEvent {
    /// An event with its fingerprint computed from `kind`, `reason`, `tool`,
    /// `path` and `policy_version`; every other member is unset (`ts` now).
    pub fn new(kind: EventKind, reason: &str, tool: Option<&str>, path: Option<&str>, policy_version: Option<&str>) -> Self {
        Self {
            kind,
            fingerprint: fingerprint(kind, reason, tool, path, policy_version),
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            release: None,
            release_digest: None,
            policy_version: policy_version.map(str::to_string),
            tool: tool.map(str::to_string),
            server: None,
            reason: reason.to_string(),
            path: path.map(str::to_string),
            decision: None,
            mode: None,
            operation_id: None,
            ledger_seq: None,
            entry_hash: None,
        }
    }

    /// The event about upstream `server`: its fingerprint's tool component
    /// becomes `<server>/<tool>`, so the same tool on two servers is two
    /// issues.
    pub fn with_server(mut self, server: &str) -> Self {
        let tool = format!("{server}/{}", self.tool.as_deref().unwrap_or(""));
        self.fingerprint = fingerprint(self.kind, &self.reason, Some(&tool), self.path.as_deref(), self.policy_version.as_deref());
        self.server = Some(server.to_string());
        self
    }

    /// The stable wire form (`"schema": "cloakpipe.event/v1"`): every member
    /// above under its own name, unset ones as `null`.
    pub fn to_json(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Value::Object(map) = &mut v {
            map.insert("schema".into(), Value::String(EVENT_SCHEMA.into()));
        }
        v
    }
}

/// The deterministic fingerprint of an event: `"sha256:<hex>"` of
///
/// ```text
/// kind | reason | tool | path | policy_version
/// ```
///
/// (the five strings joined with `|`, an absent one as the empty string;
/// for an event about an upstream server, `tool` is `<server>/<tool>`:
/// [`GateEvent::with_server`]).
/// The same failure (rule, tool, contract path, policy) gets the same
/// fingerprint across runs and gates, so an alerting pipeline can group
/// repeats into one issue; a change of policy is a new issue. It holds no
/// argument value, the time, or anything else that varies per call.
pub fn fingerprint(kind: EventKind, reason: &str, tool: Option<&str>, path: Option<&str>, policy_version: Option<&str>) -> String {
    let mut h = Sha256::new();
    let parts = [kind.as_str(), reason, tool.unwrap_or(""), path.unwrap_or(""), policy_version.unwrap_or("")];
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b"|");
        }
        h.update(part.as_bytes());
    }
    let digest: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{digest}")
}

/// Where gate events go. [`emit`](Self::emit) runs on the decision path:
/// it must not block (queue and deliver asynchronously) and must not panic.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &GateEvent);
}

/// A sink that drops every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _event: &GateEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: Option<&str> = Some("sha256:0f0f");

    #[test]
    fn fingerprint_is_stable() {
        let a = fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("to"), POLICY);
        let b = fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("to"), POLICY);
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:") && a.len() == 7 + 64, "{a}");
        // sha256("decision.deny|scope_mismatch|send_email|to|sha256:0f0f"), pinned.
        let expected = format!("sha256:{}", hex(&Sha256::digest(b"decision.deny|scope_mismatch|send_email|to|sha256:0f0f")));
        assert_eq!(a, expected);
        let none = fingerprint(EventKind::DecisionDeny, "undeclared_tool", None, None, None);
        assert_eq!(none, format!("sha256:{}", hex(&Sha256::digest(b"decision.deny|undeclared_tool|||"))));
    }

    #[test]
    fn fingerprint_tells_failures_apart() {
        let base = fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("to"), POLICY);
        let others = [
            fingerprint(EventKind::ShadowFinding, "scope_mismatch", Some("send_email"), Some("to"), POLICY),
            fingerprint(EventKind::DecisionDeny, "argument_invalid", Some("send_email"), Some("to"), POLICY),
            fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("refund"), Some("to"), POLICY),
            fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("cc"), POLICY),
            fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), None, POLICY),
            fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("to"), Some("sha256:1111")),
            fingerprint(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("to"), None),
        ];
        for (i, other) in others.iter().enumerate() {
            assert_ne!(&base, other, "variant {i}");
        }
        let unique: std::collections::BTreeSet<_> = others.iter().collect();
        assert_eq!(unique.len(), others.len());
    }

    #[test]
    fn the_wire_form_names_its_schema() {
        let mut e = GateEvent::new(EventKind::ApprovalRequested, "approval_required", Some("crm.patch"), None, None);
        e.decision = Some(Decision::RequireApproval);
        e.mode = Some(Mode::Enforce);
        e.ledger_seq = Some(3);
        let v = e.to_json();
        assert_eq!(v["schema"], EVENT_SCHEMA);
        assert_eq!(v["kind"], "approval.requested");
        assert_eq!(v["decision"], "require_approval");
        assert_eq!(v["mode"], "enforce");
        assert_eq!(v["ledger_seq"], 3);
        assert_eq!(v["fingerprint"], e.fingerprint);
        assert_eq!(v["path"], Value::Null);
        for member in ["ts", "release", "release_digest", "policy_version", "tool", "server", "reason", "operation_id", "entry_hash"] {
            assert!(v.get(member).is_some(), "{member} missing: {v}");
        }
    }

    #[test]
    fn a_drift_fingerprint_names_the_server() {
        let e = GateEvent::new(EventKind::ToolDrift, "tool_drift", Some("send"), None, POLICY).with_server("mail");
        assert_eq!(e.server.as_deref(), Some("mail"));
        assert_eq!(e.tool.as_deref(), Some("send"));
        assert_eq!(e.fingerprint, fingerprint(EventKind::ToolDrift, "tool_drift", Some("mail/send"), None, POLICY));
        let other = GateEvent::new(EventKind::ToolDrift, "tool_drift", Some("send"), None, POLICY).with_server("files");
        assert_ne!(e.fingerprint, other.fingerprint);
        assert_eq!(e.to_json()["server"], "mail");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
