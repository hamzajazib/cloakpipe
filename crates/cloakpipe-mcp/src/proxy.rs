//! Transparent MCP interceptor.
//!
//! Sits between an MCP client (the agent) and an upstream MCP server, speaking
//! MCP's newline-delimited JSON-RPC in both directions. By default it forwards
//! what the agent sent: the gate allows or refuses a call, and never rewrites
//! an allowed one.
//!
//! With the opt-in PII transform ([`ProxyContext::pii`], `mcp-proxy
//! --transform pii`):
//!
//!   agent ──stdin──▶ [ mask tools/call args ] ──▶ upstream stdin
//!   agent ◀─stdout── [ rehydrate result tokens ] ◀── upstream stdout
//!
//! so PII never reaches the (possibly external) tool, and pseudonym tokens the
//! tool echoes back are restored before the agent sees them. Every masked
//! call and every result then appends a no-PII evidence-ledger hop
//! (`McpToolCall` / `McpToolResult`) — categories + counts only, never the text.
//!
//! With a gate, every decision appends one signed decision entry
//! ([`cloakpipe_ledger::decision`]) to the [`DecisionLog`]: each `tools/call`
//! (allowed, refused, approval-gated, replayed), each message refused
//! unread, and each side-effect outcome (`committed` / `failed` /
//! `unknown`). An entry is written before its call is forwarded or
//! answered; if it cannot be written, the call is refused as `fail_closed`
//! and never reaches the tool.
//!
//! The decisions live in a transport-agnostic [`Interceptor`]: a transport
//! hands it each message from the agent and from an upstream and carries
//! out the [`Action`]s it returns. [`run_proxy`] is the stdio transport, over
//! one upstream named [`DEFAULT_SERVER`].
//!
//! The pump is deliberately synchronous std I/O on two OS threads: all the work
//! (detect / mask / rehydrate / ledger append) is blocking anyway, and async
//! stdio (`tokio::io::stdin`) both buffers stdout unhelpfully and blocks runtime
//! shutdown on its background read thread.

use anyhow::{Context, Result};
use cloakpipe_core::{detector::Detector, rehydrator::Rehydrator, replacer::Replacer, vault::Vault};
use cloakpipe_ledger::decision::{Decision, DecisionDraft, DecisionEntry, Event, Mode, Outcome};
use cloakpipe_ledger::{
    record::Identity, store::LedgerStore, Action as HopAction, ActionKind, Detection, GateKey, Hop, MetadataValue, RecordBuilder,
};
use cloakpipe_release::action::fingerprint;
use cloakpipe_release::ReleaseHash;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::events::{DecisionRecord, EventKind, EventSink, GateEvent};
use crate::gate::{Denial, GateMode, OperationKey, ToolGate};
use crate::operations::{Begin, OperationState, OperationStore, ReconcileError};

/// The opt-in PII transform (`mcp-proxy --transform pii`): tool-call
/// arguments are pseudonymized through `vault` before the tool sees them,
/// and tokens in results are rehydrated before the agent does.
pub struct PiiTransform {
    pub detector: Detector,
    pub vault: Vault,
}

/// Everything the interceptor needs beyond the upstream command.
pub struct ProxyContext {
    /// The PII transform; `None` (the default) forwards arguments and
    /// results unchanged and needs no vault.
    pub pii: Option<PiiTransform>,
    /// Ledger DB path for the PII transform's hop records; `None` disables
    /// them. Gate decisions go to [`Self::decisions`].
    pub ledger_db: Option<String>,
    /// Agent Release manifest hash (`CLOAKPIPE_RELEASE`) every ledger hop is
    /// bound to; `None` records unbound hops.
    pub release: Option<[u8; 32]>,
    /// Phase C tool gate: when set, each `tools/call` must pass
    /// [`ToolGate::check`]. Refused calls (enforce mode) never reach the
    /// upstream; the agent gets a JSON-RPC error instead.
    pub gate: Option<ToolGate>,
    /// Where the gate's decisions are recorded, signed. `None`: they are
    /// not recorded (`mcp-proxy --no-ledger`).
    pub decisions: Option<DecisionLog>,
    /// Where gate events go ([`crate::events`]): each sink gets every
    /// event, after its ledger entry is written. Empty: none are emitted.
    pub events: Vec<Arc<dyn EventSink>>,
}

/// The gate's decision ledger: the ledger database the entries are
/// appended to and the gate signing key that signs each one.
pub struct DecisionLog {
    store: LedgerStore,
    key: GateKey,
}

impl DecisionLog {
    /// Open (or create) the ledger at `path`.
    pub fn open(path: &str, key: GateKey) -> Result<Self> {
        let store = LedgerStore::open(path).with_context(|| format!("ledger {path}"))?;
        Ok(Self { store, key })
    }

    /// The signing key.
    pub fn key(&self) -> &GateKey {
        &self.key
    }

    /// Append `draft`, with the call's raw fingerprint (operator state)
    /// recorded in its keyed form only.
    pub fn append(&mut self, mut draft: DecisionDraft, raw_fingerprint: Option<&[u8; 32]>) -> Result<DecisionEntry> {
        if let Some(fp) = raw_fingerprint {
            draft.args_fingerprint = Some(self.key.args_fingerprint(fp));
        }
        Ok(self.store.append_decision(draft, &self.key)?)
    }
}

/// JSON-RPC error code for a tool call the gate refused (server-defined range).
pub const TOOL_REFUSED: i64 = -32001;

/// JSON-RPC error code for a side-effecting call whose earlier attempt has
/// no settled outcome (`reconcile_before_retry`, `operation_unknown`): an
/// operator must reconcile the operation before it may run again.
pub const RECONCILE_REQUIRED: i64 = -32002;

/// JSON-RPC error code of a request the upstream never answered because
/// its transport failed (connection refused, HTTP error, a stream that
/// ended without the reply): the call fails closed, `data.reason` is
/// `upstream_unavailable`.
pub const UPSTREAM_UNAVAILABLE: i64 = -32003;

type SharedLedger = Option<Arc<Mutex<LedgerStore>>>;
/// The PII transform as both pump threads share it.
type SharedPii = Option<Arc<(Detector, Mutex<Vault>)>>;
type SharedOperations = Option<Arc<Mutex<OperationStore>>>;
type SharedDecisions = Option<Arc<Mutex<DecisionLog>>>;

/// A side-effecting call forwarded and not yet answered.
#[derive(Debug, Clone)]
struct InFlight {
    operation_id: String,
    tool: String,
    /// The call's raw fingerprint (recorded keyed only).
    fingerprint: [u8; 32],
}

/// Side-effecting calls forwarded and not yet answered.
#[derive(Default)]
struct PendingOps {
    /// JSON-RPC request id (serialized) -> the operation.
    by_request: HashMap<String, InFlight>,
    /// Other agent requests forwarded and not yet answered: request id
    /// (serialized) -> how many. A side-effecting call may not reuse one of
    /// these ids, nor any request reuse the id of a call in `by_request`, so
    /// a reply always maps to the request it answers.
    outstanding: HashMap<String, usize>,
    /// Set by the exit sweep: no call may start after it.
    closed: bool,
}
type Pending = Arc<Mutex<PendingOps>>;

/// What the coordinator decided for a side-effecting call.
enum Coordinated {
    /// Forward it; the operation is in flight under this request id.
    Forward,
    /// Answer with this (stored, rehydrated) result instead of forwarding.
    Replay(Value),
    /// Refuse it.
    Deny(Denial),
}

/// The server name of the single upstream `run_proxy` wraps (`mcp-proxy
/// --upstream`).
pub const DEFAULT_SERVER: &str = "default";

/// One upstream MCP server the gate fronts, by name.
///
/// Extension point: today the interceptor routes every message to
/// [`DEFAULT_SERVER`]. More servers (routing `tools/call` by the tool's
/// owner) are a routing rule in [`Interceptor::route`]; other transports
/// are new [`UpstreamTransport`] variants. The decision logic does not
/// change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The name actions address it by ([`Action::ToUpstream`]).
    pub name: String,
    pub transport: UpstreamTransport,
}

/// How the gate reaches an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamTransport {
    /// A child process speaking newline-delimited JSON-RPC on stdin/stdout.
    Stdio { command: Vec<String> },
    /// An MCP server over Streamable HTTP ([`crate::http`]): each message is
    /// POSTed to `url` with `headers`, the replies come back as JSON or SSE.
    Http { url: String, headers: Vec<(String, String)> },
}

impl Upstream {
    /// A stdio upstream: `command` is the program and its arguments.
    pub fn stdio(name: impl Into<String>, command: Vec<String>) -> Self {
        Self { name: name.into(), transport: UpstreamTransport::Stdio { command } }
    }

    /// A Streamable HTTP upstream at `url`; `headers` go on every request.
    pub fn http(name: impl Into<String>, url: impl Into<String>, headers: Vec<(String, String)>) -> Self {
        Self { name: name.into(), transport: UpstreamTransport::Http { url: url.into(), headers } }
    }
}

/// What the interceptor wants sent, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// One JSON-RPC message (a single line) for the agent.
    ToAgent(String),
    /// One message (a single line) for the named upstream server.
    ToUpstream { server: String, message: String },
}

/// The gate as a transport-agnostic message filter: a transport feeds it
/// each message from the agent ([`Self::on_agent_line`]) and from an
/// upstream ([`Self::on_upstream_line`]) and carries out the [`Action`]s it
/// returns, in order. All decisions (screening, request-id bookkeeping,
/// authorization, shadow mode, counters, side-effect operations and
/// replay, ledger entries, the PII transform, settling results) live here.
///
/// Agent messages are decided one at a time, in the order they are given:
/// a transport delivering several agent messages at once is serialized.
/// Upstream messages may be given concurrently with agent ones.
pub struct Interceptor {
    /// The gate; held while one agent message is decided.
    gate: Mutex<Option<ToolGate>>,
    base: Option<EntryBase>,
    pii: SharedPii,
    ledger: SharedLedger,
    operations: SharedOperations,
    decisions: SharedDecisions,
    pending: Pending,
    tenant: uuid::Uuid,
    agent: uuid::Uuid,
    release: Option<[u8; 32]>,
    events: Vec<Arc<dyn EventSink>>,
}

impl Interceptor {
    /// Check the gate can run and record what a previous process left: a
    /// side-effecting call it left in flight is now `unknown` (recorded
    /// before anything runs; a gate that cannot record does not start).
    pub fn new(ctx: ProxyContext) -> Result<Self> {
        if let Some(gate) = &ctx.gate {
            // A side-effect tool without an operations store must not run.
            gate.ready()?;
            if ctx.pii.is_none() {
                refuse_masked_results(gate)?;
            }
        }

        let decisions: SharedDecisions = ctx.decisions.map(|d| Arc::new(Mutex::new(d)));
        let gate = ctx.gate;
        let base = gate.as_ref().map(EntryBase::of);
        let operations: SharedOperations = gate.as_ref().and_then(ToolGate::operations);
        // Evidence for the start-up sweep: operations a previous process left in
        // flight are now unknown. Recorded before anything runs: a gate that
        // cannot record does not start.
        if let (Some(gate), Some(base)) = (&gate, &base) {
            for op in gate.recovered_operations() {
                let row = operations.as_ref().and_then(|s| s.lock().ok()).and_then(|s| s.get(op).ok().flatten());
                let in_flight = InFlight {
                    operation_id: op.clone(),
                    tool: row.as_ref().map(|r| r.tool.clone()).unwrap_or_default(),
                    fingerprint: row.as_ref().map(|r| r.call_digest).unwrap_or_default(),
                };
                let draft = base.outcome(&in_flight, Outcome::Unknown);
                let entry = record_decision(&decisions, draft.clone(), Some(&in_flight.fingerprint))
                    .map_err(|e| anyhow::anyhow!("the decision ledger cannot be written ({e}); refusing to start"))?;
                emit(&ctx.events, base, EventKind::SideEffectUnknown, UNKNOWN, &draft, entry.as_ref());
            }
        }

        let (tenant, agent) = stable_ids();
        Ok(Self {
            gate: Mutex::new(gate),
            base,
            pii: ctx.pii.map(|p| Arc::new((p.detector, Mutex::new(p.vault)))),
            ledger: ctx.ledger_db.as_deref().and_then(open_ledger),
            operations,
            decisions,
            pending: Arc::new(Mutex::new(PendingOps::default())),
            tenant,
            agent,
            release: ctx.release,
            events: ctx.events,
        })
    }

    /// The upstream server a message from the agent goes to. Extension
    /// point for more than one upstream; today, always [`DEFAULT_SERVER`].
    pub fn route(&self, _msg: &Value) -> &str {
        DEFAULT_SERVER
    }

    /// Decide one message from the agent (a line of JSON-RPC): forward it
    /// (as re-serialized here, or verbatim when it is not JSON and there is
    /// no gate), answer it, or refuse it.
    pub fn on_agent_line(&self, line: &str) -> Vec<Action> {
        let received = unix_nanos();
        // One agent message at a time: request ids are only registered here,
        // and `coordinate` relies on no other agent message racing it.
        let guard = match self.gate.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let gate = guard.as_ref();
        let (decisions, operations, pending, pii, ledger) = (&self.decisions, &self.operations, &self.pending, &self.pii, &self.ledger);
        let (tenant, agent, release) = (self.tenant, self.agent, self.release);
        // With a gate, only a message the gate can read in full is
        // forwarded — as re-serialized here, never the raw line.
        if let (Some(gate), Some(base)) = (gate, &self.base) {
            if let Err((reason, code)) = screen(line) {
                let draft = DecisionDraft { decision: Decision::Deny, reason: reason.to_string(), ..base.call(None) };
                let (reason, entry) = match record_decision(decisions, draft.clone(), None) {
                    Ok(entry) => (reason, entry),
                    Err(_) => (FAIL_CLOSED, None),
                };
                let event = emit(&self.events, base, EventKind::DecisionDeny, reason, &draft, entry.as_ref());
                report(&self.events, base, received, &draft, reason, entry.as_ref(), event.as_ref());
                let refusal = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": code,
                        "message": format!("message refused by CloakPipe: {reason}"),
                        "data": { "reason": reason, "release": gate.release() },
                    },
                });
                return vec![Action::ToAgent(refusal.to_string())];
            }
        }
        let mut server = DEFAULT_SERVER.to_string();
        let out = match serde_json::from_str::<Value>(line) {
            Ok(mut msg) => {
                server = self.route(&msg).to_string();
                // An agent request (any method) reusing the id of a
                // side-effecting call in flight: its reply would be
                // taken for the call's and settle the operation.
                let request_id = msg.get("method").and(msg.get("id")).filter(|id| !id.is_null()).map(Value::to_string);
                if let (Some(gate), Some(base), Some(_), Some(request)) = (gate, &self.base, operations, &request_id) {
                    let in_use = pending.lock().map(|p| p.by_request.contains_key(request)).unwrap_or(true);
                    if in_use {
                        let code = Denial::RequestIdInUse.code();
                        let draft = DecisionDraft { decision: Decision::Deny, reason: code.clone(), ..base.call(None) };
                        let (code, entry) = match record_decision(decisions, draft.clone(), None) {
                            Ok(entry) => (code, entry),
                            Err(_) => (FAIL_CLOSED.to_string(), None),
                        };
                        let event = emit(&self.events, base, EventKind::DecisionDeny, &code, &draft, entry.as_ref());
                        report(&self.events, base, received, &draft, &code, entry.as_ref(), event.as_ref());
                        let refusal = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": TOOL_REFUSED,
                                "message": format!("message refused by CloakPipe: {code}"),
                                "data": { "reason": code, "release": gate.release() },
                            },
                        });
                        return vec![Action::ToAgent(refusal.to_string())];
                    }
                }
                if msg.get("method").and_then(Value::as_str) == Some("tools/call") {
                    if let (Some(gate), Some(base)) = (gate, &self.base) {
                        let tool = msg.pointer("/params/name").and_then(Value::as_str).unwrap_or("").to_string();
                        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        // The raw arguments, as the agent sent them: the PII
                        // transform runs only after the gate has passed the call.
                        let arguments = msg.pointer("/params/arguments");
                        // The call's fingerprint, recorded keyed only.
                        let raw_fingerprint = call_fingerprint(gate, &tool, arguments);
                        // A refusal, and whether it holds in shadow mode too.
                        let mut refusal: Option<(Denial, bool)> = None;
                        let mut replay: Option<(Value, String)> = None;
                        // The operation this call is, if it is side-effecting.
                        let mut operation = None;
                        let mut approval = None;
                        match gate.authorize(&tool, arguments, &now) {
                            Ok(auth) => {
                                approval = auth.approval;
                                operation = auth.operation;
                            }
                            Err(denial) => {
                                // Shadow mode forwards it: a side-effecting call is
                                // still an operation (tracking is not a release rule).
                                if gate.mode == GateMode::Shadow {
                                    match gate.operation(&tool, arguments, &now) {
                                        Ok(op) => operation = op,
                                        Err(d) => refusal = Some((d, true)),
                                    }
                                }
                                refusal = refusal.or(Some((denial, false)));
                            }
                        }
                        let mut forwarding = match &refusal {
                            None => true,
                            Some((_, always)) => !always && gate.mode == GateMode::Shadow,
                        };
                        // Count the call for the policy's counters before it
                        // is forwarded: an uncounted call could slip past a
                        // rate limit, so a counter failure refuses it.
                        let mut counted = None;
                        if forwarding {
                            match gate.record_forwarded(&tool, &now) {
                                Ok(id) => counted = id,
                                Err(d) => {
                                    refusal = Some((d, true));
                                    forwarding = false;
                                }
                            }
                        }
                        // The operation forwarded (in flight under this
                        // request), to undo should its entry not be written.
                        let mut started: Option<String> = None;
                        if let Some(op) = operation.as_ref().filter(|_| forwarding) {
                            // Exactly-once bookkeeping is not a release rule:
                            // it holds in shadow mode too.
                            match coordinate(operations, pending, pii, msg.get("id"), &tool, op) {
                                Coordinated::Forward => started = msg.get("id").map(Value::to_string),
                                Coordinated::Replay(result) => replay = Some((result, op.operation_id.clone())),
                                Coordinated::Deny(d) => refusal = Some((d, true)),
                            }
                        }
                        // Answered from the store or refused by it: not forwarded.
                        if replay.is_some() || matches!(refusal, Some((_, true))) {
                            if let Some(id) = counted.take() {
                                gate.forget_forwarded(id);
                            }
                        }
                        let enforced = refusal.as_ref().is_some_and(|(_, always)| *always || gate.mode == GateMode::Enforce);
                        // The entry: what the gate decided (in shadow mode,
                        // what enforce mode would have).
                        let mut draft = base.call(recordable_tool(gate, &tool));
                        if let Some((denial, _)) = &refusal {
                            draft.decision = match denial {
                                Denial::ApprovalRequired => Decision::RequireApproval,
                                _ => Decision::Deny,
                            };
                            draft.reason = denial.code();
                            // A contract path comes from the contract, never
                            // from the call, so it is safe to record.
                            draft.path = denial.path().map(str::to_string);
                            draft.operation_id = denial.operation_id().map(str::to_string);
                        }
                        if let Some(a) = &approval {
                            // The receipt's digest, never the call fingerprint.
                            draft.approval = Some(format!("sha256:{}", hex(&a.receipt_digest)));
                        }
                        if draft.operation_id.is_none() {
                            draft.operation_id = operation
                                .as_ref()
                                .map(|o| o.operation_id.clone())
                                .or_else(|| approval.as_ref().map(|a| a.operation_id.clone()));
                        }
                        if replay.is_some() {
                            draft.event = Event::Replay;
                            draft.outcome = Some(Outcome::Committed);
                        } else {
                            draft.forwarded = !enforced;
                        }
                        let recorded = record_decision(decisions, draft.clone(), raw_fingerprint.as_ref());
                        // What deserves an event: anything but a plain allow.
                        let kind = match (&refusal, &replay, &recorded) {
                            (_, _, Err(_)) => Some(EventKind::DecisionDeny),
                            (_, Some(_), _) => Some(EventKind::SideEffectReplayed),
                            (Some(_), _, _) if !enforced => Some(EventKind::ShadowFinding),
                            (Some((Denial::ApprovalRequired, _)), _, _) => Some(EventKind::ApprovalRequested),
                            (Some((Denial::ApprovalInvalid, _)), _, _) => Some(EventKind::ApprovalMismatch),
                            (Some(_), _, _) => Some(EventKind::DecisionDeny),
                            (None, None, Ok(_)) => None,
                        };
                        let entry = recorded.as_ref().ok().and_then(Option::as_ref);
                        let event = kind.and_then(|kind| {
                            let reason = match (&recorded, kind) {
                                (Err(_), _) => FAIL_CLOSED,
                                (Ok(_), EventKind::SideEffectReplayed) => REPLAYED,
                                (Ok(_), _) => draft.reason.as_str(),
                            };
                            emit(&self.events, base, kind, reason, &draft, entry)
                        });
                        // Every tools/call decision, allows included (for
                        // tracing). Unrecorded, it was refused.
                        match &recorded {
                            Ok(_) => report(&self.events, base, received, &draft, &draft.reason, entry, event.as_ref()),
                            Err(_) => {
                                let refused = DecisionDraft { decision: Decision::Deny, forwarded: false, ..draft.clone() };
                                report(&self.events, base, received, &refused, FAIL_CLOSED, None, event.as_ref());
                            }
                        }
                        if recorded.is_err() {
                            // No record, no call: undo the operation's start
                            // (it was never sent) and refuse.
                            if let Some(id) = counted.take() {
                                gate.forget_forwarded(id);
                            }
                            if let Some(request) = started {
                                unstart(operations, pending, &request);
                            }
                            return match msg.get("id") {
                                Some(id) => {
                                    let reply = refusal_message(id, FAIL_CLOSED, &tool, gate, None, None, TOOL_REFUSED);
                                    vec![Action::ToAgent(reply.to_string())]
                                }
                                None => Vec::new(),
                            };
                        }
                        if let Some((result, operation_id)) = replay {
                            // Already done: answer with the stored result and
                            // never run the effect again.
                            if pii.is_some() {
                                let mut meta = operation_meta(OperationState::Done, &operation_id);
                                meta.push(("operation_replayed", MetadataValue::Bool(true)));
                                record_hop(ledger, tenant, agent, release, Hop::McpToolResult, 0, ActionKind::Pseudonymize, &meta);
                            }
                            return match msg.get("id") {
                                Some(id) => {
                                    let reply = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result });
                                    vec![Action::ToAgent(reply.to_string())]
                                }
                                None => Vec::new(),
                            };
                        }
                        if let Some((denial, _)) = refusal {
                            let code = denial.code();
                            if enforced {
                                // A notification (no id member) takes no response;
                                // `"id": null` is a request and is answered.
                                let Some(id) = msg.get("id") else { return Vec::new() };
                                let rpc_code = match denial {
                                    Denial::ReconcileBeforeRetry { .. } => RECONCILE_REQUIRED,
                                    _ => TOOL_REFUSED,
                                };
                                let mut reply = refusal_message(id, &code, &tool, gate, denial.path(), denial.operation_id(), rpc_code);
                                let data = &mut reply["error"]["data"];
                                // Policy ids come from the policy file, never the call.
                                if let Some(policies) = denial.policies() {
                                    data["policies"] = serde_json::json!(policies);
                                }
                                // What an approval broker needs to route the
                                // request: the manifest's approver routes and
                                // the exact call a receipt must cover. Sent to
                                // the agent only, never to the ledger.
                                if denial == Denial::ApprovalRequired {
                                    if let Some(req) = gate.approval_request(&tool, arguments) {
                                        data["approvers"] = serde_json::json!(req.approvers);
                                        data["fingerprint"] = Value::String(req.fingerprint);
                                    }
                                }
                                return vec![Action::ToAgent(reply.to_string())];
                            }
                            tracing::warn!(reason = %code, "MCP tool call fails the release gate (shadow mode: forwarded)");
                        }
                    }
                    // Only the opt-in PII transform rewrites an allowed call.
                    if let Some(pii) = pii {
                        let (detector, vault) = &**pii;
                        let mut v = vault.lock().expect("vault poisoned");
                        let masked = mask_value(msg.pointer_mut("/params/arguments"), detector, &mut v);
                        if masked > 0 {
                            record_hop(ledger, tenant, agent, release, Hop::McpToolCall, masked, ActionKind::Pseudonymize, &[]);
                        }
                    }
                }
                // Every other forwarded request is outstanding until
                // answered (a side-effecting call is in `by_request`).
                if let (Some(_), Some(request)) = (operations, request_id) {
                    if let Ok(mut p) = pending.lock() {
                        if !p.by_request.contains_key(&request) {
                            *p.outstanding.entry(request).or_default() += 1;
                        }
                    }
                }
                serde_json::to_string(&msg).unwrap_or_else(|_| line.to_string())
            }
            Err(_) => line.to_string(), // not JSON — forward verbatim
        };
        vec![Action::ToUpstream { server, message: out }]
    }

    /// One message (a line of JSON-RPC) from upstream `server` for the
    /// agent: the reply to a side-effecting call settles its operation
    /// first, and under the PII transform result tokens are rehydrated.
    pub fn on_upstream_line(&self, server: &str, line: &str) -> Vec<Action> {
        // One upstream today: replies are matched by request id alone.
        debug_assert_eq!(server, DEFAULT_SERVER);
        let (pii, ledger) = (&self.pii, &self.ledger);
        let (tenant, agent, release) = (self.tenant, self.agent, self.release);
        let out = match serde_json::from_str::<Value>(line) {
            Ok(mut msg) => {
                // The reply to a side-effecting call settles its operation
                // before the agent sees it.
                let settled = settle_reply(&self.operations, &self.pending, &msg, pii.is_some());
                let kind = match pii {
                    Some(pii) => {
                        if msg.pointer("/result/content").is_some() {
                            let v = pii.1.lock().expect("vault poisoned");
                            rehydrate_value(msg.pointer_mut("/result/content"), &v);
                        }
                        ActionKind::Pseudonymize
                    }
                    None => ActionKind::Passthrough,
                };
                if let (Some((op, state)), Some(base)) = (&settled, &self.base) {
                    let outcome = if *state == OperationState::Done { Outcome::Committed } else { Outcome::Failed };
                    // The call already ran: a lost record cannot undo it.
                    if let Err(e) = record_outcome(&self.decisions, base, op, outcome) {
                        tracing::warn!("decision ledger: outcome of {} not recorded: {e}", op.operation_id);
                    }
                }
                if pii.is_some() {
                    if let Some((op, state)) = &settled {
                        record_hop(ledger, tenant, agent, release, Hop::McpToolResult, 0, kind, &operation_meta(*state, &op.operation_id));
                    } else if msg.pointer("/result/content").is_some() {
                        record_hop(ledger, tenant, agent, release, Hop::McpToolResult, 0, kind, &[]);
                    }
                }
                serde_json::to_string(&msg).unwrap_or_else(|_| line.to_string())
            }
            Err(_) => line.to_string(),
        };
        vec![Action::ToAgent(out)]
    }

    /// The upstreams are gone: no call may start any more. A side-effecting
    /// call still in flight never got its reply; the tool may or may not
    /// have acted, so its operation is unknown until an operator reconciles
    /// it, and the agent is told so (the returned actions). Then the
    /// operations database is given up.
    pub fn finish(&self) -> Vec<Action> {
        let mut actions = Vec::new();
        let abandoned: Vec<(String, InFlight)> = match self.pending.lock() {
            Ok(mut p) => {
                p.closed = true;
                p.by_request.drain().collect()
            }
            Err(_) => Vec::new(),
        };
        for (request, in_flight) in abandoned {
            actions.push(self.abandon(&request, in_flight));
        }
        // The gate has stopped: give the operations database up now, even if
        // the agent side (still parked on the agent's stdin) holds the store.
        if let Some(Ok(mut s)) = self.operations.as_ref().map(|s| s.lock()) {
            s.release_gate();
        }
        actions
    }

    /// A side-effecting call that will never get its reply (the upstream
    /// went away, or its transport failed after the call was sent): the tool
    /// may or may not have acted, so its operation is `unknown` until an
    /// operator reconciles it. Records that and answers the agent.
    fn abandon(&self, request: &str, in_flight: InFlight) -> Action {
        let operation_id = in_flight.operation_id.clone();
        // Only a row this sweep changed is evidence of `unknown`. An
        // operation an operator reconciled meanwhile keeps its verdict and
        // gets no `unknown` hop, but its request is still answered (an MCP
        // client must never wait forever), with the reconciled state. A row
        // the store could not write stays in flight (a restart sweeps and
        // records it); its outcome is still unknown to the agent.
        let swept = match self.operations.as_ref().map(|s| s.lock()) {
            Some(Ok(mut s)) => match s.settle(&operation_id, OperationState::Unknown, None) {
                Ok(true) => Ok(None),
                Ok(false) => s.get(&operation_id).map(|row| row.map(|r| r.state)).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            },
            _ => Err("lock poisoned".to_string()),
        };
        let (reason, message, state) = match swept {
            Ok(Some(state)) => {
                tracing::info!("operations store: {operation_id} was reconciled meanwhile ({state}); left as is");
                ("operation_reconciled", format!("the tool server went away before answering; an operator reconciled this call as {state}"), Some(state))
            }
            Ok(None) => {
                if let Some(base) = &self.base {
                    let draft = base.outcome(&in_flight, Outcome::Unknown);
                    let entry = record_decision(&self.decisions, draft.clone(), Some(&in_flight.fingerprint)).unwrap_or_else(|e| {
                        tracing::warn!("decision ledger: unknown outcome of {operation_id} not recorded: {e}");
                        None
                    });
                    emit(&self.events, base, EventKind::SideEffectUnknown, UNKNOWN, &draft, entry.as_ref());
                }
                if self.pii.is_some() {
                    let meta = operation_meta(OperationState::Unknown, &operation_id);
                    record_hop(&self.ledger, self.tenant, self.agent, self.release, Hop::McpToolResult, 0, ActionKind::Pseudonymize, &meta);
                }
                ("operation_unknown", "the tool server went away before answering: the outcome of this call is unknown".to_string(), None)
            }
            Err(e) => {
                tracing::warn!("operations store: could not mark {operation_id} unknown ({e}); a restart will");
                ("operation_unknown", "the tool server went away before answering: the outcome of this call is unknown".to_string(), None)
            }
        };
        let id: Value = serde_json::from_str(request).unwrap_or(Value::Null);
        let mut data = serde_json::json!({ "reason": reason, "operationId": operation_id });
        if let Some(state) = state {
            data["state"] = Value::String(state.as_str().to_string());
        }
        let notice = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": RECONCILE_REQUIRED, "message": message, "data": data },
        });
        Action::ToAgent(notice.to_string())
    }

    /// The transport could not deliver `message` (one line this interceptor
    /// sent to upstream `server`) or never got its reply: connection
    /// refused, an HTTP error status, a stream that ended early. The request
    /// fails closed: a side-effecting call is abandoned as `unknown` (see
    /// [`Self::finish`]), any other request is answered with
    /// [`UPSTREAM_UNAVAILABLE`]. A notification takes no answer. `error` is
    /// logged, never sent to the agent.
    pub fn on_upstream_error(&self, server: &str, message: &str, error: &str) -> Vec<Action> {
        tracing::warn!(server, "upstream transport error: {error}");
        let Ok(msg) = serde_json::from_str::<Value>(message) else { return Vec::new() };
        let Some(id) = msg.get("method").and(msg.get("id")) else { return Vec::new() };
        let request = id.to_string();
        let in_flight = self.pending.lock().ok().and_then(|mut p| match p.by_request.remove(&request) {
            Some(op) => Some(op),
            None => {
                // No reply will come: it is no longer outstanding.
                if let Some(n) = p.outstanding.get_mut(&request) {
                    *n -= 1;
                    if *n == 0 {
                        p.outstanding.remove(&request);
                    }
                }
                None
            }
        });
        if let Some(in_flight) = in_flight {
            return vec![self.abandon(&request, in_flight)];
        }
        let reply = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": UPSTREAM_UNAVAILABLE,
                "message": "the upstream MCP server did not answer this request (transport error); it failed closed",
                "data": { "reason": "upstream_unavailable" },
            },
        });
        vec![Action::ToAgent(reply.to_string())]
    }
}

/// Run the interceptor: spawn `upstream` and pump JSON-RPC both ways. Returns
/// when the upstream exits (which happens when the agent closes stdin, or when
/// the upstream itself dies).
pub fn run_proxy(upstream: Vec<String>, ctx: ProxyContext) -> Result<()> {
    run_proxy_io(upstream, ctx, std::io::stdin(), std::io::stdout())
}

/// [`run_proxy`] with the agent side supplied by the caller instead of the
/// process's stdin/stdout, so the interceptor can be driven in-process.
pub fn run_proxy_io<R, W>(upstream: Vec<String>, ctx: ProxyContext, agent_in: R, agent_out: W) -> Result<()>
where
    R: std::io::Read + Send + 'static,
    W: Write + Send + 'static,
{
    run_upstream_io(Upstream::stdio(DEFAULT_SERVER, upstream), ctx, agent_in, agent_out)
}

/// The stdio runner: the agent on `agent_in`/`agent_out`, `upstream` a
/// child process (or an MCP server over HTTP, [`crate::http`]), and an
/// [`Interceptor`] between them.
pub fn run_upstream_io<R, W>(upstream: Upstream, ctx: ProxyContext, agent_in: R, agent_out: W) -> Result<()>
where
    R: std::io::Read + Send + 'static,
    W: Write + Send + 'static,
{
    let command = match &upstream.transport {
        UpstreamTransport::Stdio { command } => command,
        UpstreamTransport::Http { .. } => return crate::http::run_stdio_agent(&upstream, ctx, agent_in, agent_out),
    };
    anyhow::ensure!(!command.is_empty(), "upstream MCP command is empty");
    let sinks = ctx.events.clone();
    let interceptor = Arc::new(Interceptor::new(ctx)?);

    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // upstream logs pass through to our stderr
        .spawn()
        .with_context(|| format!("failed to spawn upstream MCP server: {command:?}"))?;

    let to_upstream = child.stdin.take().context("upstream has no stdin")?;
    let from_upstream = child.stdout.take().context("upstream has no stdout")?;
    // Both directions answer the agent: ingress relays upstream replies and
    // egress answers refused calls.
    let agent_out = Arc::new(Mutex::new(agent_out));

    // Egress: agent stdin → interceptor → upstream stdin (or the agent).
    {
        let interceptor = interceptor.clone();
        let agent_out = agent_out.clone();
        std::thread::spawn(move || {
            let mut to_upstream = to_upstream; // owned: dropped (→ upstream stdin EOF) when this thread ends
            for line in BufReader::new(agent_in).lines() {
                let Ok(line) = line else { break };
                let sent = interceptor.on_agent_line(&line).into_iter().all(|action| match action {
                    Action::ToAgent(reply) => write_line(&agent_out, &reply).is_ok(),
                    // The only upstream: every message is routed to it.
                    Action::ToUpstream { message, .. } => {
                        to_upstream.write_all(message.as_bytes()).is_ok()
                            && to_upstream.write_all(b"\n").is_ok()
                            && to_upstream.flush().is_ok()
                    }
                });
                if !sent {
                    break;
                }
            }
        });
    }

    // Ingress: upstream stdout → interceptor → agent stdout.
    let ingress = {
        let interceptor = interceptor.clone();
        let agent_out = agent_out.clone();
        let server = upstream.name.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(from_upstream).lines() {
                let Ok(line) = line else { break };
                let sent = interceptor.on_upstream_line(&server, &line).into_iter().all(|action| match action {
                    Action::ToAgent(out) => write_line(&agent_out, &out).is_ok(),
                    Action::ToUpstream { .. } => true,
                });
                if !sent {
                    break;
                }
            }
        })
    };

    // Wait for the upstream to exit — either because the agent closed stdin (the
    // egress thread ended and dropped the upstream's stdin) or because it died.
    let _ = child.wait();
    // Drain the last of the upstream's output so the final response reaches the
    // agent before we return. Egress may still be parked on stdin; the process
    // exiting cleans it up.
    let _ = ingress.join();

    // Exit sweep: side-effecting calls still in flight are unknown.
    for action in interceptor.finish() {
        if let Action::ToAgent(notice) = action {
            let _ = write_line(&agent_out, &notice);
        }
    }
    flush_events(&sinks, EVENT_FLUSH);
    Ok(())
}

/// How long a stopping proxy waits for its events to be delivered.
pub const EVENT_FLUSH: Duration = Duration::from_secs(5);

/// Give every sink until `timeout` (in all) to deliver what it holds; one
/// that cannot is reported on stderr and left behind.
pub fn flush_events(sinks: &[Arc<dyn EventSink>], timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    let mut left = 0;
    for sink in sinks {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if !sink.flush(remaining) {
            left += 1;
        }
    }
    if left > 0 {
        eprintln!("warning: cloakpipe: {left} event sink(s) still delivering after {}s; undelivered events are dropped", timeout.as_secs());
    }
}

/// Without the PII transform, refuse to run on an operations database that
/// holds masked results (stored under the transform, or by an earlier
/// version, which always masked): a retry would replay pseudonym tokens the
/// agent cannot read, and only the vault they came from can restore them.
fn refuse_masked_results(gate: &ToolGate) -> Result<()> {
    let Some(store) = gate.operations() else { return Ok(()) };
    let masked = store
        .lock()
        .map_err(|_| anyhow::anyhow!("operations store lock poisoned"))?
        .masked_results()?;
    if masked.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "the operations database holds {} completed operation(s) whose stored results are masked \
         (pseudonym tokens from the PII transform, which earlier versions always applied), e.g. {}. \
         A retry would replay them to the agent unreadable. Start with --transform pii and the \
         vault they were masked with (CLOAKPIPE_VAULT_KEY and the configured vault path) so \
         replays are rehydrated, or give this proxy a new --operations-db",
        masked.len(),
        masked[0]
    )
}

/// Run a side-effecting call through the operations store, in one
/// transaction: forward it (now `in_flight` under its request id), replay a
/// `done` operation's stored result, or refuse it.
fn coordinate(
    operations: &SharedOperations,
    pending: &Pending,
    pii: &SharedPii,
    id: Option<&Value>,
    tool: &str,
    op: &OperationKey,
) -> Coordinated {
    let Some(store) = operations else { return Coordinated::Deny(Denial::OperationsUnavailable) };
    // Without a request id the reply could never settle the operation.
    let Some(id) = id.filter(|id| !id.is_null()) else { return Coordinated::Deny(Denial::RequestIdMissing) };
    let request = id.to_string();
    // `pending` is never held across the store: `begin` may wait (up to the
    // busy timeout) for an operator's `operations reconcile`, and the reply
    // thread needs `pending` for every upstream reply. Checking the request
    // id, then deciding, then registering it is still race-free: request
    // ids are only added while the interceptor decides one agent message
    // (under its gate lock), and nothing is forwarded until this
    // returns, so no reply to this request can arrive in between. Only the
    // exit sweep can close `pending` meanwhile; that is checked again below.
    {
        let Ok(pending) = pending.lock() else { return Coordinated::Deny(Denial::OperationsUnavailable) };
        if pending.closed {
            return Coordinated::Deny(Denial::OperationsUnavailable);
        }
        if pending.by_request.contains_key(&request) || pending.outstanding.contains_key(&request) {
            return Coordinated::Deny(Denial::RequestIdInUse);
        }
    }
    let decision = match store.lock() {
        Ok(mut s) => s.begin(&op.operation_id, tool, &op.fingerprint.0),
        Err(_) => return Coordinated::Deny(Denial::OperationsUnavailable),
    };
    match decision {
        Ok(Begin::Forward) => {
            let registered = match pending.lock() {
                Ok(mut p) if !p.closed => {
                    let in_flight = InFlight { operation_id: op.operation_id.clone(), tool: tool.to_string(), fingerprint: op.fingerprint.0 };
                    p.by_request.insert(request, in_flight);
                    true
                }
                _ => false,
            };
            if registered {
                return Coordinated::Forward;
            }
            // The proxy is shutting down: the call is never forwarded, so it
            // certainly did not run and may be retried.
            if let Ok(mut s) = store.lock() {
                if let Err(e) = s.settle(&op.operation_id, OperationState::Failed, None) {
                    tracing::warn!("operations store: could not release unsent {} ({e}); a restart marks it unknown", op.operation_id);
                }
            }
            Coordinated::Deny(Denial::OperationsUnavailable)
        }
        Ok(Begin::Replay { result, masked }) => {
            // A masked result is replayed only through the vault (start-up
            // refuses a database holding one without the transform).
            let vault = match (masked, pii) {
                (false, _) => None,
                (true, Some(pii)) => Some(&pii.1),
                (true, None) => {
                    tracing::warn!("operations store: {} holds a masked result and no vault is configured; refused", op.operation_id);
                    return Coordinated::Deny(Denial::OperationsUnavailable);
                }
            };
            match replayed(result.as_deref(), &op.operation_id, vault) {
                Some(result) => Coordinated::Replay(result),
                None => Coordinated::Deny(Denial::OperationsUnavailable),
            }
        }
        Ok(Begin::Conflict) => Coordinated::Deny(Denial::OperationConflict { operation_id: op.operation_id.clone() }),
        Ok(Begin::ReconcileBeforeRetry(_)) => {
            Coordinated::Deny(Denial::ReconcileBeforeRetry { operation_id: op.operation_id.clone() })
        }
        Err(e) => {
            tracing::warn!("operations store: {e}; side-effecting call refused");
            Coordinated::Deny(Denial::OperationsUnavailable)
        }
    }
}

/// The answer for a retry of a `done` operation: its stored result (a masked
/// one rehydrated through `vault`, as the ingress path does), marked
/// `_meta.cloakpipe.replayed`.
/// An operation an operator reconciled as done has no stored result: the
/// agent is told it completed. `None`: the stored result is unreadable.
fn replayed(stored: Option<&str>, operation_id: &str, vault: Option<&Mutex<Vault>>) -> Option<Value> {
    let mut result = match stored {
        Some(stored) => serde_json::from_str::<Value>(stored).ok().filter(Value::is_object)?,
        None => serde_json::json!({
            "content": [{
                "type": "text",
                "text": format!("This call already completed (operation {operation_id}, reconciled by an operator); it was not run again."),
            }],
        }),
    };
    if let Some(vault) = vault.filter(|_| result.get("content").is_some()) {
        let v = vault.lock().ok()?;
        rehydrate_value(result.get_mut("content"), &v);
    }
    let meta = result.as_object_mut()?.entry("_meta").or_insert_with(|| serde_json::json!({}));
    let cloakpipe = meta.as_object_mut()?.entry("cloakpipe").or_insert_with(|| serde_json::json!({}));
    let cloakpipe = cloakpipe.as_object_mut()?;
    cloakpipe.insert("replayed".into(), Value::Bool(true));
    cloakpipe.insert("operationId".into(), Value::String(operation_id.to_string()));
    Some(result)
}

/// Settle the operation an upstream reply answers: a `result` without
/// `isError: true` is `done` (its result stored for replay; `masked`: under
/// the PII transform, so it holds pseudonym tokens); an
/// error result or a JSON-RPC `error` is `failed`. Returns the operation and
/// its new state, or `None` when the message answers no side-effecting call
/// or the store did not settle it (no longer `in_flight`, or unwritable).
/// Only a reply settles: a request or notification from the upstream
/// (`method`), or a message with neither `result` nor `error`, never does,
/// whatever its id.
fn settle_reply(operations: &SharedOperations, pending: &Pending, msg: &Value, masked: bool) -> Option<(InFlight, OperationState)> {
    let store = operations.as_ref()?;
    if msg.get("method").is_some() || (msg.get("result").is_none() && msg.get("error").is_none()) {
        return None;
    }
    let request = msg.get("id")?.to_string();
    // `pending` is released before the store write, which may wait on the
    // database.
    let in_flight = {
        let mut pending = pending.lock().ok()?;
        let Some(in_flight) = pending.by_request.remove(&request) else {
            // The reply to another request: it is no longer outstanding.
            if let Some(n) = pending.outstanding.get_mut(&request) {
                *n -= 1;
                if *n == 0 {
                    pending.outstanding.remove(&request);
                }
            }
            return None;
        };
        in_flight
    };
    let operation_id = in_flight.operation_id.clone();
    let result = msg.get("result").filter(|_| msg.get("error").is_none());
    let done = result.is_some_and(|r| r.get("isError") != Some(&Value::Bool(true)));
    let (state, stored) = if done {
        (OperationState::Done, result.map(Value::to_string))
    } else {
        (OperationState::Failed, None)
    };
    // Evidence of a settlement only when the store row did change: an
    // operation an operator reconciled meanwhile (or another process swept)
    // keeps its state, and the ledger must not claim otherwise.
    let settled = match store.lock() {
        Ok(mut s) => match if masked {
            s.settle_masked(&operation_id, state, stored.as_deref())
        } else {
            s.settle(&operation_id, state, stored.as_deref())
        } {
            Ok(changed) => {
                if !changed {
                    tracing::warn!("operations store: {operation_id} is no longer in flight; its reply settles nothing");
                }
                changed
            }
            Err(e) => {
                tracing::warn!("operations store: could not settle {operation_id} ({e}); a restart marks it unknown");
                false
            }
        },
        Err(_) => {
            tracing::warn!("operations store: lock poisoned; {operation_id} not settled");
            false
        }
    };
    settled.then_some((in_flight, state))
}

/// Ledger metadata naming an operation and its state.
fn operation_meta(state: OperationState, operation_id: &str) -> Vec<(&'static str, MetadataValue)> {
    vec![opaque("operation_id", operation_id), opaque("operation_state", state.as_str())]
}

/// An operator's verdict on an operation whose outcome is unknown
/// (`cloakpipe operations reconcile`): `done` (a retry replays) or
/// `not_applied` (a retry runs); an `in_flight` one only with `force` (a
/// running gate may still get its reply). With a decision ledger, a
/// `reconcile` entry (outcome `committed` for done, `failed` for not
/// applied; bound to `release` when given) is appended in the same
/// transaction: if it cannot be recorded, nothing changes.
pub fn reconcile_operation(
    store: &mut OperationStore,
    operation_id: &str,
    outcome: OperationState,
    force: bool,
    decisions: Option<&mut DecisionLog>,
    release: Option<&str>,
) -> Result<(), ReconcileError> {
    // Read before the reconcile transaction; `reconcile` itself reports a
    // missing operation.
    let row = store.get(operation_id).ok().flatten();
    store.reconcile(operation_id, outcome, force, || {
        let Some(log) = decisions else { return Ok(()) };
        let draft = DecisionDraft {
            release: release.map(str::to_string),
            tool: row.as_ref().map(|r| r.tool.clone()),
            operation_id: Some(operation_id.to_string()),
            outcome: Some(if outcome == OperationState::Done { Outcome::Committed } else { Outcome::Failed }),
            ..DecisionDraft::reconcile()
        };
        log.append(draft, row.as_ref().map(|r| &r.call_digest)).map(|_| ()).map_err(|e| e.to_string())
    })
}

/// The `fail_closed` reason: the gate could not record its decision.
const FAIL_CLOSED: &str = "fail_closed";

/// What every entry of one gate run shares.
#[derive(Clone)]
struct EntryBase {
    release: String,
    /// The release name (events carry it next to the digest).
    release_name: String,
    /// The digest of the manifest's Cedar policy file, when it has one.
    policy_digest: Option<String>,
    mode: Mode,
    task_id: Option<String>,
}

impl EntryBase {
    fn of(gate: &ToolGate) -> Self {
        let mode = match gate.mode {
            GateMode::Enforce => Mode::Enforce,
            GateMode::Shadow => Mode::Shadow,
        };
        Self {
            release: gate.release().to_string(),
            release_name: gate.release_name().to_string(),
            policy_digest: gate.policy_digest(),
            mode,
            task_id: gate.task_id().map(str::to_string),
        }
    }

    /// A tool call entry (`allow`, `ok`, not forwarded until set).
    fn call(&self, tool: Option<String>) -> DecisionDraft {
        DecisionDraft {
            release: Some(self.release.clone()),
            tool,
            policy_digest: self.policy_digest.clone(),
            mode: Some(self.mode),
            task_id: self.task_id.clone(),
            ..DecisionDraft::call()
        }
    }

    /// The outcome entry of a forwarded side-effecting call.
    fn outcome(&self, op: &InFlight, outcome: Outcome) -> DecisionDraft {
        DecisionDraft {
            release: Some(self.release.clone()),
            tool: Some(op.tool.clone()).filter(|t| !t.is_empty()),
            policy_digest: self.policy_digest.clone(),
            mode: Some(self.mode),
            task_id: self.task_id.clone(),
            operation_id: Some(op.operation_id.clone()),
            outcome: Some(outcome),
            forwarded: true,
            ..DecisionDraft::outcome()
        }
    }
}

/// The event reason of a retry answered from the operations store.
const REPLAYED: &str = "already_committed";
/// The event reason of a side effect whose outcome is unknown.
const UNKNOWN: &str = "operation_unknown";

/// Hand an event to every sink: `draft` is the decision as recorded (as
/// `entry`, when it was written), `reason` the event's reason code. The
/// event, unless there are no sinks.
fn emit(
    sinks: &[Arc<dyn EventSink>],
    base: &EntryBase,
    kind: EventKind,
    reason: &str,
    draft: &DecisionDraft,
    entry: Option<&DecisionEntry>,
) -> Option<GateEvent> {
    if sinks.is_empty() {
        return None;
    }
    let mut event = GateEvent::new(kind, reason, draft.tool.as_deref(), draft.path.as_deref(), base.policy_digest.as_deref());
    event.release = Some(base.release_name.clone());
    event.release_digest = Some(base.release.clone());
    event.decision = Some(draft.decision);
    event.mode = draft.mode;
    event.operation_id = draft.operation_id.clone();
    if let Some(entry) = entry {
        event.ts = entry.ts.clone();
        event.ledger_seq = Some(entry.seq);
        event.entry_hash = Some(entry.entry_hash.clone());
    }
    for sink in sinks {
        sink.emit(&event);
    }
    Some(event)
}

/// Hand a decision on an agent message (started at `started`, unix ns) to
/// every sink's [`EventSink::decision`], with the event it raised.
fn report(
    sinks: &[Arc<dyn EventSink>],
    base: &EntryBase,
    started: u64,
    draft: &DecisionDraft,
    reason: &str,
    entry: Option<&DecisionEntry>,
    event: Option<&GateEvent>,
) {
    if sinks.is_empty() {
        return;
    }
    let record = DecisionRecord {
        ts: entry.map(|e| e.ts.clone()).unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        start_unix_nanos: started,
        end_unix_nanos: unix_nanos(),
        tool: draft.tool.clone(),
        decision: draft.decision,
        reason: reason.to_string(),
        path: draft.path.clone(),
        mode: draft.mode,
        release: Some(base.release_name.clone()),
        release_digest: Some(base.release.clone()),
        policy_version: base.policy_digest.clone(),
        operation_id: draft.operation_id.clone(),
        forwarded: draft.forwarded,
        ledger_seq: entry.map(|e| e.seq),
        entry_hash: entry.map(|e| e.entry_hash.clone()),
        event: event.map(|e| e.kind),
        fingerprint: event.map(|e| e.fingerprint.clone()),
    };
    for sink in sinks {
        sink.decision(&record);
    }
}

fn unix_nanos() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// Append a decision entry. `Ok(None)` without a decision log (`--no-ledger`).
fn record_decision(decisions: &SharedDecisions, draft: DecisionDraft, raw_fingerprint: Option<&[u8; 32]>) -> Result<Option<DecisionEntry>, String> {
    let Some(log) = decisions else { return Ok(None) };
    let mut log = log.lock().map_err(|_| "decision ledger lock poisoned".to_string())?;
    log.append(draft, raw_fingerprint).map(Some).map_err(|e| {
        // The reason only, never message content.
        tracing::warn!("decision ledger: entry not recorded: {e:#}");
        format!("{e:#}")
    })
}

/// Append the outcome of a forwarded side-effecting call.
fn record_outcome(decisions: &SharedDecisions, base: &EntryBase, op: &InFlight, outcome: Outcome) -> Result<(), String> {
    record_decision(decisions, base.outcome(op, outcome), Some(&op.fingerprint)).map(|_| ())
}

/// The raw fingerprint of a call (as approval receipts and the operations
/// store name it); recorded keyed only.
fn call_fingerprint(gate: &ToolGate, tool: &str, arguments: Option<&Value>) -> Option<[u8; 32]> {
    let release: ReleaseHash = gate.release().parse().ok()?;
    Some(fingerprint(&release, tool, arguments.unwrap_or(&Value::Null)).0)
}

/// The tool name as recorded: a declared tool's name, or an undeclared
/// one's when it reads as an identifier (the agent chose it: free text is
/// never recorded).
fn recordable_tool(gate: &ToolGate, tool: &str) -> Option<String> {
    let identifier = !tool.is_empty()
        && tool.len() <= 128
        && tool.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.:/@".contains(&b));
    (gate.declares(tool) || identifier).then(|| tool.to_string())
}

/// The JSON-RPC error for a refused call.
fn refusal_message(
    id: &Value,
    code: &str,
    tool: &str,
    gate: &ToolGate,
    path: Option<&str>,
    operation_id: Option<&str>,
    rpc_code: i64,
) -> Value {
    let mut data = serde_json::json!({ "reason": code, "tool": tool, "release": gate.release() });
    if let Some(path) = path {
        data["path"] = Value::String(path.to_string());
    }
    if let Some(op) = operation_id {
        data["operationId"] = Value::String(op.to_string());
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": rpc_code,
            "message": format!("tool call refused by CloakPipe: {code}"),
            "data": data,
        },
    })
}

/// Undo [`coordinate`]'s start of an operation that is not forwarded after
/// all (its entry could not be written): it certainly did not run.
fn unstart(operations: &SharedOperations, pending: &Pending, request: &str) {
    let in_flight = pending.lock().ok().and_then(|mut p| p.by_request.remove(request));
    let (Some(op), Some(store)) = (in_flight, operations) else { return };
    if let Ok(mut s) = store.lock() {
        if let Err(e) = s.settle(&op.operation_id, OperationState::Failed, None) {
            tracing::warn!("operations store: could not release unsent {} ({e}); a restart marks it unknown", op.operation_id);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// JSON-RPC members whose spelling must be exact. Some JSON decoders (Go's
/// `encoding/json`) match keys case-insensitively, so `"Method"` could reach
/// the upstream as a method the gate never saw.
const CANONICAL_KEYS: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];
const CANONICAL_PARAMS: [&str; 2] = ["name", "arguments"];

/// Can the gate read this agent message in full? Refuses (reason, JSON-RPC
/// code) anything else: text serde_json rejects but a laxer upstream might
/// accept (out-of-range numbers, lone surrogates, deep nesting), batches,
/// non-objects, and case variants of JSON-RPC member names.
fn screen(line: &str) -> Result<(), (&'static str, i64)> {
    const PARSE_ERROR: i64 = -32700;
    const INVALID_REQUEST: i64 = -32600;
    let msg: Value = serde_json::from_str(line).map_err(|_| ("unreadable", PARSE_ERROR))?;
    let obj = match &msg {
        Value::Object(o) => o,
        Value::Array(_) => return Err(("batch", INVALID_REQUEST)),
        _ => return Err(("not_an_object", INVALID_REQUEST)),
    };
    fn noncanonical(map: &serde_json::Map<String, Value>, canonical: &[&str]) -> bool {
        map.keys().any(|k| {
            let folded = fold(k);
            canonical.iter().any(|c| folded == *c && k.as_str() != *c)
        })
    }
    if noncanonical(obj, &CANONICAL_KEYS) {
        return Err(("noncanonical", INVALID_REQUEST));
    }
    if let Some(Value::Object(params)) = obj.get("params") {
        if noncanonical(params, &CANONICAL_PARAMS) {
            return Err(("noncanonical", INVALID_REQUEST));
        }
    }
    Ok(())
}

/// Case-fold as lax decoders do (ASCII plus the two non-ASCII letters that
/// fold to ASCII: U+017F long s and U+212A Kelvin sign).
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{17F}' => 's',
            '\u{212A}' => 'k',
            c => c,
        })
        .collect::<String>()
        .to_lowercase()
}

/// Write one JSON-RPC line to the agent.
pub(crate) fn write_line<W: Write>(out: &Mutex<W>, line: &str) -> std::io::Result<()> {
    let mut w = out.lock().map_err(|_| std::io::Error::other("agent writer poisoned"))?;
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

/// Pseudonymize every string leaf under `v`, returning the number of entities
/// masked. Uses the shared vault so the same original → same token (and so the
/// tokens rehydrate on the way back).
fn mask_value(v: Option<&mut Value>, detector: &Detector, vault: &mut Vault) -> usize {
    let Some(v) = v else { return 0 };
    match v {
        Value::String(s) => {
            let entities = detector.detect(s).unwrap_or_default();
            if entities.is_empty() {
                return 0;
            }
            match Replacer::pseudonymize(s, &entities, vault) {
                Ok(r) => {
                    *s = r.text;
                    entities.len()
                }
                Err(_) => 0,
            }
        }
        Value::Array(a) => a.iter_mut().map(|x| mask_value(Some(x), detector, vault)).sum(),
        Value::Object(o) => o
            .values_mut()
            .map(|x| mask_value(Some(x), detector, vault))
            .sum(),
        _ => 0,
    }
}

/// Restore pseudonym tokens back to their originals in every string leaf under
/// `v`. Non-token text is left untouched.
fn rehydrate_value(v: Option<&mut Value>, vault: &Vault) {
    let Some(v) = v else { return };
    match v {
        Value::String(s) => {
            if let Ok(r) = Rehydrator::rehydrate(s, vault) {
                *s = r.text;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| rehydrate_value(Some(x), vault)),
        Value::Object(o) => o.values_mut().for_each(|x| rehydrate_value(Some(x), vault)),
        _ => {}
    }
}

fn open_ledger(path: &str) -> SharedLedger {
    match LedgerStore::open(path) {
        Ok(s) => Some(Arc::new(Mutex::new(s))),
        Err(e) => {
            eprintln!("cloakpipe: MCP ledger open failed ({e}); evidence disabled");
            None
        }
    }
}

/// The fixed `(tenant, agent)` ids the interceptor records ledger hops under.
pub fn stable_ids() -> (uuid::Uuid, uuid::Uuid) {
    let ns = uuid::Uuid::NAMESPACE_URL;
    (
        uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-tenant"),
        uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-agent"),
    )
}

/// A string metadata entry (reason codes, contract paths, operation ids).
fn opaque(key: &'static str, value: &str) -> (&'static str, MetadataValue) {
    (key, MetadataValue::OpaqueId(value.to_string()))
}

/// Append a no-PII hop record (categories/count only, never text). Best-effort.
/// `gate` adds metadata entries: the primary one first (a gate reason code,
/// or the approval receipt digest), then optional detail (`gate_path`,
/// `operation_id`). Should the ledger's PII check refuse the detail (a
/// contract property named `phone`, say), the hop is recorded with the
/// primary entry alone rather than lost.
#[allow(clippy::too_many_arguments)]
fn record_hop(
    ledger: &SharedLedger,
    tenant: uuid::Uuid,
    agent: uuid::Uuid,
    release: Option<[u8; 32]>,
    hop: Hop,
    count: usize,
    kind: ActionKind,
    gate: &[(&str, MetadataValue)],
) {
    let Some(ledger) = ledger else { return };
    let Ok(mut store) = ledger.lock() else {
        tracing::warn!(hop = ?hop, "evidence ledger: lock poisoned; MCP hop not recorded");
        return;
    };
    if let Err(e) = append_hop(&mut store, tenant, agent, release, hop, count, kind, gate) {
        // Payload-free: the hop kind and error only, never message content.
        tracing::warn!(hop = ?hop, "evidence ledger: failed to record MCP hop: {e}");
    }
}

/// [`record_hop`] on an open store, reporting failure.
#[allow(clippy::too_many_arguments)]
fn append_hop(
    store: &mut LedgerStore,
    tenant: uuid::Uuid,
    agent: uuid::Uuid,
    release: Option<[u8; 32]>,
    hop: Hop,
    count: usize,
    kind: ActionKind,
    gate: &[(&str, MetadataValue)],
) -> Result<(), String> {
    let next_seq = match store.head(&tenant) {
        Ok((head, _)) => head.map(|s| s + 1).unwrap_or(0),
        Err(e) => return Err(format!("cannot read chain head: {e}")),
    };
    let build = |entries: &[(&str, MetadataValue)]| {
        let mut builder = RecordBuilder::new()
            .seq(next_seq)
            .tenant(tenant)
            .hop(hop)
            .detection(Detection {
                entity_type: "mcp".to_string(),
                count: count as u32,
                detector: cloakpipe_ledger::Detector::Regex,
            })
            .action(HopAction {
                entity_type: "mcp".to_string(),
                kind,
                token_ref: Some(uuid::Uuid::new_v4().to_string()),
            })
            .identities(Identity {
                agent_id: agent,
                human_principal: None,
                upstream: "mcp".to_string(),
                region: std::env::var("CLOAKPIPE_REGION").unwrap_or_else(|_| "local".to_string()),
            });
        if let Some(release) = release {
            builder = builder.release(release);
        }
        for (key, value) in entries {
            builder = builder.metadata(*key, value.clone());
        }
        builder.build()
    };
    let record = match build(gate) {
        Err(e) if gate.len() > 1 => {
            tracing::warn!(hop = ?hop, "evidence ledger: gate detail refused ({e}); recording the reason code only");
            build(&gate[..1])
        }
        other => other,
    };
    let mut record = record.map_err(|e| e.to_string())?;
    store.append(&tenant, &mut record).map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakpipe_core::config::DetectionConfig;

    #[test]
    fn masks_tool_args_and_rehydrates_round_trip() {
        // Every DetectionConfig field has a serde default (emails on), so an
        // empty object deserializes to the default config.
        let config: DetectionConfig = serde_json::from_str("{}").unwrap();
        let detector = Detector::from_config(&config).unwrap();
        let mut vault = Vault::ephemeral();

        // A tools/call arguments object with PII in nested strings.
        let mut args = serde_json::json!({
            "to": "email alice@acme.com about invoice",
            "cc": ["bob@globex.com"],
            "count": 3
        });
        let masked = mask_value(Some(&mut args), &detector, &mut vault);
        assert!(masked >= 2, "masked the emails, got {masked}");

        let s = serde_json::to_string(&args).unwrap();
        assert!(!s.contains("alice@acme.com"), "raw PII must be gone: {s}");
        assert!(!s.contains("bob@globex.com"), "raw PII must be gone: {s}");

        // The tool echoes the (masked) args back in a result; rehydrate restores
        // the originals for the agent.
        let mut result = args.clone();
        rehydrate_value(Some(&mut result), &vault);
        let r = serde_json::to_string(&result).unwrap();
        assert!(r.contains("alice@acme.com"), "rehydrated original: {r}");
        assert!(r.contains("bob@globex.com"), "rehydrated original: {r}");
    }
}
