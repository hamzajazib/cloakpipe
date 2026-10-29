//! Approvals through a broker (`mcp-proxy --approvals-url`): the client
//! side of the open approval broker protocol (docs/APPROVALS.md). Any
//! service that implements it can route approvals to humans; the gate
//! never trusts it beyond the approver keys the operator pinned.
//!
//! - **Request.** When the gate refuses a call as `approval_required`, it
//!   hands the call to [`ApprovalBroker::submit`], which queues a signed
//!   `POST <url>/approvals` ([`REQUEST_SCHEMA`]) and returns at once. The
//!   request names the call (its fingerprint), the release, the tool, the
//!   approver routes, the task id a receipt must carry, the ttl, the
//!   decision ledger seq and **only** the argument values the manifest's
//!   `approval.show` opts in to. One request per fingerprint while it is
//!   open: a retry before the decision files nothing new.
//! - **Poll.** A background thread (every [`BrokerConfig::poll_interval`])
//!   sends a signed `GET <url>/approvals?since=<cursor>` and handles each
//!   finished request ([`ApprovalBroker::poll_once`]):
//!   - `approved`: the DSSE receipt is verified here, against the trusted
//!     approver keys, the release, the tool, the task id, the fingerprint
//!     and the tool's ttl, exactly as the gate will. Only then is it written,
//!     atomically, to `<approvals dir>/<fingerprint hex>.approval.json`,
//!     where the agent's retry finds it. A receipt that does not verify is
//!     not written; it is logged and raises an `approval.mismatch` event. An
//!     expired one is dropped.
//!   - `denied`: the call is refused as `approval_denied` until the denial's
//!     `not_after` (else the request's ttl): in memory, and as a marker
//!     `<fingerprint hex>.denied.json` (the gate honours a marker after a
//!     restart too). No new request is filed meanwhile.
//!   - `expired`: nobody decided in time. The call stays `approval_required`
//!     and the next retry files a new request.
//!
//! The decision path never waits on the network: it only queues and reads
//! local state. If the broker is down, nothing changes but that approvals
//! do not arrive (a pending call stays refused, so it expires to deny).
//!
//! **Signing.** Both requests carry `CloakPipe-Signature: t=<unix>,v1=<hex>`
//! as webhooks do ([`crate::events::webhook::sign`]), under the gate's
//! secret: the POST over its exact body, the GET over the string
//! `GET <path>?<query>` (the request target as sent, percent-encoded as on
//! the wire; no `?` without a cursor).

use crate::events::delivery::{client, post_with_retry, Post, Queue, Retry};
use crate::events::webhook::{sign, SIGNATURE_HEADER};
use crate::events::{EventKind, EventSink, GateEvent};
use crate::gate::{GateMode, ToolGate};
use cloakpipe_ledger::decision::{Decision, Mode};
use cloakpipe_receipt::approval::{verify_approval, ApprovalCheck, ApprovalError};
use cloakpipe_receipt::dsse::{parse_rfc3339, Envelope, TrustedKey};
use cloakpipe_release::action::ToolCallFingerprint;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// The `schema` of an approval request.
pub const REQUEST_SCHEMA: &str = "cloakpipe.approval-request/v1";
/// The `schema` of a denial marker (`<fingerprint hex>.denied.json`).
pub const DENIAL_SCHEMA: &str = "cloakpipe.approval-denial/v1";
/// How often finished requests are fetched (`--approvals-poll-interval`).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// A request's lifetime, and a receipt's longest validity, when the tool
/// sets no `approval.ttl`.
pub const DEFAULT_REQUEST_TTL_SECS: u64 = 900;
/// The longest a request stays open, or a denial holds: a year.
const MAX_REQUEST_SECS: u64 = 366 * 86_400;
/// The largest poll response read.
const MAX_POLL_BYTES: usize = 8 << 20;
/// Requests queued before new ones are dropped (and filed on a later retry).
const QUEUE_CAPACITY: usize = 1024;

/// Where the broker is and how to talk to it.
#[derive(Clone)]
pub struct BrokerConfig {
    /// The gate's base URL at the broker, e.g. `https://api.example/v1/gates/<id>`.
    pub url: String,
    /// The HMAC secret both requests are signed with.
    pub secret: Vec<u8>,
    /// How often [`ApprovalBroker::start`]'s poller asks (default 5 s).
    pub poll_interval: Duration,
    /// Per HTTP request (default 5 s).
    pub timeout: Duration,
    /// Tries per request filed (default 3).
    pub tries: u32,
    /// Wait before the second try, doubled before each later one (default 500 ms).
    pub backoff: Duration,
}

impl BrokerConfig {
    pub fn new(url: &str, secret: Vec<u8>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            secret,
            poll_interval: DEFAULT_POLL_INTERVAL,
            timeout: Duration::from_secs(5),
            tries: 3,
            backoff: Duration::from_millis(500),
        }
    }
}

impl std::fmt::Debug for BrokerConfig {
    /// The secret is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerConfig")
            .field("url", &self.url)
            .field("poll_interval", &self.poll_interval)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Where a call's approval request stands, as the refusal reports it
/// (`error.data.approval_request`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    /// Filed now (or being filed): retry after approval.
    Requested,
    /// The broker has it; nobody decided yet.
    Pending,
    /// An approver denied this exact call.
    Denied,
}

impl RequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RequestStatus::Requested => "requested",
            RequestStatus::Pending => "pending",
            RequestStatus::Denied => "denied",
        }
    }
}

/// One call the gate refused as `approval_required`, as the gate describes
/// it ([`ToolGate::request_approval`]).
#[derive(Debug, Clone, PartialEq)]
pub struct BrokerRequest {
    pub fingerprint: ToolCallFingerprint,
    pub tool: String,
    pub approvers: Vec<String>,
    /// The tool's `approval.ttl` (seconds), if it sets one.
    pub ttl_secs: Option<u64>,
    /// The `approval.show` values only.
    pub shown: Map<String, Value>,
    /// The decision ledger entry of the refusal.
    pub ledger_seq: Option<u64>,
}

/// What a receipt must be about: the gate's release and task, its trusted
/// approvers, and each declared tool's ttl.
struct Verifier {
    release: String,
    task_id: String,
    approvers: Vec<TrustedKey>,
    ttls: BTreeMap<String, Option<u64>>,
}

impl Verifier {
    /// Verify `envelope` for the call `fp`: with `tool` when the request is
    /// known, else for whichever declared tool it names. `Ok(tool)`.
    fn verify(&self, fp: ToolCallFingerprint, tool: Option<&str>, envelope: &Envelope, now: &str) -> Result<String, ApprovalError> {
        let candidates: Vec<&str> = match tool {
            Some(t) => vec![t],
            None => self.ttls.keys().map(String::as_str).collect(),
        };
        let mut last = ApprovalError::Invalid("no declared tool".into());
        for tool in candidates {
            let check = ApprovalCheck {
                fingerprint: fp,
                release: &self.release,
                tool,
                task_id: &self.task_id,
                approvers: &self.approvers,
                now,
            };
            match verify_approval(envelope, &check) {
                Ok(a) => {
                    let ttl = self.ttls.get(tool).copied().flatten();
                    return match (ttl, parse_rfc3339(&a.approved_at), parse_rfc3339(&a.not_after)) {
                        (None, _, _) => Ok(tool.to_string()),
                        (Some(ttl), Some(from), Some(to)) if (to - from).num_seconds() <= i64::try_from(ttl).unwrap_or(i64::MAX) => {
                            Ok(tool.to_string())
                        }
                        _ => Err(ApprovalError::Invalid("validity window exceeds the tool's approval ttl".into())),
                    };
                }
                Err(ApprovalError::Expired) => return Err(ApprovalError::Expired),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// The release fields every request and event carries.
struct Meta {
    release_name: String,
    version: String,
    release_digest: String,
    policy_digest: Option<String>,
    mode: Mode,
}

/// A request filed and not finished.
struct Open {
    tool: String,
    /// Accepted by the broker (else still being sent).
    accepted: bool,
    /// Unix seconds: after this the request is filed anew.
    expires: i64,
    ttl_secs: u64,
}

#[derive(Default)]
struct State {
    /// By fingerprint hex.
    open: HashMap<String, Open>,
    /// Fingerprint hex -> denied until (unix seconds).
    denied: HashMap<String, i64>,
    cursor: Option<String>,
    stopped: bool,
}

struct Inner {
    cfg: BrokerConfig,
    dir: PathBuf,
    verifier: Verifier,
    meta: Meta,
    events: Vec<Arc<dyn EventSink>>,
    state: Mutex<State>,
    wake: Condvar,
}

/// One request on its way to the broker.
struct Filing {
    hex: String,
    body: Vec<u8>,
}

/// The gate's approval broker client: files requests and fetches finished
/// ones in the background. Share it with the gate ([`ToolGate::with_broker`]).
pub struct ApprovalBroker {
    inner: Arc<Inner>,
    queue: Queue<Filing>,
}

impl ApprovalBroker {
    /// File requests in the background and poll every
    /// [`BrokerConfig::poll_interval`] on a thread of its own.
    pub fn start(cfg: BrokerConfig, gate: &ToolGate, events: Vec<Arc<dyn EventSink>>) -> Result<Arc<Self>, String> {
        let broker = Self::manual(cfg, gate, events)?;
        let inner = broker.inner.clone();
        std::thread::Builder::new()
            .name("cloakpipe-approvals-poll".into())
            .spawn(move || poll_loop(&inner))
            .map_err(|e| format!("cannot start the approvals poller: {e}"))?;
        Ok(broker)
    }

    /// File requests in the background; poll only when asked
    /// ([`Self::poll_once`]).
    pub fn manual(cfg: BrokerConfig, gate: &ToolGate, events: Vec<Arc<dyn EventSink>>) -> Result<Arc<Self>, String> {
        match reqwest::Url::parse(&cfg.url) {
            Ok(u) if matches!(u.scheme(), "http" | "https") && u.query().is_none() => {}
            _ => return Err(format!("approvals URL {:?}: expected an http:// or https:// URL without a query", cfg.url)),
        }
        let (dir, approvers) = gate
            .approvals_config()
            .ok_or("an approval broker needs the approvals directory and approver keys (--approvals, --approver-key)")?;
        let task_id = gate
            .task_id()
            .ok_or("an approval broker needs a task context with a taskId (--task-context): every receipt is signed for it")?
            .to_string();
        let verifier = Verifier { release: gate.release().to_string(), task_id, approvers: approvers.to_vec(), ttls: gate.approval_ttls() };
        let meta = Meta {
            release_name: gate.release_name().to_string(),
            version: gate.version().to_string(),
            release_digest: gate.release().to_string(),
            policy_digest: gate.policy_digest(),
            mode: match gate.mode {
                GateMode::Enforce => Mode::Enforce,
                GateMode::Shadow => Mode::Shadow,
            },
        };
        let inner = Arc::new(Inner {
            cfg,
            dir: dir.to_path_buf(),
            verifier,
            meta,
            events,
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        });
        let worker = inner.clone();
        let mut http = None;
        let queue = Queue::spawn("approvals", QUEUE_CAPACITY, 1, move |batch: Vec<Filing>| {
            if http.is_none() {
                http = client(worker.cfg.timeout);
            }
            for filing in batch {
                let sent = match &http {
                    Some(http) => file(http, &worker.cfg, &filing.body),
                    None => Err("no HTTP client".to_string()),
                };
                let mut s = lock(&worker.state);
                match sent {
                    Ok(_) => {
                        if let Some(open) = s.open.get_mut(&filing.hex) {
                            open.accepted = true;
                        }
                    }
                    Err(e) => {
                        // Not filed: the next retry files it again.
                        s.open.remove(&filing.hex);
                        eprintln!("warning: cloakpipe approvals: request not filed with the broker: {e}");
                    }
                }
            }
        });
        Ok(Arc::new(Self { inner, queue }))
    }

    /// File a request for `req` unless one is open or the call is denied.
    /// Never blocks: the request is sent on a background thread.
    pub fn submit(&self, req: BrokerRequest) -> RequestStatus {
        let hex = req.fingerprint.hex();
        let now = chrono::Utc::now();
        let unix = now.timestamp();
        let ttl = req.ttl_secs.unwrap_or(DEFAULT_REQUEST_TTL_SECS);
        let mut s = lock(&self.inner.state);
        if s.denied.get(&hex).is_some_and(|until| *until > unix) {
            return RequestStatus::Denied;
        }
        if let Some(open) = s.open.get(&hex).filter(|o| o.expires > unix) {
            return if open.accepted { RequestStatus::Pending } else { RequestStatus::Requested };
        }
        let meta = &self.inner.meta;
        // A request lapses after the ttl (capped, so any manifest ttl is a valid time).
        let expires = now + chrono::Duration::seconds(i64::try_from(ttl.min(MAX_REQUEST_SECS)).unwrap_or(0));
        let body = json!({
            "schema": REQUEST_SCHEMA,
            "fingerprint": req.fingerprint.to_string(),
            "release": meta.release_name,
            "version": meta.version,
            "release_digest": meta.release_digest,
            "tool": req.tool,
            "approvers": req.approvers,
            "task_id": self.inner.verifier.task_id,
            "ttl_secs": ttl,
            "requested_at": rfc3339(now),
            "expires_at": rfc3339(expires),
            "ledger_seq": req.ledger_seq,
            "shown": Value::Object(req.shown),
        });
        let body = serde_json::to_vec(&body).unwrap_or_default();
        s.open.insert(hex.clone(), Open { tool: req.tool, accepted: false, expires: expires.timestamp(), ttl_secs: ttl });
        drop(s);
        if !self.queue.push(Filing { hex: hex.clone(), body }) {
            lock(&self.inner.state).open.remove(&hex);
        }
        RequestStatus::Requested
    }

    /// Whether an approver denied the call `hex` (fingerprint hex) and the
    /// denial holds at `now` (unix seconds).
    pub fn is_denied(&self, hex: &str, now: i64) -> bool {
        lock(&self.inner.state).denied.get(hex).is_some_and(|until| *until > now)
    }

    /// Fetch finished requests once and handle each (see the module docs).
    /// `Ok(n)`: the number of records the broker returned.
    pub fn poll_once(&self) -> Result<usize, String> {
        let http = client(self.inner.cfg.timeout).ok_or("cannot build the HTTP client")?;
        poll(&self.inner, &http)
    }

    /// Wait until every queued request was sent (or given up on), at most
    /// `timeout`.
    pub fn flush(&self, timeout: Duration) -> bool {
        self.queue.flush(timeout)
    }

    /// Stop the poller.
    pub fn stop(&self) {
        lock(&self.inner.state).stopped = true;
        self.inner.wake.notify_all();
    }
}

impl Drop for ApprovalBroker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Whether a denial marker for the call `hex` holds at `now` (unix
/// seconds): `<dir>/<hex>.denied.json` names this fingerprint and its
/// `notAfter` is later. A marker that cannot be read holds nothing.
pub fn denial_in_force(dir: &Path, hex: &str, now: i64) -> bool {
    if !is_hex64(hex) {
        return false;
    }
    let Ok(bytes) = std::fs::read(dir.join(format!("{hex}.denied.json"))) else { return false };
    let Ok(marker) = serde_json::from_slice::<Value>(&bytes) else { return false };
    marker["fingerprint"].as_str() == Some(format!("sha256:{hex}").as_str())
        && marker["status"] == "denied"
        && marker["notAfter"].as_str().and_then(parse_rfc3339).is_some_and(|t| t.timestamp() > now)
}

fn poll_loop(inner: &Inner) {
    let Some(http) = client(inner.cfg.timeout) else { return };
    let mut failing = false;
    loop {
        {
            let s = lock(&inner.state);
            let (s, _) = inner.wake.wait_timeout_while(s, inner.cfg.poll_interval, |s| !s.stopped).unwrap_or_else(|p| p.into_inner());
            if s.stopped {
                return;
            }
        }
        match poll(inner, &http) {
            Ok(_) => failing = false,
            Err(e) => {
                // The first failure of a run, not every poll.
                if !failing {
                    eprintln!("warning: cloakpipe approvals: cannot poll the broker: {e}");
                }
                failing = true;
            }
        }
    }
}

/// `POST <url>/approvals`, signed over the body.
fn file(http: &reqwest::blocking::Client, cfg: &BrokerConfig, body: &[u8]) -> Result<u16, String> {
    let url = format!("{}/approvals", cfg.url);
    let headers = || vec![(SIGNATURE_HEADER, sign(&cfg.secret, chrono::Utc::now().timestamp(), body))];
    post_with_retry(http, &Post { url: &url, body, headers: &headers }, Retry { tries: cfg.tries, backoff: cfg.backoff })
}

fn poll(inner: &Inner, http: &reqwest::blocking::Client) -> Result<usize, String> {
    let cursor = lock(&inner.state).cursor.clone();
    let body = signed_get(http, &inner.cfg, "approvals", cursor.as_deref().map(|c| ("since", c)))?;
    let records = body["approvals"].as_array().ok_or("response has no approvals array")?;
    let now = chrono::Utc::now();
    for record in records {
        handle(inner, record, now);
    }
    if let Some(cursor) = body["cursor"].as_str() {
        lock(&inner.state).cursor = Some(cursor.to_string());
    }
    Ok(records.len())
}

/// `GET <url>/<what>[?<name>=<value>]`, signed over `GET <target>`: the
/// JSON body of a 2xx.
fn signed_get(http: &reqwest::blocking::Client, cfg: &BrokerConfig, what: &str, query: Option<(&str, &str)>) -> Result<Value, String> {
    let mut url = reqwest::Url::parse(&format!("{}/{what}", cfg.url)).map_err(|e| e.to_string())?;
    if let Some((name, value)) = query {
        url.query_pairs_mut().append_pair(name, value);
    }
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let signature = sign(&cfg.secret, chrono::Utc::now().timestamp(), format!("GET {target}").as_bytes());
    let resp = http.get(url).header(SIGNATURE_HEADER, signature).send().map_err(|e| {
        // The error's kind only: it may name the URL.
        if e.is_timeout() { "timed out".to_string() } else { "request failed".to_string() }
    })?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    let bytes = resp.bytes().map_err(|_| "response unreadable".to_string())?;
    if bytes.len() > MAX_POLL_BYTES {
        return Err("response too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "response is not JSON".to_string())
}

/// The broker's approver public keys (`GET <url>/approver-keys`, signed):
/// each `(keyid, publicKey hex)` as listed, unchecked. Pin them with
/// `--approver-key` (`cloakpipe approvals keys` writes the files).
pub fn fetch_approver_keys(cfg: &BrokerConfig) -> Result<Vec<(String, String)>, String> {
    let http = client(cfg.timeout).ok_or("cannot build the HTTP client")?;
    let body = signed_get(&http, cfg, "approver-keys", None)?;
    let keys = body["keys"].as_array().ok_or("response has no keys array")?;
    keys.iter()
        .map(|k| match (k["keyid"].as_str(), k["publicKey"].as_str()) {
            (Some(id), Some(public)) => Ok((id.to_string(), public.to_string())),
            _ => Err("a key without a keyid and publicKey".to_string()),
        })
        .collect()
}

/// One finished request.
fn handle(inner: &Inner, record: &Value, now: chrono::DateTime<chrono::Utc>) {
    let Some(hex) = record["fingerprint"].as_str().and_then(|f| f.strip_prefix("sha256:")).filter(|h| is_hex64(h)) else {
        eprintln!("warning: cloakpipe approvals: a record without a valid fingerprint was ignored");
        return;
    };
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0);
    }
    let fp = ToolCallFingerprint(raw);
    let unix = now.timestamp();
    match record["status"].as_str() {
        Some("approved") => {
            let tool = lock(&inner.state).open.get(hex).map(|o| o.tool.clone());
            let envelope = match serde_json::from_value::<Envelope>(record["envelope"].clone()) {
                Ok(e) => e,
                Err(_) => return mismatch(inner, tool.as_deref(), "the record carries no DSSE envelope"),
            };
            match inner.verifier.verify(fp, tool.as_deref(), &envelope, &rfc3339(now)) {
                Ok(_) => {
                    let bytes = format!("{}\n", serde_json::to_string_pretty(&envelope).unwrap_or_default());
                    if let Err(e) = write_atomic(&inner.dir, &format!("{hex}.approval.json"), bytes.as_bytes()) {
                        eprintln!("warning: cloakpipe approvals: cannot write a verified receipt: {e}");
                        return;
                    }
                    let _ = std::fs::remove_file(inner.dir.join(format!("{hex}.denied.json")));
                    let mut s = lock(&inner.state);
                    s.open.remove(hex);
                    s.denied.remove(hex);
                }
                Err(ApprovalError::Expired) => {
                    eprintln!("warning: cloakpipe approvals: an approval arrived expired and was dropped");
                    lock(&inner.state).open.remove(hex);
                }
                Err(e) => mismatch(inner, tool.as_deref(), &e.to_string()),
            }
        }
        Some("denied") => {
            let mut s = lock(&inner.state);
            let ttl = s.open.remove(hex).map(|o| o.ttl_secs).unwrap_or(DEFAULT_REQUEST_TTL_SECS);
            let until = match record["not_after"].as_str().and_then(parse_rfc3339) {
                Some(t) => t.timestamp(),
                None => unix.saturating_add(i64::try_from(ttl.min(MAX_REQUEST_SECS)).unwrap_or(0)),
            }
            .min(unix.saturating_add(i64::try_from(MAX_REQUEST_SECS).unwrap_or(0)));
            if until <= unix {
                return;
            }
            s.denied.insert(hex.to_string(), until);
            drop(s);
            let not_after = chrono::DateTime::from_timestamp(until, 0).map(rfc3339).unwrap_or_default();
            let marker = json!({
                "schema": DENIAL_SCHEMA,
                "fingerprint": format!("sha256:{hex}"),
                "status": "denied",
                "decidedAt": record["decided_at"].as_str().map(str::to_string).unwrap_or_else(|| rfc3339(now)),
                "notAfter": not_after,
            });
            let bytes = format!("{}\n", serde_json::to_string_pretty(&marker).unwrap_or_default());
            if let Err(e) = write_atomic(&inner.dir, &format!("{hex}.denied.json"), bytes.as_bytes()) {
                eprintln!("warning: cloakpipe approvals: cannot write a denial marker (the denial holds in memory): {e}");
            }
        }
        Some("expired") => {
            lock(&inner.state).open.remove(hex);
        }
        _ => eprintln!("warning: cloakpipe approvals: a record with an unknown status was ignored"),
    }
}

/// A receipt that does not verify: not written, logged, and an
/// `approval.mismatch` event (receipt diagnostics only, never argument values).
fn mismatch(inner: &Inner, tool: Option<&str>, why: &str) {
    eprintln!("warning: cloakpipe approvals: a receipt from the broker does not verify and was not written: {why}");
    let meta = &inner.meta;
    let mut event = GateEvent::new(EventKind::ApprovalMismatch, "approval_invalid", tool, None, meta.policy_digest.as_deref());
    event.release = Some(meta.release_name.clone());
    event.release_digest = Some(meta.release_digest.clone());
    event.decision = Some(Decision::Deny);
    event.mode = Some(meta.mode);
    for sink in &inner.events {
        sink.emit(&event);
    }
}

/// Write `dir/name` via a temporary file and a rename, so the gate never
/// reads a partial file.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.{}.tmp", std::process::id(), rand::random::<u64>()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dir.join(name)).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// 64 lowercase hex characters: the only thing that becomes a file name.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn lock<S>(m: &Mutex<S>) -> std::sync::MutexGuard<'_, S> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
