//! Webhook delivery of gate events (`mcp-proxy --webhook URL`).
//!
//! Each event is POSTed as JSON, in one of three formats: `generic` (the
//! event's wire form, [`GateEvent::to_json`]), `slack` (a Block Kit
//! message for an incoming webhook) or `discord` (an embed). Every format
//! carries the same members of the event and nothing else: no argument
//! value, tool result or credential is ever in a payload.
//!
//! ## Headers
//!
//! - `CloakPipe-Event: <kind>` and `CloakPipe-Fingerprint: <fingerprint>`
//! - `CloakPipe-Signature: t=<unix seconds>,v1=<hex>` when a secret is set
//!   (`--webhook-secret-file`), where
//!
//! ```text
//! v1 = hex(HMAC-SHA256(secret, "<t>." + body))
//! ```
//!
//! over the exact body bytes. A receiver recomputes `v1` from the raw body,
//! compares in constant time, and rejects a `t` too far from its clock
//! (replay). More than one `v1` may be present (secret rotation): any one
//! matching is enough. [`verify_signature`] is a reference implementation
//! (`cloakpipe events verify-signature` on the command line).
//!
//! ## Delivery
//!
//! On a background thread with a bounded queue (dropped and counted when
//! full): up to three tries per event, backoff doubling from
//! [`WebhookConfig::backoff`], [`WebhookConfig::timeout`] per try. A
//! connection error, timeout, 429 or 5xx is retried; any other status is
//! final. Each try is signed anew. Delivery never blocks or changes a
//! decision.

use super::delivery::{client, post_with_retry, Post, Queue, Retry, DEFAULT_CAPACITY};
use super::{EventKind, EventSink, GateEvent};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The signature header.
pub const SIGNATURE_HEADER: &str = "CloakPipe-Signature";
/// The event kind header.
pub const EVENT_HEADER: &str = "CloakPipe-Event";
/// The fingerprint header.
pub const FINGERPRINT_HEADER: &str = "CloakPipe-Fingerprint";

/// The payload shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WebhookFormat {
    /// The event's wire form (`cloakpipe.event/v1`).
    #[default]
    Generic,
    /// A Slack Block Kit message (incoming webhook).
    Slack,
    /// A Discord embed (channel webhook).
    Discord,
}

impl std::str::FromStr for WebhookFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "generic" => Ok(Self::Generic),
            "slack" => Ok(Self::Slack),
            "discord" => Ok(Self::Discord),
            other => Err(format!("unknown webhook format {other:?} (generic, slack or discord)")),
        }
    }
}

/// One webhook endpoint.
#[derive(Clone)]
pub struct WebhookConfig {
    pub url: String,
    /// The HMAC secret; `None` sends unsigned payloads.
    pub secret: Option<Vec<u8>>,
    pub format: WebhookFormat,
    /// Per try (default 5 s).
    pub timeout: Duration,
    /// Tries per event in all (default 3).
    pub tries: u32,
    /// Wait before the second try; doubled before each later one (default 500 ms).
    pub backoff: Duration,
    /// Events queued before new ones are dropped (default 1024).
    pub capacity: usize,
}

impl WebhookConfig {
    /// `url` with the defaults: generic, unsigned, 5 s, 3 tries.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            secret: None,
            format: WebhookFormat::Generic,
            timeout: Duration::from_secs(5),
            tries: 3,
            backoff: Duration::from_millis(500),
            capacity: DEFAULT_CAPACITY,
        }
    }

    fn retry(&self) -> Retry {
        Retry { tries: self.tries, backoff: self.backoff }
    }
}

impl std::fmt::Debug for WebhookConfig {
    /// The secret is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &self.url)
            .field("signed", &self.secret.is_some())
            .field("format", &self.format)
            .field("timeout", &self.timeout)
            .field("tries", &self.tries)
            .finish()
    }
}

#[derive(Default)]
struct Stats {
    delivered: AtomicU64,
    failed: AtomicU64,
}

/// An [`EventSink`] that POSTs each event to one webhook.
pub struct WebhookSink {
    queue: Queue<GateEvent>,
    stats: Arc<Stats>,
}

impl WebhookSink {
    /// Start delivering to `cfg.url` in the background.
    pub fn new(cfg: WebhookConfig) -> Self {
        let stats = Arc::new(Stats::default());
        let worker_stats = stats.clone();
        let mut http = None;
        let queue = Queue::spawn("webhook", cfg.capacity, 1, move |batch: Vec<GateEvent>| {
            if http.is_none() {
                http = client(cfg.timeout);
            }
            let Some(http) = &http else { return };
            for event in batch {
                match deliver_with(http, &cfg, &event) {
                    Ok(_) => worker_stats.delivered.fetch_add(1, Ordering::Relaxed),
                    Err(e) => {
                        eprintln!("warning: cloakpipe webhook: {} event {} not delivered: {e}", event.kind, event.fingerprint);
                        worker_stats.failed.fetch_add(1, Ordering::Relaxed)
                    }
                };
            }
        });
        Self { queue, stats }
    }

    /// Events delivered (a 2xx).
    pub fn delivered(&self) -> u64 {
        self.stats.delivered.load(Ordering::Relaxed)
    }

    /// Events given up on after their tries.
    pub fn failed(&self) -> u64 {
        self.stats.failed.load(Ordering::Relaxed)
    }

    /// Events dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.queue.dropped()
    }
}

impl EventSink for WebhookSink {
    fn emit(&self, event: &GateEvent) {
        self.queue.push(event.clone());
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.queue.flush(timeout)
    }
}

/// Deliver one event now, on this thread, with the configured retries
/// (`cloakpipe events test`). `Ok(status)` on a 2xx.
pub fn deliver(cfg: &WebhookConfig, event: &GateEvent) -> Result<u16, String> {
    let http = client(cfg.timeout).ok_or("cannot build the HTTP client")?;
    deliver_with(&http, cfg, event)
}

fn deliver_with(http: &reqwest::blocking::Client, cfg: &WebhookConfig, event: &GateEvent) -> Result<u16, String> {
    let body = serde_json::to_vec(&payload(cfg.format, event)).map_err(|e| e.to_string())?;
    let headers = || {
        let mut h = vec![(EVENT_HEADER, event.kind.as_str().to_string()), (FINGERPRINT_HEADER, event.fingerprint.clone())];
        if let Some(secret) = &cfg.secret {
            h.push((SIGNATURE_HEADER, sign(secret, chrono::Utc::now().timestamp(), &body)));
        }
        h
    };
    post_with_retry(http, &Post { url: &cfg.url, body: &body, headers: &headers }, cfg.retry())
}

/// The `CloakPipe-Signature` value for `body` sent at unix time `t`:
/// `t=<t>,v1=<hex(HMAC-SHA256(secret, "<t>.<body>"))>`.
pub fn sign(secret: &[u8], t: i64, body: &[u8]) -> String {
    format!("t={t},v1={}", hex(&mac(secret, t, body)))
}

fn mac(secret: &[u8], t: i64, body: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes a key of any length");
    m.update(t.to_string().as_bytes());
    m.update(b".");
    m.update(body);
    m.finalize().into_bytes().to_vec()
}

/// Why a signature does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// No `t=` or no `v1=` in the header.
    Malformed,
    /// No `v1` matches the body under the secret.
    Mismatch,
    /// `t` is further than the tolerance from now.
    Stale,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignatureError::Malformed => "malformed signature header (expected t=<unix>,v1=<hex>)",
            SignatureError::Mismatch => "signature does not match the body",
            SignatureError::Stale => "signature timestamp outside the tolerance",
        })
    }
}

impl std::error::Error for SignatureError {}

/// Check a `CloakPipe-Signature` header against the raw `body`: some `v1`
/// must equal `HMAC-SHA256(secret, "<t>.<body>")` (compared in constant
/// time) and, with `tolerance` (seconds), `t` must be within it of `now`.
pub fn verify_signature(secret: &[u8], header: &str, body: &[u8], now: i64, tolerance: Option<u64>) -> Result<(), SignatureError> {
    let mut t = None;
    let mut sigs = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => t = v.parse::<i64>().ok(),
            Some(("v1", v)) => sigs.push(v.to_ascii_lowercase()),
            _ => {}
        }
    }
    let t = t.ok_or(SignatureError::Malformed)?;
    if sigs.is_empty() {
        return Err(SignatureError::Malformed);
    }
    let expected = hex(&mac(secret, t, body));
    if !sigs.iter().any(|s| constant_time_eq(s.as_bytes(), expected.as_bytes())) {
        return Err(SignatureError::Mismatch);
    }
    if let Some(tol) = tolerance {
        if now.abs_diff(t) > tol {
            return Err(SignatureError::Stale);
        }
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The body for `format`.
pub fn payload(format: WebhookFormat, event: &GateEvent) -> Value {
    match format {
        WebhookFormat::Generic => event.to_json(),
        WebhookFormat::Slack => slack(event),
        WebhookFormat::Discord => discord(event),
    }
}

/// A human title for the kind, e.g. `Tool call denied: send_email`.
pub fn title(event: &GateEvent) -> String {
    let what = match event.kind {
        EventKind::DecisionDeny => "Tool call denied",
        EventKind::ApprovalRequested => "Approval requested",
        EventKind::ApprovalMismatch => "Approval receipt does not match",
        EventKind::SideEffectUnknown => "Side effect outcome unknown",
        EventKind::SideEffectReplayed => "Side effect replayed",
        EventKind::ShadowFinding => "Shadow mode: would deny",
        EventKind::ToolDrift => "Tool definition drifted",
        EventKind::AnchorFailed => "Ledger anchoring failed",
    };
    match &event.tool {
        Some(tool) => format!("{what}: {tool}"),
        None => what.to_string(),
    }
}

/// The labelled members a chat message shows, in order (unset ones left out).
fn fields(event: &GateEvent) -> Vec<(&'static str, String)> {
    let mut f = vec![("Reason", event.reason.clone())];
    if let Some(tool) = &event.tool {
        f.push(("Tool", tool.clone()));
    }
    if let Some(path) = &event.path {
        f.push(("Path", path.clone()));
    }
    if let Some(release) = &event.release {
        f.push(("Release", release.clone()));
    }
    if let Some(mode) = event.mode {
        f.push(("Mode", json!(mode).as_str().unwrap_or_default().to_string()));
    }
    if let Some(seq) = event.ledger_seq {
        f.push(("Ledger seq", seq.to_string()));
    }
    if let Some(op) = &event.operation_id {
        f.push(("Operation", op.clone()));
    }
    f
}

/// Slack's mrkdwn control characters.
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn slack(event: &GateEvent) -> Value {
    let title = title(event);
    let fields: Vec<Value> = fields(event)
        .into_iter()
        .map(|(k, v)| json!({ "type": "mrkdwn", "text": format!("*{k}*\n`{}`", slack_escape(&v)) }))
        .collect();
    let mut context = format!("{} · fingerprint `{}`", event.kind, event.fingerprint);
    if let Some(d) = &event.release_digest {
        context.push_str(&format!(" · release `{}`", slack_escape(d)));
    }
    json!({
        "text": slack_escape(&format!("CloakPipe: {title} ({})", event.reason)),
        "blocks": [
            { "type": "header", "text": { "type": "plain_text", "text": title } },
            { "type": "section", "fields": fields },
            { "type": "context", "elements": [ { "type": "mrkdwn", "text": context } ] },
        ],
    })
}

fn discord(event: &GateEvent) -> Value {
    // Red for a refusal, amber for what needs a human, blue otherwise.
    let color: u32 = match event.kind {
        EventKind::DecisionDeny | EventKind::ApprovalMismatch | EventKind::ToolDrift | EventKind::AnchorFailed => 0xD9_3025,
        EventKind::ApprovalRequested | EventKind::SideEffectUnknown | EventKind::ShadowFinding => 0xE3_A008,
        EventKind::SideEffectReplayed => 0x3B_82F6,
    };
    let fields: Vec<Value> = fields(event).into_iter().map(|(k, v)| json!({ "name": k, "value": v, "inline": true })).collect();
    let mut description = format!("`{}`", event.kind);
    if let Some(d) = &event.release_digest {
        description.push_str(&format!(" · release `{d}`"));
    }
    json!({
        "username": "CloakPipe",
        "embeds": [{
            "title": title(event),
            "description": description,
            "color": color,
            "fields": fields,
            "footer": { "text": event.fingerprint },
            "timestamp": event.ts,
        }],
    })
}
