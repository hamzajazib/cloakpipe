//! OpenTelemetry export (`mcp-proxy --otel-endpoint http://collector:4318`):
//! one span per gate decision, allows included, sent as OTLP/HTTP JSON to
//! `<endpoint>/v1/traces` in batches from a background thread.
//!
//! Each span is named `cloakpipe.decision` (resource `service.name` =
//! `cloakpipe-gate`) and carries only what the ledger may:
//!
//! | attribute | value |
//! |---|---|
//! | `cloakpipe.decision` | `allow`, `deny` or `require_approval` |
//! | `cloakpipe.reason` | the reason code (`ok` for an allow) |
//! | `cloakpipe.tool` | the tool, when recordable |
//! | `cloakpipe.path` | the contract path of an argument denial |
//! | `cloakpipe.release` | the release name |
//! | `cloakpipe.manifest_digest` | the manifest digest (`sha256:<hex>`) |
//! | `cloakpipe.policy_digest` | the Cedar policy digest, when there is one |
//! | `cloakpipe.mode` | `enforce` or `shadow` |
//! | `cloakpipe.forwarded` | whether the call reached the tool |
//! | `cloakpipe.operation_id` | the side-effect operation, if any |
//! | `cloakpipe.ledger.seq`, `cloakpipe.ledger.entry_hash` | the decision's ledger entry |
//! | `cloakpipe.event`, `cloakpipe.fingerprint` | the event the decision raised, if any |
//!
//! A refused call is an error span (status code 2). No argument value, tool
//! result or credential is ever an attribute. The OTLP JSON is written by
//! hand (no OpenTelemetry SDK); each span is its own trace.

use super::delivery::{client, post_with_retry, Post, Queue, Retry};
use super::{DecisionRecord, EventSink};
use cloakpipe_ledger::decision::Decision;
use serde_json::{json, Value};
use std::time::Duration;

/// The resource's `service.name`.
pub const SERVICE_NAME: &str = "cloakpipe-gate";
/// The span name.
pub const SPAN_NAME: &str = "cloakpipe.decision";

/// Where and how spans go.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// The full traces URL (`.../v1/traces`).
    pub url: String,
    pub service_name: String,
    /// Per request (default 5 s).
    pub timeout: Duration,
    /// Tries per batch (default 3).
    pub tries: u32,
    pub backoff: Duration,
    /// Spans queued before new ones are dropped (default 4096).
    pub capacity: usize,
    /// Spans per request at most (default 256).
    pub max_batch: usize,
}

impl OtelConfig {
    /// `endpoint` is the collector's OTLP/HTTP base URL (as
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`, e.g. `http://localhost:4318`); `/v1/traces`
    /// is appended unless it is already there.
    pub fn new(endpoint: &str) -> Self {
        let base = endpoint.trim_end_matches('/');
        let url = if base.ends_with("/v1/traces") { base.to_string() } else { format!("{base}/v1/traces") };
        Self {
            url,
            service_name: SERVICE_NAME.to_string(),
            timeout: Duration::from_secs(5),
            tries: 3,
            backoff: Duration::from_millis(500),
            capacity: 4096,
            max_batch: 256,
        }
    }
}

/// An [`EventSink`] exporting a span per decision.
pub struct OtelSink {
    queue: Queue<DecisionRecord>,
}

impl OtelSink {
    pub fn new(cfg: OtelConfig) -> Self {
        let mut http = None;
        let queue = Queue::spawn("otel", cfg.capacity, cfg.max_batch, move |batch: Vec<DecisionRecord>| {
            if http.is_none() {
                http = client(cfg.timeout);
            }
            let Some(http) = &http else { return };
            let body = match serde_json::to_vec(&traces(&cfg.service_name, &batch)) {
                Ok(b) => b,
                Err(_) => return,
            };
            let headers = Vec::new;
            let retry = Retry { tries: cfg.tries, backoff: cfg.backoff };
            if let Err(e) = post_with_retry(http, &Post { url: &cfg.url, body: &body, headers: &headers }, retry) {
                eprintln!("warning: cloakpipe otel: {} span(s) not exported: {e}", batch.len());
            }
        });
        Self { queue }
    }

    /// Spans dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.queue.dropped()
    }
}

impl EventSink for OtelSink {
    /// Events are not spans of their own: the decision that raised one
    /// carries its kind and fingerprint.
    fn emit(&self, _event: &super::GateEvent) {}

    fn decision(&self, record: &DecisionRecord) {
        self.queue.push(record.clone());
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.queue.flush(timeout)
    }
}

/// An OTLP/HTTP JSON `ExportTraceServiceRequest` for `records`.
pub fn traces(service_name: &str, records: &[DecisionRecord]) -> Value {
    let spans: Vec<Value> = records.iter().map(span).collect();
    json!({
        "resourceSpans": [{
            "resource": { "attributes": [string("service.name", service_name)] },
            "scopeSpans": [{
                "scope": { "name": "cloakpipe", "version": env!("CARGO_PKG_VERSION") },
                "spans": spans,
            }],
        }],
    })
}

fn span(r: &DecisionRecord) -> Value {
    let decision = match r.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::RequireApproval => "require_approval",
    };
    let mut attrs = vec![string("cloakpipe.decision", decision), string("cloakpipe.reason", &r.reason)];
    let optional = [
        ("cloakpipe.tool", &r.tool),
        ("cloakpipe.path", &r.path),
        ("cloakpipe.release", &r.release),
        ("cloakpipe.manifest_digest", &r.release_digest),
        ("cloakpipe.policy_digest", &r.policy_version),
        ("cloakpipe.operation_id", &r.operation_id),
        ("cloakpipe.ledger.entry_hash", &r.entry_hash),
        ("cloakpipe.fingerprint", &r.fingerprint),
    ];
    for (k, v) in optional {
        if let Some(v) = v {
            attrs.push(string(k, v));
        }
    }
    if let Some(mode) = r.mode {
        attrs.push(string("cloakpipe.mode", json!(mode).as_str().unwrap_or_default()));
    }
    attrs.push(json!({ "key": "cloakpipe.forwarded", "value": { "boolValue": r.forwarded } }));
    if let Some(seq) = r.ledger_seq {
        // OTLP JSON carries a 64-bit int as a decimal string.
        attrs.push(json!({ "key": "cloakpipe.ledger.seq", "value": { "intValue": seq.to_string() } }));
    }
    if let Some(kind) = r.event {
        attrs.push(string("cloakpipe.event", kind.as_str()));
    }
    // A refusal is an error; a shadow-mode would-deny was forwarded and is not.
    let status = if r.decision != Decision::Allow && !r.forwarded {
        json!({ "code": 2, "message": r.reason })
    } else {
        json!({ "code": 0 })
    };
    json!({
        "traceId": random_hex(16),
        "spanId": random_hex(8),
        "name": SPAN_NAME,
        "kind": 1,
        "startTimeUnixNano": r.start_unix_nanos.to_string(),
        "endTimeUnixNano": r.end_unix_nanos.max(r.start_unix_nanos).to_string(),
        "attributes": attrs,
        "status": status,
    })
}

fn string(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    // An all-zero id is invalid in OTLP.
    while b.iter().all(|x| *x == 0) {
        rand::thread_rng().fill_bytes(&mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}
