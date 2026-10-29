//! A stub approval broker for the broker tests: it speaks the open approval
//! broker protocol (docs/APPROVALS.md) on 127.0.0.1:0, checks every
//! request's `CloakPipe-Signature`, keeps the requests it was sent, and
//! signs receipts with `cloakpipe-receipt` when a test approves one. No
//! internet.

#![allow(dead_code)]

use cloakpipe_mcp::events::webhook::verify_signature;
use cloakpipe_receipt::approval::{sign_approval, Approval};
use cloakpipe_release::action::ToolCallFingerprint;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One request the stub got.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    /// The request target: path and query, as sent.
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// Whether its signature verified under the stub's secret.
    pub signed: bool,
}

impl Seen {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Default)]
struct State {
    seen: Vec<Seen>,
    /// The requests filed, by fingerprint (`sha256:<hex>`).
    requests: HashMap<String, Value>,
    /// Finished records, in the order they finished; the cursor is an index.
    finished: Vec<Value>,
    /// Answer every request with this status instead (an outage).
    fail_with: Option<u16>,
    /// `GET .../approver-keys` returns these.
    keys: Vec<Value>,
}

pub struct StubBroker {
    /// `http://127.0.0.1:<port>`
    pub base: String,
    pub gate_id: String,
    secret: Vec<u8>,
    state: Arc<Mutex<State>>,
}

impl StubBroker {
    pub fn start(secret: &[u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let gate_id = "g-test-1".to_string();
        {
            let (state, secret, gate_id) = (state.clone(), secret.to_vec(), gate_id.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let (state, secret, gate_id) = (state.clone(), secret.clone(), gate_id.clone());
                    std::thread::spawn(move || serve(stream, &state, &secret, &gate_id));
                }
            });
        }
        Self { base, gate_id, secret: secret.to_vec(), state }
    }

    /// What `--approvals-url` is: `<base>/v1/gates/<id>`.
    pub fn url(&self) -> String {
        format!("{}/v1/gates/{}", self.base, self.gate_id)
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    pub fn posts(&self) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.method == "POST").collect()
    }

    pub fn polls(&self) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.method == "GET").collect()
    }

    /// Wait until at least `n` POSTs arrived.
    pub fn wait_for_posts(&self, n: usize, timeout: Duration) -> Vec<Seen> {
        let deadline = Instant::now() + timeout;
        loop {
            let got = self.posts();
            if got.len() >= n || Instant::now() > deadline {
                return got;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The request filed for `fingerprint` (`sha256:<hex>`).
    pub fn request(&self, fingerprint: &str) -> Option<Value> {
        self.state.lock().unwrap().requests.get(fingerprint).cloned()
    }

    /// What `GET <url>/approver-keys` lists (`{keyid, publicKey}` objects).
    pub fn set_keys(&self, keys: Vec<Value>) {
        self.state.lock().unwrap().keys = keys;
    }

    /// Answer everything with `status` (`None`: back to normal).
    pub fn fail_with(&self, status: Option<u16>) {
        self.state.lock().unwrap().fail_with = status;
    }

    /// Approve the request for `fingerprint` as the approver `key` (keyid
    /// `keyid`), valid for `ttl` seconds from `approved_at_offset` seconds
    /// from now. Returns the envelope.
    pub fn approve_with(&self, fingerprint: &str, key: &SigningKey, keyid: &str, approved_at_offset: i64, ttl: i64) -> Value {
        let req = self.request(fingerprint).expect("a request for this fingerprint");
        let hex = fingerprint.trim_start_matches("sha256:");
        let mut raw = [0u8; 32];
        hex::decode_to_slice(hex, &mut raw).unwrap();
        let fp = ToolCallFingerprint(raw);
        let approved = chrono::Utc::now() + chrono::Duration::seconds(approved_at_offset);
        let a = Approval {
            release: req["release_digest"].as_str().unwrap().to_string(),
            tool: req["tool"].as_str().unwrap().to_string(),
            task_id: req["task_id"].as_str().unwrap().to_string(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            approver: keyid.to_string(),
            approved_at: rfc3339(approved),
            not_after: rfc3339(approved + chrono::Duration::seconds(ttl)),
        };
        let envelope = serde_json::to_value(sign_approval(&fp, &a, key, keyid)).unwrap();
        self.finish(json!({
            "request_id": req_id(fingerprint),
            "fingerprint": fingerprint,
            "status": "approved",
            "envelope": envelope,
        }));
        envelope
    }

    /// Approve as `key` for the request's ttl (900 s without one).
    pub fn approve(&self, fingerprint: &str, key: &SigningKey, keyid: &str) -> Value {
        let ttl = self.request(fingerprint).and_then(|r| r["ttl_secs"].as_i64()).unwrap_or(900);
        self.approve_with(fingerprint, key, keyid, 0, ttl)
    }

    pub fn deny(&self, fingerprint: &str, not_after: Option<&str>) {
        let mut rec = json!({
            "request_id": req_id(fingerprint),
            "fingerprint": fingerprint,
            "status": "denied",
            "decided_at": rfc3339(chrono::Utc::now()),
        });
        if let Some(t) = not_after {
            rec["not_after"] = json!(t);
        }
        self.finish(rec);
    }

    pub fn expire(&self, fingerprint: &str) {
        self.finish(json!({ "request_id": req_id(fingerprint), "fingerprint": fingerprint, "status": "expired" }));
    }

    /// Report any record (a forged one, say).
    pub fn finish(&self, record: Value) {
        self.state.lock().unwrap().finished.push(record);
    }
}

pub fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn req_id(fingerprint: &str) -> String {
    format!("req-{}", &fingerprint.trim_start_matches("sha256:")[..12.min(fingerprint.len().saturating_sub(7))])
}

fn serve(stream: TcpStream, state: &Mutex<State>, secret: &[u8], gate_id: &str) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        let mut headers = HashMap::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut body = vec![0; len];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        // POST: the body is signed; GET: "GET <target>" is.
        let signed_bytes = if method == "GET" { format!("GET {target}").into_bytes() } else { body.clone() };
        let now = chrono::Utc::now().timestamp();
        let signed = headers
            .get("cloakpipe-signature")
            .is_some_and(|h| verify_signature(secret, h, &signed_bytes, now, Some(300)).is_ok());
        let (status, reply) = handle(state, &method, &target, &body, signed, gate_id);
        state.lock().unwrap().seen.push(Seen { method, target, headers, body, signed });
        let reply = reply.to_string();
        let msg = format!(
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{reply}",
            reply.len()
        );
        if stream.write_all(msg.as_bytes()).is_err() {
            return;
        }
    }
}

fn handle(state: &Mutex<State>, method: &str, target: &str, body: &[u8], signed: bool, gate_id: &str) -> (u16, Value) {
    let mut s = state.lock().unwrap();
    if let Some(code) = s.fail_with {
        return (code, json!({"error": "unavailable"}));
    }
    if !signed {
        return (401, json!({"error": "unsigned"}));
    }
    let base = format!("/v1/gates/{gate_id}/approvals");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if method == "GET" && path == format!("/v1/gates/{gate_id}/approver-keys") {
        return (200, json!({ "keys": s.keys }));
    }
    if path != base {
        return (404, json!({"error": "not found"}));
    }
    match method {
        "POST" => {
            let Ok(req) = serde_json::from_slice::<Value>(body) else { return (400, json!({"error": "not JSON"})) };
            let Some(fp) = req["fingerprint"].as_str().map(str::to_string) else { return (400, json!({"error": "no fingerprint"})) };
            // Idempotent per fingerprint: a finished one reports its status.
            let status = s
                .finished
                .iter()
                .rev()
                .find(|r| r["fingerprint"] == fp.as_str())
                .and_then(|r| r["status"].as_str())
                .unwrap_or("pending")
                .to_string();
            let status = if status == "expired" { "pending".to_string() } else { status };
            s.requests.insert(fp.clone(), req);
            (200, json!({ "request_id": req_id(&fp), "status": status }))
        }
        "GET" => {
            let since: usize = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("since="))
                .and_then(|c| c.strip_prefix("c-"))
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let items: Vec<Value> = s.finished.iter().skip(since).cloned().collect();
            (200, json!({ "cursor": format!("c-{}", s.finished.len()), "approvals": items }))
        }
        _ => (405, json!({"error": "method"})),
    }
}
