//! MCP over HTTP (Streamable HTTP, spec rev 2025-06-18), both sides of the
//! gate:
//!
//! - `cloakpipe mcp-proxy --listen ADDR`: the agent speaks MCP over HTTP to
//!   the gate (`POST /mcp`), which fronts a stdio upstream.
//! - `cloakpipe mcp-proxy --upstream-url URL`: the gate is the HTTP client of
//!   an upstream MCP server (JSON and SSE responses), the agent on stdio.
//!
//! Every `tools/call` gets the same decision, refusal and ledger entry as
//! over stdio. The upstreams are local stand-ins (127.0.0.1, no network).
//!
//! Default build only: the legacy `certification` build refuses every call
//! of an uncertified release, which these scenarios do not set up.
#![cfg(not(feature = "certification"))]

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cloakpipe"));
    for var in [
        "CLOAKPIPE_RELEASE",
        "CLOAKPIPE_LEDGER_DB",
        "CLOAKPIPE_SIGNING_KEY",
        "CLOAKPIPE_OPERATIONS_DB",
        "CLOAKPIPE_TASK_CONTEXT",
        "CLOAKPIPE_STATE_DB",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// A file of the support-agent example (examples/support-agent).
fn example(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples").join("support-agent").join(name).to_string_lossy().into_owned()
}

/// The gate flags for the support-agent example, its state in `dir`.
fn example_gate(dir: &Path) -> Vec<String> {
    [
        "--manifest", &example("cloakpipe.manifest.yaml"),
        "--task-context", &example("task-context.json"),
        "--operations-db", &dir.join("ops.db").to_string_lossy(),
    ]
    .map(String::from)
    .to_vec()
}

fn rpc(id: Value, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn tool_call(id: Value, tool: &str, arguments: Value) -> Value {
    rpc(id, "tools/call", json!({"name": tool, "arguments": arguments}))
}

fn initialize(id: Value) -> Value {
    rpc(id, "initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}))
}

fn email(to: &str) -> Value {
    json!({"ticket_id": "T-1042", "to": to, "subject": "Your refund", "body": "Hi Dana, your refund for T-1042 is on its way."})
}

/// Run the stdio gate (no HTTP) in front of the example's mock upstream:
/// the agent messages it answers.
fn stdio_proxy(dir: &Path, lines: &[Value]) -> Vec<Value> {
    let upstream = format!("python3 {}", example("mock_upstream.py"));
    let mut child = bin()
        .current_dir(dir)
        .args(["mcp-proxy", "--upstream", &upstream])
        .args(example_gate(dir))
        .env("CLOAKPIPE_HOME", dir.join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

// ── the agent side: `mcp-proxy --listen` ────────────────────────────────

/// A running `mcp-proxy --listen 127.0.0.1:0`; killed on drop.
struct Listener {
    child: Child,
    base: String,
    stderr: Arc<Mutex<String>>,
    log: PathBuf,
}

impl Listener {
    /// Start the HTTP gate in front of the example's mock upstream.
    fn start(dir: &Path, extra: &[String]) -> Self {
        let log = dir.join("upstream.jsonl");
        let _ = std::fs::remove_file(&log);
        let upstream = format!("python3 {}", example("mock_upstream.py"));
        let mut child = bin()
            .current_dir(dir)
            .args(["mcp-proxy", "--listen", "127.0.0.1:0", "--upstream", &upstream])
            .args(extra)
            .env("MOCK_UPSTREAM_LOG", &log)
            .env("CLOAKPIPE_HOME", dir.join("home"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let stderr = stderr.clone();
            let pipe = child.stderr.take().unwrap();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines() {
                    let Ok(line) = line else { break };
                    if let Some(rest) = line.split("listening on ").nth(1) {
                        let _ = tx.send(rest.trim().trim_end_matches("/mcp").to_string());
                    }
                    stderr.lock().unwrap().push_str(&format!("{line}\n"));
                }
            });
        }
        let base = match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(base) => base,
            Err(_) => {
                let _ = child.kill();
                panic!("the listener never announced its address: {}", stderr.lock().unwrap());
            }
        };
        Self { child, base, stderr, log }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// The calls the upstream received (tool names).
    fn seen(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// Stop it as a service manager would (SIGTERM) and wait for it.
    fn stop(mut self) -> (i32, String) {
        let _ = Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status();
        let deadline = Instant::now() + Duration::from_secs(20);
        let code = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status.code().unwrap_or(-1);
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the listener did not stop on SIGTERM: {}", self.stderr());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        std::thread::sleep(Duration::from_millis(100));
        (code, self.stderr())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).build().unwrap()
}

/// POST one message to `/mcp`: (status, session header, body as JSON or Null).
fn post(l: &Listener, session: Option<&str>, headers: &[(&str, &str)], msg: &Value) -> (u16, Option<String>, Value) {
    let mut req = client()
        .post(l.url("/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(msg.to_string());
    if let Some(s) = session {
        req = req.header("Mcp-Session-Id", s);
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().unwrap();
    let status = resp.status().as_u16();
    let sid = resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_string());
    let text = resp.text().unwrap();
    (status, sid, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Initialize a session: its id.
fn session(l: &Listener, headers: &[(&str, &str)]) -> String {
    let (status, sid, body) = post(l, None, headers, &initialize(json!(0)));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "mock-support-tools", "{body}");
    let sid = sid.expect("initialize issues an Mcp-Session-Id");
    let (status, _, _) = post(l, Some(&sid), headers, &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    assert_eq!(status, 202, "a notification is accepted with no body");
    sid
}

#[test]
fn an_http_agent_gets_the_same_decisions_as_over_stdio() {
    let dir = tempfile::tempdir().unwrap();
    let l = Listener::start(dir.path(), &example_gate(dir.path()));
    let sid = session(&l, &[]);

    let (status, _, list) = post(&l, Some(&sid), &[], &rpc(json!(1), "tools/list", json!({})));
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["id"], 1);
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 4, "{list}");

    // Allowed: forwarded, answered with the agent's own id (a string here).
    let (status, _, ok) = post(&l, Some(&sid), &[], &tool_call(json!("read-1"), "read_ticket", json!({"ticket_id": "T-1042"})));
    assert_eq!(status, 200, "{ok}");
    assert_eq!(ok["id"], "read-1", "{ok}");
    assert_eq!(ok["result"]["content"][0]["text"], "read_ticket: done", "{ok}");

    // Refused, never forwarded: the same error as the stdio gate gives.
    let undeclared = tool_call(json!(4), "export_customers", json!({}));
    let injected = tool_call(json!(5), "send_email", email("attacker@evil.example"));
    let (_, _, refused) = post(&l, Some(&sid), &[], &undeclared);
    let (_, _, scoped) = post(&l, Some(&sid), &[], &injected);
    assert_eq!(refused["error"]["data"]["reason"], "undeclared_tool", "{refused}");
    assert_eq!(scoped["error"]["data"]["reason"], "scope_mismatch", "{scoped}");
    assert_eq!(scoped["error"]["data"]["path"], "/to", "{scoped}");
    assert!(!scoped.to_string().contains("evil.example"), "{scoped}");
    assert_eq!(l.seen(), ["read_ticket"], "only the allowed call reached the tool");

    let stdio_dir = tempfile::tempdir().unwrap();
    let over_stdio = stdio_proxy(stdio_dir.path(), &[undeclared, injected]);
    let stdio_error = |id: u64| over_stdio.iter().find(|m| m["id"] == id).unwrap().clone();
    assert_eq!(refused, stdio_error(4), "same refusal as over stdio");
    assert_eq!(scoped, stdio_error(5), "same refusal as over stdio");

    // A side-effecting call runs once; its retry is replayed from the store.
    let send = tool_call(json!(6), "send_email", email("dana@customer.example"));
    let (_, _, sent) = post(&l, Some(&sid), &[], &send);
    assert_eq!(sent["result"]["content"][0]["text"], "send_email: done", "{sent}");
    let (_, _, again) = post(&l, Some(&sid), &[], &tool_call(json!(7), "send_email", email("dana@customer.example")));
    assert_eq!(again["id"], 7, "{again}");
    assert_eq!(again["result"]["content"][0]["text"], "send_email: done", "{again}");
    assert_eq!(l.seen(), ["read_ticket", "send_email"], "the retry was not sent again");
    let (code, err) = l.stop();
    assert_eq!(code, 0, "{err}");
}

#[test]
fn sessions_are_issued_on_initialize_and_required_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let l = Listener::start(dir.path(), &example_gate(dir.path()));
    let list = rpc(json!(1), "tools/list", json!({}));
    let (status, _, _) = post(&l, None, &[], &list);
    assert_eq!(status, 400, "no session: bad request");
    let (status, _, _) = post(&l, Some("not-a-session"), &[], &list);
    assert_eq!(status, 404, "an unknown session is not found");
    let sid = session(&l, &[]);
    assert_eq!(post(&l, Some(&sid), &[], &list).0, 200);
    // Another agent gets its own session, both work side by side.
    let other = session(&l, &[]);
    assert_ne!(sid, other);
    assert_eq!(post(&l, Some(&other), &[], &list).0, 200);

    // GET (a server-to-client stream) is not offered.
    let resp = client().get(l.url("/mcp")).header("Mcp-Session-Id", &sid).send().unwrap();
    assert_eq!(resp.status().as_u16(), 405);
    // DELETE ends the session.
    let resp = client().delete(l.url("/mcp")).header("Mcp-Session-Id", &sid).send().unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    assert_eq!(post(&l, Some(&sid), &[], &list).0, 404, "an ended session is gone");
    assert_eq!(post(&l, Some(&other), &[], &list).0, 200, "the other session is untouched");

    // A cross-site page cannot drive the gate (DNS rebinding).
    let (status, _, _) = post(&l, Some(&other), &[("Origin", "https://evil.example")], &list);
    assert_eq!(status, 403);
    let (status, _, _) = post(&l, Some(&other), &[("Origin", "http://localhost:3000")], &list);
    assert_eq!(status, 200, "a local origin is allowed");
}

#[test]
fn health_reports_the_release() {
    let dir = tempfile::tempdir().unwrap();
    let l = Listener::start(dir.path(), &example_gate(dir.path()));
    let resp = client().get(l.url("/health")).send().unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let health: Value = resp.json().unwrap();
    assert_eq!(health["status"], "ok", "{health}");
    assert_eq!(health["release"], "support-agent", "{health}");
    assert!(health["release_digest"].as_str().unwrap().starts_with("sha256:"), "{health}");
    assert!(l.stderr().contains("listening on http://127.0.0.1:"), "{}", l.stderr());
}

#[test]
fn a_listen_token_is_required_on_every_mcp_request() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "s3cret-token\n").unwrap();
    let mut flags = example_gate(dir.path());
    flags.extend(["--listen-token-file".to_string(), token.to_string_lossy().into_owned()]);
    let l = Listener::start(dir.path(), &flags);
    let (status, _, _) = post(&l, None, &[], &initialize(json!(0)));
    assert_eq!(status, 401, "no token");
    let (status, _, _) = post(&l, None, &[("Authorization", "Bearer wrong")], &initialize(json!(0)));
    assert_eq!(status, 401, "wrong token");
    let auth = [("Authorization", "Bearer s3cret-token")];
    let sid = session(&l, &auth);
    let (status, _, _) = post(&l, Some(&sid), &[], &rpc(json!(1), "tools/list", json!({})));
    assert_eq!(status, 401, "the session alone is not enough");
    let (status, _, _) = post(&l, Some(&sid), &auth, &rpc(json!(1), "tools/list", json!({})));
    assert_eq!(status, 200);
    // Health stays open (container health checks carry no token).
    assert_eq!(client().get(l.url("/health")).send().unwrap().status().as_u16(), 200);
}

#[test]
fn the_ledger_of_http_calls_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let l = Listener::start(d, &example_gate(d));
    let sid = session(&l, &[]);
    post(&l, Some(&sid), &[], &tool_call(json!(1), "read_ticket", json!({"ticket_id": "T-1042"})));
    post(&l, Some(&sid), &[], &tool_call(json!(2), "export_customers", json!({})));
    let (code, err) = l.stop();
    assert_eq!(code, 0, "{err}");

    let run = |args: &[&str]| {
        let out = bin().current_dir(d).args(args).env("CLOAKPIPE_HOME", d.join("home")).output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let (code, _, err) = run(&["ledger", "export", "--out", "p.tar"]);
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = run(&["verify", "p.tar"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("denials: 1,"), "the refusal is in the verified pack: {out}");
}

// ── the upstream side: `mcp-proxy --upstream-url` ───────────────────────

/// One request the stub upstream received.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    headers: HashMap<String, String>,
    body: Value,
}

/// A Streamable HTTP MCP server stand-in on 127.0.0.1: answers with JSON,
/// or with an SSE stream (a log notification, then the response). Calls to
/// a tool in `fail` get an HTTP 500.
struct StubServer {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

const STUB_SESSION: &str = "stub-session-1";

impl StubServer {
    fn start(sse: bool, fail: &'static [&'static str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        {
            let seen = seen.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { break };
                    let seen = seen.clone();
                    std::thread::spawn(move || serve(stream, sse, fail, &seen));
                }
            });
        }
        Self { url, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn calls(&self) -> Vec<String> {
        self.seen()
            .iter()
            .filter(|s| s.body["method"] == "tools/call")
            .map(|s| s.body["params"]["name"].as_str().unwrap().to_string())
            .collect()
    }
}

fn serve(stream: TcpStream, sse: bool, fail: &[&str], seen: &Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let method = request_line.split_whitespace().next().unwrap_or("").to_string();
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    seen.lock().unwrap().push(Seen { method: method.clone(), headers: headers.clone(), body: body.clone() });

    let respond = |stream: &mut TcpStream, status: &str, extra: &str, ctype: &str, payload: &str| {
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
            payload.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(payload.as_bytes());
        let _ = stream.flush();
    };
    if method == "DELETE" {
        return respond(&mut stream, "200 OK", "", "text/plain", "");
    }
    let rpc_method = body["method"].as_str().unwrap_or("");
    let Some(id) = body.get("id").filter(|_| !rpc_method.is_empty()).cloned() else {
        // A notification or a response: accepted.
        return respond(&mut stream, "202 Accepted", "", "text/plain", "");
    };
    let mut extra = String::new();
    let result = match rpc_method {
        "initialize" => {
            extra = format!("Mcp-Session-Id: {STUB_SESSION}\r\n");
            json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "stub-http", "version": "0"}})
        }
        _ if headers.get("mcp-session-id").map(String::as_str) != Some(STUB_SESSION) => {
            return respond(&mut stream, "404 Not Found", "", "text/plain", "no such session");
        }
        "tools/list" => json!({"tools": [{"name": "read_ticket", "inputSchema": {"type": "object"}}]}),
        "tools/call" => {
            let name = body["params"]["name"].as_str().unwrap_or("").to_string();
            if fail.contains(&name.as_str()) {
                return respond(&mut stream, "500 Internal Server Error", "", "text/plain", "boom");
            }
            json!({"content": [{"type": "text", "text": format!("{name}: done over http")}]})
        }
        _ => json!({}),
    };
    let reply = json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
    if sse {
        let log = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "working"}});
        let events = format!("event: message\ndata: {log}\n\nid: 1\nevent: message\ndata: {reply}\n\n");
        respond(&mut stream, "200 OK", &extra, "text/event-stream", &events);
    } else {
        respond(&mut stream, "200 OK", &extra, "application/json", &reply);
    }
}

/// Run the stdio gate against `--upstream-url`: (exit code, agent messages, stderr).
fn url_proxy(dir: &Path, url: &str, extra: &[&str], lines: &[Value]) -> (i32, Vec<Value>, String) {
    let mut child = bin()
        .current_dir(dir)
        .args(["mcp-proxy", "--upstream-url", url])
        .args(extra)
        .args(example_gate(dir))
        .env("CLOAKPIPE_HOME", dir.join("home"))
        .env("STUB_API_KEY", "key-from-env")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // One at a time, as an agent waits for each answer.
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<Value>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Ok(v) = serde_json::from_str(&line) {
                let _ = tx.send(v);
            }
        }
    });
    let mut msgs = Vec::new();
    for line in lines {
        stdin.write_all(format!("{line}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
        let Some(id) = line.get("id") else { continue };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(m) => {
                    let done = m.get("id") == Some(id);
                    msgs.push(m);
                    if done {
                        break;
                    }
                }
                Err(_) => continue,
            }
        }
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    msgs.extend(rx.try_iter());
    (out.status.code().unwrap_or(-1), msgs, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn answer(msgs: &[Value], id: u64) -> Value {
    msgs.iter().find(|m| m["id"] == id).cloned().unwrap_or_else(|| panic!("no answer for {id}: {msgs:?}"))
}

fn upstream_url_session(sse: bool) {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubServer::start(sse, &[]);
    let (code, msgs, err) = url_proxy(
        dir.path(),
        &stub.url,
        &["--upstream-header", "X-Api-Key: env:STUB_API_KEY", "--upstream-header", "X-Team: support"],
        &[
            initialize(json!(1)),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            rpc(json!(2), "tools/list", json!({})),
            tool_call(json!(3), "read_ticket", json!({"ticket_id": "T-1042"})),
            tool_call(json!(4), "export_customers", json!({})),
            tool_call(json!(5), "send_email", email("attacker@evil.example")),
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(answer(&msgs, 1)["result"]["serverInfo"]["name"], "stub-http", "{msgs:?}");
    assert_eq!(answer(&msgs, 2)["result"]["tools"][0]["name"], "read_ticket", "{msgs:?}");
    assert_eq!(answer(&msgs, 3)["result"]["content"][0]["text"], "read_ticket: done over http", "{msgs:?}");
    assert_eq!(answer(&msgs, 4)["error"]["data"]["reason"], "undeclared_tool", "{msgs:?}");
    assert_eq!(answer(&msgs, 5)["error"]["data"]["reason"], "scope_mismatch", "{msgs:?}");
    if sse {
        assert!(msgs.iter().any(|m| m["method"] == "notifications/message"), "SSE notifications are relayed: {msgs:?}");
    }
    assert_eq!(stub.calls(), ["read_ticket"], "refused calls never reach the server");

    let seen = stub.seen();
    let posts: Vec<&Seen> = seen.iter().filter(|s| s.method == "POST").collect();
    assert!(posts.len() >= 4, "{seen:?}");
    for s in &posts {
        assert_eq!(s.headers.get("x-api-key").map(String::as_str), Some("key-from-env"), "{s:?}");
        assert_eq!(s.headers.get("x-team").map(String::as_str), Some("support"), "{s:?}");
        assert!(s.headers.get("accept").unwrap().contains("text/event-stream"), "{s:?}");
    }
    assert!(!posts[0].headers.contains_key("mcp-session-id"), "initialize carries no session");
    for s in &posts[1..] {
        assert_eq!(s.headers.get("mcp-session-id").map(String::as_str), Some(STUB_SESSION), "{s:?}");
    }
    assert!(!err.contains("key-from-env"), "a header value is never logged: {err}");
}

#[test]
fn an_upstream_url_answering_json_is_gated() {
    upstream_url_session(false);
}

#[test]
fn an_upstream_url_answering_sse_is_gated() {
    upstream_url_session(true);
}

#[test]
fn an_upstream_http_error_fails_the_call_closed() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubServer::start(false, &["read_ticket", "send_email"]);
    let (code, msgs, err) = url_proxy(
        dir.path(),
        &stub.url,
        &[],
        &[
            initialize(json!(1)),
            tool_call(json!(2), "read_ticket", json!({"ticket_id": "T-1042"})),
            tool_call(json!(3), "send_email", email("dana@customer.example")),
            tool_call(json!(4), "send_email", email("dana@customer.example")),
        ],
    );
    assert_eq!(code, 0, "{err}");
    let read = answer(&msgs, 2);
    assert_eq!(read["error"]["data"]["reason"], "upstream_unavailable", "{read}");
    // A side effect sent but never answered may or may not have happened:
    // unknown until reconciled, and a retry is refused rather than re-sent.
    let sent = answer(&msgs, 3);
    assert_eq!(sent["error"]["data"]["reason"], "operation_unknown", "{sent}");
    let retry = answer(&msgs, 4);
    assert_eq!(retry["error"]["data"]["reason"], "reconcile_before_retry", "{retry}");
    assert_eq!(stub.calls(), ["read_ticket", "send_email"], "the retry was not sent");

    // The unknown outcome is recorded in the ledger.
    let out = bin()
        .current_dir(dir.path())
        .args(["ledger", "export", "--out", "p.tar"])
        .env("CLOAKPIPE_HOME", dir.path().join("home"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = bin().current_dir(dir.path()).args(["verify", "p.tar"]).output().unwrap();
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{report}");
    assert!(report.contains("unknown side effects: 1"), "{report}");
}

#[test]
fn upstream_and_upstream_url_are_mutually_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .current_dir(dir.path())
        .args(["mcp-proxy", "--upstream", "cat", "--upstream-url", "http://127.0.0.1:9/mcp"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    let out = bin().current_dir(dir.path()).args(["mcp-proxy"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "one of them is required: {}", String::from_utf8_lossy(&out.stderr));
    let out = bin()
        .current_dir(dir.path())
        .args(["mcp-proxy", "--upstream-url", "http://127.0.0.1:9/mcp", "--upstream-header", "no colon here"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
}
