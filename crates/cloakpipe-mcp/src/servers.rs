//! The upstream MCP servers the gate is the client of.
//!
//! With more than one server (`mcp-proxy --server NAME=COMMAND …`) or a
//! tools lock, the gate does not pass the agent's handshake through: at
//! start-up it initializes every server itself (as client
//! `cloakpipe-gate`, declaring no client capabilities) and lists each one's
//! tools, following `nextCursor` to the last page. What it found
//! ([`ServerTools`]) is what the interceptor routes and pins against
//! ([`crate::Interceptor::with_servers`]); `cloakpipe tools pin` writes it
//! into a lock ([`list_servers`]).

use crate::proxy::{Upstream, UpstreamTransport};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The MCP protocol version the gate asks each server for.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// The `clientInfo` / `serverInfo` name the gate uses.
pub const GATE_NAME: &str = "cloakpipe-gate";

/// How long a server may take to answer each start-up request.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// At most this many `tools/list` pages are read from one server.
pub const MAX_PAGES: usize = 1000;

/// What one server said at start-up.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerTools {
    /// The server's name (`--server NAME=…`; `default` for `--upstream`).
    pub name: String,
    /// Its `initialize` result.
    pub init: Value,
    /// Its tools, every page, in the order it listed them.
    pub tools: Vec<Value>,
}

/// Is `name` usable as a server name? Letters, digits, `-` and `_`, without
/// `__` (the separator of a per-server tool name, `<server>__<tool>`).
pub fn check_server_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("a server name may not be empty".into());
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(format!("server name {name:?}: use letters, digits, '-' and '_' only"));
    }
    if name.contains("__") {
        return Err(format!("server name {name:?}: '__' separates a server from a tool name (<server>__<tool>)"));
    }
    Ok(())
}

/// Tool names more than one server lists. Each one `declares` (the
/// manifest) per server as `<server>__<tool>` is served that way: those are
/// the first set. Each other one is a collision the gate refuses to start
/// on: the second, one message per tool.
pub fn collisions(listing: &[ServerTools], declares: &dyn Fn(&str) -> bool) -> (HashSet<String>, Vec<String>) {
    let mut owners: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, s) in listing.iter().enumerate() {
        for name in s.tools.iter().filter_map(|t| t.get("name").and_then(Value::as_str)) {
            let o = owners.entry(name).or_default();
            if !o.contains(&i) {
                o.push(i);
            }
        }
    }
    let (mut namespaced, mut refused) = (HashSet::new(), Vec::new());
    for (tool, o) in owners.iter().filter(|(_, o)| o.len() > 1) {
        let per_server: Vec<String> = o.iter().map(|&i| format!("{}__{tool}", listing[i].name)).collect();
        if per_server.iter().any(|n| declares(n)) {
            namespaced.insert(tool.to_string());
        } else {
            let servers: Vec<&str> = o.iter().map(|&i| listing[i].name.as_str()).collect();
            refused.push(format!(
                "tool {tool:?} is served by {}: declare it per server in the manifest as {} to serve each under that name",
                servers.join(" and "),
                per_server.join(", ")
            ));
        }
    }
    (namespaced, refused)
}

/// A stdio server the gate spawned: its stdin, and its stdout as lines (read
/// on a thread of its own, so a silent server cannot hang start-up).
pub(crate) struct StdioServer {
    pub(crate) name: String,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl StdioServer {
    pub(crate) fn spawn(upstream: &Upstream) -> Result<Self> {
        let UpstreamTransport::Stdio { command } = &upstream.transport else {
            bail!("server {}: the gate lists and pins stdio servers only (not an MCP server over HTTP, yet)", upstream.name);
        };
        anyhow::ensure!(!command.is_empty(), "the command of server {} is empty", upstream.name);
        let mut child = Command::new(&command[0])
            .args(&command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // server logs pass through to our stderr
            .spawn()
            .with_context(|| format!("failed to spawn MCP server {}: {command:?}", upstream.name))?;
        let stdin = child.stdin.take().context("server has no stdin")?;
        let stdout = child.stdout.take().context("server has no stdout")?;
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self { name: upstream.name.clone(), child: Some(child), stdin: Some(stdin), lines })
    }

    /// Initialize the server and list every page of its tools.
    pub(crate) fn discover(&mut self, timeout: Duration) -> Result<ServerTools> {
        let params = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": GATE_NAME, "version": env!("CARGO_PKG_VERSION") },
        });
        let init = self.request(1, "initialize", Some(params), timeout)?;
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..MAX_PAGES {
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let result = self.request(2 + page as u64, "tools/list", params, timeout)?;
            if let Some(list) = result.get("tools").and_then(Value::as_array) {
                tools.extend(list.iter().cloned());
            }
            match result.get("nextCursor").and_then(Value::as_str).filter(|c| !c.is_empty()) {
                Some(next) if cursor.as_deref() != Some(next) => cursor = Some(next.to_string()),
                _ => return Ok(ServerTools { name: self.name.clone(), init, tools }),
            }
        }
        bail!("server {}: tools/list did not end after {MAX_PAGES} pages", self.name)
    }

    fn send(&mut self, msg: &Value) -> Result<()> {
        let stdin = self.stdin.as_mut().context("server stdin closed")?;
        let mut line = msg.to_string();
        line.push('\n');
        stdin.write_all(line.as_bytes()).and_then(|_| stdin.flush()).with_context(|| format!("server {} closed its stdin", self.name))
    }

    /// One request; its result. Anything else the server sends meanwhile
    /// (logs, notifications) is skipped.
    fn request(&mut self, id: u64, method: &str, params: Option<Value>, timeout: Duration) -> Result<Value> {
        let mut msg = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if let Some(params) = params {
            msg["params"] = params;
        }
        self.send(&msg)?;
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(left) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => bail!("server {} did not answer {method} within {}s", self.name, timeout.as_secs()),
                Err(RecvTimeoutError::Disconnected) => bail!("server {} exited before answering {method}", self.name),
            };
            let Ok(reply) = serde_json::from_str::<Value>(&line) else { continue };
            if reply.get("method").is_some() || reply.get("id") != Some(&json!(id)) {
                continue;
            }
            if let Some(error) = reply.get("error") {
                bail!("server {} refused {method}: {error}", self.name);
            }
            return Ok(reply.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Hand the running server over: its process, stdin and stdout lines.
    pub(crate) fn into_parts(mut self) -> (Child, ChildStdin, Receiver<String>) {
        let child = self.child.take().expect("spawned");
        let stdin = self.stdin.take().expect("spawned");
        // An empty, closed receiver stays behind for `Drop`.
        let lines = std::mem::replace(&mut self.lines, std::sync::mpsc::channel().1);
        (child, stdin, lines)
    }

    /// Close its stdin and give it a few seconds to exit (then `Drop`
    /// stops it).
    pub(crate) fn close(mut self) {
        self.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                Ok(None) => return,
                _ => {
                    self.child = None;
                }
            }
        }
    }
}

impl Drop for StdioServer {
    /// A server not handed over (start-up failed) is stopped.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn `upstreams`, initialize each, list its tools, then stop them all
/// (`cloakpipe tools pin` / `tools diff`).
pub fn list_servers(upstreams: &[Upstream], timeout: Duration) -> Result<Vec<ServerTools>> {
    let mut servers = upstreams.iter().map(StdioServer::spawn).collect::<Result<Vec<_>>>()?;
    let mut listed = Vec::new();
    for server in &mut servers {
        listed.push(server.discover(timeout)?);
    }
    for server in servers {
        server.close();
    }
    Ok(listed)
}
