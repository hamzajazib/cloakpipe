//! The container image runs the gate by default: `ENTRYPOINT` is
//! `docker/gate-entrypoint.sh`, which turns `CLOAKPIPE_*` environment
//! variables into `cloakpipe mcp-proxy --listen …` flags, and passes any
//! other command (`start`, `verify`, …) to `cloakpipe` unchanged. The
//! Dockerfile and docker/compose.example.yaml are checked as text; the
//! entrypoint runs against a stub `cloakpipe` (which prints its arguments)
//! and against the real binary. No docker needed.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The variables the entrypoint reads, removed so the host's cannot leak in.
const VARS: &[&str] = &[
    "CLOAKPIPE_UPSTREAM_URL",
    "CLOAKPIPE_UPSTREAM",
    "CLOAKPIPE_UPSTREAM_HEADER",
    "CLOAKPIPE_MANIFEST",
    "CLOAKPIPE_LISTEN",
    "CLOAKPIPE_LISTEN_TOKEN_FILE",
    "CLOAKPIPE_INSECURE_NO_TOKEN",
    "CLOAKPIPE_WEBHOOK_URL",
    "CLOAKPIPE_WEBHOOK_SECRET_FILE",
    "CLOAKPIPE_WEBHOOK_FORMAT",
    "CLOAKPIPE_OTEL_ENDPOINT",
    "CLOAKPIPE_EVENTS_LOG",
    "CLOAKPIPE_TOOLS_LOCK",
];

/// Run the entrypoint with `args` and `env`, `cloakpipe` on PATH being a
/// stub that prints one argument per line.
fn entrypoint(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (Output, Vec<String>) {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let stub = bin.join("cloakpipe");
    std::fs::write(&stub, "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n").unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = Command::new("sh");
    cmd.arg(repo("docker/gate-entrypoint.sh")).args(args);
    for var in VARS {
        cmd.env_remove(var);
    }
    cmd.env("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let argv = String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect();
    (out, argv)
}

/// A manifest and a token file in `dir`, for the gate's defaults.
fn files(dir: &Path) -> (String, String) {
    let manifest = dir.join("cloakpipe.manifest.yaml");
    std::fs::write(&manifest, "release: docker\nversion: \"1\"\ntools:\n  read_ticket: {}\n").unwrap();
    let token = dir.join("listen.token");
    std::fs::write(&token, "a-long-random-token\n").unwrap();
    (manifest.to_string_lossy().into_owned(), token.to_string_lossy().into_owned())
}

fn flag<'a>(argv: &'a [String], name: &str) -> Option<&'a str> {
    argv.iter().position(|a| a == name).map(|i| argv[i + 1].as_str())
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn the_image_runs_the_gate_by_default() {
    let dockerfile = read("Dockerfile");
    let line = |prefix: &str| dockerfile.lines().find(|l| l.starts_with(prefix)).unwrap_or_else(|| panic!("no {prefix} line")).to_string();
    assert_eq!(line("ENTRYPOINT"), r#"ENTRYPOINT ["cloakpipe-entrypoint"]"#);
    assert_eq!(line("CMD"), r#"CMD ["gate"]"#);
    assert!(dockerfile.contains("COPY docker/gate-entrypoint.sh /usr/local/bin/cloakpipe-entrypoint"), "{dockerfile}");
    // Ledger, gate key and operations store live on the /data volume.
    for env in ["CLOAKPIPE_HOME=/data", "CLOAKPIPE_OPERATIONS_DB=/data/operations.db", "CLOAKPIPE_LISTEN=0.0.0.0:8900"] {
        assert!(dockerfile.lines().any(|l| l.starts_with("ENV ") && l.contains(env)), "ENV {env}: {dockerfile}");
    }
    assert!(dockerfile.contains("VOLUME [\"/data\"]"), "{dockerfile}");
    // The health check asks the gate's /health (no token needed), on the
    // port it listens on.
    let health = dockerfile.lines().skip_while(|l| !l.starts_with("HEALTHCHECK")).take(2).collect::<Vec<_>>().join("\n");
    assert!(health.contains("/health") && health.contains("CLOAKPIPE_LISTEN"), "{health}");
    // The old PII proxy keeps its bundled config.
    assert!(dockerfile.contains("COPY docker/cloakpipe.docker.toml /app/cloakpipe.toml"));
}

#[test]
fn the_gate_flags_come_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let (manifest, token) = files(dir.path());
    let secret = dir.path().join("webhook.secret");
    std::fs::write(&secret, "s3cret\n").unwrap();
    let (out, argv) = entrypoint(
        dir.path(),
        &["gate", "--tools-lock", "/app/cloakpipe.tools.lock"],
        &[
            ("CLOAKPIPE_MANIFEST", &manifest),
            ("CLOAKPIPE_LISTEN", "0.0.0.0:8900"),
            ("CLOAKPIPE_LISTEN_TOKEN_FILE", &token),
            ("CLOAKPIPE_UPSTREAM_URL", "https://tools.example.com/mcp"),
            ("CLOAKPIPE_UPSTREAM_HEADER", "Authorization: env:TOOLS_AUTH"),
            ("CLOAKPIPE_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X"),
            ("CLOAKPIPE_WEBHOOK_SECRET_FILE", secret.to_str().unwrap()),
            ("CLOAKPIPE_WEBHOOK_FORMAT", "slack"),
            ("CLOAKPIPE_OTEL_ENDPOINT", "http://otel:4318"),
            ("CLOAKPIPE_EVENTS_LOG", "/data/events.jsonl"),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(argv[0], "mcp-proxy", "{argv:?}");
    assert_eq!(flag(&argv, "--listen"), Some("0.0.0.0:8900"));
    assert_eq!(flag(&argv, "--manifest"), Some(manifest.as_str()));
    assert_eq!(flag(&argv, "--listen-token-file"), Some(token.as_str()));
    assert_eq!(flag(&argv, "--upstream-url"), Some("https://tools.example.com/mcp"));
    assert_eq!(flag(&argv, "--upstream-header"), Some("Authorization: env:TOOLS_AUTH"));
    assert_eq!(flag(&argv, "--webhook"), Some("https://hooks.slack.com/services/T/B/X"));
    assert_eq!(flag(&argv, "--webhook-secret-file"), Some(secret.to_str().unwrap()));
    assert_eq!(flag(&argv, "--webhook-format"), Some("slack"));
    assert_eq!(flag(&argv, "--otel-endpoint"), Some("http://otel:4318"));
    assert_eq!(flag(&argv, "--events-log"), Some("/data/events.jsonl"));
    // Arguments after `gate` are passed on.
    assert_eq!(flag(&argv, "--tools-lock"), Some("/app/cloakpipe.tools.lock"));
    assert!(!argv.iter().any(|a| a == "--upstream"), "{argv:?}");
}

#[test]
fn a_stdio_upstream_and_the_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let (manifest, token) = files(dir.path());
    let env = [
        ("CLOAKPIPE_MANIFEST", manifest.as_str()),
        ("CLOAKPIPE_LISTEN_TOKEN_FILE", token.as_str()),
        ("CLOAKPIPE_UPSTREAM", "npx -y @acme/tools"),
        ("CLOAKPIPE_TOOLS_LOCK", "/app/cloakpipe.tools.lock"),
    ];
    let (out, argv) = entrypoint(dir.path(), &[], &env);
    assert!(out.status.success(), "no command is `gate`: {}", stderr(&out));
    assert_eq!(flag(&argv, "--upstream"), Some("npx -y @acme/tools"), "one argument, split by the gate: {argv:?}");
    assert_eq!(flag(&argv, "--tools-lock"), Some("/app/cloakpipe.tools.lock"));
    assert_eq!(flag(&argv, "--listen"), Some("0.0.0.0:8900"), "the default address");
    for absent in ["--upstream-url", "--webhook", "--otel-endpoint", "--events-log", "--webhook-format"] {
        assert!(!argv.iter().any(|a| a == absent), "{absent}: {argv:?}");
    }
}

#[test]
fn the_gate_refuses_to_start_without_what_it_needs() {
    let dir = tempfile::tempdir().unwrap();
    let (manifest, token) = files(dir.path());
    let url = ("CLOAKPIPE_UPSTREAM_URL", "https://tools.example.com/mcp");
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        // No upstream.
        (vec![("CLOAKPIPE_MANIFEST", &manifest), ("CLOAKPIPE_LISTEN_TOKEN_FILE", &token)], "CLOAKPIPE_UPSTREAM_URL"),
        // Both upstreams.
        (vec![("CLOAKPIPE_MANIFEST", &manifest), ("CLOAKPIPE_LISTEN_TOKEN_FILE", &token), url, ("CLOAKPIPE_UPSTREAM", "x")], "not both"),
        // No manifest mounted.
        (vec![("CLOAKPIPE_MANIFEST", "/nonexistent/m.yaml"), ("CLOAKPIPE_LISTEN_TOKEN_FILE", &token), url], "/nonexistent/m.yaml"),
        // A non-loopback listener without a token.
        (vec![("CLOAKPIPE_MANIFEST", &manifest), url], "CLOAKPIPE_LISTEN_TOKEN_FILE"),
    ];
    for (env, says) in cases {
        let (out, argv) = entrypoint(dir.path(), &["gate"], &env);
        assert_eq!(out.status.code(), Some(2), "{env:?}: {argv:?}");
        assert!(argv.is_empty(), "cloakpipe not run: {argv:?}");
        assert!(stderr(&out).contains(says), "{env:?}: {}", stderr(&out));
    }
    // Without a token only when asked, explicitly.
    let (out, argv) = entrypoint(dir.path(), &["gate"], &[("CLOAKPIPE_MANIFEST", &manifest), url, ("CLOAKPIPE_INSECURE_NO_TOKEN", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!argv.iter().any(|a| a == "--listen-token-file"), "{argv:?}");
    // A loopback listener needs no token.
    let (out, _) = entrypoint(dir.path(), &["gate"], &[("CLOAKPIPE_MANIFEST", &manifest), url, ("CLOAKPIPE_LISTEN", "127.0.0.1:8900")]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn other_commands_go_to_cloakpipe_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let (out, argv) = entrypoint(dir.path(), &["start"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(argv, ["start"], "the old PII proxy (docker run … start)");
    let (_, argv) = entrypoint(dir.path(), &["verify", "--ledger", "/data/ledger.db"], &[]);
    assert_eq!(argv, ["verify", "--ledger", "/data/ledger.db"]);
    let (_, argv) = entrypoint(dir.path(), &["--version"], &[]);
    assert_eq!(argv, ["--version"]);
}

#[test]
fn the_compose_example_runs_the_gate_in_front_of_an_example_upstream() {
    let compose: serde_yaml::Value = serde_yaml::from_str(&read("docker/compose.example.yaml")).unwrap();
    let gate = &compose["services"]["gate"];
    let env = serde_yaml::to_string(&gate["environment"]).unwrap();
    assert!(env.contains("CLOAKPIPE_UPSTREAM_URL") && env.contains("http://tools:"), "{env}");
    assert!(env.contains("CLOAKPIPE_LISTEN_TOKEN_FILE"), "{env}");
    assert!(serde_yaml::to_string(&gate["volumes"]).unwrap().contains("/data"));
    assert!(serde_yaml::to_string(&gate["volumes"]).unwrap().contains("/app/cloakpipe.manifest.yaml"));
    let ports = serde_yaml::to_string(&gate["ports"]).unwrap();
    assert!(ports.contains("127.0.0.1:8900:8900"), "published on loopback only: {ports}");
    assert!(compose["services"]["tools"].is_mapping(), "an example upstream");
    // The example upstream it runs exists.
    assert!(repo("examples/support-agent/mock_http_upstream.py").exists());
}

/// Against the real binary (default build: the legacy `certification`
/// build refuses every call of an uncertified release).
#[cfg(not(feature = "certification"))]
mod real_gate {
    use super::*;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A gate started through the entrypoint with the real binary; killed on drop.
    struct Gate {
        child: std::process::Child,
        base: String,
    }

    impl Gate {
        /// `env` on top of a manifest (the support-agent example), a token, a
        /// loopback listener on a free port and a /data directory in `dir`.
        fn start(dir: &Path, env: &[(&str, String)]) -> Self {
            let (_, token) = files(dir);
            // The image's /data volume.
            std::fs::create_dir_all(dir.join("data")).unwrap();
            let bin = PathBuf::from(env!("CARGO_BIN_EXE_cloakpipe"));
            let mut cmd = Command::new("sh");
            cmd.arg(repo("docker/gate-entrypoint.sh"));
            for var in VARS {
                cmd.env_remove(var);
            }
            for var in ["CLOAKPIPE_RELEASE", "CLOAKPIPE_LEDGER_DB", "CLOAKPIPE_SIGNING_KEY", "CLOAKPIPE_TASK_CONTEXT", "CLOAKPIPE_STATE_DB", "OTEL_EXPORTER_OTLP_ENDPOINT"] {
                cmd.env_remove(var);
            }
            cmd.env("PATH", format!("{}:{}", bin.parent().unwrap().display(), std::env::var("PATH").unwrap()))
                .env("CLOAKPIPE_HOME", dir.join("data"))
                .env("CLOAKPIPE_OPERATIONS_DB", dir.join("data/operations.db"))
                .env("CLOAKPIPE_MANIFEST", repo("examples/support-agent/cloakpipe.manifest.yaml"))
                .env("CLOAKPIPE_TASK_CONTEXT", repo("examples/support-agent/task-context.json"))
                .env("CLOAKPIPE_LISTEN", "127.0.0.1:0")
                .env("CLOAKPIPE_LISTEN_TOKEN_FILE", &token);
            for (k, v) in env {
                cmd.env(k, v);
            }
            let mut child = cmd.current_dir(dir).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let pipe = child.stderr.take().unwrap();
            std::thread::spawn(move || {
                let mut seen = String::new();
                for line in BufReader::new(pipe).lines() {
                    let Ok(line) = line else { break };
                    seen.push_str(&line);
                    seen.push('\n');
                    if let Some(rest) = line.split("listening on ").nth(1) {
                        let _ = tx.send(Ok(rest.trim().trim_end_matches("/mcp").to_string()));
                    }
                }
                let _ = tx.send(Err(seen));
            });
            let base = match rx.recv_timeout(Duration::from_secs(30)) {
                Ok(Ok(base)) => base,
                other => {
                    let _ = child.kill();
                    panic!("the gate did not start: {other:?}");
                }
            };
            Self { child, base }
        }

        /// POST one message with the token: (status, session, body).
        fn post(&self, session: Option<&str>, msg: Value) -> (u16, Option<String>, Value) {
            let mut req = reqwest::blocking::Client::new()
                .post(format!("{}/mcp", self.base))
                .header("Authorization", "Bearer a-long-random-token")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .body(msg.to_string());
            if let Some(s) = session {
                req = req.header("Mcp-Session-Id", s);
            }
            let resp = req.send().unwrap();
            let status = resp.status().as_u16();
            let sid = resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_string());
            (status, sid, serde_json::from_str(&resp.text().unwrap()).unwrap_or(Value::Null))
        }

        /// SIGTERM (docker stop): the exit code.
        fn stop(mut self) -> Option<i32> {
            let _ = Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status();
            self.child.wait().unwrap().code()
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// The real binary accepts what the entrypoint builds: it serves /health
    /// over HTTP in front of the example's stdio upstream, with every event
    /// flag set.
    #[test]
    fn the_entrypoint_starts_the_real_gate() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("webhook.secret");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let upstream = format!("python3 {}", repo("examples/support-agent/mock_upstream.py").display());
        let gate = Gate::start(
            dir.path(),
            &[
                ("CLOAKPIPE_UPSTREAM", upstream),
                ("CLOAKPIPE_WEBHOOK_URL", "http://127.0.0.1:9/hook".into()),
                ("CLOAKPIPE_WEBHOOK_SECRET_FILE", secret.to_string_lossy().into_owned()),
                ("CLOAKPIPE_WEBHOOK_FORMAT", "generic".into()),
                ("CLOAKPIPE_OTEL_ENDPOINT", "http://127.0.0.1:9".into()),
                ("CLOAKPIPE_EVENTS_LOG", dir.path().join("data/events.jsonl").to_string_lossy().into_owned()),
            ],
        );
        let health: Value = reqwest::blocking::get(format!("{}/health", gate.base)).unwrap().json().unwrap();
        assert_eq!(health["status"], "ok", "{health}");
        assert_eq!(health["release"], "support-agent", "{health}");
        // /mcp needs the token.
        let denied = reqwest::blocking::Client::new().post(format!("{}/mcp", gate.base)).body("{}").send().unwrap();
        assert_eq!(denied.status().as_u16(), 401);
        assert_eq!(gate.stop(), Some(0), "stops cleanly on SIGTERM (docker stop)");
    }

    /// What docker/compose.example.yaml runs, without docker: the gate (through
    /// the entrypoint) in front of examples/support-agent/mock_http_upstream.py
    /// over HTTP, enforcing Example 2.
    #[test]
    fn the_compose_example_gate_enforces_example_2_over_http() {
        let dir = tempfile::tempdir().unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut tools = Command::new("python3")
            .arg(repo("examples/support-agent/mock_http_upstream.py"))
            .env("MOCK_PORT", port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let received = Arc::new(Mutex::new(String::new()));
        {
            let (pipe, received) = (tools.stderr.take().unwrap(), received.clone());
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    received.lock().unwrap().push_str(&format!("{line}\n"));
                }
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(std::time::Instant::now() < deadline, "the example upstream did not start");
            std::thread::sleep(Duration::from_millis(50));
        }

        let gate = Gate::start(dir.path(), &[("CLOAKPIPE_UPSTREAM_URL", format!("http://127.0.0.1:{port}/mcp"))]);
        let init = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agent", "version": "1"}}});
        let (status, sid, body) = gate.post(None, init);
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["result"]["serverInfo"]["name"], "mock-support-tools", "{body}");
        let sid = sid.expect("a session");
        let call = |id: u64, tool: &str, arguments: Value| json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}});
        let email = |to: &str| json!({"ticket_id": "T-1042", "to": to, "subject": "Your refund", "body": "Hi Dana, your refund is on its way."});
        let (_, _, read) = gate.post(Some(&sid), call(1, "read_ticket", json!({"ticket_id": "T-1042"})));
        assert_eq!(read["result"]["content"][0]["text"], "read_ticket: done", "{read}");
        let (_, _, sent) = gate.post(Some(&sid), call(2, "send_email", email("dana@customer.example")));
        assert_eq!(sent["result"]["content"][0]["text"], "send_email: done", "{sent}");
        let (_, _, injected) = gate.post(Some(&sid), call(3, "send_email", email("attacker@evil.example")));
        assert_eq!(injected["error"]["data"]["reason"], "scope_mismatch", "{injected}");
        assert_eq!(gate.stop(), Some(0));
        let _ = tools.kill();
        let _ = tools.wait();
        let seen = received.lock().unwrap().clone();
        assert!(seen.contains("upstream received: read_ticket") && seen.contains("dana@customer.example"), "{seen}");
        assert!(!seen.contains("evil.example"), "the injected mail never reached the tool: {seen}");
    }
}

/// The root docker-compose.yml still runs the PII proxy: it asks for
/// `start`, now that the image's default is the gate.
#[test]
fn the_root_compose_file_keeps_running_the_pii_proxy() {
    let compose: serde_yaml::Value = serde_yaml::from_str(&read("docker-compose.yml")).unwrap();
    let command = &compose["services"]["cloakpipe"]["command"];
    assert_eq!(serde_yaml::to_string(command).unwrap().trim(), "- start", "{command:?}");
}
