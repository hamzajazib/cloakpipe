//! `cloakpipe release register` against a stub CloakPipe Cloud API.
//!
//! Exit codes: 0 registered (new or existing), 1 manifest rejected (locally or
//! by the API), 2 configuration, network or server error.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cloakpipe-release/testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// A captured HTTP request.
#[derive(Default, Clone, Debug)]
struct Seen {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Serve exactly one request with `status` and `body`; returns the base URL
/// and a handle to what the server received.
fn stub(status: u16, body: &'static str) -> (String, Arc<Mutex<Option<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(None));
    let out = seen.clone();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut req = Seen::default();
        reader.read_line(&mut req.request_line).unwrap();
        let mut len = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (k, v) = line.split_once(':').unwrap();
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap();
            }
            req.headers.push((k.to_string(), v.trim().to_string()));
        }
        let mut buf = vec![0; len];
        reader.read_exact(&mut buf).unwrap();
        req.body = String::from_utf8(buf).unwrap();
        *out.lock().unwrap() = Some(req);
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    (url, seen)
}

fn register(args: &[&str], url: Option<&str>) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cloakpipe"));
    cmd.arg("release").arg("register").args(args);
    cmd.env_remove("CLOAKPIPE_API_URL").env("CLOAKPIPE_API_KEY", "cpk_test_123");
    if let Some(u) = url {
        cmd.env("CLOAKPIPE_API_URL", u);
    }
    let out = cmd.output().unwrap();
    (out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

const CREATED: &str = r#"{"created":true,"release":{"agent":"support-agent","version":"184","manifest_hash":"sha256:ae7bc9e404c194c9fcf80d95cafe4c322e4e9f69595c693ffb48441647d03c32"},"baseline":{"version":"183","source":"production","manifest_hash":"sha256:00"},"diff":{"changes":[{}],"required_suites":["prompt_contract","privacy"],"requires_approval":true},"evidence":{"seq":7}}"#;

#[test]
fn posts_the_manifest_to_the_agents_release_endpoint_with_the_api_key() {
    let (url, seen) = stub(201, CREATED);
    let (code, out, err) = register(&[&fixture("support-agent-184.yaml")], Some(&url));
    assert_eq!(code, 0, "{out}{err}");

    let req = seen.lock().unwrap().clone().expect("request sent");
    assert_eq!(req.request_line.trim(), "POST /v1/agents/support-agent/releases HTTP/1.1");
    assert_eq!(req.header("x-cloakpipe-key"), Some("cpk_test_123"));
    let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
    assert_eq!(body["metadata"]["agent"], "support-agent");
    assert_eq!(body["spec"]["model"]["ref"], "model:openai/gpt-5@2026-08-01");

    assert!(out.contains("registered"), "{out}");
    assert!(out.contains("sha256:ae7bc9e4"), "{out}");
    assert!(out.contains("prompt_contract"), "{out}");
    assert!(out.contains("approval required"), "{out}");
}

#[test]
fn existing_release_is_success() {
    let (url, _) = stub(200, r#"{"created":false,"release":{"agent":"support-agent","version":"184","manifest_hash":"sha256:ae"},"baseline":null,"diff":null,"evidence":null}"#);
    let (code, out, _) = register(&[&fixture("support-agent-184.yaml")], Some(&url));
    assert_eq!(code, 0);
    assert!(out.contains("already registered"), "{out}");
}

#[test]
fn json_flag_prints_the_server_response() {
    let (url, _) = stub(201, CREATED);
    let (code, out, _) = register(&["--json", &fixture("support-agent-184.yaml")], Some(&url));
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["evidence"]["seq"], 7);
}

#[test]
fn invalid_manifest_is_rejected_locally_without_a_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.yaml");
    let src = std::fs::read_to_string(fixture("support-agent-184.yaml")).unwrap().replace("@31", "@latest");
    std::fs::write(&path, src).unwrap();

    let (url, seen) = stub(201, CREATED);
    let (code, _, err) = register(&[path.to_str().unwrap()], Some(&url));
    assert_eq!(code, 1);
    assert!(err.contains("spec.prompts[0].ref"), "{err}");
    assert!(seen.lock().unwrap().is_none(), "nothing may be sent");
}

#[test]
fn server_rejection_is_exit_1_with_its_message() {
    let (url, _) = stub(409, r#"{"error":"version \"184\" is already registered with different content","existing_hash":"sha256:11"}"#);
    let (code, _, err) = register(&[&fixture("support-agent-184.yaml")], Some(&url));
    assert_eq!(code, 1);
    assert!(err.contains("already registered with different content"), "{err}");
}

#[test]
fn server_error_is_exit_2() {
    let (url, _) = stub(503, r#"{"error":"agent release registry is not configured"}"#);
    let (code, _, err) = register(&[&fixture("support-agent-184.yaml")], Some(&url));
    assert_eq!(code, 2);
    assert!(err.contains("not configured"), "{err}");
}

#[test]
fn missing_api_url_is_exit_2() {
    let (code, _, err) = register(&[&fixture("support-agent-184.yaml")], None);
    assert_eq!(code, 2);
    assert!(err.contains("CLOAKPIPE_API_URL"), "{err}");
}

#[test]
fn unreachable_api_is_exit_2() {
    // Bind then drop to get a port nothing listens on.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (code, _, err) = register(&[&fixture("support-agent-184.yaml")], Some(&format!("http://127.0.0.1:{port}")));
    assert_eq!(code, 2);
    assert!(err.contains("request failed"), "{err}");
}
