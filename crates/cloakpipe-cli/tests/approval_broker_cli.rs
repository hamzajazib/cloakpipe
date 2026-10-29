//! `cloakpipe mcp-proxy --approvals-url … --approvals-secret-file …` and
//! `cloakpipe approvals keys`: Example 3 through the real binary against a
//! stub approval broker (127.0.0.1) that signs receipts with
//! `cloakpipe-receipt`. A $350 refund is refused as approval_required and
//! filed with only the amount shown; once approved, the gate's poller
//! fetches and verifies the receipt and the retry runs; reusing it for
//! $3,500 is approval_required, and a denied call is approval_denied.

#[path = "../../cloakpipe-mcp/tests/support/broker.rs"]
mod broker;

use broker::StubBroker;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const SECRET: &str = "gate-secret-0123456789";
const WAIT: Duration = Duration::from_secs(20);

const MANIFEST: &str = r#"release: refunds
version: "3"
tools:
  issue_refund:
    args:
      ticket_id: { type: string, one_of_context: ["ticket.id"], required: true }
      amount: { type: integer, min: 0, max: 5000, required: true }
      note: { type: string, max_len: 200 }
    approval: { when: "amount > 100", approvers: ["slack:#support-leads"], ttl: 15m, show: [amount] }
"#;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn p(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

fn refund(amount: u64) -> Value {
    json!({"ticket_id": "T-1042", "amount": amount, "note": "customer-private-note"})
}

fn call(id: u64, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "issue_refund", "arguments": arguments}}).to_string()
}

/// The files Example 3 runs on; returns the approver's signing key and keyid.
fn world(dir: &Path) -> (SigningKey, String) {
    std::fs::write(dir.join("cloakpipe.manifest.yaml"), MANIFEST).unwrap();
    std::fs::write(dir.join("task.json"), r#"{"taskId": "t-981", "ticket": {"id": "T-1042"}}"#).unwrap();
    std::fs::write(dir.join("gate.secret"), format!("{SECRET}\n")).unwrap();
    std::fs::create_dir_all(dir.join("approvals")).unwrap();
    let out = bin().args(["release", "keygen", "--out", &p(dir, "approver.json")]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let key: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("approver.json")).unwrap()).unwrap();
    let mut seed = [0u8; 32];
    hex::decode_to_slice(key["privateKey"].as_str().unwrap(), &mut seed).unwrap();
    (SigningKey::from_bytes(&seed), key["keyid"].as_str().unwrap().to_string())
}

/// A fake tool: records each line, answers with an empty result for its id.
fn upstream(dir: &Path) -> (String, PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  id=$(printf '%s' \"$line\" | grep -o '\"id\":[0-9]*' | head -n 1 | cut -d: -f2)\n  printf '{{\"id\":%s,\"jsonrpc\":\"2.0\",\"result\":{{\"content\":[]}}}}\\n' \"$id\"\ndone\n",
            received.display()
        ),
    )
    .unwrap();
    (format!("sh {}", script.display()), received)
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut c = bin();
    c.current_dir(dir)
        .args(args)
        .env("CLOAKPIPE_LEDGER_DB", dir.join("ledger.db"))
        .env("CLOAKPIPE_HOME", dir.join("home"))
        .env_remove("CLOAKPIPE_SIGNING_KEY")
        .env_remove("CLOAKPIPE_RELEASE")
        .env_remove("CLOAKPIPE_TASK_CONTEXT")
        .env_remove("CLOAKPIPE_OPERATIONS_DB");
    c
}

fn gate_flags(dir: &Path, url: &str) -> Vec<String> {
    [
        "--manifest", &p(dir, "cloakpipe.manifest.yaml"), "--task-context", &p(dir, "task.json"),
        "--approvals", &p(dir, "approvals"), "--approver-key", &p(dir, "approver.json"),
        "--approvals-url", url, "--approvals-secret-file", &p(dir, "gate.secret"),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// The gate as a running process the test talks to line by line.
struct Gate {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: mpsc::Receiver<Value>,
    received: PathBuf,
}

impl Gate {
    fn start(dir: &Path, extra: &[String]) -> Self {
        let (up, received) = upstream(dir);
        let mut args = vec!["mcp-proxy".to_string(), "--upstream".into(), up];
        args.extend_from_slice(extra);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut child = command(dir, &args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    let _ = tx.send(v);
                }
            }
        });
        let stdin = child.stdin.take();
        Self { child, stdin, replies, received }
    }

    fn ask(&mut self, line: &str) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(format!("{line}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
        self.replies.recv_timeout(WAIT).expect("a reply")
    }

    fn finish(mut self) -> (i32, String) {
        drop(self.stdin.take());
        let status = self.child.wait().unwrap();
        (status.code().unwrap_or(-1), std::fs::read_to_string(&self.received).unwrap_or_default())
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + WAIT;
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} never appeared", path.display());
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn example_3_through_the_binary_with_a_broker() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (key, keyid) = world(d);
    let stub = StubBroker::start(SECRET.as_bytes());
    let mut flags = gate_flags(d, &stub.url());
    flags.extend(["--approvals-poll-interval".to_string(), "1s".to_string()]);
    let mut gate = Gate::start(d, &flags);

    // $350: refused, and the request is filed with only the amount shown.
    let r = gate.ask(&call(1, refund(350)));
    let data = &r["error"]["data"];
    assert_eq!((data["reason"].as_str(), data["approval_request"].as_str()), (Some("approval_required"), Some("requested")), "{r}");
    let fp = data["fingerprint"].as_str().unwrap().to_string();
    let posts = stub.wait_for_posts(1, WAIT);
    assert_eq!(posts.len(), 1);
    assert!(posts[0].signed);
    let req = posts[0].json();
    assert_eq!((req["fingerprint"].as_str(), req["shown"].clone()), (Some(fp.as_str()), json!({"amount": 350})));
    assert_eq!(req["task_id"], "t-981");
    for private in ["T-1042", "customer-private-note"] {
        assert!(!posts[0].text().contains(private), "{private} reached the broker");
    }

    // Approved at the broker: the poller writes the verified receipt.
    stub.approve(&fp, &key, &keyid);
    wait_for_file(&d.join("approvals").join(format!("{}.approval.json", fp.trim_start_matches("sha256:"))));
    let r = gate.ask(&call(2, refund(350)));
    assert!(r.get("error").is_none(), "the retry runs: {r}");

    // Reused for $3,500: another call.
    let r = gate.ask(&call(3, refund(3500)));
    assert_eq!(r["error"]["data"]["reason"], "approval_required", "{r}");
    let big = r["error"]["data"]["fingerprint"].as_str().unwrap().to_string();
    assert_ne!(big, fp);
    assert_eq!(stub.wait_for_posts(2, WAIT).len(), 2);

    // Denied at the broker: approval_denied.
    stub.deny(&big, None);
    wait_for_file(&d.join("approvals").join(format!("{}.denied.json", big.trim_start_matches("sha256:"))));
    let r = gate.ask(&call(4, refund(3500)));
    assert_eq!(
        (r["error"]["data"]["reason"].as_str(), r["error"]["data"]["approval_request"].as_str()),
        (Some("approval_denied"), Some("denied")),
        "{r}"
    );

    let (code, seen) = gate.finish();
    assert_eq!(code, 0);
    assert_eq!(seen.lines().count(), 1, "only the approved call reached the tool: {seen}");
    assert!(seen.contains("\"amount\":350"), "{seen}");
    assert!(stub.polls().iter().all(|p| p.signed));
}

#[test]
fn broker_flags_are_checked_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    world(d);
    std::fs::write(d.join("empty.secret"), "\n").unwrap();
    let url = "http://127.0.0.1:9/v1/gates/g";
    let base = gate_flags(d, url);
    let without = |flag: &str, n: usize| -> Vec<String> {
        let i = base.iter().position(|a| a == flag).unwrap();
        [&base[..i], &base[i + n..]].concat()
    };
    let with = |extra: &[&str]| -> Vec<String> { [base.clone(), extra.iter().map(|s| s.to_string()).collect()].concat() };
    let replace = |flag: &str, value: &str| -> Vec<String> {
        let mut v = base.clone();
        let i = v.iter().position(|a| a == flag).unwrap();
        v[i + 1] = value.to_string();
        v
    };
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("no secret", without("--approvals-secret-file", 2)),
        ("no approvals dir", without("--approvals", 2)),
        ("no task context", without("--task-context", 2)),
        ("not http", replace("--approvals-url", "ftp://broker.example/v1/gates/g")),
        ("empty secret", replace("--approvals-secret-file", &p(d, "empty.secret"))),
        ("missing secret", replace("--approvals-secret-file", &p(d, "nope.secret"))),
        ("zero interval", with(&["--approvals-poll-interval", "0s"])),
        ("bad interval", with(&["--approvals-poll-interval", "soon"])),
        ("secret without url", without("--approvals-url", 2)),
        ("interval without url", [without("--approvals-url", 2), vec!["--approvals-poll-interval".into(), "5s".into()]].concat()),
    ];
    for (what, flags) in cases {
        let (up, received) = upstream(d);
        let mut args = vec!["mcp-proxy".to_string(), "--upstream".into(), up];
        args.extend(flags);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = command(d, &args).stdin(Stdio::null()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{what}: {err}");
        assert!(err.contains("error:"), "{what}: {err}");
        assert!(!received.exists(), "{what}: the upstream must not start");
    }
}

#[test]
fn approvals_keys_writes_the_broker_keys_as_approver_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (key, keyid) = world(d);
    let stub = StubBroker::start(SECRET.as_bytes());
    let public = hex::encode(key.verifying_key().to_bytes());
    stub.set_keys(vec![json!({"keyid": keyid, "publicKey": public})]);
    let keys_dir = d.join("keys");
    let keys = |url: &str, secret: &str| {
        command(d, &["approvals", "keys", "--approvals-url", url, "--approvals-secret-file", secret, "--out", &p(d, "keys")])
            .output()
            .unwrap()
    };
    let out = keys(&stub.url(), &p(d, "gate.secret"));
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let written: Vec<PathBuf> = std::fs::read_dir(&keys_dir).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(written.len(), 1, "{written:?}");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(&written[0]).unwrap()).unwrap();
    assert_eq!(file, json!({"keyid": keyid, "publicKey": public}));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&keyid));
    let polls = stub.polls();
    assert_eq!(polls.last().unwrap().target, "/v1/gates/g-test-1/approver-keys");
    assert!(polls.last().unwrap().signed);

    // The written file works as --approver-key: the gate starts with it.
    let (up, _) = upstream(d);
    let out = command(
        d,
        &[
            "mcp-proxy", "--upstream", &up, "--manifest", &p(d, "cloakpipe.manifest.yaml"), "--task-context", &p(d, "task.json"),
            "--approvals", &p(d, "approvals"), "--approver-key", &written[0].to_string_lossy(),
        ],
    )
    .stdin(Stdio::null())
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));

    // A keyid that is not the key's: refused, nothing written.
    std::fs::remove_dir_all(&keys_dir).unwrap();
    stub.set_keys(vec![json!({"keyid": "ed25519:0000000000000000", "publicKey": public})]);
    let out = keys(&stub.url(), &p(d, "gate.secret"));
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!keys_dir.exists() || std::fs::read_dir(&keys_dir).unwrap().next().is_none());

    // The wrong secret: the broker refuses.
    std::fs::write(d.join("wrong.secret"), "not-the-secret").unwrap();
    let out = keys(&stub.url(), &p(d, "wrong.secret"));
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
}
