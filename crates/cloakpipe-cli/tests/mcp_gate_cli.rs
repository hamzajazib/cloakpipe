//! `cloakpipe mcp-proxy --manifest … --certification …`: the interceptor only
//! lets a certified release call the tools its manifest declares.

use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const VAULT_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn root(rel: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel).to_string_lossy().into_owned()
}

fn manifest() -> String {
    root("../cloakpipe-release/testdata/support-agent-184.yaml")
}

fn run_ok(dir: &std::path::Path, args: &[&str]) -> String {
    let out = bin().current_dir(dir).args(args).output().unwrap();
    assert!(out.status.success(), "{args:?}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

/// keygen + JUnit import + certify (now) → (envelope, key file).
fn certify(dir: &std::path::Path, environment: &str) -> (String, String) {
    let p = |n: &str| dir.join(n).to_string_lossy().into_owned();
    run_ok(dir, &["release", "keygen", "--out", &p("key.json")]);
    run_ok(dir, &[
        "eval", "import", "--junit", &root("tests/fixtures/certification/passing.junit.xml"), "--release", &manifest(),
        "--suite", "support-critical@23", "--covers", "privacy,functional", "--out", &p("run.json"),
    ]);
    run_ok(dir, &[
        "release", "certify", &manifest(), "--policy", &root("tests/fixtures/certification/policy.yaml"),
        "--run", &p("run.json"), "--require", "privacy,functional", "--environment", environment,
        "--issuer", "ci:test", "--key", &p("key.json"), "--out", &p("cert.dsse.json"),
    ]);
    (p("cert.dsse.json"), p("key.json"))
}

/// A fake tool: records each line, answers with an empty result for its id.
fn upstream(dir: &std::path::Path) -> (String, PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  id=$(printf '%s' \"$line\" | sed 's/^{{\"id\":\\([0-9]*\\),.*$/\\1/')\n  printf '{{\"id\":%s,\"jsonrpc\":\"2.0\",\"result\":{{\"content\":[]}}}}\\n' \"$id\"\ndone\n",
            received.display()
        ),
    )
    .unwrap();
    (format!("sh {}", script.display()), received)
}

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}}).to_string()
}

/// Run the interceptor over `lines`; returns (exit code, agent messages, what the tool saw, stderr).
fn proxy(dir: &std::path::Path, extra: &[&str], envs: &[(&str, &str)], lines: &[String]) -> (i32, Vec<Value>, String, String) {
    let (up, received) = upstream(dir);
    let mut args = vec!["mcp-proxy", "--upstream", up.as_str()];
    args.extend_from_slice(extra);
    let mut cmd = bin();
    cmd.current_dir(dir).args(&args).env("CLOAKPIPE_VAULT_KEY", VAULT_KEY).env_remove("CLOAKPIPE_RELEASE");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let msgs = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let seen = std::fs::read_to_string(&received).unwrap_or_default();
    (out.status.code().unwrap_or(-1), msgs, seen, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn refusal(msgs: &[Value], id: u64) -> Option<String> {
    msgs.iter().find(|m| m["id"] == id).and_then(|m| m["error"]["data"]["reason"].as_str().map(str::to_string))
}

#[test]
fn a_certified_release_calls_declared_tools_only() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = certify(dir.path(), "production");
    let (code, msgs, seen, err) = proxy(
        dir.path(),
        &["--manifest", &manifest(), "--certification", &cert, "--trust", &key],
        &[],
        &[call(1, "refund"), call(2, "delete_customer")],
    );
    assert_eq!(code, 0, "{err}");
    assert!(seen.contains("\"refund\"") && !seen.contains("delete_customer"), "{seen}");
    assert_eq!(refusal(&msgs, 1), None, "{msgs:?}");
    assert_eq!(refusal(&msgs, 2).as_deref(), Some("undeclared_tool"), "{msgs:?}");
}

#[test]
fn without_a_certification_nothing_is_called() {
    let dir = tempfile::tempdir().unwrap();
    let (_, msgs, seen, err) = proxy(dir.path(), &["--manifest", &manifest()], &[], &[call(1, "refund")]);
    assert!(!seen.contains("refund"), "{seen}");
    assert_eq!(refusal(&msgs, 1).as_deref(), Some("uncertified"), "{msgs:?} {err}");
}

#[test]
fn the_environment_must_match() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = certify(dir.path(), "staging");
    let args = ["--manifest", manifest().as_str(), "--certification", cert.as_str(), "--trust", key.as_str()].map(String::from);
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let (_, msgs, _, _) = proxy(dir.path(), &a, &[], &[call(1, "refund")]);
    assert_eq!(refusal(&msgs, 1).as_deref(), Some("wrong_environment"));
    let mut staging = a.clone();
    staging.extend(["--environment", "staging"]);
    let (_, msgs, seen, _) = proxy(dir.path(), &staging, &[], &[call(1, "refund")]);
    assert_eq!(refusal(&msgs, 1), None, "{msgs:?}");
    assert!(seen.contains("refund"));
}

#[test]
fn warn_mode_forwards() {
    let dir = tempfile::tempdir().unwrap();
    let (_, msgs, seen, err) = proxy(dir.path(), &["--manifest", &manifest(), "--gate", "warn"], &[], &[call(1, "refund")]);
    assert!(seen.contains("refund"), "{seen}");
    assert_eq!(refusal(&msgs, 1), None);
    assert!(err.contains("warn mode: forwarded") && err.contains("uncertified"), "the call's violation is reported: {err}");
}

#[test]
fn misconfiguration_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    // A certification without a manifest to check it against.
    let (cert, key) = certify(dir.path(), "production");
    let (code, _, _, err) = proxy(dir.path(), &["--certification", &cert, "--trust", &key], &[], &[]);
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("--manifest"), "{err}");
    // CLOAKPIPE_RELEASE naming a different release than the manifest.
    let other = format!("sha256:{}", "ab".repeat(32));
    let (code, _, _, err) = proxy(dir.path(), &["--manifest", &manifest()], &[("CLOAKPIPE_RELEASE", &other)], &[]);
    assert_ne!(code, 0);
    assert!(err.contains("CLOAKPIPE_RELEASE"), "{err}");
    // An unreadable certification.
    let (code, _, _, err) = proxy(dir.path(), &["--manifest", &manifest(), "--certification", "/nonexistent.json"], &[], &[]);
    assert_ne!(code, 0, "{err}");
}

#[test]
fn gate_flags_without_a_manifest_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    for flags in [
        vec!["--gate", "warn"],
        vec!["--environment", "staging"],
        vec!["--revoked-statement", &"ab".repeat(32)],
        vec!["--revoked-key", "ed25519:0011223344556677"],
    ] {
        let (code, _, _, err) = proxy(dir.path(), &flags, &[], &[]);
        assert_ne!(code, 0, "{flags:?} must not run ungated");
        assert!(err.contains("--manifest"), "{flags:?}: {err}");
    }
}

#[test]
fn malformed_revocations_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _, _, err) = proxy(dir.path(), &["--manifest", &manifest(), "--revoked-statement", "not-a-digest"], &[], &[]);
    assert_ne!(code, 0, "a typo must not silently disable revocation");
    assert!(err.contains("--revoked-statement"), "{err}");
}

#[test]
fn a_revoked_signer_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = certify(dir.path(), "production");
    let keyid = serde_json::from_str::<Value>(&std::fs::read_to_string(&key).unwrap()).unwrap()["keyid"].as_str().unwrap().to_string();
    let (_, msgs, seen, err) = proxy(
        dir.path(),
        &["--manifest", &manifest(), "--certification", &cert, "--trust", &key, "--revoked-key", &keyid],
        &[],
        &[call(1, "refund")],
    );
    assert!(!seen.contains("refund"), "{seen}");
    assert_eq!(refusal(&msgs, 1).as_deref(), Some("revoked"), "{msgs:?} {err}");
}
