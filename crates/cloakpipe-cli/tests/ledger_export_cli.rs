//! End to end: `cloakpipe mcp-proxy --anchor-every N` seals the decision
//! ledger into epochs and anchors them (RFC 3161 + Rekor) in the
//! background; `cloakpipe ledger export --out audit-pack.tar` packs it; and
//! `cloakpipe verify audit-pack.tar` checks it offline. The TSA and Rekor
//! are local test authorities (no network).
//!
//! Default build only: the legacy `certification` build refuses every call
//! of an uncertified release, which these scenarios do not set up.
#![cfg(not(feature = "certification"))]

use cloakpipe_anchor::testkit::{MockRekor, MockTsa};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cloakpipe"));
    for var in ["CLOAKPIPE_RELEASE", "CLOAKPIPE_LEDGER_DB", "CLOAKPIPE_SIGNING_KEY", "CLOAKPIPE_OPERATIONS_DB", "CLOAKPIPE_TASK_CONTEXT"] {
        cmd.env_remove(var);
    }
    cmd
}

fn manifest() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../cloakpipe-release/testdata/support-agent-184.yaml").to_string_lossy().into_owned()
}

/// A fake tool that answers every request with an empty result.
fn upstream(dir: &Path) -> String {
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nwhile IFS= read -r line; do\n  id=$(printf '%s' \"$line\" | sed 's/^{\"id\":\\([0-9]*\\),.*$/\\1/')\n  printf '{\"id\":%s,\"jsonrpc\":\"2.0\",\"result\":{\"content\":[]}}\\n' \"$id\"\ndone\n",
    )
    .unwrap();
    format!("sh {}", script.display())
}

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"ticket": "T-777123"}}}).to_string()
}

struct Kit {
    tsa: MockTsa,
    rekor: MockRekor,
    tsa_root: String,
    rekor_key: String,
}

fn kit(dir: &Path) -> Kit {
    let (tsa, rekor) = (MockTsa::start(), MockRekor::start());
    let tsa_root = dir.join("tsa-root.pem");
    std::fs::write(&tsa_root, tsa.root_pem()).unwrap();
    let rekor_key = dir.join("rekor.pub");
    std::fs::write(&rekor_key, rekor.key_pem()).unwrap();
    Kit { tsa, rekor, tsa_root: tsa_root.to_string_lossy().into_owned(), rekor_key: rekor_key.to_string_lossy().into_owned() }
}

impl Kit {
    fn flags(&self) -> Vec<String> {
        ["--tsa", self.tsa.url(), "--tsa-root", &self.tsa_root, "--rekor", self.rekor.url(), "--rekor-key", &self.rekor_key]
            .map(String::from)
            .to_vec()
    }
}

/// Run `cloakpipe <args>` in `dir` with `CLOAKPIPE_HOME=<dir>/home`,
/// feeding `stdin`: (exit code, stdout, stderr).
fn run(dir: &Path, args: &[String], stdin: &str) -> (i32, String, String) {
    let mut child = bin()
        .current_dir(dir)
        .args(args)
        .env("CLOAKPIPE_HOME", dir.join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn proxy(dir: &Path, extra: &[String], calls: &[String]) -> (i32, String, String) {
    let mut args: Vec<String> = ["mcp-proxy", "--upstream", &upstream(dir), "--manifest", &manifest()].map(String::from).to_vec();
    args.extend_from_slice(extra);
    run(dir, &args, &calls.iter().map(|c| format!("{c}\n")).collect::<String>())
}

fn s(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| a.to_string()).collect()
}

fn gate_public_key(dir: &Path) -> String {
    let v: Value = serde_json::from_slice(&std::fs::read(dir.join("home/gate.key")).unwrap()).unwrap();
    v["publicKey"].as_str().unwrap().to_string()
}

#[test]
fn the_gate_anchors_epochs_and_the_exported_pack_verifies_offline() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let k = kit(d);
    let mut flags = s(&["--anchor-every", "2"]);
    flags.extend(k.flags());
    let calls: Vec<String> = (1..=5).map(|i| call(i, if i == 3 { "delete_customer" } else { "refund" })).collect();
    let (code, _, err) = proxy(d, &flags, &calls);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("anchor.ok epoch=0"), "{err}");
    assert!(!err.contains("anchor.failed"), "{err}");
    assert!(k.tsa.issued() >= 1 && k.rekor.entries() >= 1);

    let (code, out, err) = run(d, &s(&["ledger", "export", "--out", "audit-pack.tar"]), "");
    assert_eq!(code, 0, "{err}");
    let summary: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(summary["entries"], 5);
    assert!(d.join("audit-pack.tar").is_file());

    let key = gate_public_key(d);
    let verify = |extra: &[&str]| {
        let mut args = s(&["verify", "audit-pack.tar", "--tsa-root", &k.tsa_root, "--rekor-key", &k.rekor_key]);
        args.extend(s(extra));
        run(d, &args, "")
    };
    let (code, out, err) = verify(&["--key", &key]);
    assert_eq!(code, 0, "{out}{err}");
    for line in ["entries: 5 (seq 0..4), chain OK, signatures OK", "gaps: none", "denials: 1,", "(pinned)", "result: OK"] {
        assert!(out.contains(line), "missing {line:?} in\n{out}");
    }
    assert!(out.contains("RFC3161 OK (") && out.contains("Rekor OK ("), "{out}");
    assert!(!out.contains("unanchored:"), "the gate sealed the tail on exit:\n{out}");
    assert!(!out.contains("T-777123"), "no argument values: {out}");

    // Pinned to another key: refused.
    let (code, out, _) = verify(&["--key", &"11".repeat(32)]);
    assert_eq!(code, 1, "{out}");
    // A tampered pack: refused.
    let mut tar = std::fs::read(d.join("audit-pack.tar")).unwrap();
    let at = tar.windows(8).position(|w| w == b"\"refund\"").unwrap();
    tar[at + 1] = b'R';
    std::fs::write(d.join("audit-pack.tar"), tar).unwrap();
    let (code, out, _) = verify(&[]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("result: FAIL"), "{out}");
}

#[test]
fn a_failed_anchor_is_reported_and_retried_by_the_next_run() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let k = kit(d);
    let mut flags = s(&["--anchor-every", "1"]);
    flags.extend(k.flags());
    k.tsa.set_failing(true);
    k.rekor.set_failing(true);
    let (code, _, err) = proxy(d, &flags, &[call(1, "refund")]);
    assert_eq!(code, 0, "anchoring never blocks the gate: {err}");
    assert!(err.contains("anchor.failed epoch=0 seq=0..0 anchor=rfc3161"), "{err}");
    assert!(err.contains("anchor=rekor"), "{err}");

    let (code, _, err) = run(d, &s(&["ledger", "export", "--out", "p.tar"]), "");
    assert_eq!(code, 0, "{err}");
    let verify = || run(d, &s(&["verify", "p.tar", "--tsa-root", &k.tsa_root, "--rekor-key", &k.rekor_key]), "");
    let (code, out, _) = verify();
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("epoch 0 is not anchored"), "{out}");

    // The authorities are back: the next run anchors the pending epoch.
    k.tsa.set_failing(false);
    k.rekor.set_failing(false);
    let (code, _, err) = proxy(d, &flags, &[]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("anchor.ok epoch=0"), "{err}");
    let (code, _, err) = run(d, &s(&["ledger", "export", "--out", "p.tar"]), "");
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = verify();
    assert_eq!(code, 0, "{out}");
}

#[test]
fn anchoring_flags_are_checked_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let k = kit(d);
    let cases: Vec<(Vec<String>, &str)> = vec![
        (s(&["--tsa", "http://127.0.0.1:9/tsr"]), "--anchor-every"),
        (s(&["--anchor-every", "0"]), "--anchor-every"),
        (s(&["--anchor-interval", "soon"]), "anchor-interval"),
        (s(&["--anchor-every", "5", "--no-tsa", "--no-rekor"]), "nothing to anchor"),
        (s(&["--anchor-every", "5", "--no-ledger"]), "--no-ledger"),
        (s(&["--anchor-every", "5", "--tsa-root", "/nonexistent.pem"]), "/nonexistent.pem"),
    ];
    for (flags, says) in cases {
        let (code, _, err) = proxy(d, &flags, &[call(1, "refund")]);
        assert_eq!(code, 2, "{flags:?}: {err}");
        assert!(err.contains(says), "{flags:?}: {err}");
    }
    // Without a manifest there is no gate to anchor for.
    let (code, _, err) = run(d, &s(&["mcp-proxy", "--upstream", &upstream(d), "--anchor-every", "5"]), "");
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--manifest"), "{err}");
    assert_eq!(k.tsa.requests() + k.rekor.requests(), 0);
}

#[test]
fn export_takes_a_time_range_and_needs_a_ledger_and_key() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (code, _, err) = run(d, &s(&["ledger", "export", "--out", "p.tar"]), "");
    assert_eq!(code, 2, "no ledger yet: {err}");

    let (code, _, err) = proxy(d, &[], &[call(1, "refund"), call(2, "refund")]);
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = run(d, &s(&["ledger", "export", "--out", "p.tar", "--since", "24h"]), "");
    assert_eq!(code, 0, "{err}");
    assert_eq!(serde_json::from_str::<Value>(out.trim()).unwrap()["entries"], 2);
    let (code, _, err) = run(d, &s(&["ledger", "export", "--out", "p.tar", "--since", "2999-01-01"]), "");
    assert_eq!(code, 1, "empty range: {err}");
    assert!(err.contains("no decision entries"), "{err}");
    let (code, _, err) = run(d, &s(&["ledger", "export", "--out", "p.tar", "--until", "yesterday-ish"]), "");
    assert_eq!(code, 2, "{err}");

    // No anchoring configured: the pack verifies, its entries reported as
    // unanchored; --require-anchors makes that a failure.
    let (code, _, err) = run(d, &s(&["ledger", "export", "--out", "p.tar"]), "");
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = run(d, &s(&["verify", "p.tar"]), "");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("anchors: none") && out.contains("unanchored: seq 0..1"), "{out}");
    let (code, out, _) = run(d, &s(&["verify", "p.tar", "--require-anchors"]), "");
    assert_eq!(code, 1, "{out}");
    let (code, _, err) = run(d, &s(&["verify", "missing.tar"]), "");
    assert_eq!(code, 2, "{err}");
}
