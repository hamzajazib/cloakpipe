//! `cloakpipe mcp-proxy` records every gate decision by default: a signed
//! decision ledger at `$CLOAKPIPE_HOME/ledger.db` with a gate signing key
//! at `$CLOAKPIPE_HOME/gate.key` (made on first use), or the ones the
//! operator names. `--no-ledger` opts out loudly; `--mode shadow` forwards
//! and records what enforce mode would have done. `cloakpipe ledger
//! entries | public-key` hand an auditor what `cloakpipe-verify decisions`
//! checks.
//!
//! Default build only: the legacy `certification` build refuses every call
//! of an uncertified release, which these scenarios do not set up.
#![cfg(not(feature = "certification"))]

use cloakpipe_verify::decisions::{parse_jsonl, verify_decisions};
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

/// A fake tool: records each line, answers with an empty result for its id.
fn upstream(dir: &Path) -> (String, PathBuf) {
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
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"ticket": "T-777123"}}}).to_string()
}

struct Out {
    code: i32,
    messages: Vec<Value>,
    seen: String,
    stderr: String,
}

/// Run the gate in `dir` with `CLOAKPIPE_HOME=<dir>/home`.
fn proxy(dir: &Path, extra: &[&str], envs: &[(&str, &str)], lines: &[String]) -> Out {
    let (up, received) = upstream(dir);
    let _ = std::fs::remove_file(&received);
    let mut cmd = bin();
    cmd.current_dir(dir).args(["mcp-proxy", "--upstream", &up]).args(extra).env("CLOAKPIPE_HOME", dir.join("home"));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        messages: String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect(),
        seen: std::fs::read_to_string(&received).unwrap_or_default(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `cloakpipe ledger <args>` with `CLOAKPIPE_HOME=<dir>/home`: (exit code, stdout, stderr).
fn ledger(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = bin().arg("ledger").args(args).env("CLOAKPIPE_HOME", dir.join("home")).output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn public_key(key_file: &Path) -> [u8; 32] {
    let v: Value = serde_json::from_slice(&std::fs::read(key_file).unwrap()).unwrap();
    hex::decode(v["publicKey"].as_str().unwrap()).unwrap().try_into().unwrap()
}

#[test]
fn decisions_are_recorded_by_default_under_cloakpipe_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let out = proxy(dir.path(), &["--manifest", &manifest()], &[], &[call(1, "refund"), call(2, "delete_customer")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.seen.contains("\"refund\"") && !out.seen.contains("delete_customer"), "{}", out.seen);

    // The gate key was made owner-only, and its public key printed once.
    let key = home.join("gate.key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let public = hex::encode(public_key(&key));
    assert_eq!(out.stderr.matches(&public).count(), 1, "{}", out.stderr);
    let again = proxy(dir.path(), &["--manifest", &manifest()], &[], &[call(3, "refund")]);
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert!(!again.stderr.contains(&public), "printed once only: {}", again.stderr);

    // `ledger entries` prints them; they verify with the public key alone.
    let (code, jsonl, err) = ledger(dir.path(), &["entries"]);
    assert_eq!(code, 0, "{err}");
    let entries = parse_jsonl(&jsonl).unwrap();
    let s = verify_decisions(&entries, &[public_key(&key)]).expect("verifies");
    assert_eq!((s.entries, s.allowed, s.denied), (3, 2, 1));
    assert_eq!(entries[1]["reason"], "undeclared_tool");
    assert_eq!(entries[1]["mode"], "enforce");
    assert!(!jsonl.contains("T-777123"), "no argument values: {jsonl}");

    let (code, printed, err) = ledger(dir.path(), &["public-key"]);
    assert_eq!(code, 0, "{err}");
    assert!(printed.contains(&public), "{printed}");
}

#[test]
fn the_ledger_and_key_can_be_named() {
    let dir = tempfile::tempdir().unwrap();
    let keygen = bin().args(["release", "keygen", "--out"]).arg(dir.path().join("ops.key")).output().unwrap();
    assert!(keygen.status.success());
    let db = dir.path().join("evidence.db");
    let out = proxy(
        dir.path(),
        &["--manifest", &manifest(), "--ledger-db", db.to_str().unwrap(), "--signing-key", dir.path().join("ops.key").to_str().unwrap()],
        &[],
        &[call(1, "refund")],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!dir.path().join("home").exists(), "nothing made under CLOAKPIPE_HOME");
    let (_, jsonl, _) = ledger(dir.path(), &["entries", "--ledger-db", db.to_str().unwrap()]);
    let entries = parse_jsonl(&jsonl).unwrap();
    verify_decisions(&entries, &[public_key(&dir.path().join("ops.key"))]).expect("signed with the named key");

    // The same through the environment.
    let db2 = dir.path().join("env.db");
    let out = proxy(
        dir.path(),
        &["--manifest", &manifest()],
        &[("CLOAKPIPE_LEDGER_DB", db2.to_str().unwrap()), ("CLOAKPIPE_SIGNING_KEY", dir.path().join("ops.key").to_str().unwrap())],
        &[call(1, "refund")],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!dir.path().join("home").exists());
    let (_, jsonl, _) = ledger(dir.path(), &["entries", "--ledger-db", db2.to_str().unwrap()]);
    verify_decisions(&parse_jsonl(&jsonl).unwrap(), &[public_key(&dir.path().join("ops.key"))]).unwrap();
}

#[test]
fn no_ledger_opts_out_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let out = proxy(dir.path(), &["--manifest", &manifest(), "--no-ledger"], &[], &[call(1, "refund")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.seen.contains("\"refund\""));
    assert!(out.stderr.contains("WARNING") && out.stderr.contains("not recorded"), "{}", out.stderr);
    assert!(!dir.path().join("home").exists(), "no ledger, no key");
}

#[test]
fn shadow_mode_forwards_and_marks_its_entries() {
    for flags in [["--mode", "shadow"], ["--gate", "warn"]] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = vec!["--manifest", manifest().leak() as &str];
        args.extend(flags);
        let out = proxy(dir.path(), &args, &[], &[call(1, "delete_customer")]);
        assert_eq!(out.code, 0, "{flags:?}: {}", out.stderr);
        assert!(out.seen.contains("delete_customer"), "{flags:?}: shadow forwards");
        assert!(out.messages.iter().all(|m| m.get("error").is_none()), "{:?}", out.messages);
        let (_, jsonl, _) = ledger(dir.path(), &["entries"]);
        let entries = parse_jsonl(&jsonl).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!((entries[0]["decision"].as_str(), entries[0]["mode"].as_str()), (Some("deny"), Some("shadow")), "{flags:?}");
        assert_eq!(entries[0]["forwarded"], true);
    }
}

#[test]
fn mode_flags_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let both = proxy(dir.path(), &["--manifest", &manifest(), "--mode", "shadow", "--gate", "warn"], &[], &[]);
    assert_eq!(both.code, 2, "{}", both.stderr);
    let no_manifest = proxy(dir.path(), &["--mode", "shadow"], &[], &[]);
    assert_eq!(no_manifest.code, 2, "{}", no_manifest.stderr);
    assert!(no_manifest.stderr.contains("--manifest"), "{}", no_manifest.stderr);
    let help = bin().args(["mcp-proxy", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("--mode") && help.contains("--no-ledger") && help.contains("--signing-key"), "{help}");
    assert!(!help.contains("--gate "), "--gate is a hidden alias: {help}");
}

#[test]
fn a_ledger_that_cannot_be_opened_stops_the_gate() {
    let dir = tempfile::tempdir().unwrap();
    // A directory is not a ledger database.
    let out = proxy(dir.path(), &["--manifest", &manifest(), "--ledger-db", dir.path().to_str().unwrap()], &[], &[call(1, "refund")]);
    assert_ne!(out.code, 0, "{}", out.stderr);
    assert!(!out.seen.contains("refund"), "nothing forwarded: {}", out.seen);
    // So is a key file that is not a signing key.
    std::fs::write(dir.path().join("bad.key"), "{}").unwrap();
    let out = proxy(dir.path(), &["--manifest", &manifest(), "--signing-key", dir.path().join("bad.key").to_str().unwrap()], &[], &[call(1, "refund")]);
    assert_ne!(out.code, 0, "{}", out.stderr);
    assert!(!out.seen.contains("refund"));
}
