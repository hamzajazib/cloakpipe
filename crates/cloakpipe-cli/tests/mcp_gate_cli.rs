//! `cloakpipe mcp-proxy --manifest …`: the interceptor only lets the agent
//! call the tools its release declares, with arguments its tool contracts
//! allow. The default build needs nothing else; the legacy `certification`
//! build also requires a certification of the release (`--certification`).

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



/// A fake tool: records each line, answers with an empty result for its id.
fn upstream(dir: &std::path::Path) -> (String, PathBuf) {
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

// ── default build: the release manifest and its tool contracts alone ────

#[cfg(not(feature = "certification"))]
mod manifest_only {
    use super::*;

    /// A file of the support-agent example (examples/support-agent).
    fn example(name: &str) -> String {
        root(&format!("../../examples/support-agent/{name}"))
    }

    /// The gate flags for the support-agent example, with its operations
    /// store in `dir` (send_email and issue_refund are side-effecting).
    fn example_gate(dir: &std::path::Path) -> Vec<String> {
        [
            "--manifest", &example("cloakpipe.manifest.yaml"),
            "--task-context", &example("task-context.json"),
            "--operations-db", &dir.join("ops.db").to_string_lossy(),
        ]
        .map(String::from)
        .to_vec()
    }

    /// Run the interceptor in front of the example's mock upstream; returns
    /// (exit code, agent messages, the calls the upstream received, stderr).
    fn example_proxy(dir: &std::path::Path, extra: &[String], lines: &[String]) -> (i32, Vec<Value>, Vec<Value>, String) {
        let log = dir.join("upstream.jsonl");
        let _ = std::fs::remove_file(&log);
        let upstream = format!("python3 {}", example("mock_upstream.py"));
        let mut cmd = bin();
        cmd.current_dir(dir)
            .args(["mcp-proxy", "--upstream", &upstream])
            .args(extra)
            .env("CLOAKPIPE_VAULT_KEY", VAULT_KEY)
            .env("MOCK_UPSTREAM_LOG", &log)
            .env_remove("CLOAKPIPE_RELEASE")
            .env_remove("CLOAKPIPE_TASK_CONTEXT")
            .env_remove("CLOAKPIPE_OPERATIONS_DB")
            .env_remove("CLOAKPIPE_LEDGER_DB");
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        let msgs = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
        let seen = std::fs::read_to_string(&log).unwrap_or_default().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        (out.status.code().unwrap_or(-1), msgs, seen, String::from_utf8_lossy(&out.stderr).into_owned())
    }

    fn tool_call(id: u64, tool: &str, arguments: Value) -> String {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}).to_string()
    }

    fn email(to: &str) -> Value {
        json!({"ticket_id": "T-1042", "to": to, "subject": "Your refund", "body": "Hi Dana, your refund for T-1042 is on its way."})
    }

    fn refund(amount: u64) -> Value {
        json!({"ticket_id": "T-1042", "amount": amount})
    }

    fn names(seen: &[Value]) -> Vec<&str> {
        seen.iter().map(|c| c["name"].as_str().unwrap()).collect()
    }

    fn cli(dir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
        let out = bin().current_dir(dir).args(args).output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    }

    #[test]
    fn mcp_proxy_manifest_only_enforces_contract() {
        // Example 2: a prompt-injected agent tries to mail the customer list to
        // an attacker. No certification is involved.
        let dir = tempfile::tempdir().unwrap();
        let (code, msgs, seen, err) = example_proxy(
            dir.path(),
            &example_gate(dir.path()),
            &[
                tool_call(1, "read_ticket", json!({"ticket_id": "T-1042"})),
                tool_call(2, "send_email", email("dana@customer.example")),
                tool_call(3, "send_email", email("attacker@evil.example")),
                tool_call(4, "export_customers", json!({})),
                tool_call(5, "read_ticket", json!({"ticket_id": "T-1042", "include": "all"})),
            ],
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(names(&seen), ["read_ticket", "send_email"], "only the conforming calls reach the upstream: {seen:?}");
        assert!(!format!("{seen:?}").contains("evil.example"), "{seen:?}");
        // The allowed email reaches the tool exactly as the agent sent it:
        // the gate never rewrites an allowed call (no --transform pii).
        assert_eq!(seen[1]["arguments"], email("dana@customer.example"), "{seen:?}");
        assert_eq!(refusal(&msgs, 1), None, "{msgs:?}");
        assert_eq!(refusal(&msgs, 2), None, "{msgs:?}");

        let denied = msgs.iter().find(|m| m["id"] == 3).expect("an answer for the refused call");
        assert_eq!(denied["error"]["code"], -32001, "{denied}");
        assert_eq!(denied["error"]["data"]["reason"], "scope_mismatch", "{denied}");
        assert_eq!(denied["error"]["data"]["path"], "/to", "{denied}");
        assert_eq!(denied["error"]["data"]["tool"], "send_email", "{denied}");
        assert!(!denied.to_string().contains("evil.example"), "a refusal never echoes the value: {denied}");
        assert_eq!(refusal(&msgs, 4).as_deref(), Some("undeclared_tool"), "{msgs:?}");
        let extra = msgs.iter().find(|m| m["id"] == 5).unwrap();
        assert_eq!(extra["error"]["data"]["reason"], "undeclared_argument", "{extra}");
        assert!(!extra.to_string().contains("include"), "the undeclared argument is not named: {extra}");
        assert!(!err.contains("certification"), "no certification warning in the default build: {err}");
        assert!(!err.contains("deprecated"), "a v1 manifest is not deprecated: {err}");
    }

    #[test]
    fn an_internal_recipient_matches_the_or_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let (code, msgs, seen, err) =
            example_proxy(dir.path(), &example_gate(dir.path()), &[tool_call(1, "send_email", email("billing@ourcompany.com"))]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(refusal(&msgs, 1), None, "{msgs:?}");
        assert_eq!(names(&seen), ["send_email"]);
    }

    #[test]
    fn a_retried_email_is_the_same_operation_and_never_sent_twice() {
        let dir = tempfile::tempdir().unwrap();
        let (_, msgs, seen, err) =
            example_proxy(dir.path(), &example_gate(dir.path()), &[tool_call(1, "send_email", email("dana@customer.example"))]);
        assert_eq!(refusal(&msgs, 1), None, "{msgs:?} {err}");
        assert_eq!(names(&seen), ["send_email"]);
        // The agent retries after a restart: the stored result is replayed.
        let (_, msgs, seen, err) =
            example_proxy(dir.path(), &example_gate(dir.path()), &[tool_call(7, "send_email", email("dana@customer.example"))]);
        assert!(seen.is_empty(), "the email is not sent again: {seen:?} {err}");
        let answer = msgs.iter().find(|m| m["id"] == 7).expect("an answer");
        assert_eq!(answer["result"]["content"][0]["text"], "send_email: done", "the stored result is replayed: {answer}");
        // Same ticket and body (the idempotency key) to another allowed
        // recipient: the same operation with other arguments is a conflict,
        // never a second send.
        let mut changed = email("dana@customer.example");
        changed["to"] = json!("support@ourcompany.com");
        let (_, msgs, seen, _) = example_proxy(dir.path(), &example_gate(dir.path()), &[tool_call(8, "send_email", changed)]);
        assert!(seen.is_empty(), "{seen:?}");
        assert_eq!(refusal(&msgs, 8).as_deref(), Some("operation_conflict"), "{msgs:?}");
        // Another body is another operation: it is sent.
        let mut second = email("dana@customer.example");
        second["body"] = json!("A second, different email.");
        let (_, msgs, seen, _) = example_proxy(dir.path(), &example_gate(dir.path()), &[tool_call(9, "send_email", second)]);
        assert_eq!(refusal(&msgs, 9), None, "{msgs:?}");
        assert_eq!(names(&seen), ["send_email"]);
    }

    #[test]
    fn a_large_refund_needs_an_approval_routed_to_the_manifest_approvers() {
        let dir = tempfile::tempdir().unwrap();
        let (code, msgs, seen, err) = example_proxy(
            dir.path(),
            &example_gate(dir.path()),
            &[tool_call(1, "issue_refund", refund(50)), tool_call(2, "issue_refund", refund(350))],
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(refusal(&msgs, 1), None, "50 is under the approval threshold: {msgs:?}");
        assert_eq!(names(&seen), ["issue_refund"]);
        let denied = msgs.iter().find(|m| m["id"] == 2).unwrap();
        assert_eq!(denied["error"]["data"]["reason"], "approval_required", "{denied}");
        assert_eq!(denied["error"]["data"]["approvers"], json!(["slack:#support-leads"]), "{denied}");
        // The fingerprint is the one `cloakpipe action fingerprint` prints.
        let args = dir.path().join("refund.json");
        std::fs::write(&args, refund(350).to_string()).unwrap();
        let (code, out, err) = cli(
            dir.path(),
            &["action", "fingerprint", "--manifest", &example("cloakpipe.manifest.yaml"), "--tool", "issue_refund", "--args", &args.to_string_lossy()],
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(denied["error"]["data"]["fingerprint"], out.trim(), "{denied}");
    }

    #[test]
    fn an_approved_refund_runs_and_a_reused_receipt_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let d = |n: &str| dir.path().join(n).to_string_lossy().into_owned();
        let (code, _, err) = cli(dir.path(), &["release", "keygen", "--out", &d("approver.json")]);
        assert_eq!(code, 0, "{err}");
        std::fs::write(d("refund.json"), refund(350).to_string()).unwrap();
        let (code, _, err) = cli(
            dir.path(),
            &[
                "approve", "--manifest", &example("cloakpipe.manifest.yaml"), "--tool", "issue_refund",
                "--args", &d("refund.json"), "--task-context", &example("task-context.json"),
                "--key", &d("approver.json"), "--expires", "15m", "--out", &d("approvals"),
            ],
        );
        assert_eq!(code, 0, "{err}");
        let mut gate = example_gate(dir.path());
        gate.extend(["--approvals", &d("approvals"), "--approver-key", &d("approver.json")].map(String::from));
        let (code, msgs, seen, err) = example_proxy(
            dir.path(),
            &gate,
            &[tool_call(1, "issue_refund", refund(350)), tool_call(2, "issue_refund", refund(500))],
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(refusal(&msgs, 1), None, "the approved call runs: {msgs:?}");
        assert_eq!(refusal(&msgs, 2).as_deref(), Some("approval_required"), "the receipt covers 350 only: {msgs:?}");
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0]["arguments"], refund(350));
    }

    #[test]
    fn a_receipt_valid_longer_than_the_ttl_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let d = |n: &str| dir.path().join(n).to_string_lossy().into_owned();
        cli(dir.path(), &["release", "keygen", "--out", &d("approver.json")]);
        std::fs::write(d("refund.json"), refund(350).to_string()).unwrap();
        let (code, _, err) = cli(
            dir.path(),
            &[
                "approve", "--manifest", &example("cloakpipe.manifest.yaml"), "--tool", "issue_refund",
                "--args", &d("refund.json"), "--task-context", &example("task-context.json"),
                "--key", &d("approver.json"), "--expires", "1h", "--out", &d("approvals"),
            ],
        );
        assert_eq!(code, 0, "{err}");
        let mut gate = example_gate(dir.path());
        gate.extend(["--approvals", &d("approvals"), "--approver-key", &d("approver.json")].map(String::from));
        let (_, msgs, seen, _) = example_proxy(dir.path(), &gate, &[tool_call(1, "issue_refund", refund(350))]);
        assert_eq!(refusal(&msgs, 1).as_deref(), Some("approval_invalid"), "1h receipt vs a 15m ttl: {msgs:?}");
        assert!(seen.is_empty());
    }

    #[test]
    fn the_example_manifest_validates() {
        let dir = tempfile::tempdir().unwrap();
        let (code, out, err) = cli(dir.path(), &["manifest", "validate", &example("cloakpipe.manifest.yaml")]);
        assert_eq!(code, 0, "{out}{err}");
        assert!(out.contains("support-agent@2026.10.3"), "{out}");
    }

    #[test]
    fn mcp_proxy_refuses_a_manifest_it_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = std::fs::read_to_string(example("cloakpipe.manifest.yaml")).unwrap();
        let cases = [
            // An unknown key would silently drop a rule.
            ("side_effect: true", "sideEffect: true"),
            ("max_len: 200", "maxLength: 200"),
            // A condition that cannot be parsed.
            ("when: \"amount > 100\"", "when: \"amount >\""),
            // A condition on an argument the tool does not declare.
            ("when: \"amount > 100\"", "when: \"total > 100\""),
            // A template over an undeclared argument.
            ("{sha256(body)}", "{sha256(message)}"),
            // Neither format.
            ("release: support-agent", "name: support-agent"),
        ];
        for (from, to) in cases {
            let path = dir.path().join("cloakpipe.manifest.yaml");
            assert!(manifest.contains(from), "{from}");
            std::fs::write(&path, manifest.replace(from, to)).unwrap();
            let mut gate = example_gate(dir.path());
            gate[1] = path.to_string_lossy().into_owned();
            let (code, _, seen, err) = example_proxy(dir.path(), &gate, &[tool_call(1, "read_ticket", json!({"ticket_id": "T-1042"}))]);
            assert_eq!(code, 1, "{to}: {err}");
            assert!(seen.is_empty(), "{to}: the upstream must not start");
        }
    }

    #[test]
    fn a_v1_manifest_takes_no_tool_contract() {
        let dir = tempfile::tempdir().unwrap();
        let mut gate = example_gate(dir.path());
        gate.extend(["--tool-contract", &root("../../examples/action-boundary/crm-tools.contract.yaml")].map(String::from));
        let (code, _, seen, err) = example_proxy(dir.path(), &gate, &[tool_call(1, "read_ticket", json!({"ticket_id": "T-1042"}))]);
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("--tool-contract"), "{err}");
        assert!(seen.is_empty());
    }

    #[test]
    fn certification_flags_rejected_without_feature() {
        let dir = tempfile::tempdir().unwrap();
        let digest = "ab".repeat(32);
        for flags in [
            ["--certification", "cert.dsse.json"],
            ["--trust", "key.json"],
            ["--trust-key", "k1=00"],
            ["--revoked-statement", digest.as_str()],
            ["--revoked-key", "k1"],
            ["--environment", "staging"],
        ] {
            let extra = [example_gate(dir.path()), flags.map(String::from).to_vec()].concat();
            let (code, _, seen, err) = example_proxy(dir.path(), &extra, &[tool_call(1, "read_ticket", json!({"ticket_id": "T-1042"}))]);
            assert_eq!(code, 2, "{flags:?}: {err}");
            assert!(err.contains("unexpected argument"), "{flags:?}: {err}");
            assert!(seen.is_empty(), "{flags:?}: the upstream must not start");
        }
    }

    #[test]
    fn warn_mode_forwards_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let extra = [example_gate(dir.path()), vec!["--gate".into(), "warn".into()]].concat();
        let (_, msgs, seen, err) = example_proxy(dir.path(), &extra, &[tool_call(1, "export_customers", json!({}))]);
        assert_eq!(seen.len(), 1, "warn mode forwards: {seen:?}");
        assert_eq!(refusal(&msgs, 1), None);
        assert!(err.contains("warn mode: forwarded") && err.contains("undeclared_tool"), "the call's violation is reported: {err}");
    }

    #[test]
    fn a_legacy_manifest_still_runs_with_a_deprecation_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (code, _, seen, err) = example_proxy(
            dir.path(),
            &["--manifest".into(), manifest()],
            &[tool_call(1, "refund", json!({}))],
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(err.contains("deprecated") && err.contains("cloakpipe.manifest.yaml"), "{err}");
    }
}

#[test]
fn a_release_variable_naming_another_release_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let other = format!("sha256:{}", "ab".repeat(32));
    let (code, _, _, err) = proxy(dir.path(), &["--manifest", &manifest()], &[("CLOAKPIPE_RELEASE", &other)], &[]);
    assert_ne!(code, 0);
    assert!(err.contains("CLOAKPIPE_RELEASE"), "{err}");
}

#[test]
fn gate_flags_without_a_manifest_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    for flags in [vec!["--gate", "warn"], vec!["--task-context", "task.json"], vec!["--tool-contract", "c.yaml"]] {
        let (code, _, _, err) = proxy(dir.path(), &flags, &[], &[]);
        assert_ne!(code, 0, "{flags:?} must not run ungated");
        assert!(err.contains("--manifest"), "{flags:?}: {err}");
    }
}


// ── legacy: certification requirement (`certification` feature) ─────────

#[cfg(feature = "certification")]
mod certification {
    use super::*;

    fn run_ok(dir: &std::path::Path, args: &[&str]) -> String {
        let out = bin().current_dir(dir).args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }

    fn call(id: u64, tool: &str) -> String {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}}).to_string()
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
    fn certification_flags_without_a_manifest_refuse_to_start() {
        let dir = tempfile::tempdir().unwrap();
        for flags in [
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
}
