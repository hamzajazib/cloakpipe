//! `cloakpipe mcp-proxy` with the Cedar policy a v1 manifest references
//! (examples/support-agent/policies/support.cedar): policy_denied with the
//! determining policies, @approval routes, persistent counters across
//! restarts, and refusing to start on a bad policy or counter store.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/support-agent").join(name)
}

/// Copy the example's manifest and policy into `dir`, applying `edit` to the policy.
fn example_copy(dir: &Path, edit: impl Fn(String) -> String) -> PathBuf {
    std::fs::create_dir_all(dir.join("policies")).unwrap();
    let policy = std::fs::read_to_string(example("policies/support.cedar")).unwrap();
    std::fs::write(dir.join("policies/support.cedar"), edit(policy)).unwrap();
    let manifest = dir.join("cloakpipe.manifest.yaml");
    std::fs::copy(example("cloakpipe.manifest.yaml"), &manifest).unwrap();
    manifest
}

#[cfg(not(feature = "certification"))]
mod gate {
    use super::*;
    use serde_json::{json, Value};
    use std::io::Write;
    use std::process::Stdio;

    fn tool_call(id: u64, tool: &str, arguments: Value) -> String {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}).to_string()
    }

    fn email(n: u64) -> Value {
        json!({"ticket_id": "T-1042", "to": "dana@customer.example", "subject": "Update", "body": format!("Update number {n} on T-1042.")})
    }

    fn refund(amount: u64) -> Value {
        json!({"ticket_id": "T-1042", "amount": amount})
    }

    struct Run {
        code: i32,
        msgs: Vec<Value>,
        seen: Vec<Value>,
        stderr: String,
    }

    impl Run {
        fn reply(&self, id: u64) -> &Value {
            self.msgs.iter().find(|m| m["id"] == id).unwrap_or_else(|| panic!("no reply to {id}: {:?} {}", self.msgs, self.stderr))
        }

        fn reason(&self, id: u64) -> Option<&str> {
            self.reply(id)["error"]["data"]["reason"].as_str()
        }
    }

    /// Run the proxy in `dir` (also its CLOAKPIPE_HOME) in front of the
    /// example's mock upstream.
    fn proxy(dir: &Path, manifest: &Path, extra: &[&str], envs: &[(&str, &str)], lines: &[String]) -> Run {
        let log = dir.join("upstream.jsonl");
        let _ = std::fs::remove_file(&log);
        let upstream = format!("python3 {}", example("mock_upstream.py").display());
        let mut cmd = bin();
        cmd.current_dir(dir)
            .args(["mcp-proxy", "--upstream", &upstream, "--manifest"])
            .arg(manifest)
            .arg("--task-context")
            .arg(example("task-context.json"))
            .arg("--operations-db")
            .arg(dir.join("ops.db"))
            .args(extra)
            .env("MOCK_UPSTREAM_LOG", &log)
            .env("CLOAKPIPE_HOME", dir.join("home"))
            .env_remove("CLOAKPIPE_STATE_DB")
            .env_remove("CLOAKPIPE_RELEASE")
            .env_remove("CLOAKPIPE_TASK_CONTEXT")
            .env_remove("CLOAKPIPE_OPERATIONS_DB")
            .env_remove("CLOAKPIPE_LEDGER_DB");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            msgs: String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect(),
            seen: std::fs::read_to_string(&log).unwrap_or_default().lines().map(|l| serde_json::from_str(l).unwrap()).collect(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    #[test]
    fn small_refunds_pass_and_large_ones_need_the_policy_route() {
        let dir = tempfile::tempdir().unwrap();
        let r = proxy(dir.path(), &example("cloakpipe.manifest.yaml"), &[], &[], &[
            tool_call(1, "issue_refund", refund(50)),
            tool_call(2, "issue_refund", refund(350)),
        ]);
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert!(r.reply(1)["result"].is_object(), "{:?}", r.msgs);
        assert_eq!(r.reason(2), Some("approval_required"));
        // The manifest's route and the policy's @approval route, once.
        assert_eq!(r.reply(2)["error"]["data"]["approvers"], json!(["slack:#support-leads"]));
        assert_eq!(r.seen.len(), 1);
        assert!(r.stderr.contains("policy"), "the start-up log names the policy: {}", r.stderr);
    }

    #[test]
    fn a_policy_denial_names_the_determining_policies() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = example_copy(dir.path(), |p| {
            p + "\n@id(\"no-refunds-on-1042\")\nforbid (principal, action == Tool::\"issue_refund\", resource)\nwhen { context.task.ticket.id == \"T-1042\" };\n"
        });
        let r = proxy(dir.path(), &manifest, &[], &[], &[tool_call(1, "issue_refund", refund(50))]);
        assert_eq!(r.reason(1), Some("policy_denied"));
        assert_eq!(r.reply(1)["error"]["data"]["policies"], json!(["no-refunds-on-1042"]));
        assert_eq!(r.reply(1)["error"]["code"], -32001);
        assert!(r.seen.is_empty());
    }

    #[test]
    fn the_email_rate_limit_holds_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = example("cloakpipe.manifest.yaml");
        // 50 emails in the first run: all within the limit.
        let first: Vec<String> = (1..=50).map(|n| tool_call(n, "send_email", email(n))).collect();
        let r = proxy(dir.path(), &manifest, &[], &[], &first);
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(r.seen.len(), 50, "{}", r.stderr);
        // A new process on the same CLOAKPIPE_HOME: the 51st is refused.
        let r = proxy(dir.path(), &manifest, &[], &[], &[tool_call(51, "send_email", email(51))]);
        assert_eq!(r.reason(51), Some("policy_denied"));
        assert_eq!(r.reply(51)["error"]["data"]["policies"], json!(["email-rate-limit"]));
        assert!(r.seen.is_empty());
        // Reads are counted apart and still allowed.
        let r = proxy(dir.path(), &manifest, &[], &[], &[tool_call(52, "read_ticket", json!({"ticket_id": "T-1042"}))]);
        assert!(r.reply(52)["result"].is_object(), "{:?}", r.msgs);
        assert!(dir.path().join("home/state.db").exists());
    }

    #[test]
    fn a_replayed_call_is_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = example_copy(dir.path(), |p| p.replace("send_email_1h >= 50", "send_email_1h >= 2"));
        // The same email in three runs: sent once, then replayed from the
        // operations store (never forwarded again).
        for id in 1..=3 {
            let r = proxy(dir.path(), &manifest, &[], &[], &[tool_call(id, "send_email", email(1))]);
            assert!(r.reply(id)["result"].is_object(), "{:?} {}", r.msgs, r.stderr);
            assert_eq!(r.seen.len(), usize::from(id == 1), "{}", r.stderr);
        }
        // One forwarded so far: one more email fits under the limit of 2.
        let r = proxy(dir.path(), &manifest, &[], &[], &[tool_call(4, "send_email", email(2)), tool_call(5, "send_email", email(3))]);
        assert!(r.reply(4)["result"].is_object(), "{:?}", r.msgs);
        assert_eq!(r.reason(5), Some("policy_denied"));
    }

    #[test]
    fn the_state_db_can_be_named() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = example_copy(dir.path(), |p| p.replace("send_email_1h >= 50", "send_email_1h >= 1"));
        let db = dir.path().join("custom-state.db");
        let db = db.to_str().unwrap();
        let r = proxy(dir.path(), &manifest, &["--state-db", db], &[], &[tool_call(1, "send_email", email(1))]);
        assert!(r.reply(1)["result"].is_object(), "{:?} {}", r.msgs, r.stderr);
        // The environment variable names the same store.
        let r = proxy(dir.path(), &manifest, &[], &[("CLOAKPIPE_STATE_DB", db)], &[tool_call(2, "send_email", email(2))]);
        assert_eq!(r.reason(2), Some("policy_denied"));
        assert!(!dir.path().join("home/state.db").exists());
    }

    #[test]
    fn an_invalid_policy_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = example_copy(dir.path(), |p| p.replace("when { resource.args.amount <= 100 };", "when { resource.args.amount <= };"));
        let r = proxy(dir.path(), &manifest, &[], &[], &[tool_call(1, "read_ticket", json!({"ticket_id": "T-1042"}))]);
        assert_eq!(r.code, 1, "{}", r.stderr);
        assert!(r.stderr.contains("support.cedar"), "{}", r.stderr);
        assert!(r.seen.is_empty(), "the upstream must not start");
    }

    #[test]
    fn an_unusable_counter_store_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("no-such-dir/state.db");
        let r = proxy(dir.path(), &example("cloakpipe.manifest.yaml"), &["--state-db", db.to_str().unwrap()], &[], &[
            tool_call(1, "read_ticket", json!({"ticket_id": "T-1042"})),
        ]);
        assert_eq!(r.code, 2, "{}", r.stderr);
        assert!(r.stderr.contains("--state-db"), "{}", r.stderr);
        assert!(r.seen.is_empty());
    }

    #[test]
    fn a_policy_evaluation_error_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let manifest =
            example_copy(dir.path(), |p| p.replace("context.counters.send_email_1h >= 50", "resource.args.subject >= 50"));
        let r = proxy(dir.path(), &manifest, &[], &[], &[tool_call(1, "send_email", email(1))]);
        assert_eq!(r.reason(1), Some("fail_closed"));
        assert!(r.seen.is_empty());
    }
}

#[test]
fn manifest_validate_checks_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin().args(["manifest", "validate"]).arg(example("cloakpipe.manifest.yaml")).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("5 Cedar policies"), "{stdout}");
    let manifest = example_copy(dir.path(), |p| p + "\nforbid (principal, action, resource) when { ;\n");
    let out = bin().args(["manifest", "validate"]).arg(&manifest).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid Cedar policy"), "{}", String::from_utf8_lossy(&out.stderr));
}
