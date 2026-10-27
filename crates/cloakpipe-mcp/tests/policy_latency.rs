//! The gate's decision for a typical call (contract + Cedar, with counters
//! read from SQLite) is fast enough to sit on every tool call: p99 < 2ms is
//! the target; CI asserts a generous 5ms so a busy runner does not flake.

use cloakpipe_mcp::{Counters, GateMode, ToolGate};
use cloakpipe_release::v1::Manifest;
use serde_json::json;
use std::time::{Duration, Instant};

const NOW: &str = "2026-10-27T12:00:00Z";

#[test]
fn p99_contract_and_policy_evaluation_is_under_budget() {
    let example = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/support-agent/cloakpipe.manifest.yaml");
    let m = Manifest::parse_path(&example).unwrap();
    assert!(m.policy.is_some(), "the example references its Cedar policy");
    let dir = tempfile::tempdir().unwrap();
    let task = json!({"taskId": "t-1042", "ticket": {"id": "T-1042", "customer_email": "dana@customer.example"}});
    let g = ToolGate::from_manifest(GateMode::Enforce, &m)
        .with_task_context(Some(task))
        .unwrap()
        .with_policy(Counters::open(dir.path().join("state.db")).unwrap())
        .unwrap();
    // Some history in the counters, as a running gate would have.
    for _ in 0..40 {
        g.record_forwarded("send_email", NOW).unwrap();
        g.record_forwarded("read_ticket", NOW).unwrap();
    }
    let args = json!({"ticket_id": "T-1042"});
    for _ in 0..50 {
        g.check("read_ticket", Some(&args), NOW).unwrap();
    }
    let mut samples: Vec<Duration> = (0..1000)
        .map(|_| {
            let t = Instant::now();
            g.check("read_ticket", Some(&args), NOW).unwrap();
            t.elapsed()
        })
        .collect();
    samples.sort();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    eprintln!("contract + Cedar decision: p50 {p50:?}, p99 {p99:?}");
    assert!(p99 < Duration::from_millis(5), "p99 {p99:?} is over budget");
}
