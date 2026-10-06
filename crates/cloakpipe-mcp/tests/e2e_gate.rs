//! The interceptor enforces the tool gate: refused calls never reach the
//! upstream tool, the agent gets a JSON-RPC error for them, and the refusal
//! is evidence bound to the release.

use cloakpipe_cert::statement::{sign, statement, Certification, TrustedKey, VerifyContext};
use cloakpipe_core::{config::DetectionConfig, detector::Detector, vault::Vault};
use cloakpipe_ledger::{ActionKind, LedgerStore, MetadataValue};
use cloakpipe_mcp::{run_proxy_io, stable_ids, GateMode, ProxyContext, ToolGate};
use cloakpipe_release::AgentRelease;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn messages(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

/// A fake tool that records every line and answers each with an empty
/// result carrying the request's id.
fn fake_upstream(dir: &std::path::Path) -> (Vec<String>, std::path::PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{received}'
  id=$(printf '%s' "$line" | sed 's/^{{"id":\([0-9]*\),.*$/\1/')
  printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[]}}}}\n' "$id"
done
"#,
            received = received.display()
        ),
    )
    .unwrap();
    (vec!["sh".into(), script.to_string_lossy().into_owned()], received)
}

fn manifest() -> AgentRelease {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cloakpipe-release/testdata/support-agent-184.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn certified_gate(mode: GateMode) -> ToolGate {
    let m = manifest();
    let release = m.manifest_hash().to_string();
    let now = chrono::Utc::now();
    let c: Certification = serde_json::from_value(json!({
        "id": "cert-e2e",
        "release": release,
        "environment": "production",
        "decision": {
            "outcome": "certified", "release": release,
            "policy": {"name": "p", "version": "1", "hash": format!("sha256:{}", "cd".repeat(32))},
            "requiredSuites": [], "runs": [{"runId": "r", "suite": "s", "hash": format!("sha256:{}", "11".repeat(32))}],
            "baselineRuns": [], "summaries": [], "reasons": []
        },
        "issuedAt": (now - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "validUntil": (now + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": "test"
    }))
    .unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let trust = VerifyContext {
        trusted: vec![TrustedKey { keyid: "k1".into(), public_key: key.verifying_key().to_bytes() }],
        ..Default::default()
    };
    ToolGate::new(mode, &m, "production", Some(sign(&statement(&c), &key, "k1")), trust)
}

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"q": "x"}}}).to_string()
}

fn run(gate: ToolGate, lines: &[String]) -> (Capture, String, Vec<cloakpipe_ledger::record::LedgerRecord>, [u8; 32]) {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = fake_upstream(dir.path());
    let ledger_db = dir.path().join("ledger.db");
    let release = gate.release_bytes();
    let ctx = ProxyContext {
        detector: Detector::from_config(&serde_json::from_str::<DetectionConfig>("{}").unwrap()).unwrap(),
        vault: Vault::ephemeral(),
        ledger_db: Some(ledger_db.to_string_lossy().into_owned()),
        release: Some(release),
        gate: Some(gate),
    };
    let out = Capture::default();
    let input = Cursor::new(lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes());
    run_proxy_io(upstream, ctx, input, out.clone()).unwrap();
    let seen = std::fs::read_to_string(&received).unwrap_or_default();
    let store = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap();
    let records = store.records_for_tenant(&stable_ids().0).unwrap().into_iter().map(|r| r.record).collect();
    (out, seen, records, release)
}

#[test]
fn refused_calls_never_reach_the_tool() {
    let lines = [call(1, "refund"), call(2, "delete_customer"), json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).to_string()];
    let (out, seen, records, release) = run(certified_gate(GateMode::Enforce), &lines);

    assert!(seen.contains("\"refund\""), "the declared tool was called: {seen}");
    assert!(!seen.contains("delete_customer"), "the refused call reached the tool: {seen}");
    assert!(seen.contains("tools/list"), "other methods pass through: {seen}");

    let msgs = out.messages();
    let refusal = msgs.iter().find(|m| m["id"] == 2).expect("the agent gets an answer for the refused call");
    assert_eq!(refusal["error"]["code"], -32001);
    assert_eq!(refusal["error"]["data"]["reason"], "undeclared_tool");
    assert_eq!(refusal["error"]["data"]["tool"], "delete_customer");
    assert!(refusal.get("result").is_none());
    assert!(msgs.iter().any(|m| m["id"] == 1 && m.get("result").is_some()), "{msgs:?}");

    let blocks: Vec<_> = records.iter().filter(|r| r.actions.iter().any(|a| a.kind == ActionKind::Block)).collect();
    assert_eq!(blocks.len(), 1, "{records:?}");
    assert_eq!(blocks[0].release_hash(), Some(release));
    assert_eq!(blocks[0].metadata.get("gate_denial"), Some(&MetadataValue::OpaqueId("undeclared_tool".into())));
}

#[test]
fn warn_mode_forwards_and_records_the_violation() {
    let (out, seen, records, _) = run(certified_gate(GateMode::Warn), &[call(2, "delete_customer")]);
    assert!(seen.contains("delete_customer"), "warn mode forwards: {seen}");
    assert!(out.messages().iter().all(|m| m.get("error").is_none()));
    let flagged: Vec<_> = records.iter().filter(|r| r.metadata.contains_key("gate_violation")).collect();
    assert_eq!(flagged.len(), 1, "{records:?}");
    assert_eq!(flagged[0].metadata.get("gate_violation"), Some(&MetadataValue::OpaqueId("undeclared_tool".into())));
    assert!(records.iter().all(|r| r.actions.iter().all(|a| a.kind != ActionKind::Block)));
}

#[test]
fn a_refused_call_without_an_id_gets_no_reply() {
    // JSON-RPC notifications have no id and take no response.
    let note = json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_customer"}}).to_string();
    let (out, seen, _, _) = run(certified_gate(GateMode::Enforce), &[note]);
    assert!(!seen.contains("delete_customer"));
    assert!(out.messages().is_empty());
}
