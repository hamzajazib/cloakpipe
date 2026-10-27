//! Offline verification of decision ledger entries (`cloakpipe.decision/v1`)
//! with the gate's public key: hash chain, entry hashes and per-entry
//! signatures. The entries are produced by `cloakpipe-ledger` (a test-only
//! dependency); the verifier re-derives everything with its own code.

use cloakpipe_ledger::decision::{Decision, DecisionDraft, Mode, Outcome};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_verify::decisions::{parse_jsonl, verify_decisions, DecisionError};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cloakpipe-verify"))
}

fn draft(decision: Decision, reason: &str, mode: Mode, forwarded: bool) -> DecisionDraft {
    DecisionDraft {
        release: Some(format!("sha256:{}", "cd".repeat(32))),
        tool: Some("send_email".into()),
        decision,
        reason: reason.into(),
        mode: Some(mode),
        forwarded,
        ..DecisionDraft::call()
    }
}

/// A ledger of six entries: allow, deny, require_approval, a shadow deny,
/// an unknown outcome and its reconciliation.
fn ledger(key: &GateKey) -> (tempfile::TempDir, Vec<Value>) {
    let dir = tempfile::tempdir().unwrap();
    let mut s = LedgerStore::open(dir.path().join("ledger.db").to_str().unwrap()).unwrap();
    s.append_decision(draft(Decision::Allow, "ok", Mode::Enforce, true), key).unwrap();
    s.append_decision(draft(Decision::Deny, "scope_mismatch", Mode::Enforce, false), key).unwrap();
    s.append_decision(draft(Decision::RequireApproval, "approval_required", Mode::Enforce, false), key).unwrap();
    s.append_decision(draft(Decision::Deny, "undeclared_tool", Mode::Shadow, true), key).unwrap();
    s.append_decision(DecisionDraft { outcome: Some(Outcome::Unknown), operation_id: Some("op-1".into()), ..DecisionDraft::outcome() }, key)
        .unwrap();
    s.append_decision(DecisionDraft { outcome: Some(Outcome::Committed), operation_id: Some("op-1".into()), ..DecisionDraft::reconcile() }, key)
        .unwrap();
    let entries = s.decisions().unwrap().iter().map(|e| serde_json::to_value(e).unwrap()).collect();
    (dir, entries)
}

fn jsonl(entries: &[Value]) -> String {
    entries.iter().map(|e| format!("{e}\n")).collect()
}

#[test]
fn a_ledger_verifies_with_the_gate_public_key_and_is_summarised() {
    let key = GateKey::from_seed([4; 32]);
    let (_dir, entries) = ledger(&key);
    let parsed = parse_jsonl(&jsonl(&entries)).unwrap();
    let s = verify_decisions(&parsed, &[key.public_key()]).expect("verifies");
    assert_eq!(s.entries, 6);
    assert_eq!((s.first_seq, s.last_seq), (Some(0), Some(5)));
    assert_eq!(s.head, entries[5]["entry_hash"].as_str().unwrap());
    assert_eq!(s.allowed, 1);
    assert_eq!(s.denied, 2);
    assert_eq!(s.approvals_required, 1);
    assert_eq!(s.shadow, 1);
    assert_eq!(s.unknown_outcomes, 1);
    assert_eq!(s.reconciled, 1);
}

#[test]
fn tampering_with_any_field_is_detected() {
    let key = GateKey::from_seed([4; 32]);
    let (_dir, entries) = ledger(&key);
    // A denial rewritten as an allow.
    let mut forged = entries.clone();
    forged[1]["decision"] = "allow".into();
    forged[1]["reason"] = "ok".into();
    assert!(matches!(verify_decisions(&forged, &[key.public_key()]), Err(DecisionError::EntryHash { seq: 1 })));
    // ... with its hash recomputed: the signature no longer matches.
    let mut rehashed = forged.clone();
    let h = hex::encode(cloakpipe_ledger::decision::entry_hash_of(&rehashed[1]));
    rehashed[1]["entry_hash"] = h.into();
    assert!(matches!(verify_decisions(&rehashed, &[key.public_key()]), Err(DecisionError::BadSignature { seq: 1 })));
    // A field added after the fact is covered by the hash too.
    let mut added = entries.clone();
    added[2]["note"] = "approved by phone".into();
    assert!(matches!(verify_decisions(&added, &[key.public_key()]), Err(DecisionError::EntryHash { seq: 2 })));
}

#[test]
fn a_dropped_or_reordered_entry_breaks_the_chain() {
    let key = GateKey::from_seed([4; 32]);
    let (_dir, mut entries) = ledger(&key);
    let mut dropped = entries.clone();
    dropped.remove(1);
    assert!(matches!(verify_decisions(&dropped, &[key.public_key()]), Err(DecisionError::SeqGap { expected: 1, actual: 2 })));
    entries.swap(2, 3);
    assert!(verify_decisions(&entries, &[key.public_key()]).is_err());
}

#[test]
fn only_the_given_keys_are_trusted() {
    let key = GateKey::from_seed([4; 32]);
    let (_dir, entries) = ledger(&key);
    let other = GateKey::from_seed([5; 32]);
    assert!(matches!(verify_decisions(&entries, &[other.public_key()]), Err(DecisionError::UnknownSigner { seq: 0, .. })));
    assert!(matches!(verify_decisions(&entries, &[]), Err(DecisionError::NoKeys)));
    // An entry re-signed by an untrusted key that claims the trusted keyid.
    let mut forged = entries.clone();
    forged[0]["sig"] = hex::encode(other.sign(&hex::decode(entries[0]["entry_hash"].as_str().unwrap()).unwrap())).into();
    assert!(matches!(verify_decisions(&forged, &[key.public_key()]), Err(DecisionError::BadSignature { seq: 0 })));
}

#[test]
fn a_range_from_a_later_seq_verifies_from_its_first_prev_hash() {
    let key = GateKey::from_seed([4; 32]);
    let (_dir, entries) = ledger(&key);
    let s = verify_decisions(&entries[2..], &[key.public_key()]).unwrap();
    assert_eq!(s.first_seq, Some(2));
    assert!(!s.from_genesis);
    assert!(verify_decisions(&entries, &[key.public_key()]).unwrap().from_genesis);
}

#[test]
fn malformed_lines_and_foreign_kinds_are_refused() {
    assert!(matches!(parse_jsonl("{\"seq\":0}\nnot json\n"), Err(DecisionError::Malformed { line: 2, .. })));
    let key = GateKey::from_seed([4; 32]);
    let (_dir, mut entries) = ledger(&key);
    entries[0]["kind"] = "cloakpipe.decision/v9".into();
    assert!(matches!(verify_decisions(&entries, &[key.public_key()]), Err(DecisionError::Kind { seq: 0 })));
}

#[test]
fn the_cli_verifies_entries_jsonl_offline() {
    let key = GateKey::from_seed([4; 32]);
    let (dir, entries) = ledger(&key);
    let file = dir.path().join("entries.jsonl");
    std::fs::write(&file, jsonl(&entries)).unwrap();
    // The key as hex, or as a key file holding only the public part.
    let keyfile = dir.path().join("gate.pub.json");
    std::fs::write(&keyfile, serde_json::json!({ "keyid": key.keyid(), "publicKey": key.public_hex() }).to_string()).unwrap();
    for k in [key.public_hex(), keyfile.to_string_lossy().into_owned()] {
        let out = Command::new(bin()).args(["decisions", file.to_str().unwrap(), "--key", &k]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert!(stdout.starts_with("OK  entries=6"), "{stdout}");
        assert!(stdout.contains("chain OK"), "{stdout}");
        assert!(stdout.contains("signatures OK"), "{stdout}");
        assert!(stdout.contains("denied=2"), "{stdout}");
    }

    let mut tampered = entries.clone();
    tampered[3]["mode"] = "enforce".into();
    std::fs::write(&file, jsonl(&tampered)).unwrap();
    let out = Command::new(bin()).args(["decisions", file.to_str().unwrap(), "--key", &key.public_hex()]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("FAIL"));

    // No key: a usage error, never an unpinned pass.
    let out = Command::new(bin()).args(["decisions", file.to_str().unwrap()]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
