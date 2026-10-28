//! Decision ledger entries (`cloakpipe.decision/v1`): one per gate
//! decision, hash-chained and Ed25519-signed one by one with the gate
//! signing key, stored next to (never inside) the legacy PII hop records.

use cloakpipe_ledger::decision::{Decision, DecisionDraft, Event, Mode, Outcome, DECISION_KIND, GENESIS};
use cloakpipe_ledger::gate_key::GateKey;
use cloakpipe_ledger::{Hop, LedgerStore, RecordBuilder};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn store(dir: &tempfile::TempDir) -> LedgerStore {
    LedgerStore::open(dir.path().join("ledger.db").to_str().unwrap()).unwrap()
}

fn deny(tool: &str, reason: &str) -> DecisionDraft {
    DecisionDraft {
        release: Some(format!("sha256:{}", "ab".repeat(32))),
        tool: Some(tool.into()),
        decision: Decision::Deny,
        reason: reason.into(),
        mode: Some(Mode::Enforce),
        ..DecisionDraft::call()
    }
}

#[test]
fn entries_carry_the_decision_fields_and_chain_from_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir);
    let key = GateKey::from_seed([7; 32]);
    let a = s.append_decision(DecisionDraft { task_id: Some("t-1".into()), ..deny("export_customers", "undeclared_tool") }, &key).unwrap();
    let b = s
        .append_decision(
            DecisionDraft {
                tool: Some("read_ticket".into()),
                decision: Decision::Allow,
                reason: "ok".into(),
                forwarded: true,
                ..deny("x", "y")
            },
            &key,
        )
        .unwrap();
    assert_eq!(a.kind, DECISION_KIND);
    assert_eq!((a.seq, b.seq), (0, 1));
    assert_eq!(a.prev_hash, GENESIS);
    assert_eq!(b.prev_hash, a.entry_hash);
    assert_eq!(a.decision, Decision::Deny);
    assert_eq!(a.reason, "undeclared_tool");
    assert_eq!(a.tool.as_deref(), Some("export_customers"));
    assert_eq!(a.task_id.as_deref(), Some("t-1"));
    assert_eq!(a.event, Event::Call);
    assert_eq!(a.mode, Some(Mode::Enforce));
    assert_eq!(a.outcome, None);
    assert!(!a.forwarded && b.forwarded);
    assert_eq!(a.signer, key.keyid());
    // The manifest digest stands in for the policy version until the policy
    // engine adds its own digest.
    assert_eq!(a.policy_version, a.release);
    assert_eq!(a.policy_digest, None);

    let read = s.decisions().unwrap();
    assert_eq!(read, vec![a.clone(), b]);

    // The wire form: every field present (null when absent), snake_case.
    let json = serde_json::to_value(&a).unwrap();
    for field in [
        "kind", "seq", "ts", "event", "release", "tool", "args_fingerprint", "decision", "reason", "path", "policy_version",
        "policy_digest", "mode", "task_id", "operation_id", "approval", "outcome", "forwarded", "signer", "prev_hash",
        "entry_hash", "sig",
    ] {
        assert!(json.get(field).is_some(), "{field} missing: {json}");
    }
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["outcome"], serde_json::Value::Null);
}

#[test]
fn each_entry_is_signed_over_its_entry_hash() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir);
    let key = GateKey::from_seed([9; 32]);
    let e = s.append_decision(deny("send_email", "scope_mismatch"), &key).unwrap();
    // entry_hash is the hash of the entry without entry_hash and sig.
    assert_eq!(e.entry_hash, e.compute_hash());
    let hash = hex::decode(&e.entry_hash).unwrap();
    let sig: [u8; 64] = hex::decode(&e.sig).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&key.public_key()).unwrap();
    vk.verify(&hash, &Signature::from_bytes(&sig)).expect("signed over entry_hash");

    // Any change to a recorded field changes the hash.
    let mut forged = e.clone();
    forged.reason = "ok".into();
    assert_ne!(forged.compute_hash(), e.entry_hash);
}

#[test]
fn outcomes_and_reconcile_actions_are_entries_too() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir);
    let key = GateKey::from_seed([1; 32]);
    let outcome = s
        .append_decision(
            DecisionDraft {
                operation_id: Some("op-1".into()),
                outcome: Some(Outcome::Unknown),
                ..DecisionDraft::outcome()
            },
            &key,
        )
        .unwrap();
    assert_eq!(outcome.event, Event::Outcome);
    assert_eq!(outcome.decision, Decision::Allow);
    assert_eq!(outcome.outcome, Some(Outcome::Unknown));
    let rec = s
        .append_decision(DecisionDraft { operation_id: Some("op-1".into()), outcome: Some(Outcome::Committed), ..DecisionDraft::reconcile() }, &key)
        .unwrap();
    assert_eq!(rec.event, Event::Reconcile);
    assert_eq!(rec.reason, "reconciled");
    assert_eq!(serde_json::to_value(&rec).unwrap()["outcome"], "committed");
}

#[test]
fn old_records_are_still_read_next_to_decision_entries() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir);
    let tenant = uuid::Uuid::nil();
    let mut old = RecordBuilder::new().seq(0).tenant(tenant).hop(Hop::McpToolCall).build().unwrap();
    s.append(&tenant, &mut old).unwrap();
    s.append_decision(deny("a", "undeclared_tool"), &GateKey::from_seed([2; 32])).unwrap();
    drop(s);
    let s = store(&dir);
    assert_eq!(s.records_for_tenant(&tenant).unwrap().len(), 1);
    assert_eq!(s.decisions().unwrap().len(), 1);
}

#[test]
fn two_writers_on_one_ledger_keep_one_chain() {
    // The gate and `cloakpipe operations reconcile` may append at once.
    let dir = tempfile::tempdir().unwrap();
    let key = GateKey::from_seed([3; 32]);
    let path = dir.path().join("ledger.db");
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            let key = GateKey::from_seed([3; 32]);
            std::thread::spawn(move || {
                let mut s = LedgerStore::open(path.to_str().unwrap()).unwrap();
                for _ in 0..10 {
                    s.append_decision(deny("t", "undeclared_tool"), &key).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let entries = store(&dir).decisions().unwrap();
    assert_eq!(entries.len(), 40);
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.seq, i as u64);
        assert_eq!(e.prev_hash, prev);
        prev = e.entry_hash.clone();
    }
    assert_eq!(entries[0].signer, key.keyid());
}

#[test]
fn args_fingerprints_are_keyed_so_values_cannot_be_guessed_from_them() {
    let raw = [5u8; 32];
    let a = GateKey::from_seed([1; 32]).args_fingerprint(&raw);
    let b = GateKey::from_seed([2; 32]).args_fingerprint(&raw);
    assert!(a.starts_with("hmac-sha256:"), "{a}");
    assert_eq!(a.len(), "hmac-sha256:".len() + 64);
    assert_ne!(a, b, "keyed by the gate key");
    assert_eq!(a, GateKey::from_seed([1; 32]).args_fingerprint(&raw), "stable for one key");
    assert!(!a.contains(&hex::encode(raw)));
}

#[test]
fn a_gate_key_is_created_once_owner_only_and_then_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("home").join("gate.key");
    let (key, created) = GateKey::load_or_create(&path).unwrap();
    assert!(created);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }
    // The `release keygen` key file format.
    let file: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(file["publicKey"], key.public_hex());
    assert_eq!(file["keyid"], key.keyid());
    assert!(file["privateKey"].is_string());

    let (again, created) = GateKey::load_or_create(&path).unwrap();
    assert!(!created);
    assert_eq!(again.public_key(), key.public_key());
    assert_eq!(GateKey::load(&path).unwrap().keyid(), key.keyid());
    assert!(key.keyid().starts_with("ed25519:"));
}

#[test]
fn a_key_file_that_is_not_a_signing_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    std::fs::write(&path, r#"{"publicKey":"00"}"#).unwrap();
    assert!(GateKey::load(&path).is_err());
    assert!(GateKey::load_or_create(&path).is_err(), "an existing bad file is never replaced");
    std::fs::write(&path, "not json").unwrap();
    assert!(GateKey::load(&path).is_err());
}

#[test]
fn the_tools_lock_digest_is_recorded_only_when_there_is_one() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir);
    let key = GateKey::from_seed([3; 32]);
    let lock = format!("sha256:{}", "ef".repeat(32));
    let plain = s.append_decision(deny("send_email", "scope_mismatch"), &key).unwrap();
    let pinned = s.append_decision(DecisionDraft { tools_lock: Some(lock.clone()), ..deny("send_email", "tool_drift") }, &key).unwrap();

    // Without a lock the member is absent, so an entry reads (and hashes)
    // exactly as one written before the field existed.
    let line: serde_json::Value = serde_json::from_str(&plain.to_json_line()).unwrap();
    assert!(line.get("tools_lock").is_none(), "{line}");
    assert_eq!(pinned.tools_lock.as_deref(), Some(lock.as_str()));
    let line: serde_json::Value = serde_json::from_str(&pinned.to_json_line()).unwrap();
    assert_eq!(line["tools_lock"], lock.as_str());
    // The digest is covered by the entry hash.
    let mut edited = pinned.clone();
    edited.tools_lock = Some(format!("sha256:{}", "00".repeat(32)));
    assert_ne!(edited.compute_hash(), pinned.entry_hash);
    assert_eq!(s.decisions().unwrap(), [plain, pinned]);
}
