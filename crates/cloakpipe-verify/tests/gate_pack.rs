//! The gate's audit pack (`audit-pack.tar`), verified offline with this
//! crate's own code: entries (chain, per-entry signatures), the signed pack
//! manifest, the epochs and their RFC 3161 and Rekor anchors, gaps, and the
//! counts an auditor asks for. Packs are produced by `cloakpipe-ledger` and
//! anchored by the local test authorities (test-only dependencies).

use cloakpipe_anchor::anchor::rekor::RekorClient;
use cloakpipe_anchor::anchor::rfc3161::TsaClient;
use cloakpipe_anchor::testkit::{MockRekor, MockTsa};
use cloakpipe_ledger::anchoring::{Anchorer, AnchorPolicy, AnchorScheduler};
use cloakpipe_ledger::audit_pack::{export_pack, PackRange};
use cloakpipe_ledger::decision::{Decision, DecisionDraft, Mode, Outcome};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_verify::gate_pack::{pack_hash, verify_pack, PackTrust};
use cloakpipe_verify::rekor::RekorKey;
use cloakpipe_verify::rfc3161::TrustedRoots;
use cloakpipe_verify::ustar;
use ed25519_dalek::Signer;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const SEED: [u8; 32] = [9; 32];

struct Env {
    dir: tempfile::TempDir,
    tsa: MockTsa,
    rekor: MockRekor,
    key: GateKey,
    store: LedgerStore,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let store = LedgerStore::open(dir.path().join("ledger.db").to_str().unwrap()).unwrap();
    Env { dir, tsa: MockTsa::start(), rekor: MockRekor::start(), key: GateKey::from_seed(SEED), store }
}

impl Env {
    fn trust(&self) -> PackTrust {
        PackTrust {
            gate_keys: vec![],
            tsa_roots: Some(TrustedRoots::from_pem(&self.tsa.root_pem()).unwrap()),
            rekor_key: Some(RekorKey::from_pem(&self.rekor.key_pem()).unwrap()),
            clock_skew_secs: 60,
            require_anchors: false,
        }
    }

    fn scheduler(&self) -> AnchorScheduler {
        let anchorer = Anchorer::new(
            Some(TsaClient::new(self.tsa.url(), TrustedRoots::from_pem(&self.tsa.root_pem()).unwrap())),
            Some(RekorClient::new(self.rekor.url(), RekorKey::from_pem(&self.rekor.key_pem()).unwrap())),
        );
        let store = LedgerStore::open(self.dir.path().join("ledger.db").to_str().unwrap()).unwrap();
        let policy = AnchorPolicy { every: None, interval: None, retry: Duration::ZERO };
        AnchorScheduler::new(store, self.key.clone(), anchorer, policy, Instant::now())
    }

    fn append(&mut self, draft: DecisionDraft) {
        self.store.append_decision(draft, &self.key).unwrap();
    }

    /// Seal what is new into an epoch and anchor it.
    fn epoch(&mut self) {
        self.scheduler().flush().unwrap();
    }

    fn pack(&self) -> Vec<u8> {
        export_pack(&self.store, &self.key, &PackRange::default(), chrono::Utc::now()).unwrap().tar
    }
}

fn call(decision: Decision, reason: &str) -> DecisionDraft {
    DecisionDraft {
        release: Some(format!("sha256:{}", "ab".repeat(32))),
        tool: Some("send_email".into()),
        decision,
        reason: reason.into(),
        mode: Some(Mode::Enforce),
        forwarded: decision == Decision::Allow,
        ..DecisionDraft::call()
    }
}

/// Two anchored epochs and an unanchored tail: allow, deny, approval
/// required, an approved allow, an unknown outcome reconciled, a deny.
fn honest() -> Env {
    let mut e = env();
    e.append(call(Decision::Allow, "ok"));
    e.append(call(Decision::Deny, "scope_mismatch"));
    e.append(call(Decision::RequireApproval, "approval_required"));
    e.epoch();
    e.append(DecisionDraft { approval: Some(format!("sha256:{}", "11".repeat(32))), ..call(Decision::Allow, "ok") });
    e.append(DecisionDraft { outcome: Some(Outcome::Unknown), operation_id: Some("op-1".into()), ..DecisionDraft::outcome() });
    e.append(DecisionDraft { outcome: Some(Outcome::Committed), operation_id: Some("op-1".into()), ..DecisionDraft::reconcile() });
    e.epoch();
    e.append(call(Decision::Deny, "undeclared_tool"));
    e
}

#[test]
fn an_honest_pack_verifies_and_is_summarised() {
    let e = honest();
    let r = verify_pack(&e.pack(), &e.trust());
    assert!(r.ok(), "{}", r.render());
    assert_eq!(r.entries, 7);
    assert_eq!(r.epochs, 2);
    assert_eq!((r.rfc3161_ok, r.rfc3161_total, r.rekor_ok, r.rekor_total), (2, 2, 2, 2));
    assert!(r.gaps.is_empty());
    assert_eq!(r.unanchored_tail, Some((6, 6)));
    assert_eq!((r.denials, r.approvals_required, r.approvals_granted), (2, 1, 1));
    assert_eq!((r.unknown_side_effects, r.reconciled), (1, 1));
    assert_eq!(r.manifests, vec![format!("sha256:{}", "ab".repeat(32))]);
    let text = r.render();
    for line in [
        "entries: 7 (seq 0..6), chain OK, signatures OK",
        "anchors: 2 epochs (seq 0..5), RFC3161 OK (2/2), Rekor OK (2/2 inclusion proofs)",
        "gaps: none",
        "unanchored: seq 6..6 (after the last epoch)",
        "denials: 2, approvals: 1 required, 1 granted, unknown side effects: 1, reconciled: 1",
        "result: OK",
    ] {
        assert!(text.contains(line), "missing {line:?} in\n{text}");
    }
    assert!(text.contains("not pinned"), "{text}");
}

#[test]
fn require_anchors_fails_an_unanchored_tail() {
    let e = honest();
    let r = verify_pack(&e.pack(), &PackTrust { require_anchors: true, ..e.trust() });
    assert!(!r.ok());
    assert!(r.render().contains("result: FAIL"), "{}", r.render());
}

#[test]
fn a_pinned_key_must_have_signed_everything() {
    let e = honest();
    let pinned = PackTrust { gate_keys: vec![e.key.public_key()], ..e.trust() };
    let r = verify_pack(&e.pack(), &pinned);
    assert!(r.ok(), "{}", r.render());
    assert!(r.render().contains("(pinned)"), "{}", r.render());
    let other = PackTrust { gate_keys: vec![GateKey::from_seed([1; 32]).public_key()], ..e.trust() };
    let r = verify_pack(&e.pack(), &other);
    assert!(!r.ok(), "{}", r.render());
}

#[test]
fn a_rotated_gate_key_verifies_with_both_keys_pinned_and_names_the_pack_signer() {
    // Entries signed by the old key, then by the new one; the pack is
    // exported (and signed) with the new key.
    let mut e = env();
    e.append(call(Decision::Allow, "ok"));
    let old = e.key.clone();
    e.key = GateKey::from_seed([3; 32]);
    e.append(call(Decision::Deny, "scope_mismatch"));
    let pack = e.pack();
    for keys in [vec![old.public_key(), e.key.public_key()], vec![e.key.public_key(), old.public_key()]] {
        let r = verify_pack(&pack, &PackTrust { gate_keys: keys, ..e.trust() });
        assert!(r.ok(), "{}", r.render());
        let signed_by = format!("signed by {} (pinned)", e.key.keyid());
        assert!(r.render().contains(&signed_by), "missing {signed_by:?} in\n{}", r.render());
    }
    // Only the new key pinned: the old entry is not trusted.
    let r = verify_pack(&pack, &PackTrust { gate_keys: vec![e.key.public_key()], ..e.trust() });
    assert!(!r.ok(), "{}", r.render());
}

fn files(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
    ustar::read(tar).unwrap().into_iter().map(|f| (f.name, f.data)).collect()
}

fn tar_of(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    ustar::write(&refs, 0)
}

/// Rewrite the pack with `edit`, then re-list and re-sign `pack.json` with
/// the gate key: what an operator holding the key could do.
fn resigned(tar: &[u8], edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>)) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut fs = files(tar);
    edit(&mut fs);
    let mut manifest: Value = serde_json::from_slice(&fs.iter().find(|(n, _)| n == "pack.json").unwrap().1).unwrap();
    let listed: serde_json::Map<String, Value> = fs
        .iter()
        .filter(|(n, _)| n != "pack.json")
        .map(|(n, d)| (n.clone(), Value::String(format!("sha256:{}", hex::encode(Sha256::digest(d))))))
        .collect();
    manifest["files"] = Value::Object(listed);
    let epochs: Vec<u64> = fs.iter().filter_map(|(n, _)| n.strip_prefix("anchors/epoch-")?.strip_suffix(".json")?.parse().ok()).collect();
    manifest["epochs"] = serde_json::json!(epochs);
    let h = pack_hash(&manifest);
    manifest["pack_hash"] = Value::String(hex::encode(h));
    let sig = ed25519_dalek::SigningKey::from_bytes(&SEED).sign(&h);
    manifest["sig"] = Value::String(hex::encode(sig.to_bytes()));
    let at = fs.iter().position(|(n, _)| n == "pack.json").unwrap();
    fs[at].1 = serde_json::to_vec(&manifest).unwrap();
    tar_of(&fs)
}

#[test]
fn a_tampered_entry_fails() {
    let e = honest();
    let mut fs = files(&e.pack());
    let at = fs.iter().position(|(n, _)| n == "entries.jsonl").unwrap();
    fs[at].1 = String::from_utf8(fs[at].1.clone()).unwrap().replacen("scope_mismatch", "ok", 1).into_bytes();
    let r = verify_pack(&tar_of(&fs), &e.trust());
    assert!(!r.ok());
    assert!(r.failures.iter().any(|f| f.contains("entries.jsonl")), "{}", r.render());

    // Re-signing the pack does not help: the entry's own hash and signature fail.
    let r = verify_pack(&resigned(&e.pack(), |fs| {
        let at = fs.iter().position(|(n, _)| n == "entries.jsonl").unwrap();
        fs[at].1 = String::from_utf8(fs[at].1.clone()).unwrap().replacen("scope_mismatch", "ok", 1).into_bytes();
    }), &e.trust());
    assert!(!r.ok());
    assert!(r.render().contains("entries:") && r.render().contains("FAIL"), "{}", r.render());
}

#[test]
fn a_dropped_epoch_is_a_gap() {
    let mut e = honest();
    e.epoch(); // epoch 2 covers the tail
    let r = verify_pack(&e.pack(), &e.trust());
    assert!(r.ok(), "{}", r.render());
    assert_eq!(r.epochs, 3);
    let r = verify_pack(&resigned(&e.pack(), |fs| fs.retain(|(n, _)| n != "anchors/epoch-00000001.json")), &e.trust());
    assert!(!r.ok());
    assert!(r.gaps.iter().any(|g| g.contains("epoch 1")), "{}", r.render());
    assert!(r.render().contains("gaps: "), "{}", r.render());
}

#[test]
fn an_epoch_whose_anchors_all_failed_is_a_gap() {
    let mut e = env();
    e.append(call(Decision::Allow, "ok"));
    e.tsa.set_failing(true);
    e.rekor.set_failing(true);
    e.epoch();
    let r = verify_pack(&e.pack(), &e.trust());
    assert!(!r.ok());
    assert!(r.gaps.iter().any(|g| g.contains("epoch 0 is not anchored")), "{}", r.render());
}

#[test]
fn entries_stamped_after_their_anchor_are_back_dated() {
    let mut e = env();
    e.tsa.set_clock_offset(-3600);
    e.rekor.set_clock_offset(-3600);
    e.append(call(Decision::Allow, "ok"));
    e.epoch();
    let r = verify_pack(&e.pack(), &e.trust());
    assert!(!r.ok());
    assert!(r.failures.iter().any(|f| f.contains("after its anchor")), "{}", r.render());
}

#[test]
fn anchors_need_the_auditors_trust_inputs() {
    let e = honest();
    let stranger = MockRekor::start();
    let r = verify_pack(&e.pack(), &PackTrust { rekor_key: Some(RekorKey::from_pem(&stranger.key_pem()).unwrap()), ..e.trust() });
    assert!(!r.ok());
    assert!(r.render().contains("Rekor FAIL"), "{}", r.render());
    let r = verify_pack(&e.pack(), &PackTrust { tsa_roots: None, ..e.trust() });
    assert!(!r.ok());
    assert!(r.render().contains("RFC3161 FAIL"), "{}", r.render());
}

#[test]
fn an_unlisted_file_or_a_bad_pack_signature_fails() {
    let e = honest();
    let mut fs = files(&e.pack());
    fs.push(("extra.txt".into(), b"hi".to_vec()));
    assert!(!verify_pack(&tar_of(&fs), &e.trust()).ok());
    let mut fs = files(&e.pack());
    let at = fs.iter().position(|(n, _)| n == "pack.json").unwrap();
    fs[at].1 = String::from_utf8(fs[at].1.clone()).unwrap().replace("\"entries\": 7", "\"entries\": 8").into_bytes();
    let r = verify_pack(&tar_of(&fs), &e.trust());
    assert!(!r.ok());
    assert!(r.failures.iter().any(|f| f.contains("pack.json")), "{}", r.render());
    assert!(!verify_pack(b"not a tar", &e.trust()).ok());
}

// ── The standalone binary ──────────────────────────────────────────────

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cloakpipe-verify"))
}

fn write(dir: &Path, name: &str, data: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn the_standalone_verifier_accepts_the_tar() {
    let e = honest();
    let d = e.dir.path();
    let pack = write(d, "audit-pack.tar", &e.pack());
    let root = write(d, "tsa.pem", &e.tsa.root_pem());
    let rekor = write(d, "rekor.pem", &e.rekor.key_pem());
    let key = hex::encode(e.key.public_key());
    for args in [vec!["pack", &pack], vec![&pack]] {
        let out = Command::new(bin()).args(&args).args(["--tsa-root", &root, "--rekor-key", &rekor, "--key", &key]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert!(stdout.contains("RFC3161 OK (2/2)") && stdout.contains("result: OK"), "{stdout}");
    }
    let bad = write(d, "bad.tar", &resigned(&e.pack(), |fs| fs.retain(|(n, _)| n != "anchors/epoch-00000000.json")));
    let out = Command::new(bin()).args(["pack", &bad, "--tsa-root", &root, "--rekor-key", &rekor]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stdout));
}
