//! Anchoring epochs: the decision chain is sealed into numbered epochs
//! (epoch n covers seq a..b and links to epoch n-1), each signed by the gate
//! key and anchored externally (RFC 3161 + Rekor) off the request path. The
//! scheduler seals every N entries or every T, retries failed anchors and
//! reports `anchor.failed`.

use cloakpipe_anchor::anchor::rekor::RekorClient;
use cloakpipe_anchor::anchor::rfc3161::TsaClient;
use cloakpipe_anchor::receipt::ExternalReceipt;
use cloakpipe_anchor::testkit::{MockRekor, MockTsa};
use cloakpipe_ledger::anchoring::{AnchorEvent, AnchorPolicy, AnchorScheduler, Anchorer};
use cloakpipe_ledger::decision::{Decision, DecisionDraft};
use cloakpipe_ledger::epoch::{EpochHead, EPOCH_GENESIS};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_verify::rekor::RekorKey;
use cloakpipe_verify::rfc3161::TrustedRoots;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::time::{Duration, Instant};

fn key() -> GateKey {
    GateKey::from_seed([3; 32])
}

fn store(dir: &tempfile::TempDir) -> LedgerStore {
    LedgerStore::open(dir.path().join("ledger.db").to_str().unwrap()).unwrap()
}

fn append(s: &mut LedgerStore, k: &GateKey, n: usize) {
    for _ in 0..n {
        s.append_decision(DecisionDraft { tool: Some("t".into()), decision: Decision::Allow, ..DecisionDraft::call() }, k).unwrap();
    }
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

#[test]
fn sealing_makes_numbered_linked_signed_epochs() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, k) = (store(&dir), key());
    assert_eq!(s.seal_epoch(&k, now()).unwrap(), None, "nothing to seal");
    append(&mut s, &k, 3);
    let e0 = s.seal_epoch(&k, now()).unwrap().expect("sealed");
    let entries = s.decisions().unwrap();
    assert_eq!((e0.epoch, e0.first_seq, e0.last_seq), (0, 0, 2));
    assert_eq!(e0.entries_head, entries[2].entry_hash);
    assert_eq!(e0.prev_epoch, EPOCH_GENESIS);
    assert_eq!(e0.signer, k.keyid());
    assert_eq!(e0.epoch_hash, e0.compute_hash());
    let vk = VerifyingKey::from_bytes(&k.public_key()).unwrap();
    let sig = Signature::from_slice(&hex::decode(&e0.sig).unwrap()).unwrap();
    vk.verify(&hex::decode(&e0.epoch_hash).unwrap(), &sig).expect("signed by the gate key");
    assert_eq!(s.seal_epoch(&k, now()).unwrap(), None, "no new entries");

    append(&mut s, &k, 2);
    let e1 = s.seal_epoch(&k, now()).unwrap().unwrap();
    assert_eq!((e1.epoch, e1.first_seq, e1.last_seq), (1, 3, 4));
    assert_eq!(e1.prev_epoch, e0.epoch_hash);
    let stored: Vec<EpochHead> = s.epochs().unwrap().into_iter().map(|e| e.head).collect();
    assert_eq!(stored, vec![e0.clone(), e1]);

    // The anchored artifact is the canonical JSON of the whole signed head,
    // and every field is covered by the hash.
    let artifact: serde_json::Value = serde_json::from_slice(&e0.artifact()).unwrap();
    assert_eq!(artifact, serde_json::to_value(&e0).unwrap());
    let mut forged = e0.clone();
    forged.last_seq = 1;
    assert_ne!(forged.compute_hash(), e0.epoch_hash);
}

#[test]
fn anchors_are_stored_per_epoch_and_merged() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, k) = (store(&dir), key());
    append(&mut s, &k, 1);
    let e0 = s.seal_epoch(&k, now()).unwrap().unwrap();
    let r = |kind: &str| match kind {
        "rfc3161" => ExternalReceipt::Rfc3161 {
            batch_id: e0.id(),
            subject_hash: "00".repeat(32),
            tsa_url: "u".into(),
            nonce: "01".into(),
            tsr: "AA==".into(),
        },
        _ => ExternalReceipt::Rekor {
            batch_id: e0.id(),
            subject_hash: "00".repeat(32),
            rekor_url: "u".into(),
            entry_uuid: "x".into(),
            entry: serde_json::json!({}),
        },
    };
    s.add_epoch_anchors(0, vec![r("rfc3161")], Some("rekor: down".into())).unwrap();
    let got = &s.epochs().unwrap()[0];
    assert_eq!(got.anchors.len(), 1);
    assert_eq!(got.last_error.as_deref(), Some("rekor: down"));
    s.add_epoch_anchors(0, vec![r("rekor")], None).unwrap();
    let got = &s.epochs().unwrap()[0];
    assert_eq!(got.kinds(), ["rekor", "rfc3161"]);
    assert_eq!(got.last_error, None);
}

struct Kit {
    tsa: MockTsa,
    rekor: MockRekor,
}

fn kit() -> Kit {
    Kit { tsa: MockTsa::start(), rekor: MockRekor::start() }
}

impl Kit {
    fn anchorer(&self) -> Anchorer {
        Anchorer::new(
            Some(TsaClient::new(self.tsa.url(), TrustedRoots::from_pem(&self.tsa.root_pem()).unwrap())),
            Some(RekorClient::new(self.rekor.url(), RekorKey::from_pem(&self.rekor.key_pem()).unwrap())),
        )
    }
}

fn scheduler(dir: &tempfile::TempDir, kit: &Kit, policy: AnchorPolicy) -> AnchorScheduler {
    AnchorScheduler::new(store(dir), key(), kit.anchorer(), policy, Instant::now())
}

#[test]
fn every_n_entries_seals_and_anchors_an_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let kit = kit();
    let mut sched = scheduler(&dir, &kit, AnchorPolicy { every: Some(3), interval: None, retry: Duration::from_secs(60) });
    let (mut writer, k) = (store(&dir), key());
    append(&mut writer, &k, 2);
    assert!(sched.tick(Instant::now()).unwrap().is_empty(), "2 < 3: not due");
    append(&mut writer, &k, 1);
    let events = sched.tick(Instant::now()).unwrap();
    assert!(matches!(events[0], AnchorEvent::Sealed { epoch: 0, first_seq: 0, last_seq: 2 }), "{events:?}");
    assert!(events.iter().any(|e| matches!(e, AnchorEvent::Anchored { epoch: 0, .. })), "{events:?}");
    let epochs = writer.epochs().unwrap();
    assert_eq!(epochs[0].kinds(), ["rekor", "rfc3161"]);
    assert_eq!((kit.tsa.issued(), kit.rekor.entries()), (1, 1));
    assert!(sched.tick(Instant::now()).unwrap().is_empty(), "nothing new");
}

#[test]
fn the_interval_seals_whatever_is_new() {
    let dir = tempfile::tempdir().unwrap();
    let kit = kit();
    let start = Instant::now();
    let mut sched = AnchorScheduler::new(
        store(&dir),
        key(),
        kit.anchorer(),
        AnchorPolicy { every: None, interval: Some(Duration::from_secs(600)), retry: Duration::from_secs(60) },
        start,
    );
    let (mut writer, k) = (store(&dir), key());
    append(&mut writer, &k, 1);
    assert!(sched.tick(start + Duration::from_secs(10)).unwrap().is_empty(), "interval not reached");
    let events = sched.tick(start + Duration::from_secs(601)).unwrap();
    assert!(matches!(events[0], AnchorEvent::Sealed { epoch: 0, first_seq: 0, last_seq: 0 }), "{events:?}");
    // Nothing new: the next interval seals nothing.
    assert!(sched.tick(start + Duration::from_secs(1300)).unwrap().is_empty());
}

#[test]
fn a_failed_anchor_is_reported_and_retried() {
    let dir = tempfile::tempdir().unwrap();
    let kit = kit();
    let start = Instant::now();
    let mut sched = AnchorScheduler::new(
        store(&dir),
        key(),
        kit.anchorer(),
        AnchorPolicy { every: Some(1), interval: None, retry: Duration::from_secs(30) },
        start,
    );
    let (mut writer, k) = (store(&dir), key());
    kit.tsa.set_failing(true);
    append(&mut writer, &k, 1);
    let events = sched.tick(start).unwrap();
    let failed: Vec<String> = events.iter().filter(|e| matches!(e, AnchorEvent::Failed { .. })).map(|e| e.to_string()).collect();
    assert_eq!(failed.len(), 1, "{events:?}");
    assert!(failed[0].starts_with("anchor.failed epoch=0 seq=0..0 anchor=rfc3161"), "{}", failed[0]);
    // Rekor succeeded and is kept; the TSA is retried only after `retry`.
    assert_eq!(writer.epochs().unwrap()[0].kinds(), ["rekor"]);
    kit.tsa.set_failing(false);
    assert!(sched.tick(start + Duration::from_secs(5)).unwrap().is_empty(), "retry not due");
    let events = sched.tick(start + Duration::from_secs(31)).unwrap();
    assert!(events.iter().any(|e| matches!(e, AnchorEvent::Anchored { epoch: 0, .. })), "{events:?}");
    assert_eq!(writer.epochs().unwrap()[0].kinds(), ["rekor", "rfc3161"]);
    assert_eq!(kit.rekor.entries(), 1, "Rekor is not asked twice");
}

#[test]
fn a_new_scheduler_retries_epochs_a_previous_run_left_unanchored() {
    let dir = tempfile::tempdir().unwrap();
    let kit = kit();
    let (mut writer, k) = (store(&dir), key());
    append(&mut writer, &k, 2);
    writer.seal_epoch(&k, now()).unwrap().unwrap();
    let mut sched = scheduler(&dir, &kit, AnchorPolicy { every: Some(100), interval: None, retry: Duration::from_secs(60) });
    let events = sched.tick(Instant::now()).unwrap();
    assert!(events.iter().any(|e| matches!(e, AnchorEvent::Anchored { epoch: 0, .. })), "{events:?}");
}

#[test]
fn flush_seals_the_tail_and_anchors_it() {
    let dir = tempfile::tempdir().unwrap();
    let kit = kit();
    let mut sched = scheduler(&dir, &kit, AnchorPolicy { every: Some(100), interval: None, retry: Duration::from_secs(60) });
    let (mut writer, k) = (store(&dir), key());
    append(&mut writer, &k, 4);
    let events = sched.flush().unwrap();
    assert!(matches!(events[0], AnchorEvent::Sealed { epoch: 0, first_seq: 0, last_seq: 3 }), "{events:?}");
    assert_eq!(writer.epochs().unwrap()[0].kinds(), ["rekor", "rfc3161"]);
}

#[test]
fn the_background_loop_anchors_off_the_request_path() {
    use cloakpipe_ledger::anchoring::AnchorLoop;
    let dir = tempfile::tempdir().unwrap();
    let kit = kit();
    let path = dir.path().join("ledger.db");
    let (mut writer, k) = (store(&dir), key());
    let lp = AnchorLoop::spawn(
        path.to_str().unwrap(),
        key(),
        kit.anchorer(),
        AnchorPolicy { every: Some(2), interval: None, retry: Duration::from_secs(60) },
    )
    .unwrap();
    append(&mut writer, &k, 5);
    let deadline = Instant::now() + Duration::from_secs(20);
    while writer.epochs().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!writer.epochs().unwrap().is_empty(), "the loop sealed an epoch on its own");
    lp.finish();
    let epochs = writer.epochs().unwrap();
    assert_eq!(epochs.last().unwrap().head.last_seq, 4, "finish seals the tail");
    assert!(epochs.iter().all(|e| e.kinds() == ["rekor", "rfc3161"]));
    for w in epochs.windows(2) {
        assert_eq!(w[1].head.first_seq, w[0].head.last_seq + 1);
        assert_eq!(w[1].head.prev_epoch, w[0].head.epoch_hash);
    }
}

#[test]
fn the_background_loop_hands_every_anchor_event_to_its_hook() {
    use cloakpipe_ledger::anchoring::AnchorLoop;
    use std::sync::{Arc, Mutex};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let (mut writer, k) = (store(&dir), key());
    // A TSA nothing listens on: its anchor fails.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsr", dead.local_addr().unwrap());
    drop(dead);
    let tsa = TsaClient::new(&url, TrustedRoots::from_pem(&MockTsa::start().root_pem()).unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let hook = seen.clone();
    let lp = AnchorLoop::spawn_with(
        path.to_str().unwrap(),
        key(),
        Anchorer::new(Some(tsa), None),
        AnchorPolicy { every: Some(100), interval: None, retry: Duration::from_secs(60) },
        move |e: &AnchorEvent| hook.lock().unwrap().push(e.clone()),
    )
    .unwrap();
    append(&mut writer, &k, 2);
    lp.finish();
    let seen = seen.lock().unwrap();
    assert!(matches!(seen[0], AnchorEvent::Sealed { epoch: 0, first_seq: 0, last_seq: 1 }), "{seen:?}");
    assert!(
        seen.iter().any(|e| matches!(e, AnchorEvent::Failed { epoch: 0, last_seq: 1, kind: "rfc3161", .. })),
        "{seen:?}"
    );
}
