//! `export_pack`: the decision ledger as an audit pack (a plain tar) with
//! entries.jsonl, the gate public key, the epochs and their anchors, the
//! manifest digests and a pack manifest signed by the gate key. A time
//! range widens to whole epochs, so every epoch in the pack can be checked
//! against its entries.

use cloakpipe_ledger::audit_pack::{export_pack, ExportError, PackRange};
use cloakpipe_ledger::decision::{Decision, DecisionDraft};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_verify::ustar;
use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::Value;

fn at(min: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap() + Duration::minutes(min)
}

/// Entries at minutes 0..10, epochs over seq 0..3 and 4..7, tail 8..9.
fn ledger() -> (tempfile::TempDir, LedgerStore, GateKey) {
    let dir = tempfile::tempdir().unwrap();
    let mut s = LedgerStore::open(dir.path().join("ledger.db").to_str().unwrap()).unwrap();
    let k = GateKey::from_seed([2; 32]);
    for i in 0..10 {
        let release = if i < 5 { "sha256:aa" } else { "sha256:bb" };
        s.append_decision(
            DecisionDraft {
                ts: Some(at(i)),
                release: Some(release.into()),
                tool: Some("t".into()),
                decision: Decision::Allow,
                ..DecisionDraft::call()
            },
            &k,
        )
        .unwrap();
        if i == 3 || i == 7 {
            s.seal_epoch(&k, at(i)).unwrap().unwrap();
        }
    }
    (dir, s, k)
}

fn contents(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
    ustar::read(tar).unwrap().into_iter().map(|f| (f.name, f.data)).collect()
}

fn json(files: &[(String, Vec<u8>)], name: &str) -> Value {
    serde_json::from_slice(&files.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no {name}")).1).unwrap()
}

fn seqs(files: &[(String, Vec<u8>)]) -> Vec<u64> {
    let jsonl = String::from_utf8(files.iter().find(|(n, _)| n == "entries.jsonl").unwrap().1.clone()).unwrap();
    jsonl.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["seq"].as_u64().unwrap()).collect()
}

#[test]
fn the_whole_ledger_is_packed_and_signed() {
    let (_d, s, k) = ledger();
    let pack = export_pack(&s, &k, &PackRange::default(), at(60)).unwrap();
    assert_eq!((pack.entries, pack.first_seq, pack.last_seq, pack.epochs.clone()), (10, Some(0), Some(9), vec![0, 1]));
    let files = contents(&pack.tar);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["pack.json", "entries.jsonl", "gate.pub.json", "manifests.json", "anchors/epoch-00000000.json", "anchors/epoch-00000001.json"]
    );
    assert_eq!(seqs(&files), (0..10).collect::<Vec<_>>());
    let gate = json(&files, "gate.pub.json");
    assert_eq!(gate["keyid"], k.keyid());
    assert_eq!(gate["publicKey"], k.public_hex());
    assert!(gate.get("privateKey").is_none());
    assert_eq!(json(&files, "manifests.json")["releases"], serde_json::json!(["sha256:aa", "sha256:bb"]));
    let epoch = json(&files, "anchors/epoch-00000001.json");
    assert_eq!((epoch["epoch"]["first_seq"].as_u64(), epoch["epoch"]["last_seq"].as_u64()), (Some(4), Some(7)));
    assert_eq!(epoch["anchors"], serde_json::json!([]));

    let m = json(&files, "pack.json");
    assert_eq!(m["kind"], "cloakpipe.audit-pack/v1");
    assert_eq!(m["signer"], k.keyid());
    assert_eq!(m["entries"], 10);
    assert_eq!(m["files"].as_object().unwrap().len(), 5);
    let report = cloakpipe_verify::gate_pack::verify_pack(
        &pack.tar,
        &cloakpipe_verify::gate_pack::PackTrust { gate_keys: vec![k.public_key()], ..Default::default() },
    );
    assert!(report.failures.is_empty(), "{}", report.render());
}

#[test]
fn a_range_widens_to_whole_epochs() {
    let (_d, s, k) = ledger();
    // Minutes 5..6 fall inside epoch 1 (seq 4..7): the pack holds all of it.
    let r = PackRange { since: Some(at(5)), until: Some(at(6)) };
    let pack = export_pack(&s, &k, &r, at(60)).unwrap();
    assert_eq!(pack.epochs, vec![1]);
    assert_eq!(seqs(&contents(&pack.tar)), vec![4, 5, 6, 7]);
    // From minute 7: the end of epoch 1, then the unanchored tail.
    let pack = export_pack(&s, &k, &PackRange { since: Some(at(7)), until: None }, at(60)).unwrap();
    assert_eq!(pack.epochs, vec![1]);
    assert_eq!(seqs(&contents(&pack.tar)), (4..10).collect::<Vec<_>>());
    // Only the tail.
    let pack = export_pack(&s, &k, &PackRange { since: Some(at(9)), until: None }, at(60)).unwrap();
    assert!(pack.epochs.is_empty());
    assert_eq!(seqs(&contents(&pack.tar)), vec![9]);
    let m = json(&contents(&pack.tar), "pack.json");
    assert_eq!(m["range"]["since"], at(9).to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
}

#[test]
fn an_empty_range_is_an_error() {
    let (_d, s, k) = ledger();
    let r = PackRange { since: Some(at(100)), until: None };
    assert!(matches!(export_pack(&s, &k, &r, at(200)), Err(ExportError::Empty)));
}
