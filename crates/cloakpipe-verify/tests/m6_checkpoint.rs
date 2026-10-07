//! M6 gate: the signed manifest is a checkpoint over the exact records, and
//! the verifier can pin the signer.
//!
//! Before v4 the manifest signed only the record count and sequence range, so
//! a different, internally consistent chain of the same length verified
//! under the original signature; and any bundle verified under whatever key it
//! carried. v4 signs the chain tip; `check_trusted_signer` pins keys.

use cloakpipe_ledger::export::{export_bundle, write_bundle};
use cloakpipe_ledger::{Ed25519Signer, Hop, LedgerStore, RecordBuilder, Signer};
use cloakpipe_verify::anchor::{check_trusted_signer, verify_manifest, ManifestError};
use cloakpipe_verify::bundle::{Bundle, BUNDLE_FORMAT_VERSION};
use cloakpipe_verify::verify::verify_chain;
use std::collections::BTreeMap;
use std::process::Command;

fn store_with(n: u64, hop: Hop) -> (LedgerStore, uuid::Uuid) {
    let mut store = LedgerStore::open(":memory:").unwrap();
    let tenant = uuid::Uuid::from_u128(7);
    for seq in 0..n {
        let mut r = RecordBuilder::new().seq(seq).tenant(tenant).hop(hop).build().unwrap();
        store.append(&tenant, &mut r).unwrap();
    }
    (store, tenant)
}

/// Export through the producer, parse with the standalone verifier types.
fn exported(store: &LedgerStore, tenant: &uuid::Uuid, signer: &Ed25519Signer) -> Bundle {
    let b = export_bundle(store, tenant, signer).unwrap();
    serde_json::from_value(serde_json::to_value(b).unwrap()).unwrap()
}

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_bytes(&[seed; 32])
}

#[test]
fn exports_are_v4_and_sign_the_chain_tip() {
    let (store, tenant) = store_with(3, Hop::LlmPrompt);
    let b = exported(&store, &tenant, &signer(1));
    assert_eq!(b.format_version, 4);
    assert_eq!(BUNDLE_FORMAT_VERSION, 4);
    let tip = b.records.last().unwrap().record_hash.clone();
    assert_eq!(b.manifest.as_ref().unwrap().chain_tip.as_deref(), Some(tip.as_str()));
    verify_chain(&b).unwrap();
    verify_manifest(&b).unwrap();
}

#[test]
fn substituting_a_consistent_chain_of_the_same_length_is_detected() {
    let (honest, tenant) = store_with(3, Hop::LlmPrompt);
    let (forged, _) = store_with(3, Hop::Unmask);
    let mut b = exported(&honest, &tenant, &signer(1));
    let other = exported(&forged, &tenant, &signer(1));

    b.records = other.records; // same count and seq range, different content
    verify_chain(&b).expect("the substituted chain is internally consistent");
    assert!(matches!(verify_manifest(&b), Err(ManifestError::ChainTipMismatch { .. })), "{:?}", verify_manifest(&b));
}

#[test]
fn a_v4_manifest_without_a_chain_tip_is_rejected() {
    let (store, tenant) = store_with(2, Hop::LlmPrompt);
    let mut b = exported(&store, &tenant, &signer(1));
    b.manifest.as_mut().unwrap().chain_tip = None;
    assert!(verify_manifest(&b).is_err());
}

#[test]
fn empty_bundles_checkpoint_the_genesis_hash() {
    let (store, tenant) = store_with(0, Hop::LlmPrompt);
    let b = exported(&store, &tenant, &signer(1));
    assert_eq!(b.manifest.as_ref().unwrap().chain_tip.as_deref(), Some("0".repeat(64).as_str()));
    verify_manifest(&b).unwrap();
}

#[test]
fn v3_bundles_without_a_chain_tip_still_verify() {
    // A bundle issued before v4: its manifest signature does not cover a
    // chain tip, and it must keep verifying.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.v3.bundle.json");
    let b: Bundle = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(b.format_version, 3);
    assert!(b.manifest.as_ref().unwrap().chain_tip.is_none());
    verify_chain(&b).unwrap();
    verify_manifest(&b).unwrap();
}

#[test]
fn trusted_signer_pinning() {
    let (store, tenant) = store_with(2, Hop::LlmPrompt);
    let operator = signer(1);
    let b = exported(&store, &tenant, &operator);
    let key_id = b.manifest.as_ref().unwrap().signature.key_id.clone();

    let trust = |pk: [u8; 32]| BTreeMap::from([(key_id.clone(), pk)]);
    check_trusted_signer(&b, &trust(operator.public_key())).unwrap();

    // Same key id, different key: an attacker re-signed with their own key.
    let attacker = signer(2);
    let forged = exported(&store, &tenant, &attacker);
    assert!(check_trusted_signer(&forged, &trust(operator.public_key())).is_err());
    // Unknown key id.
    assert!(check_trusted_signer(&b, &BTreeMap::from([("someone-else".to_string(), operator.public_key())])).is_err());
}

#[test]
fn cli_pins_the_signer_with_trust_key() {
    let dir = tempfile::tempdir().unwrap();
    let (store, tenant) = store_with(2, Hop::LlmPrompt);
    let operator = signer(1);
    let raw = export_bundle(&store, &tenant, &operator).unwrap();
    let path = dir.path().join("b.json");
    write_bundle(&path, &raw).unwrap();
    let key_id = raw.manifest.as_ref().unwrap().signature.key_id.clone();
    let bin = env!("CARGO_BIN_EXE_cloakpipe-verify");

    let good = format!("{key_id}={}", hex::encode(operator.public_key()));
    let out = Command::new(bin).args(["all", path.to_str().unwrap(), "--trust-key", &good]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(String::from_utf8_lossy(&out.stdout).contains("signer trusted"));

    let bad = format!("{key_id}={}", hex::encode(signer(2).public_key()));
    let out = Command::new(bin).args(["all", path.to_str().unwrap(), "--trust-key", &bad]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stdout));

    let out = Command::new(bin).args(["all", path.to_str().unwrap()]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("signer not pinned"), "{}", String::from_utf8_lossy(&out.stdout));
}
