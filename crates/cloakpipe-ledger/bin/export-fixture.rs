//! Produce a fixture bundle for the `cloakpipe-verify` gate tests.
//!
//! Usage:
//!   cargo run -p cloakpipe-ledger --bin ledger-export-fixture -- [out_path [release_hash trust_out]]
//!
//! With `release_hash` (`sha256:<hex>`) every hop is bound to that Agent
//! Release, and the signer's public key is written to `trust_out` in the
//! `release keygen` trust-file format, so a release audit pack built from
//! the bundle can pin it (`cloakpipe-verify release-pack --trust`).
//!
//! Writes a self-describing bundle containing 10 records across one
//! tenant, signed with a fresh Ed25519 key (the pubkey is included in
//! the bundle so the verifier can check signatures).

use cloakpipe_ledger::export::{export_bundle, write_bundle};
use cloakpipe_ledger::record::{Action, ActionKind, Detection, Detector, Hop, RecordBuilder};
use cloakpipe_ledger::sign::Ed25519Signer;
use cloakpipe_ledger::store::LedgerStore;
use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let out_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "crates/cloakpipe-verify/tests/fixtures/sample.bundle.json".to_string());

    // Write a ledger to a temp file, append 10 records, export.
    let tmp = tempfile::tempdir()?;
    let db_path = tmp.path().join("ledger.sqlite");
    let mut store = LedgerStore::open(db_path.to_str().unwrap())?;
    let tenant = uuid::Uuid::new_v4();
    let signer = Ed25519Signer::generate();
    let release = match args.get(2) {
        Some(h) => {
            let hex = h.strip_prefix("sha256:").ok_or_else(|| anyhow::anyhow!("release must be sha256:<hex>"))?;
            let mut out = [0u8; 32];
            hex::decode_to_slice(hex, &mut out)?;
            Some(out)
        }
        None => None,
    };

    for i in 0..10u64 {
        let mut b = RecordBuilder::new()
            .seq(i)
            .tenant(tenant)
            .hop(if i % 2 == 0 { Hop::LlmPrompt } else { Hop::LlmResponse })
            .detection(Detection {
                entity_type: "PAN".into(),
                count: 1,
                detector: Detector::Regex,
            })
            .action(Action {
                entity_type: "PAN".into(),
                kind: ActionKind::Pseudonymize,
                token_ref: Some(format!("tok_{i}")),
            });
        if let Some(h) = release {
            b = b.release(h);
        }
        let mut r = b.build()?;
        store.append(&tenant, &mut r)?;
    }

    let bundle = export_bundle(&store, &tenant, &signer)?;
    let path = PathBuf::from(&out_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_bundle(&path, &bundle)?;
    println!("wrote bundle to {}", path.display());
    if let Some(trust_out) = args.get(3) {
        use cloakpipe_ledger::Signer;
        use sha2::Digest;
        let public = signer.public_key();
        let keyid = format!("ed25519:{}", &hex::encode(sha2::Sha256::digest(public))[..16]);
        let trust = serde_json::json!({"keyid": keyid, "publicKey": hex::encode(public)});
        std::fs::write(trust_out, trust.to_string())?;
        println!("wrote signer trust file to {trust_out}");
    }
    Ok(())
}