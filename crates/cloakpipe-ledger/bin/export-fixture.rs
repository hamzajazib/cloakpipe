//! Produce a fixture bundle for the `cloakpipe-verify` gate tests.
//!
//! Usage:
//!   cargo run -p cloakpipe-ledger --bin ledger-export-fixture -- [out_path] [--key-out key.json]
//!
//! `--key-out` also writes the operator key in `cloakpipe release keygen`
//! format (mode 0600), so the bundle can be sealed and anchored with
//! `cloakpipe anchor`.
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
    let mut out_path = "crates/cloakpipe-verify/tests/fixtures/sample.bundle.json".to_string();
    let mut key_out: Option<PathBuf> = None;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key-out" => key_out = Some(args.next().ok_or_else(|| anyhow::anyhow!("--key-out needs a path"))?.into()),
            s if s.starts_with('-') => anyhow::bail!("unknown option `{s}`"),
            _ => out_path = a,
        }
    }

    // Write a ledger to a temp file, append 10 records, export.
    let tmp = tempfile::tempdir()?;
    let db_path = tmp.path().join("ledger.sqlite");
    let mut store = LedgerStore::open(db_path.to_str().unwrap())?;
    let tenant = uuid::Uuid::new_v4();
    let seed: [u8; 32] = rand::random();
    let signer = Ed25519Signer::from_bytes(&seed);

    for i in 0..10u64 {
        let mut r = RecordBuilder::new()
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
            })
            .build()?;
        store.append(&tenant, &mut r)?;
    }

    let bundle = export_bundle(&store, &tenant, &signer)?;
    let path = PathBuf::from(&out_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_bundle(&path, &bundle)?;
    if let Some(key_out) = key_out {
        use cloakpipe_ledger::sign::Signer;
        use sha2::Digest;
        let public = signer.public_key();
        let key = serde_json::json!({
            "keyid": format!("ed25519:{}", &hex::encode(sha2::Sha256::digest(public))[..16]),
            "publicKey": hex::encode(public),
            "privateKey": hex::encode(seed),
        });
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        std::io::Write::write_all(&mut opts.open(&key_out)?, serde_json::to_string_pretty(&key)?.as_bytes())?;
        println!("wrote operator key to {}", key_out.display());
    }
    println!("wrote bundle to {}", path.display());
    Ok(())
}