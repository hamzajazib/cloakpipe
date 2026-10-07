//! Producer side of external anchoring: seal an exported bundle's records
//! under a signed batch head, attach anchor receipts, re-sign the manifest.
//! The standalone verifier must accept everything but the (here unverifiable)
//! receipts themselves.

use cloakpipe_anchor::receipt::ExternalReceipt;
use cloakpipe_ledger::export::bundle_format::{AnchorReceiptRef, Bundle};
use cloakpipe_ledger::export::{attach_receipts, export_bundle, seal_batch, ExportError};
use cloakpipe_ledger::record::{Hop, RecordBuilder};
use cloakpipe_ledger::sign::{Ed25519Signer, Signer};
use cloakpipe_ledger::store::LedgerStore;

fn exported(n: u64, seed: [u8; 32]) -> (Bundle, Ed25519Signer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = LedgerStore::open(dir.path().join("l.sqlite").to_str().unwrap()).unwrap();
    let tenant = uuid::Uuid::new_v4();
    for i in 0..n {
        let mut r = RecordBuilder::new().seq(i).tenant(tenant).hop(Hop::LlmPrompt).build().unwrap();
        store.append(&tenant, &mut r).unwrap();
    }
    let signer = Ed25519Signer::from_bytes(&seed);
    let b = export_bundle(&store, &tenant, &signer).unwrap();
    (b, signer, dir)
}

fn as_verifier(b: &Bundle) -> cloakpipe_verify::bundle::Bundle {
    serde_json::from_slice(&serde_json::to_vec(b).unwrap()).unwrap()
}

fn later() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(1)
}

#[test]
fn sealed_bundle_verifies_signatures_proofs_and_manifest() {
    let (mut b, signer, _d) = exported(7, [9; 32]);
    let head = seal_batch(&mut b, &signer, "batch-1", later()).expect("seal");
    assert_eq!((head.first_seq, head.last_seq), (0, 6));
    assert_eq!(b.batch_heads.len(), 1);
    assert_eq!(b.inclusion_proofs.len(), 7);
    // The head handed to the anchors is the head in the bundle, byte for byte.
    assert_eq!(serde_json::to_vec(&head).unwrap(), serde_json::to_vec(&b.batch_heads[0]).unwrap());
    let v = as_verifier(&b);
    cloakpipe_verify::verify::verify_all(&v).expect("chain + head signature");
    assert_eq!(cloakpipe_verify::anchor::verify_inclusion_proofs(&v).unwrap(), 7);
    cloakpipe_verify::anchor::verify_manifest(&v).expect("re-signed manifest lists the head");
    assert_eq!(v.manifest.as_ref().unwrap().batch_head_ids, ["batch-1"]);
}

#[test]
fn attached_receipts_are_listed_in_the_resigned_manifest() {
    let (mut b, signer, _d) = exported(3, [9; 32]);
    let bundle_id = b.manifest.as_ref().unwrap().bundle_id.clone();
    seal_batch(&mut b, &signer, "batch-1", later()).unwrap();
    let receipts = vec![
        ExternalReceipt::Rfc3161 {
            batch_id: "batch-1".into(),
            subject_hash: "00".repeat(32),
            tsa_url: "https://freetsa.org/tsr".into(),
            nonce: "0102".into(),
            tsr: "MAA=".into(),
        },
        ExternalReceipt::Rekor {
            batch_id: "batch-1".into(),
            subject_hash: "00".repeat(32),
            rekor_url: "https://rekor.sigstore.dev".into(),
            entry_uuid: "ab".repeat(40),
            entry: serde_json::json!({}),
        },
    ];
    attach_receipts(&mut b, receipts, &signer).unwrap();
    assert!(matches!(b.anchor_receipts[0], AnchorReceiptRef::Rfc3161 { .. }));
    let m = b.manifest.as_ref().unwrap();
    assert_eq!(m.bundle_id, bundle_id, "bundle id survives re-signing");
    assert_eq!(m.anchor_receipt_refs, ["rfc3161:batch-1:0102".to_string(), format!("rekor:batch-1:{}", "ab".repeat(40))]);
    let v = as_verifier(&b);
    cloakpipe_verify::anchor::verify_manifest(&v).expect("manifest");
    // The receipts are fake: anchors must fail, and must ask for trust first.
    assert!(matches!(
        cloakpipe_verify::anchor::verify_anchors(&v).unwrap_err(),
        cloakpipe_verify::anchor::AnchorVerifyError::MissingTrust { .. }
    ));
}

#[test]
fn sealing_refuses_ambiguous_input() {
    // A key other than the manifest's operator.
    let (mut b, _signer, _d) = exported(2, [9; 32]);
    let other = Ed25519Signer::from_bytes(&[8; 32]);
    assert!(matches!(seal_batch(&mut b, &other, "b", later()), Err(ExportError::Anchoring(_))));
    // Already sealed.
    let (mut b, signer, _d) = exported(2, [9; 32]);
    seal_batch(&mut b, &signer, "b", later()).unwrap();
    assert!(matches!(seal_batch(&mut b, &signer, "c", later()), Err(ExportError::Anchoring(_))));
    // Nothing to seal.
    let (mut b, signer, _d) = exported(0, [9; 32]);
    assert!(matches!(seal_batch(&mut b, &signer, "b", later()), Err(ExportError::Anchoring(_))));
    // A seal time before the records.
    let (mut b, signer, _d) = exported(2, [9; 32]);
    let past = chrono::Utc::now() - chrono::Duration::days(1);
    assert!(matches!(seal_batch(&mut b, &signer, "b", past), Err(ExportError::Anchoring(_))));
    // Receipts for a head that is not in the bundle.
    let (mut b, signer, _d) = exported(2, [9; 32]);
    seal_batch(&mut b, &signer, "b", later()).unwrap();
    let stray = ExternalReceipt::Rfc3161 {
        batch_id: "other".into(),
        subject_hash: String::new(),
        tsa_url: String::new(),
        nonce: String::new(),
        tsr: String::new(),
    };
    assert!(matches!(attach_receipts(&mut b, vec![stray], &signer), Err(ExportError::Anchoring(_))));
    assert_eq!(signer.algorithm(), "ed25519");
}
