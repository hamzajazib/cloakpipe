//! `cloakpipe anchor`: seal an exported evidence bundle under a signed batch
//! head and anchor that head externally (RFC 3161 TSA and/or Sigstore
//! Rekor). Every receipt is verified before the anchored bundle is written,
//! and the finished bundle is re-verified as an auditor would.
//!
//! Exit codes: 0 anchored, 1 refused or an anchor failed, 2 usage / I/O.

use crate::release::{EXIT_INVALID, EXIT_IO, EXIT_OK};
use cloakpipe_anchor::anchor::rekor::{RekorClient, DEFAULT_REKOR_URL};
use cloakpipe_anchor::anchor::rfc3161::{fresh_nonce, TsaClient, DEFAULT_TSA_URL};
use cloakpipe_ledger::export::bundle_format::Bundle;
use cloakpipe_ledger::export::{attach_receipts, seal_batch};
use cloakpipe_ledger::sign::Ed25519Signer;
use cloakpipe_verify::anchor::AnchorTrust;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(clap::Args)]
pub struct AnchorArgs {
    /// Exported evidence bundle (not yet sealed)
    pub bundle: PathBuf,
    /// Operator signing key (`cloakpipe release keygen` format); must be the
    /// key that signed the bundle's manifest
    #[arg(long)]
    pub key: PathBuf,
    /// Where to write the anchored bundle
    #[arg(long)]
    pub out: PathBuf,
    /// Batch id for the new head (default: batch-<first>-<last>-<unix time>)
    #[arg(long)]
    pub batch_id: Option<String>,
    /// RFC 3161 TSA endpoint (DigiCert: http://timestamp.digicert.com)
    #[arg(long, default_value = DEFAULT_TSA_URL)]
    pub tsa_url: String,
    /// PEM root(s) the TSA must chain to (required unless --no-tsa)
    #[arg(long)]
    pub tsa_root: Option<PathBuf>,
    /// Skip the TSA anchor
    #[arg(long)]
    pub no_tsa: bool,
    /// Rekor (v1 API) base URL
    #[arg(long, default_value = DEFAULT_REKOR_URL)]
    pub rekor_url: String,
    /// PEM public key of the Rekor log (required unless --no-rekor)
    #[arg(long)]
    pub rekor_key: Option<PathBuf>,
    /// Skip the Rekor anchor
    #[arg(long)]
    pub no_rekor: bool,
    /// Per-request network timeout
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,
    /// How far this host's clock may run ahead of the TSA's and Rekor's.
    /// The head's seal time is backed off by up to this much (never before
    /// the newest record), so a slightly fast clock cannot make the honest
    /// seal look later than its own anchor.
    #[arg(long, default_value_t = 60)]
    pub clock_skew_secs: u32,
}

/// The seal time claimed in the batch head: `now` backed off by `skew`,
/// but never before the newest record (every record must precede the
/// seal) and never after `now`. A claim earlier than the real seal is
/// harmless: anchors prove the head existed *by* their time, and the
/// verifier rejects only claims made after it.
pub fn seal_time(
    now: chrono::DateTime<chrono::Utc>,
    newest_record: Option<chrono::DateTime<chrono::Utc>>,
    skew: chrono::Duration,
) -> chrono::DateTime<chrono::Utc> {
    let backed_off = now - skew;
    match newest_record {
        Some(t) if t > backed_off => t.min(now),
        _ => backed_off,
    }
}

/// The newest `ts=` among the records; unreadable times are left to
/// `seal_batch`, which refuses them.
fn newest_record_time(b: &Bundle) -> Option<chrono::DateTime<chrono::Utc>> {
    b.records
        .iter()
        .filter_map(|r| r.canonical_bytes.lines().find_map(|l| l.strip_prefix("ts=")))
        .filter_map(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
        .max()
}

fn usage(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    EXIT_IO
}

fn refused(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    EXIT_INVALID
}

fn read(p: &Path) -> Result<Vec<u8>, i32> {
    std::fs::read(p).map_err(|e| usage(format_args!("cannot read {}: {e}", p.display())))
}

pub fn run(a: AnchorArgs) -> i32 {
    match anchor(a, chrono::Utc::now(), &fresh_nonce()) {
        Ok(()) => EXIT_OK,
        Err(code) => code,
    }
}

/// `now` is this host's clock and `tsa_nonce` the request nonce; both are
/// parameters only so tests can replay recorded replies.
fn anchor(a: AnchorArgs, now: chrono::DateTime<chrono::Utc>, tsa_nonce: &[u8]) -> Result<(), i32> {
    // Trust inputs first: nothing is anchored without them.
    if a.no_tsa && a.no_rekor {
        return Err(usage("--no-tsa and --no-rekor leave nothing to anchor"));
    }
    let tsa_roots = match (a.no_tsa, &a.tsa_root) {
        (true, _) => None,
        (false, None) => return Err(usage("--tsa-root PEM is required (or pass --no-tsa)")),
        (false, Some(p)) => Some(
            cloakpipe_verify::rfc3161::TrustedRoots::from_pem(&read(p)?)
                .map_err(|e| usage(format_args!("--tsa-root {}: {e}", p.display())))?,
        ),
    };
    let rekor_key = match (a.no_rekor, &a.rekor_key) {
        (true, _) => None,
        (false, None) => return Err(usage("--rekor-key PEM is required (or pass --no-rekor)")),
        (false, Some(p)) => Some(
            cloakpipe_verify::rekor::RekorKey::from_pem(&read(p)?)
                .map_err(|e| usage(format_args!("--rekor-key {}: {e}", p.display())))?,
        ),
    };
    let (key, _) = crate::cert::signing_key(&a.key)?;
    let signer = Ed25519Signer::from_bytes(&key.to_bytes());
    let mut bundle: Bundle = serde_json::from_slice(&read(&a.bundle)?)
        .map_err(|e| usage(format_args!("{}: not a bundle: {e}", a.bundle.display())))?;

    let batch_id = a.batch_id.clone().unwrap_or_else(|| {
        let first = bundle.records.first().map(|r| r.seq).unwrap_or(0);
        let last = bundle.records.last().map(|r| r.seq).unwrap_or(0);
        format!("batch-{first}-{last}-{}", now.timestamp())
    });
    let sealed_at = seal_time(now, newest_record_time(&bundle), chrono::Duration::seconds(a.clock_skew_secs.into()));
    let head = seal_batch(&mut bundle, &signer, &batch_id, sealed_at).map_err(refused)?;

    let timeout = Duration::from_secs(a.timeout_secs);
    let mut receipts = Vec::new();
    if let Some(roots) = &tsa_roots {
        let tsa = TsaClient::new(&a.tsa_url, roots.clone()).with_timeout(timeout);
        receipts.push(
            tsa.anchor_head_with_nonce(&head, tsa_nonce).map_err(|e| refused(format_args!("TSA {}: {e}", a.tsa_url)))?,
        );
    }
    if let Some(k) = &rekor_key {
        let rekor = RekorClient::new(&a.rekor_url, k.clone()).with_timeout(timeout);
        receipts.push(rekor.anchor_head(&head, &key).map_err(|e| refused(format_args!("Rekor {}: {e}", a.rekor_url)))?);
    }
    attach_receipts(&mut bundle, receipts, &signer).map_err(refused)?;

    // Re-verify the finished bundle exactly as an auditor would.
    let json = serde_json::to_vec_pretty(&bundle).map_err(usage)?;
    let audit: cloakpipe_verify::bundle::Bundle = serde_json::from_slice(&json).map_err(refused)?;
    let trust = AnchorTrust { tsa_roots, rekor_key };
    cloakpipe_verify::verify::verify_all(&audit).map_err(|e| refused(format_args!("self-check: {e}")))?;
    cloakpipe_verify::anchor::verify_manifest(&audit).map_err(|e| refused(format_args!("self-check: {e}")))?;
    let n = cloakpipe_verify::anchor::verify_anchors_with_trust(&audit, &trust).map_err(|e| match e {
        cloakpipe_verify::anchor::AnchorVerifyError::BackDating { .. } => refused(format_args!(
            "self-check: {e} (a record or the seal is stamped after the anchor: is a clock here or where the \
             records were written ahead of the TSA / Rekor? see --clock-skew-secs)"
        )),
        e => refused(format_args!("self-check: {e}")),
    })?;

    std::fs::write(&a.out, &json).map_err(|e| usage(format_args!("cannot write {}: {e}", a.out.display())))?;
    let kinds: Vec<&str> = audit.anchor_receipts.iter().map(|r| r.kind()).collect();
    println!(
        "{}",
        serde_json::json!({
            "outcome": "anchored",
            "batch_id": batch_id,
            "records": audit.records.len(),
            "anchors": n,
            "kinds": kinds,
            "out": a.out.display().to_string(),
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The success path, offline: the unsealed bundle and the seal inputs
    //! reproduce exactly the batch head recorded in
    //! `cloakpipe-verify/tests/fixtures/anchoring/head-honest.json`, and two
    //! local servers replay the real freetsa.org and rekor.sigstore.dev
    //! answers for it.

    use super::*;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, BufReader, Read, Write};

    const TENANT: &str = "550e8400-e29b-41d4-a716-446655440000";
    const RECORD_TS: &str = "2026-10-07T10:00:00Z";

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../cloakpipe-verify/tests/fixtures/anchoring").join(name)
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture_path(name)).unwrap()
    }

    fn hex_lower(b: &[u8]) -> String {
        hex::encode(b)
    }

    /// Five chained records stamped `RECORD_TS`, a manifest signed by the
    /// fixture operator (seed 0x42, key id `default`), no head yet.
    fn unsealed_bundle() -> serde_json::Value {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let mut records = Vec::new();
        let mut prev = "0".repeat(64);
        for seq in 0..5u64 {
            let canonical = format!("seq={seq}\nts={RECORD_TS}\ntenant_id={TENANT}\nhop=llm_prompt");
            let hash = hex_lower(&Sha256::digest(canonical.as_bytes()));
            records.push(serde_json::json!({
                "seq": seq, "tenant_id": TENANT, "canonical_bytes": canonical,
                "record_hash": hash, "prev_hash": prev,
            }));
            prev = hash;
        }
        #[derive(serde::Serialize)]
        struct Unsigned<'a> {
            bundle_id: &'a str,
            range_start: &'a str,
            range_end: &'a str,
            record_count: u64,
            first_seq: u64,
            last_seq: u64,
            batch_head_ids: [String; 0],
            anchor_receipt_refs: [String; 0],
            policy_pack_versions: [String; 0],
            operator: &'a str,
            created_at: &'a str,
            chain_tip: &'a str,
        }
        let unsigned = Unsigned {
            bundle_id: "bundle-cli-test",
            range_start: RECORD_TS,
            range_end: RECORD_TS,
            record_count: 5,
            first_seq: 0,
            last_seq: 4,
            batch_head_ids: [],
            anchor_receipt_refs: [],
            policy_pack_versions: [],
            operator: "default",
            created_at: "2026-10-07T10:01:00Z",
            chain_tip: &prev,
        };
        let sig = key.sign(&serde_json::to_vec(&unsigned).unwrap());
        let mut manifest = serde_json::to_value(&unsigned).unwrap();
        manifest["signature"] =
            serde_json::json!({ "key_id": "default", "algorithm": "ed25519", "value": hex_lower(&sig.to_bytes()) });
        serde_json::json!({
            "format": "cloakpipe.bundle", "format_version": 4, "tenant_id": TENANT,
            "created_at": "2026-10-07T10:01:00Z", "records": records, "inclusion_proofs": [],
            "batch_heads": [], "anchor_receipts": [], "policy_packs": [],
            "signer_public_keys": [{ "key_id": "default", "algorithm": "ed25519",
                                     "public_key": hex_lower(&key.verifying_key().to_bytes()) }],
            "manifest": manifest,
        })
    }

    /// Serve one canned reply per connection, in order.
    fn serve(replies: Vec<(u16, &'static str, Vec<u8>)>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for (status, ctype, body) in replies {
                let Ok((stream, _)) = listener.accept() else { return };
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim_end().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut req = vec![0; len];
                let _ = r.read_exact(&mut req);
                let mut out = stream;
                let _ = out.write_all(
                    format!("HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
                        .as_bytes(),
                );
                let _ = out.write_all(&body);
            }
        });
        url
    }

    fn args(dir: &Path, tsa_url: String, rekor_url: String) -> AnchorArgs {
        let bundle = dir.join("bundle.json");
        std::fs::write(&bundle, serde_json::to_vec_pretty(&unsealed_bundle()).unwrap()).unwrap();
        let key = dir.join("op.json");
        std::fs::write(&key, format!(r#"{{"privateKey":"{}"}}"#, hex::encode([0x42; 32]))).unwrap();
        AnchorArgs {
            bundle,
            key,
            out: dir.join("anchored.json"),
            batch_id: Some("batch-honest-001".into()),
            tsa_url,
            tsa_root: Some(fixture_path("freetsa-root.pem")),
            no_tsa: false,
            rekor_url,
            rekor_key: Some(fixture_path("rekor.pub")),
            no_rekor: false,
            timeout_secs: 10,
            clock_skew_secs: 60,
        }
    }

    fn recorded_nonce() -> Vec<u8> {
        hex::decode(String::from_utf8(fixture("freetsa-honest.nonce")).unwrap().trim()).unwrap()
    }

    fn replay_servers() -> (String, String) {
        let tsa = serve(vec![(200, "application/timestamp-reply", fixture("freetsa-honest.tsr"))]);
        let rekor = serve(vec![(201, "application/json", fixture("rekor-honest.json"))]);
        (format!("{tsa}/tsr"), rekor)
    }

    #[test]
    fn anchors_seals_and_writes_a_bundle_an_auditor_accepts() {
        let d = tempfile::tempdir().unwrap();
        let (tsa, rekor) = replay_servers();
        let a = args(d.path(), tsa, rekor);
        let out = a.out.clone();
        // This host's clock reads 10:06:00; backed off 60s the seal is
        // 10:05:00, the recorded head's signed_time.
        let now = Utc.with_ymd_and_hms(2026, 10, 7, 10, 6, 0).unwrap();
        anchor(a, now, &recorded_nonce()).expect("anchored");

        let b: cloakpipe_verify::bundle::Bundle = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(serde_json::to_vec(&b.batch_heads[0]).unwrap(), fixture("head-honest.json"));
        let kinds: Vec<&str> = b.anchor_receipts.iter().map(|r| r.kind()).collect();
        assert_eq!(kinds, ["rfc3161", "rekor"]);
        cloakpipe_verify::verify::verify_all(&b).unwrap();
        cloakpipe_verify::anchor::verify_manifest(&b).unwrap();
        let m = b.manifest.as_ref().unwrap();
        assert!(m.batch_head_ids == ["batch-honest-001"], "{:?}", m.batch_head_ids);
        assert!(m.anchor_receipt_refs.iter().any(|r| r.starts_with("rfc3161:batch-honest-001:")));
        assert!(m.anchor_receipt_refs.iter().any(|r| r.starts_with("rekor:batch-honest-001:")));
        assert_eq!(cloakpipe_verify::anchor::verify_inclusion_proofs(&b).unwrap(), 5);
        let trust = AnchorTrust {
            tsa_roots: Some(cloakpipe_verify::rfc3161::TrustedRoots::from_pem(&fixture("freetsa-root.pem")).unwrap()),
            rekor_key: Some(cloakpipe_verify::rekor::RekorKey::from_pem(&fixture("rekor.pub")).unwrap()),
        };
        assert_eq!(cloakpipe_verify::anchor::verify_anchors_with_trust(&b, &trust).unwrap(), 2);
    }

    #[test]
    fn a_failed_self_check_writes_nothing() {
        // The TSA answers for this head, but the Rekor entry is for another
        // head: refused, nothing written.
        let d = tempfile::tempdir().unwrap();
        let tsa = serve(vec![(200, "application/timestamp-reply", fixture("freetsa-honest.tsr"))]);
        let rekor = serve(vec![(201, "application/json", fixture("rekor-future.json"))]);
        let a = args(d.path(), format!("{tsa}/tsr"), rekor);
        let out = a.out.clone();
        let now = Utc.with_ymd_and_hms(2026, 10, 7, 10, 6, 0).unwrap();
        assert_eq!(anchor(a, now, &recorded_nonce()), Err(EXIT_INVALID));
        assert!(!out.exists());
    }

    #[test]
    fn the_seal_time_backs_off_for_clock_skew_but_never_before_a_record() {
        let t = |h, m, s| Utc.with_ymd_and_hms(2026, 10, 7, h, m, s).unwrap();
        let skew = chrono::Duration::seconds(60);
        // Old records: the full back-off.
        assert_eq!(seal_time(t(12, 0, 0), Some(t(10, 0, 0)), skew), t(11, 59, 0));
        assert_eq!(seal_time(t(12, 0, 0), None, skew), t(11, 59, 0));
        // A record inside the window: the seal is that record's time.
        assert_eq!(seal_time(t(12, 0, 0), Some(t(11, 59, 30)), skew), t(11, 59, 30));
        // A record stamped after `now` (its clock is ahead of ours): never
        // claim a seal after `now`; seal_batch then refuses the record.
        assert_eq!(seal_time(t(12, 0, 0), Some(t(12, 0, 5)), skew), t(12, 0, 0));
        assert_eq!(seal_time(t(12, 0, 0), Some(t(10, 0, 0)), chrono::Duration::zero()), t(12, 0, 0));
    }
}
