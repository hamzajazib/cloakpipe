//! `cloakpipe anchor`: seal an exported evidence bundle under a signed batch
//! head and anchor that head externally (RFC 3161 TSA and/or Sigstore
//! Rekor). Every receipt is verified before the anchored bundle is written,
//! and the finished bundle is re-verified as an auditor would.
//!
//! Exit codes: 0 anchored, 1 refused or an anchor failed, 2 usage / I/O.

use crate::release::{EXIT_INVALID, EXIT_IO, EXIT_OK};
use cloakpipe_anchor::anchor::rekor::{RekorClient, DEFAULT_REKOR_URL};
use cloakpipe_anchor::anchor::rfc3161::{TsaClient, DEFAULT_TSA_URL};
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
    match anchor(a) {
        Ok(()) => EXIT_OK,
        Err(code) => code,
    }
}

fn anchor(a: AnchorArgs) -> Result<(), i32> {
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

    let now = chrono::Utc::now();
    let batch_id = a.batch_id.clone().unwrap_or_else(|| {
        let first = bundle.records.first().map(|r| r.seq).unwrap_or(0);
        let last = bundle.records.last().map(|r| r.seq).unwrap_or(0);
        format!("batch-{first}-{last}-{}", now.timestamp())
    });
    let head = seal_batch(&mut bundle, &signer, &batch_id, now).map_err(refused)?;

    let timeout = Duration::from_secs(a.timeout_secs);
    let mut receipts = Vec::new();
    if let Some(roots) = &tsa_roots {
        let tsa = TsaClient::new(&a.tsa_url, roots.clone()).with_timeout(timeout);
        receipts.push(tsa.anchor_head(&head).map_err(|e| refused(format_args!("TSA {}: {e}", a.tsa_url)))?);
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
    let n = cloakpipe_verify::anchor::verify_anchors_with_trust(&audit, &trust)
        .map_err(|e| refused(format_args!("self-check: {e}")))?;

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
