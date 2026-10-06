//! `cloakpipe-verify` — standalone auditor CLI for CloakPipe bundles.
//!
//! ## Commands
//!
//! ```text
//! cloakpipe-verify chain   <bundle.json>   # hash chain unbroken, no seq gaps
//! cloakpipe-verify sigs    <bundle.json>   # Ed25519 batch-head signatures valid
//! cloakpipe-verify anchors <bundle.json>   # TSA + log receipts valid offline
//! cloakpipe-verify all     <bundle.json> [--trust-key KEYID=HEX]...
//!                                          # everything; exit 0 / nonzero for CI
//! ```
//!
//! `--trust-key` pins the signer: the manifest must be signed by one of the
//! given keys. Without it the bundle is checked against the key it carries,
//! which proves integrity but not who produced it.
//!
//! ## Why standalone
//!
//! Per the v2 plan: "If it needs internal crates, the format is
//! wrong." This binary depends only on `serde`, `sha2`, `ed25519-dalek`,
//! and `serde_json` — no `cloakpipe-ledger`. A hostile third party
//! can clone only this crate, build it, and verify any bundle the
//! producer emits.

use anyhow::{Context, Result};
use cloakpipe_verify::{anchor, bundle, verify};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("cloakpipe-verify: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode> {
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let path = args.get(2).cloned().unwrap_or_default();
    if path.is_empty() && cmd != "help" && cmd != "--help" && cmd != "-h" {
        anyhow::bail!("missing bundle path");
    }

    let trusted = parse_trust_keys(&args[3.min(args.len())..])?;

    match cmd {
        "chain" => {
            let b = load_bundle(&path)?;
            match verify::verify_chain(&b) {
                Ok(tip) => {
                    println!(
                        "OK  {} record(s) verified; chain tip = {}",
                        b.records.len(),
                        tip
                    );
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "sigs" => {
            let b = load_bundle(&path)?;
            match verify::verify_sigs(&b) {
                Ok(n) => {
                    println!("OK  {n} batch-head signature(s) valid");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "all" => {
            let b = load_bundle(&path)?;
            // v2 bundles get full anchor + inclusion-proof checks.
            if b.format_version >= 2 {
                match run_all_v2(&b).and_then(|s| {
                    let signer = signer_status(&b, &trusted)?;
                    Ok((s, signer))
                }) {
                    Ok((s, signer)) => {
                        println!(
                            "OK  records={} batch_signatures={} anchors={} inclusion_proofs={} chain_tip={} {signer}",
                            s.records, s.signatures, s.anchors, s.proofs, s.chain_tip
                        );
                        Ok(ExitCode::from(0))
                    }
                    Err(e) => {
                        println!("FAIL  {e}");
                        Ok(ExitCode::from(1))
                    }
                }
            } else {
                match verify::verify_all(&b) {
                    Ok(s) => {
                        println!(
                            "OK  records={} batch_signatures={} chain_tip={}",
                            s.records, s.signatures, s.chain_tip
                        );
                        Ok(ExitCode::from(0))
                    }
                    Err(e) => {
                        println!("FAIL  {e}");
                        Ok(ExitCode::from(1))
                    }
                }
            }
        }
        "anchors" => {
            let b = load_bundle(&path)?;
            match anchor::verify_anchors(&b) {
                Ok(n) => {
                    println!("OK  {n} anchor receipt(s) verified");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "proofs" => {
            let b = load_bundle(&path)?;
            match anchor::verify_inclusion_proofs(&b) {
                Ok(n) => {
                    println!("OK  {n} inclusion proof(s) verified");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "manifest" => {
            let b = load_bundle(&path)?;
            match anchor::verify_manifest(&b) {
                Ok(()) => {
                    println!("OK  manifest verified");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "help" | "--help" | "-h" => {
            println!("{}", USAGE);
            Ok(ExitCode::from(0))
        }
        other => anyhow::bail!("unknown command `{other}`; try `cloakpipe-verify help`"),
    }
}

/// `--trust-key KEYID=HEX` pairs (64 hex chars = Ed25519 public key).
fn parse_trust_keys(rest: &[String]) -> Result<std::collections::BTreeMap<String, [u8; 32]>> {
    let mut keys = std::collections::BTreeMap::new();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        if arg != "--trust-key" {
            anyhow::bail!("unexpected argument `{arg}`");
        }
        let spec = it.next().context("--trust-key needs KEYID=HEX")?;
        let (id, hex_key) = spec.split_once('=').context("--trust-key needs KEYID=HEX")?;
        let bytes = hex::decode(hex_key).ok().filter(|b| b.len() == 32).context("--trust-key: HEX must be 64 hex chars")?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        keys.insert(id.to_string(), key);
    }
    Ok(keys)
}

/// "signer trusted" when pinned keys were given and match; an explicit
/// warning when none were given, so an unpinned pass is never mistaken for
/// proof of origin.
fn signer_status(b: &bundle::Bundle, trusted: &std::collections::BTreeMap<String, [u8; 32]>) -> Result<&'static str> {
    if b.manifest.is_none() {
        return Ok("signer=none");
    }
    if trusted.is_empty() {
        return Ok("WARNING signer not pinned (pass --trust-key to verify who signed)");
    }
    anchor::check_trusted_signer(b, trusted).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok("signer trusted")
}

fn load_bundle(path: &str) -> Result<bundle::Bundle> {
    let p = PathBuf::from(path);
    let bytes = std::fs::read(&p).with_context(|| format!("reading {path}"))?;
    let b: bundle::Bundle =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {path}"))?;
    Ok(b)
}

struct AllV2Summary {
    records: usize,
    signatures: usize,
    anchors: usize,
    proofs: usize,
    chain_tip: bundle::Hex32,
}

fn run_all_v2(b: &bundle::Bundle) -> Result<AllV2Summary, anyhow::Error> {
    let summary = verify::verify_all(b).map_err(|e| anyhow::anyhow!("{e}"))?;
    let anchors = anchor::verify_anchors(b).map_err(|e| anyhow::anyhow!("{e}"))?;
    let proofs = anchor::verify_inclusion_proofs(b).map_err(|e| anyhow::anyhow!("{e}"))?;
    // v3 bundles additionally require a manifest check.
    if b.format_version >= 3 {
        anchor::verify_manifest(b).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(AllV2Summary {
        records: summary.records,
        signatures: summary.signatures,
        anchors,
        proofs,
        chain_tip: summary.chain_tip,
    })
}

const USAGE: &str = "\
cloakpipe-verify — standalone auditor for CloakPipe evidence bundles

USAGE:
  cloakpipe-verify chain    <bundle.json>
  cloakpipe-verify sigs     <bundle.json>
  cloakpipe-verify anchors  <bundle.json>
  cloakpipe-verify proofs   <bundle.json>
  cloakpipe-verify manifest <bundle.json>
  cloakpipe-verify all      <bundle.json> [--trust-key KEYID=HEX]...

EXITS:
  0   bundle verified
  1   verification failed (tamper / gap / bad signature)
  2   usage error / could not read bundle

NOTES:
  This binary has NO dependency on cloakpipe-ledger or any other
  CloakPipe crate. If you find that it does, the format is wrong.
";