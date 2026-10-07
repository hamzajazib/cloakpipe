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
//! cloakpipe-verify release-pack <pack.json> --trust KEYFILE [--ledger-trust KEYFILE]
//!                                [--cert-trust KEYFILE] [--now RFC3339] [--json]
//!                                          # each trust flag takes one file; repeat it
//!                                          # a release audit pack (docs/AUDIT_PACK.md)
//! ```
//!
//! `--trust-key` pins the signer: the manifest must be signed by one of the
//! given keys. Without it the bundle is checked against the key it carries,
//! which proves integrity but not who produced it.
//!
//! ## Why standalone
//!
//! Per the v2 plan: "If it needs internal crates, the format is
//! wrong." Evidence bundles are verified with this crate's own code — no
//! `cloakpipe-ledger`. A hostile third party can clone only this crate,
//! build it, and verify any bundle the producer emits. Release audit packs
//! additionally use the two spec crates `cloakpipe-release` (manifest hash)
//! and `cloakpipe-cert` (DSSE certification verification); neither produces
//! evidence, and the release hash also has an independent Python reference
//! (`tools/release_hash_reference.py`).

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
    if cmd == "release-pack" {
        return release_pack(&args[2..]);
    }
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

/// `release-pack PACK --trust KEYFILE [--ledger-trust KEYFILE] [--cert-trust KEYFILE]
/// [--now T] [--json]`, each trust flag repeatable with one file per use.
/// Usage and I/O problems are errors (exit 2); everything about the pack's
/// content is a verification result (exit 0 or 1).
fn release_pack(args: &[String]) -> Result<ExitCode> {
    use cloakpipe_verify::pack::{trusted_key_from_json, verify_pack_bytes, VerifyOptions, MAX_PACK_BYTES};
    use std::io::Read;
    let mut pack = None;
    let (mut trust, mut ledger_trust, mut cert_trust) = (Vec::new(), Vec::new(), Vec::new());
    let (mut now, mut json) = (None, false);
    let mut it = args.iter();
    let key_file = |path: &str| -> Result<cloakpipe_verify::pack::TrustedKey> {
        let src = std::fs::read_to_string(path).with_context(|| format!("reading key file {path}"))?;
        trusted_key_from_json(&src).map_err(|e| anyhow::anyhow!("{path}: {e}"))
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--trust" => trust.push(key_file(it.next().context("--trust needs a KEYFILE")?)?),
            "--ledger-trust" => ledger_trust.push(key_file(it.next().context("--ledger-trust needs a KEYFILE")?)?),
            "--cert-trust" => cert_trust.push(key_file(it.next().context("--cert-trust needs a KEYFILE")?)?),
            "--now" => {
                let t = it.next().context("--now needs an RFC 3339 time")?;
                let ok = matches!(t.as_bytes().get(10), Some(b'T' | b't'));
                let parsed = chrono::DateTime::parse_from_rfc3339(t).ok().filter(|_| ok);
                now = Some(parsed.with_context(|| format!("--now {t:?} is not RFC 3339"))?.with_timezone(&chrono::Utc));
            }
            "--json" => json = true,
            flag if flag.starts_with("--") => anyhow::bail!("unexpected argument `{flag}`"),
            path if pack.is_none() => pack = Some(path.to_string()),
            extra => anyhow::bail!(
                "unexpected argument `{extra}` (one pack at a time; each trust flag takes one KEYFILE, repeat the flag)"
            ),
        }
    }
    let pack = pack.context("missing pack path; usage: cloakpipe-verify release-pack PACK --trust KEYFILE")?;
    if trust.is_empty() {
        anyhow::bail!("--trust KEYFILE is required: a pack proves nothing without a pinned exporter key");
    }
    let file = std::fs::File::open(&pack).with_context(|| format!("reading {pack}"))?;
    let len = file.metadata().with_context(|| format!("reading {pack}"))?.len();
    let mut bytes = Vec::new();
    file.take(MAX_PACK_BYTES + 1).read_to_end(&mut bytes).with_context(|| format!("reading {pack}"))?;
    if len > MAX_PACK_BYTES || bytes.len() as u64 > MAX_PACK_BYTES {
        anyhow::bail!("{pack} is larger than {MAX_PACK_BYTES} bytes; not read");
    }
    let opts = VerifyOptions {
        trusted: trust,
        ledger_trusted: ledger_trust,
        cert_trusted: cert_trust,
        now: now.unwrap_or_else(chrono::Utc::now),
    };
    let report = verify_pack_bytes(&bytes, &opts);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.render_text());
    }
    Ok(ExitCode::from(if report.ok { 0 } else { 1 }))
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
  cloakpipe-verify release-pack <pack.json> --trust KEYFILE [--ledger-trust KEYFILE]
                                [--cert-trust KEYFILE] [--now RFC3339] [--json]
      Verify a release audit pack (docs/AUDIT_PACK.md). Each role has its
      own keys (release keygen files; the public part is enough): --trust
      the exporter that signed the pack, --ledger-trust the ledger signers,
      --cert-trust the certification issuers. Each flag takes one KEYFILE;
      repeat the flag for more. One key may not hold two roles. Offline;
      --now defaults to the current time; packs over 256 MiB are refused.

EXITS:
  0   bundle / pack verified
  1   verification failed (tamper / gap / bad signature / inconsistency)
  2   usage error / could not read bundle, pack or key file

NOTES:
  This binary has NO dependency on cloakpipe-ledger or any other
  evidence producer. Release packs use the spec crates cloakpipe-release
  and cloakpipe-cert for the manifest hash and certifications.
";