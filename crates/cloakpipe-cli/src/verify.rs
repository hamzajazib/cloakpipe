//! `cloakpipe verify <audit-pack.tar>`: check a gate audit pack offline
//! with the standalone verifier library (`cloakpipe_verify::gate_pack`), the
//! same code as `cloakpipe-verify pack`. Nothing in the pack vouches for
//! itself: pin the gate key with `--key`; anchors are checked against the
//! built-in public TSA roots and Rekor key, or the ones given.
//!
//! Exit codes: 0 verified, 1 a check failed or something is missing,
//! 2 usage or I/O error.

use crate::keys::{finish, read, usage, Res};
use crate::release::{EXIT_INVALID, EXIT_OK};
use clap::Args;
use cloakpipe_verify::gate_pack::{verify_pack, PackTrust};
use std::path::PathBuf;

#[derive(Args)]
pub struct VerifyArgs {
    /// The audit pack (`cloakpipe ledger export --out audit-pack.tar`)
    pub pack: PathBuf,
    /// Pinned gate public key: 64 hex chars, or a key file's publicKey
    /// (repeatable for rotated keys). Without it, the pack's own key is
    /// used and the report says so.
    #[arg(long = "key", value_name = "HEX|KEYFILE")]
    pub keys: Vec<String>,
    /// PEM root(s) RFC 3161 anchors must chain to (default: the
    /// freetsa.org and DigiCert roots built in)
    #[arg(long = "tsa-root", value_name = "PEM")]
    pub tsa_root: Option<PathBuf>,
    /// PEM public key of the Rekor log (default: rekor.sigstore.dev's, built in)
    #[arg(long = "rekor-key", value_name = "PEM")]
    pub rekor_key: Option<PathBuf>,
    /// How far an entry's time may run ahead of its anchor's
    #[arg(long = "clock-skew-secs", default_value_t = 60)]
    pub clock_skew_secs: i64,
    /// Also fail when entries after the last epoch are not anchored yet
    #[arg(long = "require-anchors")]
    pub require_anchors: bool,
}

/// A gate public key: 64 hex chars, or a key file whose `publicKey` is
/// read (`privateKey` never is).
fn gate_key(arg: &str) -> Res<[u8; 32]> {
    let hex32 = |s: &str| hex::decode(s.trim()).ok().and_then(|b| <[u8; 32]>::try_from(b).ok());
    if let Some(k) = hex32(arg) {
        return Ok(k);
    }
    let src = read(std::path::Path::new(arg))?;
    let v: serde_json::Value =
        serde_json::from_str(&src).map_err(|e| usage(format_args!("--key {arg}: not 64 hex chars or a key file: {e}")))?;
    v.get("publicKey")
        .and_then(serde_json::Value::as_str)
        .and_then(hex32)
        .ok_or_else(|| usage(format_args!("--key {arg}: publicKey must be 64 hex chars")))
}

pub fn run(a: VerifyArgs) -> i32 {
    finish(verify(a))
}

fn verify(a: VerifyArgs) -> Res<i32> {
    let bytes = |p: &PathBuf| std::fs::read(p).map_err(|e| usage(format_args!("cannot read {}: {e}", p.display())));
    let tsa = a.tsa_root.as_ref().map(bytes).transpose()?;
    let rekor = a.rekor_key.as_ref().map(bytes).transpose()?;
    let mut trust = PackTrust::from_pem(tsa.as_deref(), rekor.as_deref()).map_err(usage)?;
    trust.gate_keys = a.keys.iter().map(|k| gate_key(k)).collect::<Res<_>>()?;
    trust.clock_skew_secs = a.clock_skew_secs;
    trust.require_anchors = a.require_anchors;
    let report = verify_pack(&bytes(&a.pack)?, &trust);
    print!("{}", report.render());
    Ok(if report.ok() { EXIT_OK } else { EXIT_INVALID })
}
