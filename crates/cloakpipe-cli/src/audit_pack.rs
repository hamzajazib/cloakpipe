//! `cloakpipe release audit-pack`: assemble and sign a release audit pack
//! from local files (docs/AUDIT_PACK.md).
//!
//! Exit codes follow `release`: 0 written, 1 an input that could never
//! verify (wrong release, malformed run/envelope/event/ledger export,
//! uncertifiable manifest, key without a private part), 2 usage or I/O.

use crate::cert::{finish, invalid, now_arg, read, rfc3339, signing_key, usage, Res};
use crate::release::{load, EXIT_OK};
use clap::Args;
use cloakpipe_cert::statement::Envelope;
use cloakpipe_cert::EvaluationRun;
use cloakpipe_verify::pack::{GovernanceEvent, PackBuilder};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct AuditPackArgs {
    /// Release manifest (must be certifiable)
    #[arg(long, value_name = "MANIFEST")]
    manifest: PathBuf,
    /// Evaluation run (native JSON); repeatable
    #[arg(long = "run", value_name = "FILE")]
    runs: Vec<PathBuf>,
    /// Certification DSSE envelope; repeatable
    #[arg(long = "certification", value_name = "FILE")]
    certifications: Vec<PathBuf>,
    /// Signed ledger export (cloakpipe.bundle v4) with hops bound to this release; repeatable
    #[arg(long = "ledger-export", value_name = "FILE")]
    ledger_exports: Vec<PathBuf>,
    /// Governance events: a JSON array in the pack's event format
    #[arg(long, value_name = "FILE")]
    events: Option<PathBuf>,
    /// Exporter signing key from `cloakpipe release keygen --out`
    #[arg(long, value_name = "KEYFILE")]
    key: PathBuf,
    /// Who assembled the pack
    #[arg(long, default_value = "cloakpipe-cli")]
    exporter: String,
    /// Pack creation time, RFC 3339 (default: now)
    #[arg(long)]
    now: Option<String>,
    /// Exporter-declared limitation; repeatable
    #[arg(long = "limitation", value_name = "TEXT")]
    limitations: Vec<String>,
    /// Output file
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

pub fn audit_pack(a: AuditPackArgs) -> i32 {
    finish(inner(a))
}

fn json_file<T: DeserializeOwned>(path: &Path, what: &str) -> Res<T> {
    let src = read(path)?;
    serde_json::from_str(&src).map_err(|e| invalid(format_args!("{}: invalid {what}: {e}", path.display())))
}

fn inner(a: AuditPackArgs) -> Res<i32> {
    let created_at = rfc3339(now_arg(a.now.as_deref())?);
    let manifest = load(&a.manifest)?;
    let (key, _) = signing_key(&a.key)?;

    let mut builder = PackBuilder::new(manifest, a.exporter, created_at);
    for p in &a.runs {
        builder = builder.run(json_file::<EvaluationRun>(p, "evaluation run")?);
    }
    for p in &a.certifications {
        builder = builder.certification(json_file::<Envelope>(p, "certification envelope")?);
    }
    for p in &a.ledger_exports {
        let bundle = json_file::<serde_json::Value>(p, "ledger export")?;
        builder = builder.ledger_export_json(bundle).map_err(|e| invalid(format_args!("{}: {e}", p.display())))?;
    }
    if let Some(p) = &a.events {
        builder = builder.events(json_file::<Vec<GovernanceEvent>>(p, "governance events (a JSON array)")?);
    }
    for l in a.limitations {
        builder = builder.limitation(l);
    }
    let pack = builder.build(&key).map_err(|e| invalid(format_args!("cannot build the pack: {e}")))?;
    std::fs::write(&a.out, pack.to_json_pretty())
        .map_err(|e| usage(format_args!("cannot write {}: {e}", a.out.display())))?;
    println!("wrote {}", a.out.display());
    println!("release  {}", pack.spec.release.hash);
    println!("digest   {}", pack.digest);
    println!("signer   {}", pack.signature.keyid);
    println!(
        "contents {} run(s), {} certification(s), {} event(s), {} ledger export(s)",
        pack.spec.evaluation_runs.len(),
        pack.spec.certifications.len(),
        pack.spec.governance.events.len(),
        pack.spec.ledger_exports.len()
    );
    Ok(EXIT_OK)
}
