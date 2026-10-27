//! The gate's decision ledger on the command line: where it is written
//! (`--ledger-db`, `CLOAKPIPE_LEDGER_DB`, else `$CLOAKPIPE_HOME/ledger.db`),
//! the key that signs it (`--signing-key`, `CLOAKPIPE_SIGNING_KEY`, else
//! `$CLOAKPIPE_HOME/gate.key`, made on first use), the `--no-ledger` opt-out,
//! scheduled anchoring (`--anchor-every`, `--anchor-interval`), and
//! `cloakpipe ledger entries | public-key | export` for auditors
//! (docs/ACTION_BOUNDARY.md, "The decision ledger"; docs/ANCHORING.md).
//!
//! Exit codes follow `release`: 0 ok, 1 invalid input, 2 usage or I/O error.

use crate::keys::{invalid, usage, Res};
use crate::release::EXIT_OK;
use clap::{Args, Subcommand};
use cloakpipe_anchor::anchor::rekor::{RekorClient, DEFAULT_REKOR_URL};
use cloakpipe_anchor::anchor::rfc3161::{TsaClient, DEFAULT_TSA_URL};
use cloakpipe_ledger::anchoring::{AnchorLoop, AnchorPolicy, Anchorer};
use cloakpipe_ledger::audit_pack::{export_pack, ExportError, PackRange};
use cloakpipe_ledger::gate_key::KeyError;
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::DecisionLog;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the decision ledger goes and what signs it.
#[derive(Debug, Clone, Default, Args)]
pub struct LedgerArgs {
    /// Decision ledger database (default: $CLOAKPIPE_LEDGER_DB, else
    /// $CLOAKPIPE_HOME/ledger.db; CLOAKPIPE_HOME defaults to ~/.cloakpipe)
    #[arg(long = "ledger-db", conflicts_with = "no_ledger")]
    pub ledger_db: Option<PathBuf>,
    /// Do not record decisions (not recommended: nothing will show what the
    /// gate allowed or refused)
    #[arg(long = "no-ledger")]
    pub no_ledger: bool,
    /// Gate signing key that signs each decision entry (a `release keygen`
    /// file; default: $CLOAKPIPE_SIGNING_KEY, else $CLOAKPIPE_HOME/gate.key,
    /// created on first use)
    #[arg(long = "signing-key", conflicts_with = "no_ledger")]
    pub signing_key: Option<PathBuf>,
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// `$CLOAKPIPE_HOME`, else `~/.cloakpipe`.
pub fn cloakpipe_home() -> Res<PathBuf> {
    if let Some(home) = env_path("CLOAKPIPE_HOME") {
        return Ok(home);
    }
    let home = env_path("HOME").or_else(|| env_path("USERPROFILE"));
    home.map(|h| h.join(".cloakpipe"))
        .ok_or_else(|| usage("no home directory: set CLOAKPIPE_HOME, or pass --ledger-db and --signing-key"))
}

impl LedgerArgs {
    /// The ledger database path (never `None` unless `--no-ledger`).
    pub fn ledger_path(&self) -> Res<Option<PathBuf>> {
        if self.no_ledger {
            return Ok(None);
        }
        match self.ledger_db.clone().or_else(|| env_path("CLOAKPIPE_LEDGER_DB")) {
            Some(p) => Ok(Some(p)),
            None => Ok(Some(cloakpipe_home()?.join("ledger.db"))),
        }
    }

    /// The configured key file path.
    fn key_path(&self) -> Res<PathBuf> {
        match self.signing_key.clone().or_else(|| env_path("CLOAKPIPE_SIGNING_KEY")) {
            Some(p) => Ok(p),
            None => Ok(cloakpipe_home()?.join("gate.key")),
        }
    }

    /// The gate signing key. A named key must exist; the default one is
    /// created on first use, and its public key printed once on stderr.
    pub fn signing_key(&self) -> Res<GateKey> {
        let path = self.key_path()?;
        let named = self.signing_key.is_some() || env_path("CLOAKPIPE_SIGNING_KEY").is_some();
        if named {
            return GateKey::load(&path).map_err(key_error);
        }
        let (key, created) = GateKey::load_or_create(&path).map_err(key_error)?;
        if created {
            eprintln!("cloakpipe: created the gate signing key {} (owner-only; keep it safe)", path.display());
            eprintln!(
                "cloakpipe: gate public key {} ({}): auditors verify the decision ledger with it (`cloakpipe ledger public-key` prints it again)",
                key.public_hex(),
                key.keyid()
            );
        }
        Ok(key)
    }

    /// The decision log: `None` with `--no-ledger`, after a loud warning.
    /// A ledger or key that cannot be opened stops the caller (fail closed).
    pub fn decision_log(&self, what: &str) -> Res<Option<DecisionLog>> {
        let Some(path) = self.ledger_path()? else {
            eprintln!("WARNING: --no-ledger: {what} are not recorded. Nothing will show what was allowed or refused, and nothing can be verified later.");
            return Ok(None);
        };
        let key = self.signing_key()?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
            std::fs::create_dir_all(dir).map_err(|e| usage(format_args!("--ledger-db {}: {e}", dir.display())))?;
        }
        DecisionLog::open(&path.to_string_lossy(), key)
            .map(Some)
            .map_err(|e| usage(format_args!("decision ledger {}: {e:#}", path.display())))
    }
}

/// Scheduled anchoring of the decision ledger (docs/ANCHORING.md): epochs
/// sealed and anchored in the background, never on the request path.
#[derive(Debug, Clone, Default, Args)]
pub struct AnchoringArgs {
    /// Seal the decision ledger into an anchored epoch every N entries
    #[arg(long = "anchor-every", value_name = "N")]
    pub anchor_every: Option<u64>,
    /// Seal and anchor whatever is new this often (e.g. 30s, 10m, 1h)
    #[arg(long = "anchor-interval", value_name = "DURATION", value_parser = parse_duration)]
    pub anchor_interval: Option<Duration>,
    /// RFC 3161 timestamp authority (default: https://freetsa.org/tsr)
    #[arg(long = "tsa", value_name = "URL", conflicts_with = "no_tsa")]
    pub tsa: Option<String>,
    /// PEM root(s) the TSA must chain to (default: the freetsa.org and
    /// DigiCert roots built in)
    #[arg(long = "tsa-root", value_name = "PEM", conflicts_with = "no_tsa")]
    pub tsa_root: Option<PathBuf>,
    /// Do not timestamp epochs with a TSA
    #[arg(long = "no-tsa")]
    pub no_tsa: bool,
    /// Sigstore Rekor log (default: https://rekor.sigstore.dev)
    #[arg(long = "rekor", value_name = "URL", conflicts_with = "no_rekor")]
    pub rekor: Option<String>,
    /// PEM public key of the Rekor log (default: rekor.sigstore.dev's,
    /// built in)
    #[arg(long = "rekor-key", value_name = "PEM", conflicts_with = "no_rekor")]
    pub rekor_key: Option<PathBuf>,
    /// Do not log epochs to Rekor
    #[arg(long = "no-rekor")]
    pub no_rekor: bool,
}

/// `30s`, `10m`, `1h`, `2d`, or plain seconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| format!("`{s}` is not a duration (e.g. 30s, 10m, 1h, 2d)"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(format!("`{s}` is not a duration (e.g. 30s, 10m, 1h, 2d)")),
    };
    if secs == 0 {
        return Err("a duration must be positive".into());
    }
    Ok(Duration::from_secs(secs))
}

impl AnchoringArgs {
    /// Whether any anchoring flag is set.
    pub fn any(&self) -> bool {
        self.anchor_every.is_some()
            || self.anchor_interval.is_some()
            || self.tsa.is_some()
            || self.tsa_root.is_some()
            || self.no_tsa
            || self.rekor.is_some()
            || self.rekor_key.is_some()
            || self.no_rekor
    }

    /// The anchoring the flags ask for, checked and with its trust inputs
    /// loaded; `None` when anchoring is off.
    pub fn configure(&self, ledger: &LedgerArgs) -> Res<Option<(Anchorer, AnchorPolicy)>> {
        if !self.any() {
            return Ok(None);
        }
        if self.anchor_every.is_none() && self.anchor_interval.is_none() {
            return Err(usage("anchoring flags need --anchor-every N and/or --anchor-interval DURATION (when to anchor)"));
        }
        if self.anchor_every == Some(0) {
            return Err(usage("--anchor-every must be at least 1"));
        }
        if self.no_tsa && self.no_rekor {
            return Err(usage("--no-tsa and --no-rekor leave nothing to anchor with"));
        }
        if ledger.no_ledger {
            return Err(usage("anchoring needs the decision ledger: drop --no-ledger"));
        }
        let read = |p: &Path| std::fs::read(p).map_err(|e| usage(format_args!("cannot read {}: {e}", p.display())));
        let tsa = if self.no_tsa {
            None
        } else {
            let roots = match &self.tsa_root {
                Some(p) => cloakpipe_verify::rfc3161::TrustedRoots::from_pem(&read(p)?)
                    .map_err(|e| invalid(format_args!("--tsa-root {}: {e}", p.display())))?,
                None => cloakpipe_verify::trust::default_tsa_roots(),
            };
            Some(TsaClient::new(self.tsa.as_deref().unwrap_or(DEFAULT_TSA_URL), roots))
        };
        let rekor = if self.no_rekor {
            None
        } else {
            let key = match &self.rekor_key {
                Some(p) => cloakpipe_verify::rekor::RekorKey::from_pem(&read(p)?)
                    .map_err(|e| invalid(format_args!("--rekor-key {}: {e}", p.display())))?,
                None => cloakpipe_verify::trust::default_rekor_key(),
            };
            Some(RekorClient::new(self.rekor.as_deref().unwrap_or(DEFAULT_REKOR_URL), key))
        };
        let policy = AnchorPolicy { every: self.anchor_every, interval: self.anchor_interval, retry: Duration::from_secs(30) };
        Ok(Some((Anchorer::new(tsa, rekor), policy)))
    }
}

/// Start anchoring the ledger in the background (after the decision log is
/// open, so the ledger and key exist).
pub fn start_anchoring(ledger: &LedgerArgs, anchoring: Option<(Anchorer, AnchorPolicy)>) -> Res<Option<AnchorLoop>> {
    let Some((anchorer, policy)) = anchoring else { return Ok(None) };
    let path = ledger.ledger_path()?.expect("anchoring is refused with --no-ledger");
    let key = ledger.signing_key()?;
    AnchorLoop::spawn(&path.to_string_lossy(), key, anchorer, policy)
        .map(Some)
        .map_err(|e| usage(format_args!("decision ledger {}: {e}", path.display())))
}

fn key_error(e: KeyError) -> i32 {
    match e {
        KeyError::Io(..) => usage(format_args!("signing key {e}")),
        KeyError::Invalid(..) => invalid(format_args!("signing key {e}")),
    }
}

#[derive(Subcommand)]
pub enum LedgerCommands {
    /// Print the decision ledger entries, one JSON object per line (for `cloakpipe-verify decisions`)
    Entries(EntriesArgs),
    /// Print the gate signing key's keyid and public key (what auditors verify with)
    PublicKey(PublicKeyArgs),
    /// Write a signed audit pack (tar: entries, gate public key, epochs with
    /// their RFC 3161 / Rekor anchors, manifest digests) for `cloakpipe verify`
    Export(ExportArgs),
}

#[derive(Args)]
pub struct ExportArgs {
    /// Where to write the pack
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    /// Only entries at or after this time: RFC 3339, YYYY-MM-DD, or an age
    /// such as 24h or 30d. The range widens to whole anchored epochs.
    #[arg(long, value_name = "WHEN")]
    pub since: Option<String>,
    /// Only entries at or before this time (same forms as --since)
    #[arg(long, value_name = "WHEN")]
    pub until: Option<String>,
    /// Decision ledger database (default: $CLOAKPIPE_LEDGER_DB, else $CLOAKPIPE_HOME/ledger.db)
    #[arg(long = "ledger-db")]
    pub ledger_db: Option<PathBuf>,
    /// Gate signing key that signs the pack (default: $CLOAKPIPE_SIGNING_KEY, else $CLOAKPIPE_HOME/gate.key)
    #[arg(long = "signing-key")]
    pub signing_key: Option<PathBuf>,
}

#[derive(Args)]
pub struct EntriesArgs {
    /// Decision ledger database (default: $CLOAKPIPE_LEDGER_DB, else $CLOAKPIPE_HOME/ledger.db)
    #[arg(long = "ledger-db")]
    pub ledger_db: Option<PathBuf>,
    /// Only entries from this seq on
    #[arg(long = "from-seq", default_value_t = 0)]
    pub from_seq: u64,
}

#[derive(Args)]
pub struct PublicKeyArgs {
    /// Gate signing key (default: $CLOAKPIPE_SIGNING_KEY, else $CLOAKPIPE_HOME/gate.key)
    #[arg(long = "signing-key")]
    pub signing_key: Option<PathBuf>,
}

pub fn run(cmd: LedgerCommands) -> i32 {
    crate::keys::finish(match cmd {
        LedgerCommands::Entries(a) => entries(&a),
        LedgerCommands::PublicKey(a) => public_key(&a),
        LedgerCommands::Export(a) => export(&a),
    })
}

/// Open an existing ledger (never create one).
fn existing_ledger(ledger_db: Option<PathBuf>) -> Res<(PathBuf, LedgerStore)> {
    let args = LedgerArgs { ledger_db, ..Default::default() };
    let path = args.ledger_path()?.expect("a ledger path without --no-ledger");
    if !path.is_file() {
        return Err(usage(format_args!("{}: no such ledger", path.display())));
    }
    let store = LedgerStore::open(&path.to_string_lossy()).map_err(|e| usage(format_args!("{}: {e}", path.display())))?;
    Ok((path, store))
}

/// An existing gate key (never create one).
fn existing_key(signing_key: Option<PathBuf>) -> Res<GateKey> {
    let args = LedgerArgs { signing_key, ..Default::default() };
    let path = args.key_path()?;
    if !Path::new(&path).exists() {
        return Err(usage(format_args!("{}: no gate signing key yet (mcp-proxy creates it on first use)", path.display())));
    }
    GateKey::load(&path).map_err(key_error)
}

/// `--since` / `--until`: RFC 3339, YYYY-MM-DD (midnight UTC), or an age
/// back from `now` (24h, 30d).
fn parse_when(flag: &str, s: &str, now: chrono::DateTime<chrono::Utc>) -> Res<chrono::DateTime<chrono::Utc>> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&chrono::Utc));
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(d.and_hms_opt(0, 0, 0).expect("midnight").and_utc());
    }
    if let Ok(age) = parse_duration(s) {
        return Ok(now - chrono::Duration::from_std(age).map_err(|e| usage(format_args!("{flag} {s}: {e}")))?);
    }
    Err(usage(format_args!("{flag} {s:?}: expected RFC 3339, YYYY-MM-DD or an age such as 24h or 30d")))
}

fn export(a: &ExportArgs) -> Res<i32> {
    let now = chrono::Utc::now();
    let range = PackRange {
        since: a.since.as_deref().map(|s| parse_when("--since", s, now)).transpose()?,
        until: a.until.as_deref().map(|s| parse_when("--until", s, now)).transpose()?,
    };
    let (path, store) = existing_ledger(a.ledger_db.clone())?;
    let key = existing_key(a.signing_key.clone())?;
    let pack = export_pack(&store, &key, &range, now).map_err(|e| match e {
        ExportError::Empty => invalid(e),
        e => usage(format_args!("{}: {e}", path.display())),
    })?;
    std::fs::write(&a.out, &pack.tar).map_err(|e| usage(format_args!("cannot write {}: {e}", a.out.display())))?;
    let out = serde_json::json!({
        "outcome": "exported",
        "out": a.out.display().to_string(),
        "entries": pack.entries,
        "first_seq": pack.first_seq,
        "last_seq": pack.last_seq,
        "epochs": pack.epochs,
        "signer": key.keyid(),
    });
    println!("{out}");
    Ok(EXIT_OK)
}

fn entries(a: &EntriesArgs) -> Res<i32> {
    let (path, store) = existing_ledger(a.ledger_db.clone())?;
    let entries = store.decisions_from(a.from_seq).map_err(|e| usage(format_args!("{}: {e}", path.display())))?;
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    for e in entries {
        writeln!(out, "{}", e.to_json_line()).map_err(|e| usage(format_args!("stdout: {e}")))?;
    }
    Ok(EXIT_OK)
}

fn public_key(a: &PublicKeyArgs) -> Res<i32> {
    let key = existing_key(a.signing_key.clone())?;
    let out = serde_json::json!({ "keyid": key.keyid(), "publicKey": key.public_hex() });
    println!("{}", serde_json::to_string_pretty(&out).expect("JSON"));
    Ok(EXIT_OK)
}
