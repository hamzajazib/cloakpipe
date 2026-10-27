//! The gate's decision ledger on the command line: where it is written
//! (`--ledger-db`, `CLOAKPIPE_LEDGER_DB`, else `$CLOAKPIPE_HOME/ledger.db`),
//! the key that signs it (`--signing-key`, `CLOAKPIPE_SIGNING_KEY`, else
//! `$CLOAKPIPE_HOME/gate.key`, made on first use), the `--no-ledger` opt-out,
//! and `cloakpipe ledger entries | public-key` for auditors
//! (docs/ACTION_BOUNDARY.md, "The decision ledger").
//!
//! Exit codes follow `release`: 0 ok, 1 invalid input, 2 usage or I/O error.

use crate::keys::{invalid, usage, Res};
use crate::release::EXIT_OK;
use clap::{Args, Subcommand};
use cloakpipe_ledger::gate_key::KeyError;
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::DecisionLog;
use std::path::{Path, PathBuf};

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
    })
}

fn entries(a: &EntriesArgs) -> Res<i32> {
    let args = LedgerArgs { ledger_db: a.ledger_db.clone(), ..Default::default() };
    let path = args.ledger_path()?.expect("a ledger path without --no-ledger");
    if !path.is_file() {
        return Err(usage(format_args!("{}: no such ledger", path.display())));
    }
    let store = LedgerStore::open(&path.to_string_lossy()).map_err(|e| usage(format_args!("{}: {e}", path.display())))?;
    let entries = store.decisions_from(a.from_seq).map_err(|e| usage(format_args!("{}: {e}", path.display())))?;
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    for e in entries {
        writeln!(out, "{}", e.to_json_line()).map_err(|e| usage(format_args!("stdout: {e}")))?;
    }
    Ok(EXIT_OK)
}

fn public_key(a: &PublicKeyArgs) -> Res<i32> {
    let args = LedgerArgs { signing_key: a.signing_key.clone(), ..Default::default() };
    let path = args.key_path()?;
    if !Path::new(&path).exists() {
        return Err(usage(format_args!("{}: no gate signing key yet (mcp-proxy creates it on first use)", path.display())));
    }
    let key = GateKey::load(&path).map_err(key_error)?;
    let out = serde_json::json!({ "keyid": key.keyid(), "publicKey": key.public_hex() });
    println!("{}", serde_json::to_string_pretty(&out).expect("JSON"));
    Ok(EXIT_OK)
}
