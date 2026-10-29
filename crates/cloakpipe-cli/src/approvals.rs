//! Approvals through a broker on the command line: the `mcp-proxy` flags
//! (`--approvals-url`, `--approvals-secret-file`,
//! `--approvals-poll-interval`) and `cloakpipe approvals keys`, which
//! writes the broker's approver public keys as `--approver-key` files
//! (docs/APPROVALS.md; `cloakpipe_mcp::broker`).
//!
//! Exit codes follow `release`: 0 ok, 1 the broker refused or sent a key
//! that does not check out, 2 usage or I/O error.

use crate::keys::{finish, keyid, usage, Res};
use crate::release::{EXIT_INVALID, EXIT_OK};
use clap::{Args, Subcommand};
use cloakpipe_mcp::broker::{fetch_approver_keys, ApprovalBroker, BrokerConfig};
use cloakpipe_mcp::{EventSink, ToolGate};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Where `mcp-proxy` files approval requests.
#[derive(Debug, Clone, Default, Args)]
pub struct BrokerArgs {
    /// The gate's URL at an approval broker, e.g.
    /// https://api.example/v1/gates/<id>: a call refused as
    /// approval_required is filed there (in the background; only the
    /// manifest's approval.show values are sent), and finished approvals
    /// are fetched, verified against --approver-key and written to
    /// --approvals. Needs --approvals, --approver-key,
    /// --approvals-secret-file and a task context with a taskId.
    #[arg(long = "approvals-url", value_name = "URL")]
    pub url: Option<String>,
    /// HMAC secret (file) both directions are signed with, as webhooks are
    /// (the webhook secret file may be reused).
    #[arg(long = "approvals-secret-file", value_name = "FILE")]
    pub secret_file: Option<PathBuf>,
    /// How often finished approvals are fetched, e.g. 5s (default) or 1m.
    #[arg(long = "approvals-poll-interval", value_name = "DURATION")]
    pub poll_interval: Option<String>,
}

impl BrokerArgs {
    pub fn any(&self) -> bool {
        self.url.is_some() || self.secret_file.is_some() || self.poll_interval.is_some()
    }

    /// The broker configuration the flags ask for, checked; `Ok(None)`
    /// without `--approvals-url`.
    pub fn config(&self) -> Res<Option<BrokerConfig>> {
        let Some(url) = &self.url else {
            if self.secret_file.is_some() {
                return Err(usage("--approvals-secret-file needs --approvals-url (the broker it signs for)"));
            }
            if self.poll_interval.is_some() {
                return Err(usage("--approvals-poll-interval needs --approvals-url"));
            }
            return Ok(None);
        };
        let Some(secret_file) = &self.secret_file else {
            return Err(usage("--approvals-url needs --approvals-secret-file (requests to the broker are signed)"));
        };
        let mut cfg = broker_config(url, secret_file)?;
        if let Some(i) = &self.poll_interval {
            let secs = cloakpipe_release::v1::parse_duration(i)
                .map_err(|e| usage(format_args!("--approvals-poll-interval {i:?}: {e} (e.g. 5s, 1m)")))?;
            cfg.poll_interval = Duration::from_secs(secs);
        }
        Ok(Some(cfg))
    }
}

fn broker_config(url: &str, secret_file: &Path) -> Res<BrokerConfig> {
    match reqwest::Url::parse(url) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.query().is_none() => {}
        _ => return Err(usage(format_args!("--approvals-url {url:?}: expected an http:// or https:// URL without a query"))),
    }
    Ok(BrokerConfig::new(url, read_secret(secret_file)?))
}

/// Start the broker client for `gate` when `--approvals-url` is set: its
/// poller runs on a thread of its own from now on.
pub(crate) fn attach(args: &BrokerArgs, gate: Option<ToolGate>, events: &[Arc<dyn EventSink>]) -> Res<Option<ToolGate>> {
    let Some(cfg) = args.config()? else { return Ok(gate) };
    let Some(gate) = gate else { return Err(usage("--approvals-url needs --manifest (the release it is about)")) };
    let broker = ApprovalBroker::start(cfg, &gate, events.to_vec()).map_err(|e| usage(format_args!("--approvals-url: {e}")))?;
    eprintln!("cloakpipe: approval requests go to the broker; verified receipts are written to the approvals directory");
    Ok(Some(gate.with_broker(broker)))
}

/// The secret's bytes, without a trailing newline; empty is refused.
fn read_secret(path: &Path) -> Res<Vec<u8>> {
    let raw = std::fs::read(path).map_err(|e| usage(format_args!("cannot read {}: {e}", path.display())))?;
    let trimmed = raw.strip_suffix(b"\n").unwrap_or(&raw);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(usage(format_args!("{}: the approvals secret is empty", path.display())));
    }
    Ok(trimmed.to_vec())
}

#[derive(Subcommand)]
pub enum ApprovalsCommands {
    /// Fetch the broker's approver public keys and write each as an
    /// --approver-key file (<keyid>.approver.json)
    Keys(KeysArgs),
}

#[derive(Args)]
pub struct KeysArgs {
    /// The gate's URL at the broker (as for mcp-proxy)
    #[arg(long = "approvals-url", value_name = "URL")]
    pub url: String,
    /// HMAC secret file (as for mcp-proxy)
    #[arg(long = "approvals-secret-file", value_name = "FILE")]
    pub secret_file: PathBuf,
    /// Directory to write the key files into (created if missing)
    #[arg(long)]
    pub out: PathBuf,
}

pub fn run(cmd: ApprovalsCommands) -> i32 {
    match cmd {
        ApprovalsCommands::Keys(a) => finish(keys(&a)),
    }
}

fn keys(a: &KeysArgs) -> Res<i32> {
    let cfg = broker_config(&a.url, &a.secret_file)?;
    let listed = fetch_approver_keys(&cfg).map_err(|e| {
        eprintln!("error: the broker did not list its approver keys: {e}");
        EXIT_INVALID
    })?;
    // Every key checks out, or none is written.
    let mut files = Vec::new();
    for (id, public) in listed {
        let mut raw = [0u8; 32];
        if hex::decode_to_slice(public.trim(), &mut raw).is_err() {
            eprintln!("error: key {id:?}: publicKey is not a 32-byte hex Ed25519 key");
            return Err(EXIT_INVALID);
        }
        let expected = keyid(&raw);
        if id != expected {
            eprintln!("error: key {id:?}: the keyid is not the key's (expected {expected})");
            return Err(EXIT_INVALID);
        }
        let name = format!("{}.approver.json", expected.trim_start_matches("ed25519:"));
        let body = serde_json::json!({ "keyid": expected, "publicKey": hex::encode(raw) });
        files.push((name, expected, format!("{}\n", serde_json::to_string_pretty(&body).expect("serialisable"))));
    }
    std::fs::create_dir_all(&a.out).map_err(|e| usage(format_args!("cannot create {}: {e}", a.out.display())))?;
    for (name, id, body) in &files {
        let path = a.out.join(name);
        std::fs::write(&path, body).map_err(|e| usage(format_args!("cannot write {}: {e}", path.display())))?;
        println!("{id} {}", path.display());
    }
    if files.is_empty() {
        eprintln!("warning: the broker lists no approver keys");
    }
    Ok(EXIT_OK)
}
