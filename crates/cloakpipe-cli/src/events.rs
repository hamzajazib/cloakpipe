//! Gate event delivery on the command line: the `mcp-proxy` flags
//! (`--events-log`, `--webhook`, `--webhook-secret-file`, `--webhook-format`,
//! `--otel-endpoint`, `--otel`) and `cloakpipe events test |
//! verify-signature` (docs: `cloakpipe_mcp::events::webhook`).
//!
//! Delivery is best effort and off the decision path: a dead endpoint never
//! delays or changes a decision. Payloads carry no argument values.
//!
//! Exit codes follow `release`: 0 ok, 1 not delivered / signature invalid,
//! 2 usage or I/O error.

use crate::keys::{finish, usage, Res};
use crate::release::{EXIT_INVALID, EXIT_OK};
use clap::{Args, Subcommand};
use cloakpipe_ledger::decision::{Decision, Mode};
use cloakpipe_mcp::events::webhook;
use cloakpipe_mcp::{EventKind, EventSink, GateEvent, JsonlSink, OtelConfig, OtelSink, WebhookConfig, WebhookFormat, WebhookSink};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const FORMATS: [&str; 3] = ["generic", "slack", "discord"];

/// Where `mcp-proxy` sends gate events.
#[derive(Debug, Clone, Default, Args)]
pub struct EventArgs {
    /// Append every gate event (decision.deny, approval.requested, ...) to
    /// this JSONL file, one `cloakpipe.event/v1` object per line.
    #[arg(long = "events-log", value_name = "PATH")]
    pub events_log: Option<PathBuf>,
    /// POST every gate event to this URL (repeatable). Off the decision
    /// path: queued, 3 tries, 5 s timeout; a dead endpoint never delays or
    /// changes a decision.
    #[arg(long = "webhook", value_name = "URL")]
    pub webhooks: Vec<String>,
    /// HMAC-SHA256 secret (file) the webhooks are signed with:
    /// `CloakPipe-Signature: t=<unix>,v1=hex(HMAC(secret, "<t>.<body>"))`.
    #[arg(long = "webhook-secret-file", value_name = "FILE")]
    pub webhook_secret_file: Option<PathBuf>,
    /// Webhook payload: generic (the event JSON, default), slack (Block Kit,
    /// for a Slack incoming webhook) or discord (an embed).
    #[arg(long = "webhook-format", value_parser = FORMATS)]
    pub webhook_format: Option<String>,
    /// OTLP/HTTP collector (e.g. http://localhost:4318): one
    /// `cloakpipe.decision` span per tool-call decision, allows included,
    /// to <URL>/v1/traces.
    #[arg(long = "otel-endpoint", value_name = "URL")]
    pub otel_endpoint: Option<String>,
    /// Export spans to $OTEL_EXPORTER_OTLP_ENDPOINT (the variable alone
    /// exports nothing).
    #[arg(long, conflicts_with = "otel_endpoint")]
    pub otel: bool,
}

impl EventArgs {
    /// Whether any event flag is set.
    pub fn any(&self) -> bool {
        self.events_log.is_some()
            || !self.webhooks.is_empty()
            || self.webhook_secret_file.is_some()
            || self.webhook_format.is_some()
            || self.otel_endpoint.is_some()
            || self.otel
    }

    /// The sinks the flags ask for, checked: a bad flag fails here, before
    /// anything starts.
    pub fn sinks(&self) -> Res<Vec<Arc<dyn EventSink>>> {
        let mut sinks: Vec<Arc<dyn EventSink>> = Vec::new();
        if self.webhooks.is_empty() {
            if self.webhook_secret_file.is_some() {
                return Err(usage("--webhook-secret-file needs --webhook (the endpoint it signs for)"));
            }
            if self.webhook_format.is_some() {
                return Err(usage("--webhook-format needs --webhook"));
            }
        }
        if let Some(path) = &self.events_log {
            let sink = JsonlSink::open(path).map_err(|e| usage(format_args!("--events-log {}: {e}", path.display())))?;
            sinks.push(Arc::new(sink));
        }
        let format = self.format();
        let secret = self.webhook_secret_file.as_deref().map(read_secret).transpose()?;
        if !self.webhooks.is_empty() && secret.is_none() && format == WebhookFormat::Generic {
            eprintln!("warning: --webhook without --webhook-secret-file: payloads are unsigned");
        }
        for url in &self.webhooks {
            http_url("--webhook", url)?;
            let mut cfg = WebhookConfig::new(url);
            cfg.secret = secret.clone();
            cfg.format = format;
            sinks.push(Arc::new(WebhookSink::new(cfg)));
        }
        let endpoint = match (&self.otel_endpoint, self.otel) {
            (Some(url), _) => Some(url.clone()),
            (None, true) => match std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
                Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
                _ => return Err(usage("--otel needs OTEL_EXPORTER_OTLP_ENDPOINT (or pass --otel-endpoint URL)")),
            },
            (None, false) => None,
        };
        if let Some(url) = endpoint {
            http_url("--otel-endpoint", &url)?;
            let cfg = OtelConfig::new(&url);
            eprintln!("cloakpipe: exporting a span per decision to {}", cfg.url);
            sinks.push(Arc::new(OtelSink::new(cfg)));
        }
        Ok(sinks)
    }

    fn format(&self) -> WebhookFormat {
        self.webhook_format.as_deref().and_then(|f| f.parse().ok()).unwrap_or_default()
    }
}

/// The secret's bytes, without a trailing newline; empty is refused.
fn read_secret(path: &Path) -> Res<Vec<u8>> {
    let raw = std::fs::read(path).map_err(|e| usage(format_args!("cannot read {}: {e}", path.display())))?;
    let trimmed = raw.strip_suffix(b"\n").unwrap_or(&raw);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(usage(format_args!("{}: the webhook secret is empty", path.display())));
    }
    Ok(trimmed.to_vec())
}

fn http_url(flag: &str, url: &str) -> Res<()> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(())
    } else {
        Err(usage(format_args!("{flag} {url:?}: expected an http:// or https:// URL")))
    }
}

/// `anchor.failed`: anchoring an epoch of the ledger failed (`reason` is
/// the anchor kind, `rfc3161` or `rekor`; `ledger_seq` the epoch's last
/// entry). The error text is not in the event: stderr has it.
pub fn anchor_failed(release: &ReleaseInfo, kind: &str, last_seq: u64) -> GateEvent {
    let mut e = GateEvent::new(EventKind::AnchorFailed, kind, None, None, release.policy_digest.as_deref());
    e.release = Some(release.name.clone());
    e.release_digest = Some(release.digest.clone());
    e.ledger_seq = Some(last_seq);
    e
}

/// What an event names of the release the gate runs.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub name: String,
    pub digest: String,
    pub policy_digest: Option<String>,
}

#[derive(Subcommand)]
pub enum EventsCommands {
    /// Send a sample decision.deny event to a webhook (check Slack/Discord wiring)
    Test(TestArgs),
    /// Check a CloakPipe-Signature header against a webhook body
    VerifySignature(VerifySignatureArgs),
}

#[derive(Args)]
pub struct TestArgs {
    /// The webhook URL
    #[arg(long)]
    pub webhook: String,
    /// HMAC secret file (as for mcp-proxy)
    #[arg(long = "webhook-secret-file", value_name = "FILE")]
    pub webhook_secret_file: Option<PathBuf>,
    /// generic, slack or discord
    #[arg(long = "webhook-format", value_parser = FORMATS, default_value = "generic")]
    pub webhook_format: String,
}

#[derive(Args)]
pub struct VerifySignatureArgs {
    /// The HMAC secret file the sender signs with
    #[arg(long = "secret-file", value_name = "FILE")]
    pub secret_file: PathBuf,
    /// The CloakPipe-Signature header value (t=<unix>,v1=<hex>)
    #[arg(long)]
    pub header: String,
    /// The raw request body, byte for byte
    #[arg(long = "body-file", value_name = "FILE")]
    pub body_file: PathBuf,
    /// Reject a timestamp more than this many seconds from now (0: no check)
    #[arg(long, default_value_t = 300)]
    pub tolerance: u64,
}

pub fn run(cmd: EventsCommands) -> i32 {
    finish(match cmd {
        EventsCommands::Test(a) => test(&a),
        EventsCommands::VerifySignature(a) => verify(&a),
    })
}

fn test(a: &TestArgs) -> Res<i32> {
    http_url("--webhook", &a.webhook)?;
    let mut cfg = WebhookConfig::new(&a.webhook);
    cfg.secret = a.webhook_secret_file.as_deref().map(read_secret).transpose()?;
    cfg.format = a.webhook_format.parse().map_err(usage)?;
    let mut event = GateEvent::new(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("/to"), None);
    event.release = Some("cloakpipe-events-test".into());
    event.decision = Some(Decision::Deny);
    event.mode = Some(Mode::Enforce);
    match webhook::deliver(&cfg, &event) {
        Ok(status) => {
            println!("delivered a sample {} event to {} (HTTP {status})", event.kind, a.webhook);
            Ok(EXIT_OK)
        }
        Err(e) => {
            eprintln!("error: not delivered to {}: {e}", a.webhook);
            Ok(EXIT_INVALID)
        }
    }
}

fn verify(a: &VerifySignatureArgs) -> Res<i32> {
    let secret = read_secret(&a.secret_file)?;
    let body = std::fs::read(&a.body_file).map_err(|e| usage(format_args!("cannot read {}: {e}", a.body_file.display())))?;
    let tolerance = (a.tolerance > 0).then_some(a.tolerance);
    match webhook::verify_signature(&secret, &a.header, &body, chrono::Utc::now().timestamp(), tolerance) {
        Ok(()) => {
            println!("signature ok");
            Ok(EXIT_OK)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Ok(EXIT_INVALID)
        }
    }
}
