//! `cloakpipe tools pin|diff`: pin the upstream MCP servers' tool
//! definitions in `cloakpipe.tools.lock`, and show what changed since
//! (`mcp-proxy --tools-lock` hides and refuses a tool that drifted).
//!
//! Also the upstream flags `mcp-proxy` shares with them: `--upstream
//! COMMAND` (the server named `default`) and `--server NAME=COMMAND`
//! (repeatable).
//!
//! Exit codes follow `release`: 0 ok (`diff`: no changes), 1 refused
//! (`diff`: tools changed; `pin`: a tool name collision the manifest does
//! not resolve), 2 usage or I/O error (a server that does not start).

use crate::keys::{invalid, read, usage, Res};
use crate::manifest::{kind, load_v1};
use crate::release::{EXIT_INVALID, EXIT_OK};
use clap::{Args, Subcommand};
use cloakpipe_mcp::servers::{check_server_name, collisions, list_servers, DISCOVERY_TIMEOUT};
use cloakpipe_mcp::tools_lock::ToolsLock;
use cloakpipe_mcp::{ServerTools, Upstream, DEFAULT_SERVER};
use cloakpipe_release::v1::ManifestKind;
use std::path::{Path, PathBuf};

/// The default lock file name.
pub const DEFAULT_LOCK: &str = "cloakpipe.tools.lock";

#[derive(Subcommand)]
pub enum ToolsCommands {
    /// Start the MCP servers, list their tools, and pin each tool's definition in a lock file
    Pin(PinArgs),
    /// Show how tools differ from a lock: as the servers list them now, or in another lock
    Diff(DiffArgs),
}

/// The upstream MCP servers.
#[derive(Debug, Args)]
pub struct ServerArgs {
    /// Upstream MCP server command + args: the server named `default`
    #[arg(long)]
    pub upstream: Option<String>,
    /// An upstream MCP server as NAME=COMMAND (repeatable), e.g.
    /// --server 'mail=npx -y @acme/mail-mcp'. Names: letters, digits, '-'
    /// and '_', without '__'.
    #[arg(long = "server", value_name = "NAME=COMMAND")]
    pub servers: Vec<String>,
}

impl ServerArgs {
    fn any(&self) -> bool {
        self.upstream.is_some() || !self.servers.is_empty()
    }
}

#[derive(Args)]
pub struct PinArgs {
    #[command(flatten)]
    pub servers: ServerArgs,
    /// Manifest the gate will run under (cloakpipe.manifest.yaml): a tool
    /// name two servers share must be declared per server (<server>__<tool>)
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Where to write the lock
    #[arg(long, default_value = DEFAULT_LOCK)]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct DiffArgs {
    /// The lock to compare against
    #[arg(long, default_value = DEFAULT_LOCK)]
    pub lock: PathBuf,
    /// Compare with this lock instead of starting the servers
    #[arg(long, conflicts_with_all = ["upstream", "servers"])]
    pub against: Option<PathBuf>,
    #[command(flatten)]
    pub servers: ServerArgs,
}

pub fn run(cmd: ToolsCommands) -> i32 {
    match cmd {
        ToolsCommands::Pin(a) => pin(a).unwrap_or_else(|c| c),
        ToolsCommands::Diff(a) => diff(a).unwrap_or_else(|c| c),
    }
}

/// `--upstream` and `--server`, checked: each a command, each name valid
/// and given once (`default` is `--upstream`'s).
pub(crate) fn upstreams(upstream: Option<&str>, servers: &[String]) -> Res<Vec<Upstream>> {
    let mut out: Vec<Upstream> = Vec::new();
    if let Some(command) = upstream {
        out.push(Upstream::stdio(DEFAULT_SERVER, command_words("--upstream", command)?));
    }
    for spec in servers {
        let Some((name, command)) = spec.split_once('=') else {
            return Err(usage(format_args!("--server {spec:?}: expected NAME=COMMAND")));
        };
        let name = name.trim();
        check_server_name(name).map_err(|e| usage(format_args!("--server: {e}")))?;
        if out.iter().any(|u| u.name == name) {
            let also = if name == DEFAULT_SERVER && upstream.is_some() { " (--upstream is the server named default)" } else { "" };
            return Err(usage(format_args!("--server: {name} is given twice{also}")));
        }
        out.push(Upstream::stdio(name, command_words(&format!("--server {name}"), command)?));
    }
    if out.is_empty() {
        return Err(usage("give the upstream MCP server: --upstream COMMAND or --server NAME=COMMAND"));
    }
    Ok(out)
}

fn command_words(flag: &str, command: &str) -> Res<Vec<String>> {
    let words = shell_words::split(command).map_err(|e| usage(format_args!("{flag}: cannot parse the command {command:?}: {e}")))?;
    if words.is_empty() {
        return Err(usage(format_args!("{flag}: the command is empty")));
    }
    Ok(words)
}

/// Read a lock (`--tools-lock`, `tools diff --lock`).
pub(crate) fn load_lock(flag: &str, path: &Path) -> Res<ToolsLock> {
    let text = read(path)?;
    ToolsLock::parse(&text).map_err(|e| usage(format_args!("{flag} {}: {e}", path.display())))
}

fn list(servers: &ServerArgs) -> Res<Vec<ServerTools>> {
    let upstreams = upstreams(servers.upstream.as_deref(), &servers.servers)?;
    list_servers(&upstreams, DISCOVERY_TIMEOUT).map_err(|e| usage(format_args!("{e:#}")))
}

fn pin(a: PinArgs) -> Res<i32> {
    let declared = match &a.manifest {
        None => None,
        Some(path) => match kind(path)? {
            ManifestKind::V1 => Some(load_v1(path)?.tools().keys().cloned().collect::<std::collections::BTreeSet<String>>()),
            ManifestKind::Legacy => return Err(usage(format_args!("--manifest {}: tools pin takes a v1 manifest", path.display()))),
        },
    };
    let listing = list(&a.servers)?;
    let declares = |tool: &str| declared.as_ref().is_some_and(|d| d.contains(tool));
    let (_, refused) = collisions(&listing, &declares);
    for c in &refused {
        if declared.is_some() {
            eprintln!("error: tool name collision: {c}");
        } else {
            eprintln!("warning: tool name collision: {c} (mcp-proxy refuses to start on it)");
        }
    }
    if declared.is_some() && !refused.is_empty() {
        return Err(invalid("the gate would refuse to start on these servers"));
    }
    let lock = ToolsLock::from_servers(&listing);
    std::fs::write(&a.out, lock.to_json_string()).map_err(|e| usage(format_args!("cannot write {}: {e}", a.out.display())))?;
    let servers = listing.len();
    println!(
        "pinned {} tool{} from {servers} server{} to {} ({})",
        lock.tool_count(),
        if lock.tool_count() == 1 { "" } else { "s" },
        if servers == 1 { "" } else { "s" },
        a.out.display(),
        lock.digest()
    );
    Ok(EXIT_OK)
}

fn diff(a: DiffArgs) -> Res<i32> {
    let pinned = load_lock("--lock", &a.lock)?;
    let (now, label) = match &a.against {
        Some(path) => (load_lock("--against", path)?, path.display().to_string()),
        None if a.servers.any() => (ToolsLock::from_servers(&list(&a.servers)?), "the servers now".to_string()),
        None => return Err(usage("compare the lock with the servers (--upstream / --server) or with another lock (--against)")),
    };
    println!("lock     {}  {}", pinned.digest(), a.lock.display());
    println!("against  {}  {label}", now.digest());
    let changes = pinned.diff(&now);
    if changes.is_empty() {
        println!("\nno changes");
        return Ok(EXIT_OK);
    }
    println!();
    for c in &changes {
        let detail = match (&c.before, &c.after) {
            (Some(b), Some(a)) => format!("{b} -> {a}"),
            (None, Some(a)) => format!("{a} (not pinned)"),
            (Some(b), None) => b.clone(),
            (None, None) => String::new(),
        };
        println!("  {:<8} {}/{}  {detail}", c.kind.as_str(), c.server, c.tool);
    }
    println!("\n{} tool{} changed: pin again (cloakpipe tools pin) once reviewed", changes.len(), if changes.len() == 1 { "" } else { "s" });
    Ok(EXIT_INVALID)
}
