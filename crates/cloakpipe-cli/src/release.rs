//! `cloakpipe release …` — Agent Release manifest tooling.
//!
//! Exit codes: 0 ok, 1 manifest invalid / not certifiable, 2 usage or I/O error.

use clap::Subcommand;
use cloakpipe_release::{diff, parse_path, AgentRelease, ChangeKind, ParseError};
use serde_json::json;
use std::path::{Path, PathBuf};

pub const EXIT_OK: i32 = 0;
pub const EXIT_INVALID: i32 = 1;
pub const EXIT_IO: i32 = 2;

#[derive(Subcommand)]
pub enum ReleaseCommands {
    /// Check that a manifest pins every component to an immutable version
    Validate { manifest: PathBuf },
    /// Print the canonical manifest hash (refuses uncertifiable manifests)
    Hash { manifest: PathBuf },
    /// Show material changes between two releases and the assurance they require
    Diff {
        baseline: PathBuf,
        candidate: PathBuf,
        /// Emit JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Summarise a release; with --json, emit its in-toto Statement
    Inspect {
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

pub fn run(cmd: ReleaseCommands) -> i32 {
    match cmd {
        ReleaseCommands::Validate { manifest } => validate(&manifest),
        ReleaseCommands::Hash { manifest } => hash(&manifest),
        ReleaseCommands::Diff { baseline, candidate, json } => diff_cmd(&baseline, &candidate, json),
        ReleaseCommands::Inspect { manifest, json } => inspect(&manifest, json),
    }
}

/// Load a manifest, reporting parse/I-O failures with the right exit code.
fn load(path: &Path) -> Result<AgentRelease, i32> {
    parse_path(path).map_err(|e| {
        eprintln!("error: {e}");
        match e {
            ParseError::Io(..) => EXIT_IO,
            _ => EXIT_INVALID,
        }
    })
}

/// Load and require a certifiable manifest; issues go to stderr.
fn load_valid(path: &Path) -> Result<AgentRelease, i32> {
    let r = load(path)?;
    let issues = r.validate();
    if issues.is_empty() {
        return Ok(r);
    }
    for i in &issues {
        eprintln!("error: {i}");
    }
    Err(EXIT_INVALID)
}

fn validate(path: &Path) -> i32 {
    let r = match load(path) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let issues = r.validate();
    if issues.is_empty() {
        println!("valid  {}  {}@{}", r.manifest_hash(), r.metadata.agent, r.metadata.version);
        return EXIT_OK;
    }
    println!("invalid: {} issue(s)", issues.len());
    for i in &issues {
        println!("  {i}");
    }
    EXIT_INVALID
}

fn hash(path: &Path) -> i32 {
    match load_valid(path) {
        Ok(r) => {
            println!("{}", r.manifest_hash());
            EXIT_OK
        }
        Err(code) => code,
    }
}

fn diff_cmd(baseline: &Path, candidate: &Path, as_json: bool) -> i32 {
    let (a, b) = match (load(baseline), load(candidate)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let d = diff(&a, &b);

    if as_json {
        let changes: Vec<_> = d
            .changes
            .iter()
            .map(|c| json!({
                "component": c.component.as_str(),
                "kind": c.kind.as_str(),
                "name": c.name,
                "before": c.before,
                "after": c.after,
            }))
            .collect();
        let out = json!({
            "baseline": a.manifest_hash().to_string(),
            "candidate": b.manifest_hash().to_string(),
            "comparable": d.comparable,
            "same_hash": d.same_hash,
            "changes": changes,
            "required_suites": d.required_suites.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "requires_approval": d.requires_approval,
        });
        println!("{}", serde_json::to_string_pretty(&out).expect("serialisable"));
        return EXIT_OK;
    }

    println!("baseline   {}  {}@{}", a.manifest_hash(), a.metadata.agent, a.metadata.version);
    println!("candidate  {}  {}@{}", b.manifest_hash(), b.metadata.agent, b.metadata.version);
    if !d.comparable {
        println!("warning: releases belong to different agents; changes are not an upgrade path");
    }
    if d.changes.is_empty() {
        println!("\nno material changes");
        return EXIT_OK;
    }
    println!("\nchanges:");
    for c in &d.changes {
        let detail = match (c.kind, &c.before, &c.after) {
            (ChangeKind::Added, _, Some(after)) => after.clone(),
            (ChangeKind::Removed, Some(before), _) => before.clone(),
            (_, before, after) => format!(
                "{} -> {}",
                before.as_deref().unwrap_or("-"),
                after.as_deref().unwrap_or("-")
            ),
        };
        println!("  {:<8} {:<12} {}", c.kind.as_str(), c.component.as_str(), detail);
    }
    println!("\nrequired assurance:");
    for s in &d.required_suites {
        println!("  - {}", s.as_str());
    }
    if d.requires_approval {
        println!("\napproval required: change expands or alters tool, MCP or policy authority");
    }
    EXIT_OK
}

fn inspect(path: &Path, as_json: bool) -> i32 {
    let r = match load(path) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if as_json {
        println!("{}", serde_json::to_string_pretty(&r.intoto_statement()).expect("serialisable"));
        return EXIT_OK;
    }
    let s = &r.spec;
    let refs = |v: &[cloakpipe_release::ArtifactRef]| {
        v.iter().map(|x| x.reference.as_str()).collect::<Vec<_>>().join(", ")
    };
    println!("agent       {}@{}", r.metadata.agent, r.metadata.version);
    println!("hash        {}", r.manifest_hash());
    println!("code        {}@{}", s.code.repository, s.code.commit);
    println!("prompts     {}", refs(&s.prompts));
    println!("model       {}", s.model.reference);
    println!("parameters  {}", s.parameters.len());
    println!("tools       {} [{}]", s.tools.len(), refs(&s.tools));
    println!("mcpServers  {} [{}]", s.mcp_servers.len(), refs(&s.mcp_servers));
    println!("retrieval   {}", s.retrieval.as_ref().map_or("-", |x| x.reference.as_str()));
    println!("policies    {}", refs(&s.policies));
    println!("runtime     {} ({})", s.runtime.image, s.runtime.region);
    let issues = r.validate();
    if issues.is_empty() {
        println!("certifiable yes");
    } else {
        println!("certifiable no ({} issue(s); run `cloakpipe release validate`)", issues.len());
    }
    EXIT_OK
}
