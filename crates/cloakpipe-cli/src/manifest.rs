//! `cloakpipe manifest validate|hash` and the manifest loader shared by the
//! commands that take `--manifest`.
//!
//! A file with a top-level `release` key is a single-file v1 manifest
//! (`cloakpipe.manifest.yaml`, [`cloakpipe_release::v1`]); one with
//! `apiVersion` is a legacy AgentRelease, still accepted for one release
//! with a deprecation warning on stderr.
//!
//! Exit codes follow `release`: 0 ok, 1 invalid manifest, 2 usage or I/O.

use crate::keys::{finish, invalid, read, usage, Res};
use crate::release::{load, EXIT_OK};
use clap::Subcommand;
use cloakpipe_release::v1::{self, Manifest, ManifestError, ManifestKind};
use cloakpipe_release::{AgentRelease, ReleaseHash, Reference};
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum ManifestCommands {
    /// Check a manifest (cloakpipe.manifest.yaml) loads: every tool rule,
    /// pattern, template and condition, and the policy file it references
    Validate {
        /// The manifest file
        file: PathBuf,
    },
    /// Print the manifest digest (sha256 over the JCS form)
    Hash {
        /// The manifest file
        file: PathBuf,
        /// Print {release, version, manifest_digest, policy_digest} as JSON
        #[arg(long)]
        json: bool,
    },
}

/// A manifest in either format.
pub(crate) enum Loaded {
    V1(Manifest),
    /// Deprecated.
    Legacy(Box<AgentRelease>),
}

impl Loaded {
    /// The release identity fingerprints and approvals bind to.
    pub(crate) fn digest(&self) -> ReleaseHash {
        match self {
            Loaded::V1(m) => m.digest(),
            Loaded::Legacy(r) => r.manifest_hash(),
        }
    }

    /// Whether the manifest declares `tool`.
    pub(crate) fn declares(&self, tool: &str) -> bool {
        match self {
            Loaded::V1(m) => m.rule(tool).is_some(),
            Loaded::Legacy(r) => r.spec.tools.iter().filter_map(|t| Reference::parse(&t.reference).ok()).any(|t| t.name == tool),
        }
    }
}

/// Which format `path` is in, reading it once. Problems go to stderr.
pub(crate) fn kind(path: &Path) -> Res<ManifestKind> {
    let src = read(path)?;
    v1::detect(&src).map_err(|e| invalid(format_args!("{}: {e}", path.display())))
}

/// The deprecation warning for a legacy manifest.
pub(crate) fn warn_legacy(path: &Path) {
    eprintln!(
        "warning: {}: the AgentRelease + ToolContract format is deprecated and will be removed in the next release; \
         move to a single cloakpipe.manifest.yaml (top-level release, version, policy, tools)",
        path.display()
    );
}

/// Load a v1 manifest. Problems go to stderr.
pub(crate) fn load_v1(path: &Path) -> Res<Manifest> {
    Manifest::parse_path(path).map_err(|e| match e {
        ManifestError::Io(..) => usage(&e),
        _ => invalid(format_args!("{}: {e}", path.display())),
    })
}

/// Load a manifest in either format (a legacy one with a deprecation
/// warning). Problems go to stderr.
pub(crate) fn load_any(path: &Path) -> Res<Loaded> {
    match kind(path)? {
        ManifestKind::V1 => load_v1(path).map(Loaded::V1),
        ManifestKind::Legacy => {
            warn_legacy(path);
            load(path).map(|r| Loaded::Legacy(Box::new(r)))
        }
    }
}

pub fn run(cmd: ManifestCommands) -> i32 {
    match cmd {
        ManifestCommands::Validate { file } => finish(validate(&file)),
        ManifestCommands::Hash { file, json } => finish(hash(&file, json)),
    }
}

fn validate(path: &Path) -> Res<i32> {
    match load_any(path)? {
        Loaded::V1(m) => {
            println!("valid  {}  {}@{}  {} tools", m.digest(), m.release, m.version, m.tools().len());
            if let Some(p) = &m.policy {
                println!("policy {}  {}", p.digest, p.declared);
            }
        }
        Loaded::Legacy(r) => {
            let issues = r.gate_issues();
            if !issues.is_empty() {
                for i in &issues {
                    eprintln!("error: {}: {i}", path.display());
                }
                return Err(invalid("the tool gate cannot run on this release"));
            }
            println!("valid  {}  {}@{}  (legacy AgentRelease)", r.manifest_hash(), r.metadata.agent, r.metadata.version);
        }
    }
    Ok(EXIT_OK)
}

fn hash(path: &Path, as_json: bool) -> Res<i32> {
    let loaded = load_any(path)?;
    if !as_json {
        println!("{}", loaded.digest());
        return Ok(EXIT_OK);
    }
    let report = match &loaded {
        Loaded::V1(m) => json!({
            "release": m.release,
            "version": m.version,
            "manifest_digest": m.digest().to_string(),
            "policy_digest": m.policy_digest().map(|d| d.to_string()),
        }),
        Loaded::Legacy(r) => json!({
            "release": r.metadata.agent,
            "version": r.metadata.version,
            "manifest_digest": r.manifest_hash().to_string(),
            "policy_digest": null,
        }),
    };
    println!("{}", serde_json::to_string_pretty(&report).expect("serialisable"));
    Ok(EXIT_OK)
}
