//! Material-change diff and required assurance.
//!
//! Each changed component maps to the minimum assurance it needs before the
//! candidate can be certified (master doc §6, "Change to required assurance").
//! The diff runs over the canonical view, so non-material differences (key
//! order, set order, release number, labels) never show up as changes.

use crate::manifest::AgentRelease;
use crate::reference::key_of;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    Code,
    Prompt,
    Model,
    Parameters,
    Tool,
    McpServer,
    Retrieval,
    Policy,
    Runtime,
    Dependency,
    FeatureFlag,
}

impl Component {
    pub fn as_str(self) -> &'static str {
        match self {
            Component::Code => "code",
            Component::Prompt => "prompt",
            Component::Model => "model",
            Component::Parameters => "parameters",
            Component::Tool => "tool",
            Component::McpServer => "mcp_server",
            Component::Retrieval => "retrieval",
            Component::Policy => "policy",
            Component::Runtime => "runtime",
            Component::Dependency => "dependency",
            Component::FeatureFlag => "feature_flag",
        }
    }

    /// Minimum assurance suites for a change to this component.
    pub fn required_suites(self) -> &'static [Suite] {
        use Suite::*;
        match self {
            Component::Prompt => &[PromptContract, Functional, Safety, Privacy, Regression],
            Component::Model => &[Functional, ToolUse, Safety, Privacy, Regression, Performance, Cost],
            Component::Parameters => &[Functional, Regression, Performance, Cost],
            Component::Tool => &[Trajectory, Authorization, SideEffect, Regression],
            Component::McpServer => &[PublisherTrust, CapabilityDiff, Authorization, Adversarial, Regression],
            Component::Retrieval => &[Grounding, AccessControl, Freshness, Representative],
            Component::Policy => &[PolicyStaticAnalysis, DecisionReplay],
            Component::Code | Component::Runtime | Component::Dependency | Component::FeatureFlag => {
                &[Functional, Regression]
            }
        }
    }

    /// Changes that expand or alter authority need a human approval.
    pub fn requires_approval(self) -> bool {
        matches!(self, Component::Tool | Component::McpServer | Component::Policy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Changed => "changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub component: Component,
    pub kind: ChangeKind,
    /// What changed within the component: a `kind:name` key, a parameter
    /// name, or a field such as `commit`.
    pub name: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Suite {
    PromptContract,
    Functional,
    Regression,
    Safety,
    Privacy,
    ToolUse,
    Performance,
    Cost,
    Trajectory,
    Authorization,
    SideEffect,
    PublisherTrust,
    CapabilityDiff,
    Adversarial,
    Grounding,
    AccessControl,
    Freshness,
    Representative,
    PolicyStaticAnalysis,
    DecisionReplay,
}

impl Suite {
    pub const ALL: &'static [Suite] = &[
        Suite::PromptContract,
        Suite::Functional,
        Suite::Regression,
        Suite::Safety,
        Suite::Privacy,
        Suite::ToolUse,
        Suite::Performance,
        Suite::Cost,
        Suite::Trajectory,
        Suite::Authorization,
        Suite::SideEffect,
        Suite::PublisherTrust,
        Suite::CapabilityDiff,
        Suite::Adversarial,
        Suite::Grounding,
        Suite::AccessControl,
        Suite::Freshness,
        Suite::Representative,
        Suite::PolicyStaticAnalysis,
        Suite::DecisionReplay,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Suite::PromptContract => "prompt_contract",
            Suite::Functional => "functional",
            Suite::Regression => "regression",
            Suite::Safety => "safety",
            Suite::Privacy => "privacy",
            Suite::ToolUse => "tool_use",
            Suite::Performance => "performance",
            Suite::Cost => "cost",
            Suite::Trajectory => "trajectory",
            Suite::Authorization => "authorization",
            Suite::SideEffect => "side_effect",
            Suite::PublisherTrust => "publisher_trust",
            Suite::CapabilityDiff => "capability_diff",
            Suite::Adversarial => "adversarial",
            Suite::Grounding => "grounding",
            Suite::AccessControl => "access_control",
            Suite::Freshness => "freshness",
            Suite::Representative => "representative",
            Suite::PolicyStaticAnalysis => "policy_static_analysis",
            Suite::DecisionReplay => "decision_replay",
        }
    }
}

impl std::str::FromStr for Suite {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Suite::ALL
            .iter()
            .copied()
            .find(|suite| suite.as_str() == s)
            .ok_or_else(|| format!("unknown assurance suite {s:?}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseDiff {
    /// False when the two manifests describe different agents (or API
    /// versions); the change list is still populated but not meaningful as an
    /// upgrade path.
    pub comparable: bool,
    pub same_hash: bool,
    pub changes: Vec<Change>,
    pub required_suites: BTreeSet<Suite>,
    pub requires_approval: bool,
}

pub fn diff(baseline: &AgentRelease, candidate: &AgentRelease) -> ReleaseDiff {
    let a = baseline.canonical_view();
    let b = candidate.canonical_view();
    let (sa, sb) = (&a["spec"], &b["spec"]);
    let mut changes = Vec::new();

    for field in ["repository", "commit"] {
        scalar(&mut changes, Component::Code, field, &sa["code"][field], &sb["code"][field]);
    }
    prompts(&mut changes, &sa["prompts"], &sb["prompts"]);
    scalar(&mut changes, Component::Model, "model", &sa["model"], &sb["model"]);
    map(&mut changes, Component::Parameters, &sa["parameters"], &sb["parameters"]);
    ref_set(&mut changes, Component::Tool, &sa["tools"], &sb["tools"]);
    ref_set(&mut changes, Component::McpServer, &sa["mcpServers"], &sb["mcpServers"]);
    scalar(&mut changes, Component::Retrieval, "retrieval", &sa["retrieval"], &sb["retrieval"]);
    ref_set(&mut changes, Component::Policy, &sa["policies"], &sb["policies"]);
    for field in ["image", "region"] {
        scalar(&mut changes, Component::Runtime, field, &sa["runtime"][field], &sb["runtime"][field]);
    }
    dependencies(&mut changes, &sa["dependencies"], &sb["dependencies"]);
    map(&mut changes, Component::FeatureFlag, &sa["featureFlags"], &sb["featureFlags"]);

    let required_suites = changes.iter().flat_map(|c| c.component.required_suites().iter().copied()).collect();
    let requires_approval = changes.iter().any(|c| c.component.requires_approval());

    ReleaseDiff {
        comparable: a["agent"] == b["agent"] && same_format(&baseline.api_version, &candidate.api_version),
        same_hash: baseline.manifest_hash() == candidate.manifest_hash(),
        changes,
        required_suites,
        requires_approval,
    }
}

/// The same format version: equal `apiVersion`s, or one supported version
/// spelled in either namespace (`cloakpipe.co` / legacy `cloakpipe.dev`).
fn same_format(a: &str, b: &str) -> bool {
    a == b || (crate::namespace::is_known_api_version(a) && crate::namespace::is_known_api_version(b))
}

fn render(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn push(out: &mut Vec<Change>, component: Component, name: &str, before: Option<String>, after: Option<String>) {
    let kind = match (&before, &after) {
        (None, Some(_)) => ChangeKind::Added,
        (Some(_), None) => ChangeKind::Removed,
        _ => ChangeKind::Changed,
    };
    out.push(Change { component, kind, name: name.to_string(), before, after });
}

fn scalar(out: &mut Vec<Change>, component: Component, name: &str, a: &Value, b: &Value) {
    if a != b {
        push(out, component, name, render(a), render(b));
    }
}

fn map(out: &mut Vec<Change>, component: Component, a: &Value, b: &Value) {
    let empty = serde_json::Map::new();
    let (a, b) = (a.as_object().unwrap_or(&empty), b.as_object().unwrap_or(&empty));
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    for k in keys {
        let (va, vb) = (a.get(k).unwrap_or(&Value::Null), b.get(k).unwrap_or(&Value::Null));
        scalar(out, component, k, va, vb);
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// Unordered references, matched on `kind:name` so a version bump is one
/// `Changed` rather than a `Removed` + `Added` pair.
fn ref_set(out: &mut Vec<Change>, component: Component, a: &Value, b: &Value) {
    let index = |v: &Value| -> BTreeMap<String, String> { strings(v).into_iter().map(|r| (key_of(&r), r)).collect() };
    let (ia, ib) = (index(a), index(b));
    let keys: BTreeSet<&String> = ia.keys().chain(ib.keys()).collect();
    for k in keys {
        let (ra, rb) = (ia.get(k).cloned(), ib.get(k).cloned());
        if ra != rb {
            push(out, component, k, ra, rb);
        }
    }
}

/// Prompts are ordered: report per-prompt changes, plus a reorder if the same
/// prompts appear in a different sequence.
fn prompts(out: &mut Vec<Change>, a: &Value, b: &Value) {
    let before = out.len();
    ref_set(out, Component::Prompt, a, b);
    if out.len() == before {
        let (ka, kb): (Vec<_>, Vec<_>) = (strings(a), strings(b));
        if ka != kb {
            push(out, Component::Prompt, "order", Some(ka.join(",")), Some(kb.join(",")));
        }
    }
}

fn dependencies(out: &mut Vec<Change>, a: &Value, b: &Value) {
    let index = |v: &Value| -> BTreeMap<String, String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| Some((d["name"].as_str()?.to_string(), d["version"].as_str()?.to_string())))
            .collect()
    };
    let (ia, ib) = (index(a), index(b));
    let keys: BTreeSet<&String> = ia.keys().chain(ib.keys()).collect();
    for k in keys {
        let (va, vb) = (ia.get(k).cloned(), ib.get(k).cloned());
        if va != vb {
            push(out, Component::Dependency, k, va, vb);
        }
    }
}
