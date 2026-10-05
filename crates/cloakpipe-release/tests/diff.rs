//! Material-change diff and impact-based assurance selection (master doc §6,
//! "Change to required assurance").

use cloakpipe_release::{diff, parse_path, parse_str, ChangeKind, Component, Format, Suite};
use serde_json::{json, Value};
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn base_json() -> Value {
    serde_json::from_str(&std::fs::read_to_string(testdata("support-agent-184.json")).unwrap()).unwrap()
}

fn rel(v: &Value) -> cloakpipe_release::AgentRelease {
    parse_str(&v.to_string(), Format::Json).unwrap()
}

#[test]
fn identical_releases_have_no_changes() {
    let a = parse_path(&testdata("support-agent-184.yaml")).unwrap();
    let b = parse_path(&testdata("support-agent-184.json")).unwrap();
    let d = diff(&a, &b);
    assert!(d.changes.is_empty());
    assert!(d.required_suites.is_empty());
    assert!(d.same_hash);
}

#[test]
fn prompt_change_and_tool_addition_are_reported() {
    let a = parse_path(&testdata("support-agent-184.yaml")).unwrap();
    let b = parse_path(&testdata("support-agent-185.yaml")).unwrap();
    let d = diff(&a, &b);
    assert!(!d.same_hash);

    let prompt = d.changes.iter().find(|c| c.component == Component::Prompt).expect("prompt change");
    assert_eq!(prompt.kind, ChangeKind::Changed);
    assert_eq!(prompt.before.as_deref(), Some("prompt:support-answer@31"));
    assert_eq!(prompt.after.as_deref(), Some("prompt:support-answer@32"));

    let tool = d.changes.iter().find(|c| c.component == Component::Tool).expect("tool change");
    assert_eq!(tool.kind, ChangeKind::Added);
    assert_eq!(tool.after.as_deref(), Some("tool:send-email@2"));

    assert_eq!(d.changes.len(), 2, "release number change is not material: {:?}", d.changes);
}

#[test]
fn text_only_prompt_change_requires_prompt_suites() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["prompts"][0]["ref"] = json!("prompt:support-answer@32");
    let d = diff(&a, &rel(&v));
    for s in [Suite::PromptContract, Suite::Functional, Suite::Safety, Suite::Privacy, Suite::Regression] {
        assert!(d.required_suites.contains(&s), "missing {s:?}");
    }
    assert!(!d.required_suites.contains(&Suite::Cost), "prompt text change does not need a cost benchmark");
}

#[test]
fn model_change_requires_full_benchmark() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["model"]["ref"] = json!("model:anthropic/claude-sonnet@2026-09-01");
    let d = diff(&a, &rel(&v));
    for s in [Suite::Functional, Suite::ToolUse, Suite::Safety, Suite::Privacy, Suite::Performance, Suite::Cost] {
        assert!(d.required_suites.contains(&s), "missing {s:?}");
    }
}

#[test]
fn tool_change_requires_trajectory_authorization_and_approval() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["tools"][0]["ref"] = json!("tool:refund@5");
    let d = diff(&a, &rel(&v));
    for s in [Suite::Trajectory, Suite::Authorization, Suite::SideEffect] {
        assert!(d.required_suites.contains(&s), "missing {s:?}");
    }
    assert!(d.requires_approval);
}

#[test]
fn mcp_change_requires_capability_review_and_adversarial_tests() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["mcpServers"][0]["ref"] = json!("mcp:crm@13");
    let d = diff(&a, &rel(&v));
    for s in [Suite::PublisherTrust, Suite::CapabilityDiff, Suite::Authorization, Suite::Adversarial] {
        assert!(d.required_suites.contains(&s), "missing {s:?}");
    }
    assert!(d.requires_approval);
}

#[test]
fn retrieval_change_requires_grounding_suites() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["retrieval"]["ref"] = json!("retrieval:support@23");
    let d = diff(&a, &rel(&v));
    for s in [Suite::Grounding, Suite::AccessControl, Suite::Freshness] {
        assert!(d.required_suites.contains(&s), "missing {s:?}");
    }
}

#[test]
fn policy_change_requires_replay_and_approval() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["policies"][0]["ref"] = json!("policy:support-prod@12");
    let d = diff(&a, &rel(&v));
    assert!(d.required_suites.contains(&Suite::PolicyStaticAnalysis));
    assert!(d.required_suites.contains(&Suite::DecisionReplay));
    assert!(d.requires_approval);
}

#[test]
fn parameter_change_is_reported_per_key() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["parameters"]["temperature"] = json!(0.7);
    let d = diff(&a, &rel(&v));
    let c = d.changes.iter().find(|c| c.component == Component::Parameters).expect("param change");
    assert_eq!(c.name, "temperature");
    assert_eq!(c.before.as_deref(), Some("0.2"));
    assert_eq!(c.after.as_deref(), Some("0.7"));
    assert!(d.required_suites.contains(&Suite::Functional));
}

#[test]
fn removals_are_reported() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["spec"]["tools"] = json!([{"ref": "tool:lookup-customer@7"}]);
    let d = diff(&a, &rel(&v));
    let c = d.changes.iter().find(|c| c.component == Component::Tool).unwrap();
    assert_eq!(c.kind, ChangeKind::Removed);
    assert_eq!(c.before.as_deref(), Some("tool:refund@4"));
}

#[test]
fn different_agents_are_not_comparable() {
    let a = rel(&base_json());
    let mut v = base_json();
    v["metadata"]["agent"] = json!("billing-agent");
    let d = diff(&a, &rel(&v));
    assert!(!d.comparable);
}
