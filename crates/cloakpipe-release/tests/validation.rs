//! A release is certifiable only if every reference is immutable and well
//! formed ("rejects unresolved mutable references for certification").

use cloakpipe_release::{parse_path, parse_str, Format, IssueCode};
use serde_json::{json, Value};
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn base_json() -> Value {
    serde_json::from_str(&std::fs::read_to_string(testdata("support-agent-184.json")).unwrap()).unwrap()
}

fn codes(v: &Value) -> Vec<IssueCode> {
    parse_str(&v.to_string(), Format::Json)
        .unwrap()
        .validate()
        .into_iter()
        .map(|i| i.code)
        .collect()
}

#[test]
fn fixture_is_valid() {
    let r = parse_path(&testdata("support-agent-184.yaml")).unwrap();
    assert_eq!(r.validate(), vec![]);
}

#[test]
fn wrong_api_version_or_kind_is_rejected() {
    let mut v = base_json();
    v["apiVersion"] = json!("cloakpipe.dev/v9");
    assert!(codes(&v).contains(&IssueCode::UnsupportedApiVersion));

    let mut v = base_json();
    v["kind"] = json!("Deployment");
    assert!(codes(&v).contains(&IssueCode::UnsupportedKind));
}

#[test]
fn mutable_aliases_are_rejected() {
    for alias in ["latest", "production", "staging", "candidate", "draft", "main", "head", "LATEST"] {
        let mut v = base_json();
        v["spec"]["prompts"][0]["ref"] = json!(format!("prompt:support-answer@{alias}"));
        assert!(codes(&v).contains(&IssueCode::MutableReference), "@{alias} must be rejected");
    }
}

#[test]
fn unversioned_reference_is_rejected() {
    let mut v = base_json();
    v["spec"]["model"]["ref"] = json!("model:openai/gpt-5");
    assert!(codes(&v).contains(&IssueCode::MutableReference));
}

#[test]
fn digest_pinned_reference_is_accepted() {
    let mut v = base_json();
    v["spec"]["tools"][0]["ref"] =
        json!("tool:refund@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    assert_eq!(codes(&v), vec![]);
}

#[test]
fn reference_kind_must_match_its_field() {
    let mut v = base_json();
    v["spec"]["tools"][0]["ref"] = json!("prompt:refund@4");
    assert!(codes(&v).contains(&IssueCode::WrongReferenceKind));
}

#[test]
fn malformed_reference_is_rejected() {
    for bad in ["refund@4", "tool:@4", "tool:Ref Und@4", "tool:refund@", ""] {
        let mut v = base_json();
        v["spec"]["tools"][0]["ref"] = json!(bad);
        assert!(codes(&v).contains(&IssueCode::MalformedReference), "{bad:?} must be rejected");
    }
}

#[test]
fn duplicate_set_entries_are_rejected() {
    let mut v = base_json();
    v["spec"]["tools"] = json!([{"ref": "tool:refund@4"}, {"ref": "tool:refund@5"}]);
    assert!(codes(&v).contains(&IssueCode::DuplicateEntry), "same tool twice at different versions");
}

#[test]
fn code_commit_must_be_a_hex_sha() {
    for bad in ["main", "8fd29a", "8FD29AC", "zzzzzzz"] {
        let mut v = base_json();
        v["spec"]["code"]["commit"] = json!(bad);
        assert!(codes(&v).contains(&IssueCode::InvalidCommit), "{bad:?}");
    }
}

#[test]
fn runtime_image_must_be_digest_pinned() {
    let mut v = base_json();
    v["spec"]["runtime"]["image"] = json!("registry.acme.dev/support-agent:latest");
    assert!(codes(&v).contains(&IssueCode::UnpinnedImage));
}

#[test]
fn issues_point_at_the_offending_field() {
    let mut v = base_json();
    v["spec"]["tools"][1]["ref"] = json!("tool:refund@latest");
    let r = parse_str(&v.to_string(), Format::Json).unwrap();
    let issues = r.validate();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].path, "spec.tools[1].ref");
}

#[test]
fn issue_codes_have_stable_snake_case_names() {
    // API clients match on these strings: never rename them.
    assert_eq!(IssueCode::MutableReference.as_str(), "mutable_reference");
    assert_eq!(IssueCode::MalformedReference.as_str(), "malformed_reference");
    assert_eq!(IssueCode::UnpinnedImage.as_str(), "unpinned_image");
    assert_eq!(IssueCode::UnsupportedApiVersion.as_str(), "unsupported_api_version");
}
