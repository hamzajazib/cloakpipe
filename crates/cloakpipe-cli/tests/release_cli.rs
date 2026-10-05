//! `cloakpipe release …` — exercised through the real binary.
//!
//! Exit codes: 0 ok, 1 manifest is invalid / not certifiable, 2 usage or I/O error.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cloakpipe-release/testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn golden() -> String {
    std::fs::read_to_string(fixture("support-agent-184.hash")).unwrap().trim().to_string()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let Output { status, stdout, stderr } = bin().args(args).output().expect("run cloakpipe");
    (status.code().unwrap_or(-1), String::from_utf8(stdout).unwrap(), String::from_utf8(stderr).unwrap())
}

fn write_temp(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, content).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn hash_prints_only_the_hash() {
    let (code, out, _) = run(&["release", "hash", &fixture("support-agent-184.yaml")]);
    assert_eq!(code, 0);
    assert_eq!(out, format!("{}\n", golden()), "machine-readable: hash and newline only");
}

#[test]
fn hash_is_format_independent() {
    let (_, yaml, _) = run(&["release", "hash", &fixture("support-agent-184.yaml")]);
    let (_, json, _) = run(&["release", "hash", &fixture("support-agent-184.json")]);
    assert_eq!(yaml, json);
}

#[test]
fn validate_accepts_a_certifiable_manifest() {
    let (code, out, _) = run(&["release", "validate", &fixture("support-agent-184.yaml")]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("valid"), "{out}");
    assert!(out.contains(&golden()), "{out}");
}

#[test]
fn validate_rejects_mutable_references_and_names_the_field() {
    let dir = tempfile::tempdir().unwrap();
    let src = std::fs::read_to_string(fixture("support-agent-184.yaml"))
        .unwrap()
        .replace("prompt:support-answer@31", "prompt:support-answer@latest");
    let path = write_temp(&dir, "bad.yaml", &src);

    let (code, out, _) = run(&["release", "validate", &path]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("spec.prompts[0].ref"), "{out}");
    assert!(out.contains("immutable"), "{out}");
}

#[test]
fn hash_refuses_an_uncertifiable_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let src = std::fs::read_to_string(fixture("support-agent-184.yaml"))
        .unwrap()
        .replace("commit: 8fd29ac", "commit: main");
    let path = write_temp(&dir, "bad.yaml", &src);

    let (code, out, err) = run(&["release", "hash", &path]);
    assert_eq!(code, 1);
    assert!(out.is_empty(), "no hash may be printed for an invalid manifest: {out}");
    assert!(err.contains("spec.code.commit"), "{err}");
}

#[test]
fn unparseable_manifest_is_a_validation_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_temp(&dir, "bad.json", r#"{"kind": "AgentRelease"}"#);
    let (code, _, err) = run(&["release", "validate", &path]);
    assert_eq!(code, 1);
    assert!(err.contains("invalid JSON manifest"), "{err}");
}

#[test]
fn missing_file_is_an_io_error() {
    let (code, _, err) = run(&["release", "validate", "/nonexistent/release.yaml"]);
    assert_eq!(code, 2);
    assert!(err.contains("cannot read"), "{err}");
}

#[test]
fn diff_reports_changes_and_required_assurance() {
    let (code, out, _) = run(&["release", "diff", &fixture("support-agent-184.yaml"), &fixture("support-agent-185.yaml")]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("prompt:support-answer@31 -> prompt:support-answer@32"), "{out}");
    assert!(out.contains("tool:send-email@2"), "{out}");
    assert!(out.contains("trajectory"), "{out}");
    assert!(out.contains("approval required"), "{out}");
}

#[test]
fn diff_of_equivalent_manifests_reports_no_material_change() {
    let (code, out, _) = run(&["release", "diff", &fixture("support-agent-184.yaml"), &fixture("support-agent-184.json")]);
    assert_eq!(code, 0);
    assert!(out.contains("no material changes"), "{out}");
}

#[test]
fn diff_json_is_machine_readable() {
    let (code, out, _) = run(&[
        "release", "diff", "--json", &fixture("support-agent-184.yaml"), &fixture("support-agent-185.yaml"),
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["baseline"], golden());
    assert_eq!(v["comparable"], true);
    assert_eq!(v["requires_approval"], true);
    assert_eq!(v["changes"].as_array().unwrap().len(), 2);
    assert!(v["required_suites"].as_array().unwrap().iter().any(|s| s == "prompt_contract"));
}

#[test]
fn inspect_json_emits_an_intoto_statement() {
    let (code, out, _) = run(&["release", "inspect", "--json", &fixture("support-agent-184.yaml")]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(format!("sha256:{}", v["subject"][0]["digest"]["sha256"].as_str().unwrap()), golden());
}

#[test]
fn inspect_summarises_the_release() {
    let (code, out, _) = run(&["release", "inspect", &fixture("support-agent-184.yaml")]);
    assert_eq!(code, 0);
    for needle in ["support-agent", "184", "model:openai/gpt-5@2026-08-01", "tools", &golden()] {
        assert!(out.contains(needle), "missing {needle:?} in {out}");
    }
}
