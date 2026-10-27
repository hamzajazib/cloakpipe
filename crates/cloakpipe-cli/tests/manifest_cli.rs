//! `cloakpipe manifest validate <file>` and `cloakpipe manifest hash <file>`
//! for the single-file v1 manifest (and, deprecated, the legacy AgentRelease).

use cloakpipe_release::v1::Manifest;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn support() -> PathBuf {
    root("../cloakpipe-release/testdata/v1/support.manifest.yaml")
}

fn cli(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cloakpipe")).args(args).output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn hash_prints_the_manifest_digest() {
    let m = Manifest::parse_path(&support()).unwrap();
    let (code, out, err) = cli(&["manifest", "hash", &s(&support())]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), m.digest().to_string());
}

#[test]
fn hash_json_reports_the_identity_and_the_policy_digest() {
    let m = Manifest::parse_path(&support()).unwrap();
    let (code, out, err) = cli(&["manifest", "hash", "--json", &s(&support())]);
    assert_eq!(code, 0, "{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["release"], "support-agent");
    assert_eq!(v["version"], "2026.10.3");
    assert_eq!(v["manifest_digest"], m.digest().to_string());
    assert_eq!(v["policy_digest"], m.policy_digest().unwrap().to_string());
    let (_, out, _) = cli(&["manifest", "hash", "--json", &s(&root("../cloakpipe-release/testdata/v1/minimal.manifest.yaml"))]);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["policy_digest"], Value::Null);
}

#[test]
fn validate_reports_the_release_and_digests() {
    let m = Manifest::parse_path(&support()).unwrap();
    let (code, out, err) = cli(&["manifest", "validate", &s(&support())]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("valid") && out.contains("support-agent@2026.10.3"), "{out}");
    assert!(out.contains(&m.digest().to_string()), "{out}");
    assert!(out.contains(&m.policy_digest().unwrap().to_string()), "{out}");
    assert!(out.contains("3 tools"), "{out}");
}

#[test]
fn invalid_and_unreadable_manifests_fail_with_distinct_codes() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "release: r\nversion: \"1\"\ntools:\n  t: { approval: { when: \"amount >\" } }\n").unwrap();
    for cmd in ["validate", "hash"] {
        let (code, out, err) = cli(&["manifest", cmd, &s(&bad)]);
        assert_eq!(code, 1, "{cmd}: {out}{err}");
        assert!(err.contains("approval.when"), "{cmd}: {err}");
        assert!(out.is_empty(), "{cmd}: no digest for an invalid manifest: {out}");
        let (code, _, err) = cli(&["manifest", cmd, &s(&dir.path().join("missing.yaml"))]);
        assert_eq!(code, 2, "{cmd}: {err}");
    }
}

#[test]
fn a_legacy_release_is_recognised_and_deprecated() {
    let legacy = root("../cloakpipe-release/testdata/support-agent-184.yaml");
    let (code, out, err) = cli(&["manifest", "validate", &s(&legacy)]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(err.contains("deprecated"), "{err}");
    let (code, out, _) = cli(&["manifest", "hash", &s(&legacy)]);
    assert_eq!(code, 0);
    let (_, release_hash, _) = cli(&["release", "hash", &s(&legacy)]);
    assert_eq!(out.trim(), release_hash.trim(), "a legacy release keeps its manifest hash");
}
