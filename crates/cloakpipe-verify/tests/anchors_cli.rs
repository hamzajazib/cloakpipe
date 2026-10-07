//! `cloakpipe-verify anchors|all --tsa-root PEM --rekor-key PEM` as a
//! separate process, over bundles anchored with the recorded freetsa.org
//! and rekor.sigstore.dev responses.

mod common;

use base64::Engine;
use cloakpipe_verify::bundle::{AnchorReceiptRef, Bundle};
use common::*;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cloakpipe-verify"))
}

fn anchored(s: &Scenario, tsa: &str, rekor: &str) -> Bundle {
    let mut b = bundle_for(s);
    let subject = hex_lower(&Sha256::digest(head_bytes(s)));
    let v: serde_json::Value = serde_json::from_slice(&fixture(&format!("{rekor}.json"))).unwrap();
    let (uuid, entry) = v.as_object().unwrap().iter().next().unwrap();
    b.anchor_receipts = vec![
        AnchorReceiptRef::Rfc3161 {
            batch_id: s.batch_id.into(),
            subject_hash: subject.clone(),
            tsa_url: "https://freetsa.org/tsr".into(),
            nonce: String::from_utf8(fixture(&format!("{tsa}.nonce"))).unwrap(),
            tsr: base64::engine::general_purpose::STANDARD.encode(fixture(&format!("{tsa}.tsr"))),
        },
        AnchorReceiptRef::Rekor {
            batch_id: s.batch_id.into(),
            subject_hash: subject,
            rekor_url: "https://rekor.sigstore.dev".into(),
            entry_uuid: uuid.clone(),
            entry: entry.clone(),
        },
    ];
    b
}

fn write(dir: &Path, name: &str, b: &Bundle) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(b).unwrap()).unwrap();
    p
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("run cloakpipe-verify")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn trust_args() -> Vec<String> {
    let d = fixtures_dir();
    vec![
        "--tsa-root".into(),
        d.join("freetsa-root.pem").display().to_string(),
        "--rekor-key".into(),
        d.join("rekor.pub").display().to_string(),
    ]
}

fn with<'a>(base: &[&'a str], extra: &'a [String]) -> Vec<&'a str> {
    base.iter().copied().chain(extra.iter().map(String::as_str)).collect()
}

#[test]
fn anchors_pass_with_both_trust_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "b.json", &anchored(&HONEST, "freetsa-honest", "rekor-honest"));
    let t = trust_args();
    let o = run(&with(&["anchors", p.to_str().unwrap()], &t));
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), String::from_utf8_lossy(&o.stderr));
    assert!(stdout(&o).contains("2 anchor receipt(s) verified"), "{}", stdout(&o));
}

#[test]
fn anchors_without_trust_inputs_fail_not_skip() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "b.json", &anchored(&HONEST, "freetsa-honest", "rekor-honest"));
    let o = run(&["anchors", p.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    assert!(stdout(&o).contains("--tsa-root"), "{}", stdout(&o));
    let t = trust_args();
    let o = run(&with(&["anchors", p.to_str().unwrap()], &t[..2]));
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    assert!(stdout(&o).contains("--rekor-key"), "{}", stdout(&o));
}

#[test]
fn anchors_detect_back_dating() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "b.json", &anchored(&FUTURE, "freetsa-future", "rekor-future"));
    let t = trust_args();
    let o = run(&with(&["anchors", p.to_str().unwrap()], &t));
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    assert!(stdout(&o).contains("back-dating"), "{}", stdout(&o));
}

#[test]
fn all_passes_with_trust_and_fails_without() {
    let dir = tempfile::tempdir().unwrap();
    // v2: anchors without a signed manifest (the manifest is checked from v3).
    let mut b = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    b.format_version = 2;
    let p = write(dir.path(), "b.json", &b);
    let t = trust_args();
    let o = run(&with(&["all", p.to_str().unwrap()], &t));
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), String::from_utf8_lossy(&o.stderr));
    assert!(stdout(&o).contains("anchors=2"), "{}", stdout(&o));
    let o = run(&["all", p.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
}

#[test]
fn trust_inputs_with_an_unanchored_bundle_fail() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "b.json", &bundle_for(&HONEST));
    let t = trust_args();
    let o = run(&with(&["anchors", p.to_str().unwrap()], &t));
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
}

#[test]
fn bad_trust_inputs_are_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "b.json", &anchored(&HONEST, "freetsa-honest", "rekor-honest"));
    let p = p.to_str().unwrap();
    let rekor = fixtures_dir().join("rekor.pub").display().to_string();
    let root = fixtures_dir().join("freetsa-root.pem").display().to_string();
    for args in [
        vec!["anchors", p, "--tsa-root", "/nonexistent.pem"],
        vec!["anchors", p, "--tsa-root", rekor.as_str()],
        vec!["anchors", p, "--rekor-key", root.as_str()],
        vec!["anchors", p, "--tsa-root"],
        vec!["anchors", p, "--tsa-root", root.as_str(), "--tsa-root", root.as_str()],
        vec!["anchors", p, "--bogus"],
        vec!["chain", p, "--tsa-root", root.as_str()],
    ] {
        let o = run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", stdout(&o));
    }
}

#[test]
fn all_never_ignores_trust_inputs_on_a_downgraded_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let t = trust_args();
    // Receipts stripped and the version lowered to 1: trust inputs were
    // given, so the bundle must be anchored.
    let mut stripped = bundle_for(&HONEST);
    stripped.format_version = 1;
    stripped.inclusion_proofs.clear();
    let p = write(dir.path(), "v1.json", &stripped);
    let o = run(&with(&["all", p.to_str().unwrap()], &t));
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    assert!(stdout(&o).starts_with("FAIL"), "{}", stdout(&o));
    // Without trust inputs a plain v1 bundle still verifies as before.
    let o = run(&["all", p.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));

    // External receipts left in a v1 bundle are checked, never ignored.
    let mut v1 = anchored(&HONEST, "freetsa-honest", "rekor-honest");
    v1.format_version = 1;
    let p = write(dir.path(), "v1-receipts.json", &v1);
    let o = run(&["all", p.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    assert!(stdout(&o).contains("--tsa-root"), "{}", stdout(&o));
    let o = run(&with(&["all", p.to_str().unwrap()], &t));
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), String::from_utf8_lossy(&o.stderr));
    assert!(stdout(&o).contains("anchors=2"), "{}", stdout(&o));
}
