//! The CLI writes `cloakpipe.co` identifiers and still reads, hashes,
//! certifies and verifies objects issued under `cloakpipe.dev` by CloakPipe
//! 0.10 (`crates/cloakpipe-verify/tests/fixtures/legacy-cloakpipe-dev/`).

use base64::prelude::*;
use cloakpipe_verify::pack::{trusted_key_from_json, verify_pack_bytes, VerifyOptions};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const LEGACY_RELEASE: &str = "sha256:ae7bc9e404c194c9fcf80d95cafe4c322e4e9f69595c693ffb48441647d03c32";
const LEGACY_RUN_HASH: &str = "sha256:13370c86cbd2cb372fadf1576900f46d453b5e88c3294df6db4938c82336f9a8";
const LEGACY_POLICY_HASH: &str = "sha256:ff742b6b96732a407e299ed2a7686fbc376c7184f363e088f5001fed6a7174c5";

fn legacy(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cloakpipe-verify/tests/fixtures/legacy-cloakpipe-dev")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn cert_fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/certification")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cloakpipe")).args(args).output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

fn path(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

fn read_json(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn payload(envelope: &str) -> Value {
    let env = read_json(envelope);
    serde_json::from_slice(&BASE64_STANDARD.decode(env["payload"].as_str().unwrap()).unwrap()).unwrap()
}

fn keygen(dir: &Path, name: &str) -> String {
    let p = path(dir, name);
    let (code, _, err) = run(&["release", "keygen", "--out", &p]);
    assert_eq!(code, 0, "{err}");
    p
}

#[test]
fn a_legacy_manifest_validates_and_hashes_as_issued() {
    let (code, out, err) = run(&["release", "validate", &legacy("manifest.yaml")]);
    assert_eq!(code, 0, "{out}{err}");
    let (code, out, err) = run(&["release", "hash", &legacy("manifest.yaml")]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), LEGACY_RELEASE);
}

#[test]
fn inspect_emits_the_current_predicate_type_around_a_legacy_manifest() {
    let (code, out, err) = run(&["release", "inspect", "--json", &legacy("manifest.yaml")]);
    assert_eq!(code, 0, "{err}");
    let s: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(s["predicateType"], "https://cloakpipe.co/attestations/agent-release/v1alpha1");
    assert_eq!(s["predicate"]["apiVersion"], "cloakpipe.dev/v1alpha1");
    assert_eq!(format!("sha256:{}", s["subject"][0]["digest"]["sha256"].as_str().unwrap()), LEGACY_RELEASE);
}

#[test]
fn a_legacy_certification_verifies() {
    let (code, out, err) = run(&[
        "release", "verify-cert", &legacy("cert.dsse.json"), "--trust", &legacy("cert.pub.json"),
        "--release", &legacy("manifest.yaml"), "--now", "2026-10-02T00:00:00Z",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.starts_with("VALID"), "{out}");
}

#[test]
fn eval_import_writes_the_current_api_version() {
    let dir = tempfile::tempdir().unwrap();
    let out_file = path(dir.path(), "run.json");
    let (code, _, err) = run(&[
        "eval", "import", "--junit", &cert_fixture("passing.junit.xml"), "--release", &legacy("manifest.yaml"),
        "--suite", "support-critical@23", "--covers", "privacy,functional", "--out", &out_file,
    ]);
    assert_eq!(code, 0, "{err}");
    let r = read_json(&out_file);
    assert_eq!(r["apiVersion"], "cloakpipe.co/v1alpha1");
    assert_eq!(r["release"], LEGACY_RELEASE, "a legacy release keeps its hash");
}

#[test]
fn certifying_legacy_inputs_pins_their_issued_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(dir.path(), "key.json");
    let env = path(dir.path(), "cert.dsse.json");
    let (code, out, err) = run(&[
        "release", "certify", &legacy("manifest.yaml"), "--policy", &legacy("policy.yaml"), "--run",
        &legacy("run.json"), "--require", "privacy,functional", "--environment", "production", "--issuer", "ci",
        "--key", &key, "--now", "2026-10-01T00:00:00Z", "--out", &env,
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let s = payload(&env);
    assert_eq!(s["predicateType"], "https://cloakpipe.co/attestations/certification/v1alpha1");
    let d = &s["predicate"]["certification"]["decision"];
    assert_eq!(d["release"], LEGACY_RELEASE);
    assert_eq!(d["policy"]["hash"], LEGACY_POLICY_HASH);
    assert_eq!(d["runs"][0]["hash"], LEGACY_RUN_HASH);

    let (code, out, err) = run(&[
        "release", "verify-cert", &env, "--trust", &key, "--release", &legacy("manifest.yaml"), "--now",
        "2026-10-02T00:00:00Z",
    ]);
    assert_eq!(code, 0, "{out}{err}");
}

#[test]
fn unsupported_policy_versions_fail_in_either_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let src = std::fs::read_to_string(cert_fixture("policy.yaml")).unwrap();
    assert!(src.contains("apiVersion: cloakpipe.co/v1alpha1"));
    for bad in ["cloakpipe.co/v2", "cloakpipe.dev/v2", "cloakpipe.com/v1alpha1"] {
        let p = path(dir.path(), "policy.yaml");
        std::fs::write(&p, src.replace("cloakpipe.co/v1alpha1", bad)).unwrap();
        let (code, out, err) = run(&[
            "release", "certify", &legacy("manifest.yaml"), "--policy", &p, "--run", &legacy("run.json"),
            "--require", "privacy", "--environment", "production", "--issuer", "ci",
        ]);
        assert_eq!(code, 1, "{bad}: {out}{err}");
        assert!(format!("{out}{err}").contains("apiVersion"), "{bad}: {out}{err}");
    }
}

#[test]
fn a_pack_assembled_from_legacy_evidence_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(dir.path(), "exporter.key.json");
    let out = path(dir.path(), "pack.json");
    let (code, stdout, err) = run(&[
        "release", "audit-pack", "--manifest", &legacy("manifest.yaml"), "--run", &legacy("run.json"),
        "--certification", &legacy("cert.dsse.json"), "--ledger-export", &legacy("ledger.json"), "--events",
        &legacy("events.json"), "--key", &key, "--exporter", "ci", "--now", "2026-10-10T00:00:00Z", "--out", &out,
    ]);
    assert_eq!(code, 0, "{stdout}{err}");
    let doc = read_json(&out);
    assert_eq!(doc["apiVersion"], "cloakpipe.co/v1alpha1");
    assert_eq!(doc["spec"]["release"]["manifest"]["apiVersion"], "cloakpipe.dev/v1alpha1");

    let trust = |p: &str| trusted_key_from_json(&std::fs::read_to_string(p).unwrap()).unwrap();
    let opts = VerifyOptions {
        trusted: vec![trust(&key)],
        ledger_trusted: vec![trust(&legacy("ledger.pub.json"))],
        cert_trusted: vec![trust(&legacy("cert.pub.json"))],
        now: "2026-10-15T00:00:00Z".parse().unwrap(),
    };
    let r = verify_pack_bytes(&std::fs::read(&out).unwrap(), &opts);
    assert!(r.ok, "{:#?}", r.failures);
    assert_eq!(r.release.as_deref(), Some(LEGACY_RELEASE));
}
