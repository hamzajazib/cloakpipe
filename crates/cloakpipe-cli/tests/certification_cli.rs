//! `cloakpipe release keygen | certify | verify-cert` and `cloakpipe eval
//! import` — exercised through the real binary.
//!
//! Exit codes: 0 ok / certified, 1 invalid input or not certified (blocked,
//! rejected attestation), 2 usage or I/O error.

use base64::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const NOW: &str = "2026-10-01T12:00:00Z";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn release_fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cloakpipe-release/testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/certification")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn manifest() -> String {
    release_fixture("support-agent-184.yaml")
}

fn golden() -> String {
    std::fs::read_to_string(release_fixture("support-agent-184.hash")).unwrap().trim().to_string()
}

fn run_in(dir: Option<&Path>, args: &[&str]) -> (i32, String, String) {
    let mut cmd = bin();
    if let Some(d) = dir {
        cmd.current_dir(d);
    }
    let Output { status, stdout, stderr } = cmd.args(args).output().expect("run cloakpipe");
    (status.code().unwrap_or(-1), String::from_utf8(stdout).unwrap(), String::from_utf8(stderr).unwrap())
}

fn run(args: &[&str]) -> (i32, String, String) {
    run_in(None, args)
}

fn path(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().into_owned()
}

fn write(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
    let p = path(dir, name);
    std::fs::write(&p, content).unwrap();
    p
}

fn read_json(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// `keygen --out <dir>/key.json`; returns the key file path.
fn keygen(dir: &tempfile::TempDir, name: &str) -> String {
    let p = path(dir, name);
    let (code, _, err) = run(&["release", "keygen", "--out", &p]);
    assert_eq!(code, 0, "{err}");
    p
}

/// Import a fixture JUnit report for the golden release; returns the run path.
fn import(dir: &tempfile::TempDir, junit: &str, out: &str) -> String {
    let p = path(dir, out);
    let (code, _, err) = run(&[
        "eval", "import", "--junit", &fixture(junit), "--release", &manifest(), "--suite", "support-critical@23",
        "--covers", "privacy,functional", "--critical", "privacy::*", "--tool", "pytest", "--out", &p,
    ]);
    assert_eq!(code, 0, "{err}");
    p
}

/// Certify the golden release with one run; returns (exit, stdout, stderr).
fn certify(dir: &tempfile::TempDir, run_file: &str, key: &str, out: &str, extra: &[&str]) -> (i32, String, String) {
    let policy = fixture("policy.yaml");
    let m = manifest();
    let out = path(dir, out);
    let mut args = vec![
        "release", "certify", &m, "--policy", &policy, "--run", run_file, "--require", "privacy,functional",
        "--environment", "production", "--issuer", "ci:acme/support", "--key", key, "--now", NOW, "--out", &out,
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// A passing certification envelope signed with a fresh key; returns
/// (envelope path, key path, run path).
fn certified(dir: &tempfile::TempDir) -> (String, String, String) {
    let key = keygen(dir, "key.json");
    let run_file = import(dir, "passing.junit.xml", "run.json");
    let (code, out, err) = certify(dir, &run_file, &key, "cert.dsse.json", &[]);
    assert_eq!(code, 0, "{out}{err}");
    (path(dir, "cert.dsse.json"), key, run_file)
}

fn payload(envelope: &str) -> Value {
    let env = read_json(envelope);
    let bytes = BASE64_STANDARD.decode(env["payload"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── keygen ──────────────────────────────────────────────────────────────

#[test]
fn keygen_prints_an_ed25519_keypair_with_a_derived_keyid() {
    let (code, out, _) = run(&["release", "keygen"]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).expect("JSON");
    let public = v["publicKey"].as_str().unwrap();
    let private = v["privateKey"].as_str().unwrap();
    assert_eq!(public.len(), 64, "{out}");
    assert_eq!(private.len(), 64, "32-byte seed as hex: {out}");
    let digest = hex::encode(Sha256::digest(hex::decode(public).unwrap()));
    assert_eq!(v["keyid"], format!("ed25519:{}", &digest[..16]));
}

#[test]
fn keygen_generates_a_fresh_key_each_time() {
    let (_, a, _) = run(&["release", "keygen"]);
    let (_, b, _) = run(&["release", "keygen"]);
    assert_ne!(a, b);
}

#[test]
fn keygen_out_writes_a_private_file_and_prints_only_the_public_part() {
    let dir = tempfile::tempdir().unwrap();
    let p = path(&dir, "key.json");
    let (code, out, _) = run(&["release", "keygen", "--out", &p]);
    assert_eq!(code, 0);
    let printed: Value = serde_json::from_str(&out).expect("JSON");
    assert!(printed.get("privateKey").is_none(), "secret must not be printed: {out}");
    let file = read_json(&p);
    assert_eq!(file["keyid"], printed["keyid"]);
    assert_eq!(file["publicKey"], printed["publicKey"]);
    assert_eq!(file["privateKey"].as_str().unwrap().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }
}

#[test]
fn keygen_refuses_to_overwrite_an_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "key.json", "keep me");
    let (code, _, err) = run(&["release", "keygen", "--out", &p]);
    assert_eq!(code, 2, "{err}");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "keep me");
}

// ── eval import ─────────────────────────────────────────────────────────

#[test]
fn eval_import_turns_junit_into_an_evaluation_run_bound_to_the_manifest_hash() {
    let (code, out, err) = run(&[
        "eval", "import", "--junit", &fixture("failing.junit.xml"), "--release", &manifest(), "--suite",
        "support-critical@23", "--covers", "privacy,functional", "--critical", "privacy::*", "--tool", "pytest",
        "--dataset", "dataset:support-golden@9",
    ]);
    assert_eq!(code, 0, "{err}");
    let v: Value = serde_json::from_str(&out).expect("JSON on stdout");
    assert_eq!(v["kind"], "EvaluationRun");
    assert_eq!(v["release"], golden());
    assert_eq!(v["runId"], "support-critical@23", "run id defaults to NAME@VERSION");
    assert_eq!(v["suite"]["name"], "support-critical");
    assert_eq!(v["suite"]["version"], "23");
    assert_eq!(v["covers"], serde_json::json!(["privacy", "functional"]));
    assert_eq!(v["dataset"], "dataset:support-golden@9");
    assert_eq!(v["source"], serde_json::json!({"kind": "junit", "tool": "pytest"}));
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let leak = cases.iter().find(|c| c["id"] == "privacy::no_pii_in_tool_args").unwrap();
    assert_eq!(leak["status"], "fail");
    assert_eq!(leak["critical"], true, "--critical pattern applies");
    let identity = cases.iter().find(|c| c["id"] == "refunds::requires_identity").unwrap();
    assert_eq!(identity["critical"], true, "cloakpipe.critical property applies");
}

#[test]
fn eval_import_accepts_a_release_hash_and_writes_out() {
    let dir = tempfile::tempdir().unwrap();
    let out = path(&dir, "run.json");
    let (code, stdout, err) = run(&[
        "eval", "import", "--junit", &fixture("passing.junit.xml"), "--release", &golden(), "--suite", "s@1",
        "--covers", "privacy", "--run-id", "ci-4711", "--out", &out,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(stdout.is_empty(), "the run goes to the file only: {stdout}");
    let v = read_json(&out);
    assert_eq!(v["runId"], "ci-4711");
    assert_eq!(v["release"], golden());
}

#[test]
fn eval_import_refuses_an_uncertifiable_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let src = std::fs::read_to_string(manifest()).unwrap().replace("commit: 8fd29ac", "commit: main");
    let bad = write(&dir, "bad.yaml", &src);
    let (code, out, err) = run(&[
        "eval", "import", "--junit", &fixture("passing.junit.xml"), "--release", &bad, "--suite", "s@1", "--covers",
        "privacy",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("spec.code.commit"), "{err}");
}

#[test]
fn eval_import_reports_an_invalid_run_on_stderr() {
    let (code, out, err) = run(&[
        "eval", "import", "--junit", &fixture("passing.junit.xml"), "--release", &golden(), "--suite", "s@1",
        "--covers", "privacy,vibes",
    ]);
    assert_eq!(code, 1);
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("vibes"), "{err}");
}

#[test]
fn eval_import_rejects_malformed_xml() {
    let dir = tempfile::tempdir().unwrap();
    let xml = write(&dir, "bad.xml", "<testsuite><testcase name=\"a\"></testsuite>");
    let (code, _, err) =
        run(&["eval", "import", "--junit", &xml, "--release", &golden(), "--suite", "s@1", "--covers", "privacy"]);
    assert_eq!(code, 1);
    assert!(err.contains("XML"), "{err}");
}

#[test]
fn eval_import_usage_and_io_errors_exit_2() {
    let (code, _, err) = run(&[
        "eval", "import", "--junit", "/nonexistent/report.xml", "--release", &golden(), "--suite", "s@1", "--covers",
        "privacy",
    ]);
    assert_eq!(code, 2, "{err}");
    let (code, _, err) = run(&[
        "eval", "import", "--junit", &fixture("passing.junit.xml"), "--release", &golden(), "--suite", "no-version",
        "--covers", "privacy",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("NAME@VERSION"), "{err}");
}

// ── certify ─────────────────────────────────────────────────────────────

#[test]
fn certify_a_passing_run_signs_a_certification() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir, "key.json");
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let (code, out, err) = certify(&dir, &run_file, &key, "cert.dsse.json", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.starts_with("CERTIFIED"), "{out}");
    assert!(out.contains(&golden()), "{out}");
    assert!(out.contains("support-prod@11"), "{out}");

    let env = read_json(&path(&dir, "cert.dsse.json"));
    assert_eq!(env["payloadType"], "application/vnd.in-toto+json");
    assert_eq!(env["signatures"][0]["keyid"], read_json(&key)["keyid"]);
    let st = payload(&path(&dir, "cert.dsse.json"));
    let c = &st["predicate"]["certification"];
    assert_eq!(c["release"], golden());
    assert_eq!(c["agent"], "support-agent");
    assert_eq!(c["environment"], "production");
    assert_eq!(c["issuer"], "ci:acme/support");
    assert_eq!(c["issuedAt"], NOW);
    assert_eq!(c["validUntil"], "2026-10-31T12:00:00Z", "issuedAt + policy validityDays (30)");
    assert_eq!(c["decision"]["outcome"], "certified");
    assert_eq!(c["decision"]["requiredSuites"], serde_json::json!(["functional", "privacy"]));
}

#[test]
fn certify_blocks_a_failing_critical_case_and_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir, "key.json");
    let run_file = import(&dir, "failing.junit.xml", "run.json");
    let (code, out, err) = certify(&dir, &run_file, &key, "cert.dsse.json", &[]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.starts_with("BLOCKED"), "{out}");
    assert!(out.contains("new_critical_failure"), "{out}");
    assert!(out.contains("privacy::no_pii_in_tool_args"), "{out}");
    // The block itself is attested.
    let st = payload(&path(&dir, "cert.dsse.json"));
    assert_eq!(st["predicate"]["certification"]["decision"]["outcome"], "blocked");
}

#[test]
fn certify_json_prints_the_decision_and_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir, "key.json");
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let (code, out, err) = certify(&dir, &run_file, &key, "cert.dsse.json", &["--json"]);
    assert_eq!(code, 0, "{err}");
    let v: Value = serde_json::from_str(&out).expect("JSON");
    assert_eq!(v["decision"]["outcome"], "certified");
    assert_eq!(v["decision"]["release"], golden());
    assert_eq!(v["envelope"], read_json(&path(&dir, "cert.dsse.json")));
}

#[test]
fn certify_without_a_key_decides_but_does_not_sign() {
    let dir = tempfile::tempdir().unwrap();
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let policy = fixture("policy.yaml");
    let m = manifest();
    let (code, out, err) = run_in(
        Some(dir.path()),
        &[
            "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--require", "privacy",
            "--environment", "production", "--issuer", "ci", "--json",
        ],
    );
    assert_eq!(code, 0, "{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["decision"]["outcome"], "certified");
    assert!(v.get("envelope").is_none() || v["envelope"].is_null(), "{out}");
    assert!(!dir.path().join("support-agent-184.cert.dsse.json").exists());
}

#[test]
fn certify_default_out_is_the_manifest_stem() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir, "key.json");
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let policy = fixture("policy.yaml");
    let m = manifest();
    let (code, out, err) = run_in(
        Some(dir.path()),
        &[
            "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--require", "privacy",
            "--environment", "production", "--issuer", "ci", "--key", &key,
        ],
    );
    assert_eq!(code, 0, "{out}{err}");
    let expected = dir.path().join("support-agent-184.cert.dsse.json");
    assert!(expected.exists(), "{out}");
    assert!(out.contains("support-agent-184.cert.dsse.json"), "{out}");
}

#[test]
fn certify_requires_the_suites_the_diff_demands() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir, "key.json");
    // A run of release 185, covering privacy/functional only.
    let candidate = release_fixture("support-agent-185.yaml");
    let run_file = path(&dir, "run.json");
    let (code, _, err) = run(&[
        "eval", "import", "--junit", &fixture("passing.junit.xml"), "--release", &candidate, "--suite", "s@1",
        "--covers", "privacy,functional", "--out", &run_file,
    ]);
    assert_eq!(code, 0, "{err}");
    let base_run = import(&dir, "passing.junit.xml", "base.json");
    let policy = fixture("policy.yaml");
    let base = manifest();
    let out_file = path(&dir, "cert.json");
    let (code, out, err) = run(&[
        "release", "certify", &candidate, "--policy", &policy, "--run", &run_file, "--baseline", &base,
        "--baseline-run", &base_run, "--require", "cost", "--environment", "production", "--issuer", "ci", "--key",
        &key, "--now", NOW, "--out", &out_file, "--json",
    ]);
    assert_eq!(code, 1, "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    let required: Vec<&str> =
        v["decision"]["requiredSuites"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    for s in ["trajectory", "prompt_contract", "privacy", "cost"] {
        assert!(required.contains(&s), "{s} missing from {required:?}");
    }
    let missing: Vec<&str> = v["decision"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["code"] == "missing_suite")
        .map(|r| r["suite"].as_str().unwrap())
        .collect();
    assert!(missing.contains(&"trajectory") && missing.contains(&"cost"), "{missing:?}");
    assert!(!missing.contains(&"privacy"), "{missing:?}");
    assert_eq!(v["decision"]["baselineRuns"].as_array().unwrap().len(), 1);
}

#[test]
fn certify_with_no_required_suites_warns() {
    let dir = tempfile::tempdir().unwrap();
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let policy = fixture("policy.yaml");
    let m = manifest();
    let (code, _, err) = run(&[
        "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--environment", "production",
        "--issuer", "ci",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("warning") && err.contains("no required"), "{err}");
}

#[test]
fn certify_blocks_a_run_of_another_release() {
    let dir = tempfile::tempdir().unwrap();
    let other = format!("sha256:{}", "ab".repeat(32));
    let run_file = path(&dir, "run.json");
    let (code, _, _) = run(&[
        "eval", "import", "--junit", &fixture("passing.junit.xml"), "--release", &other, "--suite", "s@1",
        "--covers", "privacy", "--out", &run_file,
    ]);
    assert_eq!(code, 0);
    let policy = fixture("policy.yaml");
    let m = manifest();
    let (code, out, _) = run(&[
        "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--require", "privacy",
        "--environment", "production", "--issuer", "ci",
    ]);
    assert_eq!(code, 1);
    assert!(out.contains("release_mismatch"), "{out}");
}

#[test]
fn certify_accepts_a_json_policy() {
    let dir = tempfile::tempdir().unwrap();
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let policy = write(
        &dir,
        "policy.json",
        r#"{"apiVersion":"cloakpipe.dev/v1alpha1","kind":"CertificationPolicy","name":"p","version":"1","validityDays":7}"#,
    );
    let m = manifest();
    let (code, out, err) = run(&[
        "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--require", "privacy",
        "--environment", "staging", "--issuer", "ci",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("p@1"), "{out}");
}

#[test]
fn certify_rejects_invalid_inputs_with_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let bad_policy = write(&dir, "bad.yaml", "kind: CertificationPolicy\nname: [");
    let bad_run = write(&dir, "bad-run.json", r#"{"runId": 1}"#);
    let m = manifest();
    let policy = fixture("policy.yaml");
    let base = ["--environment", "production", "--issuer", "ci", "--require", "privacy"];

    let mut args = vec!["release", "certify", &m, "--policy", &bad_policy, "--run", &run_file];
    args.extend_from_slice(&base);
    let (code, _, err) = run(&args);
    assert_eq!(code, 1, "malformed policy: {err}");

    let mut args = vec!["release", "certify", &m, "--policy", &policy, "--run", &bad_run];
    args.extend_from_slice(&base);
    let (code, _, err) = run(&args);
    assert_eq!(code, 1, "malformed run: {err}");
    assert!(err.contains("bad-run.json"), "{err}");
}

#[test]
fn certify_io_and_usage_errors_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let m = manifest();
    let policy = fixture("policy.yaml");
    let (code, _, err) = run(&[
        "release", "certify", &m, "--policy", "/nonexistent/policy.yaml", "--run", &run_file, "--environment", "p",
        "--issuer", "ci",
    ]);
    assert_eq!(code, 2, "{err}");
    let (code, _, err) = run(&[
        "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--environment", "p", "--issuer", "ci",
        "--now", "yesterday",
    ]);
    assert_eq!(code, 2, "{err}");
    let (code, _, err) = run(&[
        "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--environment", "p", "--issuer", "ci",
        "--require", "vibes",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("vibes"), "{err}");
    let (code, _, err) = run(&[
        "release", "certify", &m, "--policy", &policy, "--run", &run_file, "--environment", "p", "--issuer", "ci",
        "--key", "/nonexistent/key.json",
    ]);
    assert_eq!(code, 2, "{err}");
}

// ── verify-cert ─────────────────────────────────────────────────────────

#[test]
fn verify_cert_accepts_a_valid_certification() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let (code, out, err) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.starts_with("VALID"), "{out}");
    assert!(out.contains("certified"), "{out}");
    assert!(out.contains(&golden()), "{out}");
}

#[test]
fn verify_cert_json_reports_certified() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let (code, out, _) =
        run(&["release", "verify-cert", &env, "--trust", &key, "--now", "2026-10-02T00:00:00Z", "--json"]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["status"], "VALID");
    assert_eq!(v["certified"], true);
    assert_eq!(v["outcome"], "certified");
    assert_eq!(v["release"], golden());
}

#[test]
fn verify_cert_accepts_a_public_only_key_file_and_an_inline_key() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let k = read_json(&key);
    let public_only = write(
        &dir,
        "public.json",
        &serde_json::json!({"keyid": k["keyid"], "publicKey": k["publicKey"]}).to_string(),
    );
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &public_only, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 0, "{out}");
    let inline = format!("{}={}", k["keyid"].as_str().unwrap(), k["publicKey"].as_str().unwrap());
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust-key", &inline, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn verify_cert_rejects_a_tampered_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let mut st = payload(&env);
    st["predicate"]["certification"]["environment"] = "anything".into();
    let mut e = read_json(&env);
    e["payload"] = BASE64_STANDARD.encode(serde_json::to_vec(&st).unwrap()).into();
    let tampered = write(&dir, "tampered.json", &e.to_string());
    let (code, out, _) = run(&["release", "verify-cert", &tampered, "--trust", &key, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("INVALID"), "{out}");
}

#[test]
fn verify_cert_rejects_an_untrusted_signer() {
    let dir = tempfile::tempdir().unwrap();
    let (env, _, _) = certified(&dir);
    let other = keygen(&dir, "other.json");
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &other, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("INVALID"), "{out}");
    let (code, out, _) = run(&["release", "verify-cert", &env, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 1, "no trust anchors: {out}");
}

#[test]
fn verify_cert_reports_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", "2026-11-01T00:00:00Z"]);
    assert_eq!(code, 1);
    assert!(out.starts_with("EXPIRED"), "{out}");
}

#[test]
fn verify_cert_checks_the_expected_release() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let now = "2026-10-02T00:00:00Z";
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", now, "--release", &manifest()]);
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", now, "--release", &golden()]);
    assert_eq!(code, 0, "{out}");
    let other = release_fixture("support-agent-185.yaml");
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", now, "--release", &other]);
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("INVALID"), "{out}");
}

#[test]
fn verify_cert_checks_required_runs() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let now = "2026-10-02T00:00:00Z";
    let st = payload(&env);
    let cited = st["predicate"]["certification"]["decision"]["runs"][0]["hash"].as_str().unwrap().to_string();
    let (code, out, _) =
        run(&["release", "verify-cert", &env, "--trust", &key, "--now", now, "--require-run", &cited]);
    assert_eq!(code, 0, "{out}");
    let missing = format!("sha256:{}", "cd".repeat(32));
    let (code, out, _) =
        run(&["release", "verify-cert", &env, "--trust", &key, "--now", now, "--require-run", &missing]);
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("INCOMPLETE"), "{out}");
}

#[test]
fn verify_cert_honours_revocations() {
    let dir = tempfile::tempdir().unwrap();
    let (env, key, _) = certified(&dir);
    let now = "2026-10-02T00:00:00Z";
    let (_, out, _) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", now, "--json"]);
    let digest = serde_json::from_str::<Value>(&out).unwrap()["statement_digest"].as_str().unwrap().to_string();
    let (code, out, _) =
        run(&["release", "verify-cert", &env, "--trust", &key, "--now", now, "--revoked-statement", &digest]);
    assert_eq!(code, 1);
    assert!(out.starts_with("REVOKED"), "{out}");
}

#[test]
fn verify_cert_of_a_blocked_decision_is_valid_but_not_certified() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir, "key.json");
    let run_file = import(&dir, "failing.junit.xml", "run.json");
    let (code, _, _) = certify(&dir, &run_file, &key, "cert.dsse.json", &[]);
    assert_eq!(code, 1);
    let env = path(&dir, "cert.dsse.json");
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("VALID"), "{out}");
    assert!(out.contains("blocked"), "{out}");
}

#[test]
fn verify_cert_reports_limitations() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir, "key.json");
    let run_file = import(&dir, "passing.junit.xml", "run.json");
    let (code, _, err) = certify(&dir, &run_file, &key, "cert.dsse.json", &["--limitation", "locale en only"]);
    assert_eq!(code, 0, "{err}");
    let env = path(&dir, "cert.dsse.json");
    let (code, out, _) = run(&["release", "verify-cert", &env, "--trust", &key, "--now", "2026-10-02T00:00:00Z"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("VALID_WITH_LIMITATIONS"), "{out}");
}

#[test]
fn verify_cert_io_and_usage_errors_exit_2() {
    let (code, _, err) = run(&["release", "verify-cert", "/nonexistent/cert.json"]);
    assert_eq!(code, 2, "{err}");
    let dir = tempfile::tempdir().unwrap();
    let (env, _, _) = certified(&dir);
    let (code, _, err) = run(&["release", "verify-cert", &env, "--trust-key", "ed25519:abc=nothex"]);
    assert_eq!(code, 2, "{err}");
}

#[test]
fn verify_cert_rejects_a_non_envelope_with_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let junk = write(&dir, "junk.json", "{\"hello\": 1}");
    let (code, out, err) = run(&["release", "verify-cert", &junk]);
    assert_eq!(code, 1, "{out}{err}");
}
