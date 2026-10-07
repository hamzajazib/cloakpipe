//! Release audit packs are written in the `cloakpipe.co` namespace. Packs
//! (and the manifests, runs and certifications inside them) issued before
//! the rename carry `cloakpipe.dev` identifiers and must keep verifying with
//! the digest and signature they were issued with.
//!
//! `tests/fixtures/legacy-cloakpipe-dev/` was produced by CloakPipe 0.10.

mod common;

use cloakpipe_cert::statement::{Envelope, Status};
use cloakpipe_cert::EvaluationRun;
use cloakpipe_release::namespace;
use cloakpipe_verify::bundle::Bundle;
use cloakpipe_verify::pack::{
    digest_of, signing_input, trusted_key_from_json, verify_pack_bytes, GovernanceEvent, PackBuilder, PackReport,
    TrustedKey, VerifyOptions, PACK_API_VERSION, PACK_SIGNING_DOMAIN,
};
use common::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

const LEGACY_RELEASE: &str = "sha256:ae7bc9e404c194c9fcf80d95cafe4c322e4e9f69595c693ffb48441647d03c32";
const LEGACY_PACK_DIGEST: &str = "sha256:27573c0a2e243119415a27bb3e7fdf02998cb8de2a4285feebf886096b761015";
const LEGACY_NOW: &str = "2026-10-15T00:00:00Z";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-cloakpipe-dev")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(dir().join(name)).unwrap()
}

fn trust(name: &str) -> TrustedKey {
    trusted_key_from_json(&read(name)).unwrap()
}

fn legacy_options() -> VerifyOptions {
    VerifyOptions {
        trusted: vec![trust("exporter.pub.json")],
        ledger_trusted: vec![trust("ledger.pub.json")],
        cert_trusted: vec![trust("cert.pub.json")],
        now: LEGACY_NOW.parse().unwrap(),
    }
}

fn legacy_pack() -> Value {
    serde_json::from_str(&read("pack.json")).unwrap()
}

#[track_caller]
fn assert_ok(r: &PackReport) {
    assert!(r.ok, "expected PASS, failures: {:#?}", r.failures);
}

#[track_caller]
fn assert_fails(r: &PackReport, needle: &str) {
    assert!(!r.ok, "expected FAIL mentioning {needle:?}");
    assert!(r.failures.iter().any(|f| f.contains(needle)), "no failure mentions {needle:?}: {:#?}", r.failures);
}

#[test]
fn packs_are_written_in_the_cloakpipe_co_namespace() {
    assert_eq!(PACK_API_VERSION, "cloakpipe.co/v1alpha1");
    assert_eq!(PACK_SIGNING_DOMAIN, "cloakpipe.co/release-audit-pack/v1alpha1");
    let doc = pack_value();
    assert_eq!(doc["apiVersion"], "cloakpipe.co/v1alpha1");
    assert_eq!(doc["spec"]["release"]["manifest"]["apiVersion"], "cloakpipe.co/v1alpha1");
    assert_eq!(doc["spec"]["evaluationRuns"][0]["apiVersion"], "cloakpipe.co/v1alpha1");
    let input = signing_input(&doc["apiVersion"], &doc["kind"], &doc["spec"]).unwrap();
    assert!(input.starts_with(b"cloakpipe.co/release-audit-pack/v1alpha1\n"));
    assert_eq!(doc["digest"], digest_of(&input));
}

#[test]
fn a_pack_issued_by_cloakpipe_0_10_still_verifies() {
    let bytes = read("pack.json");
    let doc: Value = serde_json::from_str(&bytes).unwrap();
    assert_eq!(doc["apiVersion"], namespace::LEGACY_API_VERSION);
    assert_eq!(doc["spec"]["release"]["manifest"]["apiVersion"], namespace::LEGACY_API_VERSION);
    assert_eq!(doc["spec"]["evaluationRuns"][0]["apiVersion"], namespace::LEGACY_API_VERSION);

    let r = verify_pack_bytes(bytes.as_bytes(), &legacy_options());
    assert_ok(&r);
    assert_eq!(r.release.as_deref(), Some(LEGACY_RELEASE));
    assert_eq!(r.digest.as_deref(), Some(LEGACY_PACK_DIGEST));
    assert_eq!(r.signer.as_deref(), Some(trust("exporter.pub.json").keyid.as_str()));
    assert_eq!(r.certifications.len(), 1);
    assert_eq!(r.certifications[0].status, Status::Valid);
    assert!(r.certifications[0].certified);
    assert_eq!(r.runs.len(), 1);
    assert_eq!(r.ledger.len(), 1);
}

#[test]
fn a_legacy_pack_is_signed_under_the_legacy_domain() {
    let doc = legacy_pack();
    let input = signing_input(&doc["apiVersion"], &doc["kind"], &doc["spec"]).unwrap();
    assert!(input.starts_with(b"cloakpipe.dev/release-audit-pack/v1alpha1\n"));
    assert_eq!(digest_of(&input), LEGACY_PACK_DIGEST);
}

#[test]
fn relabelling_a_legacy_pack_breaks_its_signature() {
    // Readers never rewrite identifiers: moving a signed legacy pack into the
    // new namespace is an edit, and the exporter's signature no longer holds.
    let mut doc = legacy_pack();
    doc["apiVersion"] = json!(namespace::API_VERSION);
    let r = verify_pack_bytes(&to_bytes(&doc), &legacy_options());
    assert!(!r.ok);
    assert!(r.failures.iter().any(|f| f.contains("digest") || f.contains("signature")), "{:#?}", r.failures);

    let mut doc = legacy_pack();
    doc["spec"]["release"]["manifest"]["apiVersion"] = json!(namespace::API_VERSION);
    assert!(!verify_pack_bytes(&to_bytes(&doc), &legacy_options()).ok);
}

#[test]
fn a_new_pack_of_legacy_objects_verifies() {
    // Mixed: a pack written today (cloakpipe.co) around a release, run,
    // certification and ledger export issued before the rename.
    let manifest = cloakpipe_release::parse_str(&read("manifest.yaml"), cloakpipe_release::Format::Yaml).unwrap();
    let run: EvaluationRun = serde_json::from_str(&read("run.json")).unwrap();
    let cert: Envelope = serde_json::from_str(&read("cert.dsse.json")).unwrap();
    let ledger: Bundle = serde_json::from_str(&read("ledger.json")).unwrap();
    let events: Vec<GovernanceEvent> = serde_json::from_str(&read("events.json")).unwrap();
    let mut b = PackBuilder::new(manifest, "ci:mixed", "2026-10-10T00:00:00Z")
        .run(run)
        .certification(cert)
        .ledger_export(ledger);
    for e in events {
        b = b.event(e);
    }
    let pack = b.build(&key(EXPORTER_SEED)).unwrap();
    assert_eq!(pack.api_version, namespace::API_VERSION);
    assert_eq!(pack.spec.release.hash, LEGACY_RELEASE);
    assert_eq!(pack.spec.release.manifest.api_version, namespace::LEGACY_API_VERSION);

    let opts = VerifyOptions { trusted: vec![trusted(EXPORTER_SEED)], ..legacy_options() };
    let r = verify_pack_bytes(&to_bytes(&serde_json::to_value(&pack).unwrap()), &opts);
    assert_ok(&r);
    assert_eq!(r.release.as_deref(), Some(LEGACY_RELEASE));
    assert_eq!(r.certifications[0].status, Status::Valid);
}

#[test]
fn a_legacy_namespace_pack_resigned_by_a_trusted_exporter_verifies() {
    let mut doc = pack_value();
    doc["apiVersion"] = json!(namespace::LEGACY_API_VERSION);
    let doc = resign(doc, EXPORTER_SEED);
    let input = signing_input(&doc["apiVersion"], &doc["kind"], &doc["spec"]).unwrap();
    assert!(input.starts_with(b"cloakpipe.dev/release-audit-pack/v1alpha1\n"));
    assert_ok(&verify_pack_bytes(&to_bytes(&doc), &options()));
}

#[test]
fn unsupported_pack_versions_fail_in_either_namespace() {
    for bad in ["cloakpipe.co/v2", "cloakpipe.dev/v2", "cloakpipe.com/v1alpha1", "example.com/v1alpha1"] {
        let mut doc = pack_value();
        doc["apiVersion"] = json!(bad);
        assert_fails(&verify_pack_bytes(&to_bytes(&resign(doc, EXPORTER_SEED)), &options()), "apiVersion");
    }
}

#[test]
fn the_cli_verifies_the_legacy_pack() {
    let d = dir();
    let out = Command::new(env!("CARGO_BIN_EXE_cloakpipe-verify"))
        .current_dir(&d)
        .args([
            "release-pack",
            "pack.json",
            "--trust",
            "exporter.pub.json",
            "--ledger-trust",
            "ledger.pub.json",
            "--cert-trust",
            "cert.pub.json",
            "--now",
            LEGACY_NOW,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.starts_with("PASS"), "{stdout}");
}
