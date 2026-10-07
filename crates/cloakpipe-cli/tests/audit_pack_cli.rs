//! `cloakpipe release audit-pack`: assemble a release audit pack from local
//! files (docs/AUDIT_PACK.md) and check it with the standalone verifier.
//!
//! Exit codes: 0 written, 1 invalid input (a run, certification, event or
//! ledger export that could never verify), 2 usage or I/O error.

use cloakpipe_ledger::export::export_bundle;
use cloakpipe_ledger::{Ed25519Signer, Hop, LedgerStore, RecordBuilder};
use cloakpipe_verify::pack::{trusted_key_from_json, verify_pack_bytes, VerifyOptions};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ISSUED: &str = "2026-10-01T00:00:00Z";
const CREATED: &str = "2026-10-06T00:00:00Z";
const NOW: &str = "2026-10-07T00:00:00Z";

fn manifest() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cloakpipe-release/testdata/support-agent-184.yaml")
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

fn golden() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../cloakpipe-release/testdata/support-agent-184.hash");
    std::fs::read_to_string(p).unwrap().trim().to_string()
}

fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let Output { status, stdout, stderr } =
        Command::new(env!("CARGO_BIN_EXE_cloakpipe")).current_dir(dir).args(args).output().unwrap();
    (status.code().unwrap_or(-1), String::from_utf8(stdout).unwrap(), String::from_utf8(stderr).unwrap())
}

/// Key, passing run, production certification, ledger export and events for
/// the golden release, all as files in a temp dir.
struct Inputs {
    dir: tempfile::TempDir,
}

impl Inputs {
    fn new() -> Self {
        let i = Inputs { dir: tempfile::tempdir().unwrap() };
        let d = i.dir.path();
        for k in ["exporter.key.json", "cert.key.json"] {
            let (code, _, err) = run(d, &["release", "keygen", "--out", k]);
            assert_eq!(code, 0, "{err}");
        }
        let junit = fixture("passing.junit.xml");
        let (code, _, err) = run(
            d,
            &[
                "eval",
                "import",
                "--junit",
                &junit,
                "--release",
                &manifest(),
                "--suite",
                "support-critical@23",
                "--covers",
                "privacy,functional",
                "--critical",
                "privacy::*",
                "--out",
                "run.json",
            ],
        );
        assert_eq!(code, 0, "{err}");
        let policy = fixture("policy.yaml");
        let (code, out, err) = run(
            d,
            &[
                "release",
                "certify",
                &manifest(),
                "--policy",
                &policy,
                "--run",
                "run.json",
                "--require",
                "privacy,functional",
                "--environment",
                "production",
                "--issuer",
                "ci:acme/support",
                "--key",
                "cert.key.json",
                "--now",
                ISSUED,
                "--out",
                "cert.dsse.json",
            ],
        );
        assert_eq!(code, 0, "{out}{err}");
        i.write("ledger.json", &ledger_export(true).to_string());
        i.write("events.json", &events().to_string());
        i
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, content: &str) {
        std::fs::write(self.path(name), content).unwrap();
    }

    /// Assemble from the standard inputs; `overrides` replace a flag's value.
    fn assemble(&self, overrides: &[(&str, &str)]) -> (i32, String, String) {
        let m = manifest();
        let mut flags = vec![
            ("--manifest", m.as_str()),
            ("--run", "run.json"),
            ("--certification", "cert.dsse.json"),
            ("--ledger-export", "ledger.json"),
            ("--events", "events.json"),
            ("--key", "exporter.key.json"),
            ("--exporter", "cli:acme"),
            ("--now", CREATED),
            ("--out", "pack.json"),
        ];
        for (flag, value) in overrides {
            flags.iter_mut().find(|(f, _)| f == flag).expect("known flag").1 = value;
        }
        let mut args = vec!["release", "audit-pack"];
        for (f, v) in flags {
            args.push(f);
            args.push(v);
        }
        run(self.dir.path(), &args)
    }

    fn trust(&self, name: &str) -> cloakpipe_verify::pack::TrustedKey {
        trusted_key_from_json(&std::fs::read_to_string(self.path(name)).unwrap()).unwrap()
    }

    fn verify(&self) -> cloakpipe_verify::pack::PackReport {
        let bytes = std::fs::read(self.path("pack.json")).unwrap();
        let ledger = cloakpipe_verify::pack::TrustedKey {
            keyid: "ledger".into(),
            public_key: Ed25519Signer::from_bytes(&LEDGER_SEED).public_key_bytes(),
        };
        verify_pack_bytes(
            &bytes,
            &VerifyOptions {
                trusted: vec![self.trust("exporter.key.json")],
                ledger_trusted: vec![ledger],
                cert_trusted: vec![self.trust("cert.key.json")],
                now: NOW.parse().unwrap(),
            },
        )
    }
}

const LEDGER_SEED: [u8; 32] = [5; 32];

trait PublicKeyBytes {
    fn public_key_bytes(&self) -> [u8; 32];
}

impl PublicKeyBytes for Ed25519Signer {
    fn public_key_bytes(&self) -> [u8; 32] {
        cloakpipe_ledger::Signer::public_key(self)
    }
}

fn ledger_export(bound: bool) -> Value {
    let mut store = LedgerStore::open(":memory:").unwrap();
    let tenant = uuid::Uuid::from_u128(1);
    let mut release = [0u8; 32];
    hex::decode_to_slice(golden().trim_start_matches("sha256:"), &mut release).unwrap();
    for seq in 0..3 {
        let mut b = RecordBuilder::new().seq(seq).tenant(tenant).ts(NOW.parse().unwrap()).hop(Hop::McpToolCall);
        if bound {
            b = b.release(release);
        }
        let mut r = b.build().unwrap();
        store.append(&tenant, &mut r).unwrap();
    }
    serde_json::to_value(export_bundle(&store, &tenant, &Ed25519Signer::from_bytes(&LEDGER_SEED)).unwrap()).unwrap()
}

fn events() -> Value {
    json!([
        {"type": "release_promoted", "at": "2026-10-02T00:00:00Z", "actor": "alice@acme",
         "environment": "production", "breakGlass": false},
        {"type": "release_registered", "at": "2026-09-30T09:00:00Z", "actor": "ci:acme/support",
         "agent": "support-agent", "version": "184"}
    ])
}

#[test]
fn assembles_a_pack_that_verifies() {
    let i = Inputs::new();
    let (code, out, err) = i.assemble(&[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("sha256:"), "prints the pack digest: {out}");
    let r = i.verify();
    assert!(r.ok, "{:#?}", r.failures);
    assert_eq!(r.release.as_deref(), Some(golden().as_str()));
    assert_eq!(r.exporter.as_deref(), Some("cli:acme"));
    assert_eq!(r.created_at.as_deref(), Some(CREATED));
    assert_eq!(r.runs.len(), 1);
    assert_eq!(r.certifications.len(), 1);
    assert!(r.certifications[0].certified);
    assert_eq!(r.ledger[0].release_hops, 3);
    // Events were sorted into time order.
    let pack: Value = serde_json::from_slice(&std::fs::read(i.path("pack.json")).unwrap()).unwrap();
    assert_eq!(pack["spec"]["governance"]["events"][0]["type"], "release_registered");
}

#[test]
fn ledger_exports_are_optional_but_a_registration_is_not() {
    let i = Inputs::new();
    let (code, out, err) = run(
        i.dir.path(),
        &[
            "release",
            "audit-pack",
            "--manifest",
            &manifest(),
            "--run",
            "run.json",
            "--certification",
            "cert.dsse.json",
            "--key",
            "exporter.key.json",
            "--now",
            CREATED,
            "--out",
            "pack.json",
            "--events",
            "events.json",
        ],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(i.verify().ok);

    let i = Inputs::new();
    i.write("events.json", &json!([events()[0].clone()]).to_string());
    let (code, _, err) = i.assemble(&[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("release_registered"), "{err}");
}

#[test]
fn inputs_that_could_never_verify_exit_1() {
    let i = Inputs::new();
    i.write("ledger.json", &ledger_export(false).to_string());
    let (code, _, err) = i.assemble(&[]);
    assert_eq!(code, 1, "ledger without a hop for this release: {err}");
    assert!(err.contains("ledger"), "{err}");

    let i = Inputs::new();
    i.write("events.json", &json!([{"type": "release_teleported", "at": NOW, "actor": "x"}]).to_string());
    assert_eq!(i.assemble(&[]).0, 1);

    let i = Inputs::new();
    i.write("events.json", &json!({"not": "an array"}).to_string());
    assert_eq!(i.assemble(&[]).0, 1);

    let i = Inputs::new();
    let mut run_json: Value = serde_json::from_str(&std::fs::read_to_string(i.path("run.json")).unwrap()).unwrap();
    run_json["release"] = json!(format!("sha256:{}", "ab".repeat(32)));
    i.write("run.json", &run_json.to_string());
    let (code, _, err) = i.assemble(&[]);
    assert_eq!(code, 1, "{err}");

    let i = Inputs::new();
    i.write("cert.dsse.json", "{\"payloadType\": 1}");
    assert_eq!(i.assemble(&[]).0, 1);

    let i = Inputs::new();
    assert_eq!(i.assemble(&[("--exporter", " ")]).0, 1, "an empty exporter");
}

#[test]
fn usage_and_io_errors_exit_2() {
    let i = Inputs::new();
    // No key.
    let (code, _, _) = run(i.dir.path(), &["release", "audit-pack", "--manifest", &manifest(), "--out", "p.json"]);
    assert_eq!(code, 2);
    // Missing input files.
    let mut missing = Inputs::new();
    std::fs::remove_file(missing.path("run.json")).unwrap();
    assert_eq!(missing.assemble(&[]).0, 2);
    missing = Inputs::new();
    std::fs::remove_file(missing.path("exporter.key.json")).unwrap();
    assert_eq!(missing.assemble(&[]).0, 2);
    // Bad --now.
    assert_eq!(i.assemble(&[("--now", "yesterday")]).0, 2);
}

#[test]
fn a_public_only_key_cannot_sign() {
    let i = Inputs::new();
    let t = i.trust("exporter.key.json");
    i.write("exporter.key.json", &json!({"keyid": t.keyid, "publicKey": hex::encode(t.public_key)}).to_string());
    let (code, _, err) = i.assemble(&[]);
    assert_eq!(code, 1, "{err}");
}
