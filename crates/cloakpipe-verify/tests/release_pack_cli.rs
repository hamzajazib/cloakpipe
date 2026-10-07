//! `cloakpipe-verify release-pack` as a process: exit codes 0 ok / 1 failed
//! / 2 usage, human and JSON output, zero network.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cloakpipe-verify"))
}

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let f = Fixture { dir: tempfile::tempdir().unwrap() };
        f.write("pack.json", &serde_json::to_string_pretty(&pack()).unwrap());
        for (name, seed) in [("exporter", EXPORTER_SEED), ("ledger", LEDGER_SEED), ("cert", CERT_SEED)] {
            let t = trusted(seed);
            // Trust files carry only the public part.
            f.write(
                &format!("{name}.pub.json"),
                &json!({"keyid": t.keyid, "publicKey": hex::encode(t.public_key)}).to_string(),
            );
        }
        f
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, content: &str) {
        std::fs::write(self.path(name), content).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(bin()).current_dir(self.dir.path()).args(args).output().unwrap()
    }

    fn verify(&self, pack: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "release-pack",
            pack,
            "--trust",
            "exporter.pub.json",
            "--trust",
            "ledger.pub.json",
            "--cert-trust",
            "cert.pub.json",
            "--now",
            NOW,
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn a_valid_pack_exits_0_with_a_summary() {
    let f = Fixture::new();
    let o = f.verify("pack.json", &[]);
    assert_eq!(code(&o), 0, "stdout: {}\nstderr: {}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    assert!(out.starts_with("PASS"), "{out}");
    assert!(out.contains("TIMELINE"), "{out}");
    assert!(out.contains("production"), "{out}");
    assert!(out.contains(&release()), "{out}");
}

#[test]
fn json_output_is_the_report() {
    let f = Fixture::new();
    let o = f.verify("pack.json", &["--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let report: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["release"], release());
    assert!(report["timeline"].as_array().unwrap().len() >= 3);
}

#[test]
fn a_tampered_pack_exits_1() {
    let f = Fixture::new();
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][2]["breakGlass"] = json!(true);
    f.write("tampered.json", &doc.to_string());
    let o = f.verify("tampered.json", &[]);
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    assert!(stdout(&o).starts_with("FAIL"), "{}", stdout(&o));

    let o = f.verify("tampered.json", &["--json"]);
    assert_eq!(code(&o), 1);
    let report: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(report["ok"], false);
}

#[test]
fn a_file_that_is_not_a_pack_exits_1() {
    let f = Fixture::new();
    f.write("garbage.json", "{\"hello\": ");
    assert_eq!(code(&f.verify("garbage.json", &[])), 1);
}

#[test]
fn without_cert_trust_the_trust_keys_are_used() {
    let f = Fixture::new();
    let o = f.run(&[
        "release-pack",
        "pack.json",
        "--trust",
        "exporter.pub.json",
        "--trust",
        "ledger.pub.json",
        "--trust",
        "cert.pub.json",
        "--now",
        NOW,
    ]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    let o = f.run(&[
        "release-pack",
        "pack.json",
        "--trust",
        "exporter.pub.json",
        "--trust",
        "ledger.pub.json",
        "--now",
        NOW,
    ]);
    assert_eq!(code(&o), 1, "{}", stdout(&o));
}

#[test]
fn usage_errors_exit_2() {
    let f = Fixture::new();
    let cases: Vec<Vec<&str>> = vec![
        vec!["release-pack"],
        vec!["release-pack", "pack.json"],
        vec!["release-pack", "missing.json", "--trust", "exporter.pub.json"],
        vec!["release-pack", "pack.json", "--trust", "missing.pub.json"],
        vec!["release-pack", "pack.json", "--trust", "exporter.pub.json", "--now", "yesterday"],
        vec!["release-pack", "pack.json", "--trust", "exporter.pub.json", "--bogus"],
        vec!["release-pack", "pack.json", "--trust"],
        vec!["release-pack", "pack.json", "other.json", "--trust", "exporter.pub.json"],
    ];
    for args in cases {
        let o = f.run(&args);
        assert_eq!(code(&o), 2, "{args:?}: stdout {} stderr {}", stdout(&o), stderr(&o));
    }
}

#[test]
fn a_trust_file_whose_keyid_does_not_match_its_key_exits_2() {
    let f = Fixture::new();
    let t = trusted(EXPORTER_SEED);
    f.write(
        "liar.pub.json",
        &json!({"keyid": "ed25519:0000000000000000", "publicKey": hex::encode(t.public_key)}).to_string(),
    );
    let o = f.run(&["release-pack", "pack.json", "--trust", "liar.pub.json", "--now", NOW]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
}

#[test]
fn a_private_key_file_is_accepted_as_trust() {
    let f = Fixture::new();
    let k = key(EXPORTER_SEED);
    f.write(
        "exporter.key.json",
        &json!({"privateKey": hex::encode(k.to_bytes()), "publicKey": hex::encode(k.verifying_key().to_bytes())})
            .to_string(),
    );
    let o = f.run(&[
        "release-pack",
        "pack.json",
        "--trust",
        "exporter.key.json",
        "--trust",
        "ledger.pub.json",
        "--cert-trust",
        "cert.pub.json",
        "--now",
        NOW,
    ]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
}

#[test]
fn help_mentions_release_pack() {
    let o = Command::new(bin()).arg("help").output().unwrap();
    assert!(stdout(&o).contains("release-pack"));
    let _ = Path::new(".");
}
