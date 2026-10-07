//! `cloakpipe anchor` through the real binary, offline: every path that
//! must refuse before or instead of writing an anchored bundle. The success
//! path is tested offline against replayed recordings in `src/anchor.rs`,
//! and live against freetsa.org and rekor.sigstore.dev in the `live-anchor`
//! CI job.
//!
//! Exit codes: 0 anchored, 1 anchoring failed / refused, 2 usage or I/O.

use cloakpipe_ledger::export::{export_bundle, write_bundle};
use cloakpipe_ledger::record::{Hop, RecordBuilder};
use cloakpipe_ledger::sign::Ed25519Signer;
use cloakpipe_ledger::store::LedgerStore;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cloakpipe-verify/tests/fixtures/anchoring")
        .join(name)
        .display()
        .to_string()
}

/// An exported 3-record bundle signed with seed `[9; 32]`, plus key files.
fn setup(dir: &Path) -> (String, String, String) {
    let mut store = LedgerStore::open(dir.join("l.sqlite").to_str().unwrap()).unwrap();
    let tenant = uuid::Uuid::new_v4();
    for i in 0..3 {
        let mut r = RecordBuilder::new().seq(i).tenant(tenant).hop(Hop::LlmPrompt).build().unwrap();
        store.append(&tenant, &mut r).unwrap();
    }
    let bundle = export_bundle(&store, &tenant, &Ed25519Signer::from_bytes(&[9; 32])).unwrap();
    let b = dir.join("bundle.json");
    write_bundle(&b, &bundle).unwrap();
    let key = |name: &str, seed: [u8; 32]| {
        let p = dir.join(name);
        std::fs::write(&p, format!(r#"{{"privateKey":"{}"}}"#, hex::encode(seed))).unwrap();
        p.display().to_string()
    };
    (b.display().to_string(), key("op.json", [9; 32]), key("other.json", [8; 32]))
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe")).arg("anchor").args(args).output().expect("run cloakpipe")
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn trust_inputs_are_required_for_every_enabled_anchor() {
    let d = tempfile::tempdir().unwrap();
    let (b, key, _) = setup(d.path());
    let out = d.path().join("out.json").display().to_string();
    let rekor = fixture("rekor.pub");
    let root = fixture("freetsa-root.pem");
    for args in [
        vec![b.as_str(), "--key", &key, "--out", &out, "--rekor-key", &rekor],
        vec![b.as_str(), "--key", &key, "--out", &out, "--tsa-root", &root],
        vec![b.as_str(), "--key", &key, "--out", &out, "--no-tsa", "--no-rekor"],
        vec![b.as_str(), "--key", &key, "--out", &out, "--tsa-root", &rekor, "--rekor-key", &rekor],
        vec![b.as_str(), "--key", &key, "--out", &out, "--tsa-root", &root, "--rekor-key", &root],
        vec![b.as_str(), "--key", "/nonexistent", "--out", &out, "--tsa-root", &root, "--no-rekor"],
    ] {
        let o = run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", err(&o));
        assert!(!Path::new(&out).exists());
    }
}

#[test]
fn a_key_other_than_the_operator_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let (b, _, other) = setup(d.path());
    let out = d.path().join("out.json").display().to_string();
    let root = fixture("freetsa-root.pem");
    let o = run(&[&b, "--key", &other, "--out", &out, "--tsa-root", &root, "--no-rekor"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("operator"), "{}", err(&o));
    assert!(!Path::new(&out).exists());
}

#[test]
fn an_unreachable_anchor_writes_nothing() {
    let d = tempfile::tempdir().unwrap();
    let (b, key, _) = setup(d.path());
    let out = d.path().join("out.json").display().to_string();
    let root = fixture("freetsa-root.pem");
    let rekor = fixture("rekor.pub");
    let o = run(&[&b, "--key", &key, "--out", &out, "--tsa-url", "http://127.0.0.1:9/tsr", "--tsa-root", &root, "--no-rekor"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    let o = run(&[&b, "--key", &key, "--out", &out, "--no-tsa", "--rekor-url", "http://127.0.0.1:9", "--rekor-key", &rekor]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(!Path::new(&out).exists());
}

#[test]
fn a_tsa_that_answers_garbage_writes_nothing() {
    // A local server that answers every request with a non-timestamp.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsr", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for s in listener.incoming().flatten().take(1) {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = [0x30, 0x03, 0x02, 0x01, 0x00];
            let _ = s.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
                    .as_bytes(),
            );
            let _ = s.write_all(&body);
        }
    });
    let d = tempfile::tempdir().unwrap();
    let (b, key, _) = setup(d.path());
    let out = d.path().join("out.json").display().to_string();
    let root = fixture("freetsa-root.pem");
    let o = run(&[&b, "--key", &key, "--out", &out, "--tsa-url", &url, "--tsa-root", &root, "--no-rekor"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("rejected"), "{}", err(&o));
    assert!(!Path::new(&out).exists());
}
