//! The default `cloakpipe` binary is the lean gate: the tool-call gate, its
//! evidence and regex PII detection. NER (`ner`), RAG tooling (`rag`) and
//! release certification (`certification`) are cargo features, all off by
//! default; `full` turns them all on. These tests pin which subcommands each
//! build exposes and that the PII paths keep working on regex alone.

use std::path::Path;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn run(dir: &Path, args: &[&str]) -> Output {
    bin().current_dir(dir).args(args).output().expect("run cloakpipe")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The names in the `Commands:` section of a `--help` page.
fn subcommands(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

fn top_level() -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["--help"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    subcommands(&text(&out.stdout))
}

fn release_level() -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["release", "--help"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    subcommands(&text(&out.stdout))
}

#[test]
fn the_gate_and_regex_pii_commands_are_always_built() {
    let cmds = top_level();
    for c in ["start", "test", "scan", "mcp", "mcp-proxy", "release", "anchor", "action", "approve", "operations"] {
        assert!(cmds.iter().any(|x| x == c), "`{c}` missing from {cmds:?}");
    }
    let release = release_level();
    for c in ["validate", "hash", "diff", "inspect", "keygen"] {
        assert!(release.iter().any(|x| x == c), "`release {c}` missing from {release:?}");
    }
}

#[test]
fn the_cli_describes_itself_as_a_gate() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["--help"]);
    let help = text(&out.stdout);
    assert!(help.contains("policy-enforcement gate"), "{help}");
    assert!(!help.contains("Privacy middleware"), "{help}");
}

#[cfg(not(feature = "rag"))]
#[test]
fn rag_commands_need_the_rag_feature() {
    let cmds = top_level();
    assert!(!cmds.iter().any(|c| c == "tree" || c == "vector"), "{cmds:?}");
    let dir = tempfile::tempdir().unwrap();
    for args in [&["tree", "list"][..], &["vector", "test"][..]] {
        let out = run(dir.path(), args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("unrecognized subcommand"), "{}", text(&out.stderr));
    }
}

#[cfg(feature = "rag")]
#[test]
fn rag_commands_are_built_with_the_rag_feature() {
    let cmds = top_level();
    assert!(cmds.iter().any(|c| c == "tree"), "{cmds:?}");
    assert!(cmds.iter().any(|c| c == "vector"), "{cmds:?}");
}

#[cfg(not(feature = "certification"))]
#[test]
fn certification_commands_need_the_certification_feature() {
    let cmds = top_level();
    assert!(!cmds.iter().any(|c| c == "eval"), "{cmds:?}");
    let release = release_level();
    for c in ["certify", "verify-cert", "audit-pack"] {
        assert!(!release.iter().any(|x| x == c), "`release {c}` is built without certification: {release:?}");
    }
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["eval", "import", "--help"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let out = run(dir.path(), &["release", "certify", "--help"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
}

#[cfg(feature = "certification")]
#[test]
fn certification_commands_are_built_with_the_certification_feature() {
    assert!(top_level().iter().any(|c| c == "eval"));
    let release = release_level();
    for c in ["certify", "verify-cert", "audit-pack"] {
        assert!(release.iter().any(|x| x == c), "`release {c}` missing: {release:?}");
    }
}

/// Approver and exporter keys do not depend on certification.
#[test]
fn keygen_works_in_every_build() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["release", "keygen", "--out", "k.json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let public: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(public["keyid"].as_str().unwrap().starts_with("ed25519:"));
    assert!(public.get("privateKey").is_none());
}

const CONFIG: &str = r#"
[proxy]
listen = "127.0.0.1:0"
upstream = "http://127.0.0.1:9"
api_key_env = "OPENAI_API_KEY"
timeout_seconds = 5
max_concurrent = 4
mode = "proxy"

[vault]
path = "vault.enc"
encryption = "aes-256-gcm"
key_env = "CLOAKPIPE_VAULT_KEY"

[detection]
secrets = true
financial = true
dates = true
emails = true
phone_numbers = false
ip_addresses = false
urls_internal = false

[detection.ner]
enabled = true
backend = "bert"
"#;

/// A config that asks for NER still runs on regex in the lean build, and
/// says on stderr that the NER layer is not built in.
#[cfg(not(feature = "ner"))]
#[test]
fn ner_config_falls_back_to_regex_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cloakpipe.toml"), CONFIG).unwrap();
    let out = run(dir.path(), &["test", "--text", "mail dana@customer.example now"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.contains("dana@customer.example"), "{stdout}");
    assert!(stdout.contains("Email"), "the regex layer still detects the email: {stdout}");
    assert!(stderr.contains("`ner` feature"), "{stderr}");
}

/// With `ner`, the NER detectors are compiled in: asking for the BERT
/// backend without a model is a hard error, not a silent regex fallback.
#[cfg(feature = "ner")]
#[test]
fn ner_config_reaches_the_ner_detectors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cloakpipe.toml"), CONFIG).unwrap();
    let out = run(dir.path(), &["test", "--text", "mail dana@customer.example now"]);
    assert!(!text(&out.stderr).contains("`ner` feature"), "{}", text(&out.stderr));
}

#[test]
fn scan_detects_with_regex() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "write to dana@customer.example").unwrap();
    let out = run(dir.path(), &["scan", "a.txt", "--detect-only"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("Total entities: 1"), "{}", text(&out.stdout));
}
