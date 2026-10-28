//! `scripts/publish-crates.sh` resumes a partly published release: it skips
//! crate versions already on crates.io and waits out crates.io's new-crate
//! rate limit (HTTP 429). `cargo` and `curl` are stubbed on PATH.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const METADATA: &str = r#"{"packages":[
  {"name":"a","version":"1.0.0","publish":null},
  {"name":"b","version":"1.0.0","publish":null},
  {"name":"private","version":"1.0.0","publish":[]}]}"#;

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/publish-crates.sh")
}

fn stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/usr/bin/env bash\n{body}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Runs the script with crates in `published` already on crates.io, and a
/// `cargo publish` that answers with each of `publish_results` in turn
/// ("ok", "429" or "fail").
fn run(published: &str, publish_results: &[&str]) -> (Output, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(dir.path().join("metadata.json"), METADATA).unwrap();
    std::fs::write(dir.path().join("results"), publish_results.join("\n") + "\n").unwrap();
    stub(
        &bin,
        "cargo",
        r#"
case "$1" in
  metadata) cat "$STUB_DIR/metadata.json" ;;
  publish)
    echo "$*" >> "$STUB_DIR/publish.log"
    result=$(head -n1 "$STUB_DIR/results"); sed -i.bak 1d "$STUB_DIR/results"
    case "$result" in
      ok) exit 0 ;;
      429) echo "error: the remote server responded with an error (status 429 Too Many Requests)" >&2; exit 101 ;;
      *) echo "error: failed to verify package" >&2; exit 101 ;;
    esac ;;
esac
"#,
    );
    stub(
        &bin,
        "curl",
        r#"
url="${@: -1}"; crate=$(echo "$url" | awk -F/ '{print $(NF-1)}')
for p in $STUB_PUBLISHED; do [ "$p" = "$crate" ] && { printf 200; exit 0; }; done
printf 404
"#,
    );
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let out = Command::new("bash")
        .arg(script())
        .env("PATH", path)
        .env("STUB_DIR", dir.path())
        .env("STUB_PUBLISHED", published)
        .env("PUBLISH_RETRY_SECS", "0")
        .output()
        .unwrap();
    let calls = std::fs::read_to_string(dir.path().join("publish.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    (out, calls)
}

#[test]
fn versions_already_on_crates_io_are_excluded() {
    let (out, calls) = run("a", &["ok"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(calls, ["publish --workspace --locked --exclude a"]);
}

#[test]
fn a_fully_published_release_publishes_nothing() {
    let (out, calls) = run("a b", &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(calls.is_empty(), "{calls:?}");
}

#[test]
fn a_rate_limited_publish_is_retried() {
    let (out, calls) = run("", &["429", "ok"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(calls.len(), 2, "{calls:?}");
}

#[test]
fn any_other_publish_error_fails_at_once() {
    let (out, calls) = run("", &["fail", "ok"]);
    assert!(!out.status.success());
    assert_eq!(calls.len(), 1, "{calls:?}");
}

#[test]
fn the_release_workflow_publishes_through_the_script() {
    let wf = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml")).unwrap();
    assert!(wf.contains("run: ../tools/scripts/publish-crates.sh"));
}

/// A manual run re-publishes an old tag, which may predate the script: the
/// tag is checked out into `src`, the workflow's own commit into `tools`.
#[test]
fn the_script_comes_from_the_workflow_commit_not_the_tag() {
    let wf: serde_yaml::Value = serde_yaml::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml")).unwrap(),
    )
    .unwrap();
    let steps = wf["jobs"]["crates"]["steps"].as_sequence().unwrap();
    let checkout = |path: &str| {
        steps
            .iter()
            .find(|s| s["with"]["path"].as_str() == Some(path))
            .unwrap_or_else(|| panic!("no checkout into `{path}`"))
            .clone()
    };
    assert!(checkout("src")["with"]["ref"].as_str().unwrap().contains("inputs.tag"));
    assert_eq!(checkout("tools")["with"]["ref"].as_str(), Some("${{ github.sha }}"));
    for step in steps.iter().filter(|s| s.get("run").is_some()) {
        assert_eq!(step["working-directory"].as_str(), Some("src"), "{step:?}");
    }
}
