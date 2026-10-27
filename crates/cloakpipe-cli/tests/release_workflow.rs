//! The release workflow publishes every `v*` tag to crates.io, can re-publish
//! an existing tag on demand, and never re-pushes images for a manual run.

use serde_yaml::Value;
use std::path::Path;

fn workflow() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_yaml::from_str(&src).unwrap()
}

fn job<'a>(wf: &'a Value, name: &str) -> &'a Value {
    wf["jobs"].get(name).unwrap_or_else(|| panic!("release.yml has no `{name}` job"))
}

fn run_steps(job: &Value) -> String {
    job["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|s| s.get("run").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn tags_and_manual_runs_trigger_the_release() {
    let wf = workflow();
    // serde_yaml reads the bare `on:` key as the boolean true.
    let on = wf.get("on").or_else(|| wf.get(Value::Bool(true))).expect("on:");
    assert_eq!(on["push"]["tags"][0].as_str(), Some("v*"));
    let input = &on["workflow_dispatch"]["inputs"]["tag"];
    assert_eq!(input["required"].as_bool(), Some(true), "manual runs name the tag to publish");
}

#[test]
fn every_release_is_published_to_crates_io() {
    let wf = workflow();
    let crates = job(&wf, "crates");
    let env = &crates["env"];
    assert_eq!(
        env["CARGO_REGISTRY_TOKEN"].as_str(),
        Some("${{ secrets.CARGO_REGISTRY_TOKEN }}"),
        "the token comes from the repo secret, never the workflow file"
    );
    let run = run_steps(crates);
    assert!(run.contains("cargo publish --workspace"), "publishes every publishable crate");
    assert!(run.contains("CARGO_REGISTRY_TOKEN secret is not set"), "fails with a clear message without the secret");
    assert!(run.contains("Cargo.toml"), "checks the tag against the workspace version");
}

#[test]
fn manual_runs_publish_the_named_tag_only_to_crates_io() {
    let wf = workflow();
    let checkout = job(&wf, "crates")["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|s| s["uses"].as_str().is_some_and(|u| u.starts_with("actions/checkout")))
        .expect("checkout step");
    assert!(checkout["with"]["ref"].as_str().unwrap().contains("inputs.tag"));
    for name in ["docker", "release"] {
        let cond = job(&wf, name)["if"].as_str().unwrap_or_default();
        assert!(cond.contains("github.event_name == 'push'"), "`{name}` runs only for a pushed tag");
    }
}
