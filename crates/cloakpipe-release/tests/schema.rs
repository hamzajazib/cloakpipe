//! `schemas/agent-release.schema.json` is the language-neutral contract. It
//! must agree with the Rust validator on structure. (Mutable-alias detection,
//! e.g. `@latest`, is semantic and lives only in `validate()`.)

use serde_json::{json, Value};

/// A named edit applied to a manifest under test.
type Mutation = Box<dyn Fn(&mut Value)>;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn schema() -> jsonschema::Validator {
    let s: Value = serde_json::from_str(&std::fs::read_to_string(root().join("schemas/agent-release.schema.json")).unwrap()).unwrap();
    jsonschema::validator_for(&s).expect("schema compiles")
}

fn fixture_json() -> Value {
    let p = root().join("crates/cloakpipe-release/testdata/support-agent-184.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn fixture_yaml(name: &str) -> Value {
    let p = root().join("crates/cloakpipe-release/testdata").join(name);
    serde_yaml::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn fixtures_conform() {
    let v = schema();
    assert!(v.is_valid(&fixture_json()));
    assert!(v.is_valid(&fixture_yaml("support-agent-184.yaml")));
    assert!(v.is_valid(&fixture_yaml("support-agent-185.yaml")));
}

#[test]
fn schema_accepts_legacy_namespace_manifests() {
    // Manifests written before the cloakpipe.co rename stay valid.
    assert!(schema().is_valid(&fixture_yaml("support-agent-184.legacy.yaml")));
}

#[test]
fn schema_id_is_in_the_current_namespace() {
    let s: Value = serde_json::from_str(&std::fs::read_to_string(root().join("schemas/agent-release.schema.json")).unwrap()).unwrap();
    assert_eq!(s["$id"], cloakpipe_release::namespace::AGENT_RELEASE_SCHEMA_ID);
}

#[test]
fn schema_rejects_structural_errors() {
    let v = schema();
    let cases: Vec<(&str, Mutation)> = vec![
        ("unknown field", Box::new(|m| m["spec"]["toolz"] = json!([]))),
        ("wrong kind", Box::new(|m| m["kind"] = json!("Deployment"))),
        ("wrong apiVersion", Box::new(|m| m["apiVersion"] = json!("cloakpipe.dev/v9"))),
        ("wrong apiVersion (current namespace)", Box::new(|m| m["apiVersion"] = json!("cloakpipe.co/v9"))),
        ("foreign apiVersion domain", Box::new(|m| m["apiVersion"] = json!("cloakpipe.com/v1alpha1"))),
        ("malformed ref", Box::new(|m| m["spec"]["tools"][0]["ref"] = json!("refund@4"))),
        ("unversioned ref", Box::new(|m| m["spec"]["model"]["ref"] = json!("model:openai/gpt-5"))),
        ("moving label", Box::new(|m| m["spec"]["model"]["ref"] = json!("model:openai/gpt-5@nightly"))),
        ("wrong ref kind", Box::new(|m| m["spec"]["tools"][0]["ref"] = json!("prompt:refund@4"))),
        ("bad commit", Box::new(|m| m["spec"]["code"]["commit"] = json!("main"))),
        ("unpinned image", Box::new(|m| m["spec"]["runtime"]["image"] = json!("acme/agent:latest"))),
        ("no prompts", Box::new(|m| m["spec"]["prompts"] = json!([]))),
        ("missing model", Box::new(|m| { m["spec"].as_object_mut().unwrap().remove("model"); })),
    ];
    for (name, mutate) in cases {
        let mut m = fixture_json();
        mutate(&mut m);
        assert!(!v.is_valid(&m), "schema should reject: {name}");
    }
}
