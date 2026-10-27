//! `schemas/cloakpipe.manifest.schema.json` is the language-neutral, editor-
//! facing description of the v1 manifest. It must agree with the Rust loader
//! on structure (patterns, templates and conditions are semantic and checked
//! only by the loader).

use serde_json::{json, Value};
use std::path::PathBuf;

type Mutation = Box<dyn Fn(&mut Value)>;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn schema_json() -> Value {
    serde_json::from_str(&std::fs::read_to_string(root().join("schemas/cloakpipe.manifest.schema.json")).unwrap()).unwrap()
}

fn schema() -> jsonschema::Validator {
    jsonschema::validator_for(&schema_json()).expect("schema compiles")
}

fn yaml(rel: &str) -> Value {
    serde_yaml::from_str(&std::fs::read_to_string(root().join(rel)).unwrap()).unwrap()
}

const MANIFESTS: [&str; 3] = [
    "examples/support-agent/cloakpipe.manifest.yaml",
    "crates/cloakpipe-release/testdata/v1/support.manifest.yaml",
    "crates/cloakpipe-release/testdata/v1/minimal.manifest.yaml",
];

#[test]
fn manifests_the_loader_accepts_conform() {
    let v = schema();
    for m in MANIFESTS {
        cloakpipe_release::v1::Manifest::parse_path(&root().join(m)).unwrap_or_else(|e| panic!("{m}: {e}"));
        let doc = yaml(m);
        let errors: Vec<String> = v.iter_errors(&doc).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{m}: {errors:?}");
    }
}

#[test]
fn schema_id_is_in_the_current_namespace() {
    assert_eq!(schema_json()["$id"], cloakpipe_release::namespace::MANIFEST_V1_SCHEMA_ID);
}

#[test]
fn schema_rejects_what_the_loader_rejects() {
    let v = schema();
    let base = yaml("crates/cloakpipe-release/testdata/v1/support.manifest.yaml");
    let cases: Vec<(&str, Mutation)> = vec![
        ("missing release", Box::new(|m| { m.as_object_mut().unwrap().remove("release"); })),
        ("missing version", Box::new(|m| { m.as_object_mut().unwrap().remove("version"); })),
        ("empty release", Box::new(|m| m["release"] = json!(""))),
        ("unknown top-level key", Box::new(|m| m["apiVersion"] = json!("cloakpipe.co/v1alpha1"))),
        ("unknown tool key", Box::new(|m| m["tools"]["send_email"]["sideEffect"] = json!(true))),
        ("unknown constraint key", Box::new(|m| m["tools"]["send_email"]["args"]["body"]["maxLength"] = json!(3))),
        ("null type", Box::new(|m| m["tools"]["send_email"]["args"]["body"]["type"] = json!("null"))),
        ("bad effect", Box::new(|m| m["tools"]["send_email"]["effect"] = json!("delete"))),
        ("non-boolean required", Box::new(|m| m["tools"]["send_email"]["args"]["body"]["required"] = json!("yes"))),
        ("negative max_len", Box::new(|m| m["tools"]["send_email"]["args"]["body"]["max_len"] = json!(-1))),
        ("empty one_of_context", Box::new(|m| m["tools"]["send_email"]["args"]["to"]["one_of_context"] = json!([]))),
        ("approvers not strings", Box::new(|m| m["tools"]["issue_refund"]["approval"]["approvers"] = json!([1]))),
        ("unknown approval key", Box::new(|m| m["tools"]["issue_refund"]["approval"]["expires"] = json!("15m"))),
        ("malformed ttl", Box::new(|m| m["tools"]["issue_refund"]["approval"]["ttl"] = json!("15 minutes"))),
        ("args not a mapping", Box::new(|m| m["tools"]["read_ticket"]["args"] = json!(["ticket_id"]))),
        ("nested unknown key", Box::new(|m| {
            m["tools"]["read_ticket"]["args"]["filter"] = json!({"type": "object", "properties": {"a": {"type": "string", "bogus": 1}}});
        })),
    ];
    for (what, mutate) in cases {
        let mut doc = base.clone();
        mutate(&mut doc);
        assert!(!v.is_valid(&doc), "the schema accepts: {what}");
        let src = serde_yaml::to_string(&doc).unwrap();
        let base_dir = root().join("crates/cloakpipe-release/testdata/v1");
        assert!(cloakpipe_release::v1::Manifest::parse_str(&src, &base_dir).is_err(), "the loader accepts: {what}");
    }
}
