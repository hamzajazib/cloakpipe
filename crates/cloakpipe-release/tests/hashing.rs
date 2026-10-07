//! PRD 01: "The same normalized manifest produces the same hash; any material
//! field change produces a different hash."

use cloakpipe_release::{parse_path, parse_str, AgentRelease, Format};
use proptest::prelude::*;
use serde_json::{json, Value};

/// A named edit applied to a manifest under test.
type Mutation = Box<dyn Fn(&mut Value)>;
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn base_json() -> Value {
    let src = std::fs::read_to_string(testdata("support-agent-184.json")).unwrap();
    serde_json::from_str(&src).unwrap()
}

fn release(v: &Value) -> AgentRelease {
    parse_str(&v.to_string(), Format::Json).unwrap()
}

fn hash_of(v: &Value) -> String {
    release(v).manifest_hash().to_string()
}

#[test]
fn hash_has_algorithm_prefix_and_hex_digest() {
    let h = hash_of(&base_json());
    let hex = h.strip_prefix("sha256:").expect("sha256: prefix");
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn golden_hash_is_stable_across_versions_of_this_crate() {
    // If this changes, every previously issued release hash is invalidated.
    // Only update it together with a new hash domain (cloakpipe.co/agent-release/v2).
    // The legacy golden (cloakpipe.dev namespace) is pinned in tests/namespace.rs.
    let r = parse_path(&testdata("support-agent-184.yaml")).unwrap();
    assert_eq!(r.manifest_hash().to_string(), include_str!("../testdata/support-agent-184.hash").trim());
}

#[test]
fn yaml_and_json_with_different_key_and_set_order_hash_identically() {
    let y = parse_path(&testdata("support-agent-184.yaml")).unwrap();
    let j = parse_path(&testdata("support-agent-184.json")).unwrap();
    assert_eq!(y.manifest_hash(), j.manifest_hash());
}

#[test]
fn hashing_is_deterministic() {
    let v = base_json();
    assert_eq!(hash_of(&v), hash_of(&v));
}

#[test]
fn non_material_fields_do_not_change_the_hash() {
    let base = hash_of(&base_json());

    let mut v = base_json();
    v["metadata"]["version"] = json!("999");
    assert_eq!(hash_of(&v), base, "release number is a label, not behaviour");

    let mut v = base_json();
    v["metadata"]["labels"] = json!({"owner": "someone-else"});
    assert_eq!(hash_of(&v), base, "labels are not behaviour");
}

#[test]
fn unordered_collections_are_order_insensitive() {
    let base = hash_of(&base_json());
    for field in ["tools", "policies", "mcpServers", "dependencies"] {
        let mut v = base_json();
        v["spec"][field].as_array_mut().unwrap().reverse();
        assert_eq!(hash_of(&v), base, "{field} is a set");
    }
}

#[test]
fn prompt_order_is_semantic() {
    let mut a = base_json();
    a["spec"]["prompts"] = json!([{"ref": "prompt:system@1"}, {"ref": "prompt:footer@2"}]);
    let mut b = a.clone();
    b["spec"]["prompts"].as_array_mut().unwrap().reverse();
    assert_ne!(hash_of(&a), hash_of(&b));
}

#[test]
fn every_material_field_changes_the_hash() {
    let base = hash_of(&base_json());
    let mutations: Vec<(&str, Mutation)> = vec![
        ("agent", Box::new(|v| v["metadata"]["agent"] = json!("other-agent"))),
        ("code.repository", Box::new(|v| v["spec"]["code"]["repository"] = json!("acme/fork"))),
        ("code.commit", Box::new(|v| v["spec"]["code"]["commit"] = json!("8fd29ad"))),
        ("prompt", Box::new(|v| v["spec"]["prompts"][0]["ref"] = json!("prompt:support-answer@32"))),
        ("model", Box::new(|v| v["spec"]["model"]["ref"] = json!("model:openai/gpt-5@2026-09-01"))),
        ("parameter value", Box::new(|v| v["spec"]["parameters"]["temperature"] = json!(0.3))),
        ("parameter added", Box::new(|v| v["spec"]["parameters"]["top_p"] = json!(0.9))),
        ("tool version", Box::new(|v| v["spec"]["tools"][0]["ref"] = json!("tool:refund@5"))),
        ("tool added", Box::new(|v| v["spec"]["tools"].as_array_mut().unwrap().push(json!({"ref": "tool:send-email@2"})))),
        ("mcp", Box::new(|v| v["spec"]["mcpServers"][0]["ref"] = json!("mcp:crm@13"))),
        ("retrieval", Box::new(|v| v["spec"]["retrieval"]["ref"] = json!("retrieval:support@23"))),
        ("retrieval removed", Box::new(|v| { v["spec"].as_object_mut().unwrap().remove("retrieval"); })),
        ("policy", Box::new(|v| v["spec"]["policies"][0]["ref"] = json!("policy:support-prod@12"))),
        ("runtime.image", Box::new(|v| v["spec"]["runtime"]["image"] = json!("registry.acme.dev/support-agent@sha256:0000000000000000000000000000000000000000000000000000000000000000"))),
        ("runtime.region", Box::new(|v| v["spec"]["runtime"]["region"] = json!("eu-west"))),
        ("dependency", Box::new(|v| v["spec"]["dependencies"][0]["version"] = json!("2.4.2"))),
        ("feature flag", Box::new(|v| v["spec"]["featureFlags"] = json!({"new_router": true}))),
    ];
    for (name, mutate) in mutations {
        let mut v = base_json();
        mutate(&mut v);
        assert_ne!(hash_of(&v), base, "changing {name} must change the hash");
    }
}

#[test]
fn unicode_equivalent_strings_hash_identically() {
    // "é" precomposed (NFC) vs "e" + combining acute (NFD).
    let mut a = base_json();
    a["spec"]["parameters"]["greeting"] = json!("caf\u{00e9}");
    let mut b = base_json();
    b["spec"]["parameters"]["greeting"] = json!("cafe\u{0301}");
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn numeric_representation_is_canonical() {
    let a = parse_str(&base_json().to_string().replace("1200", "1200.0"), Format::Json).unwrap();
    let b = release(&base_json());
    assert_eq!(a.manifest_hash(), b.manifest_hash(), "1200 and 1200.0 are the same number");
}

#[test]
fn unknown_fields_are_rejected_rather_than_silently_ignored() {
    let mut v = base_json();
    v["spec"]["toolz"] = json!([]);
    assert!(parse_str(&v.to_string(), Format::Json).is_err());
}

proptest! {
    #[test]
    fn any_parameter_value_change_changes_the_hash(a in -1.0e6f64..1.0e6, b in -1.0e6f64..1.0e6) {
        prop_assume!(a != b);
        let mut va = base_json();
        va["spec"]["parameters"]["temperature"] = json!(a);
        let mut vb = base_json();
        vb["spec"]["parameters"]["temperature"] = json!(b);
        prop_assert_ne!(hash_of(&va), hash_of(&vb));
    }

    #[test]
    fn tool_set_order_never_matters(seed in any::<u64>()) {
        let mut v = base_json();
        let tools: Vec<Value> = (0..6).map(|i| json!({"ref": format!("tool:t{i}@{i}")})).collect();
        v["spec"]["tools"] = Value::Array(tools.clone());
        let base = hash_of(&v);
        let mut shuffled = tools;
        // Deterministic Fisher-Yates from the seed.
        let mut s = seed;
        for i in (1..shuffled.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            shuffled.swap(i, (s >> 33) as usize % (i + 1));
        }
        v["spec"]["tools"] = Value::Array(shuffled);
        prop_assert_eq!(hash_of(&v), base);
    }
}

#[test]
fn release_hash_parses_its_own_display_form() {
    let h = release(&base_json()).manifest_hash();
    let parsed: cloakpipe_release::ReleaseHash = h.to_string().parse().unwrap();
    assert_eq!(parsed, h);
}

#[test]
fn release_hash_rejects_malformed_input() {
    for bad in ["", "ae7b", "sha256:", "sha1:ae7bc9e404c194c9fcf80d95cafe4c322e4e9f69595c693ffb48441647d03c32",
                "sha256:AE7BC9E404C194C9FCF80D95CAFE4C322E4E9F69595C693FFB48441647D03C32",
                "sha256:ae7bc9e404c194c9fcf80d95cafe4c322e4e9f69595c693ffb48441647d03c3"] {
        assert!(bad.parse::<cloakpipe_release::ReleaseHash>().is_err(), "{bad:?}");
    }
}
