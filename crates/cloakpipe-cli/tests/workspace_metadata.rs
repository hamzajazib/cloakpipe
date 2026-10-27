//! crates.io readiness of the workspace: one MIT licence, descriptions that
//! match each crate's role, publishing metadata, and a version on every path
//! dependency so `cargo publish` can resolve it.

use std::path::{Path, PathBuf};
use toml::Value;

const DESCRIPTION: &str = "Self-hosted policy-enforcement gate for AI agent tool calls";
const HOMEPAGE: &str = "https://cloakpipe.co";
/// Workspace crates that are not published to crates.io.
const UNPUBLISHED: &[&str] = &["cloakpipe-local", "cloakleak", "cloakleak-cli"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(path: &Path) -> Value {
    let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    src.parse().unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn workspace() -> Value {
    load(&root().join("Cargo.toml"))
}

/// (member dir, parsed Cargo.toml) for every workspace member.
fn members() -> Vec<(String, Value)> {
    let ws = workspace();
    let members = ws["workspace"]["members"].as_array().expect("members");
    members
        .iter()
        .map(|m| {
            let m = m.as_str().unwrap().to_string();
            let manifest = load(&root().join(&m).join("Cargo.toml"));
            (m, manifest)
        })
        .collect()
}

fn package(manifest: &Value) -> &Value {
    &manifest["package"]
}

fn name(manifest: &Value) -> String {
    package(manifest)["name"].as_str().unwrap().to_string()
}

/// A package field is set directly or inherited with `field.workspace = true`.
fn field<'a>(manifest: &'a Value, ws: &'a Value, key: &str) -> Option<&'a Value> {
    let v = package(manifest).get(key)?;
    if v.get("workspace").and_then(Value::as_bool) == Some(true) {
        ws["workspace"]["package"].get(key)
    } else {
        Some(v)
    }
}

#[test]
fn the_workspace_describes_the_gate() {
    let ws = workspace();
    let p = &ws["workspace"]["package"];
    assert_eq!(p["description"].as_str(), Some(DESCRIPTION));
    assert_eq!(p["homepage"].as_str(), Some(HOMEPAGE));
    assert_eq!(p["license"].as_str(), Some("MIT"));
}

#[test]
fn every_crate_is_mit_under_the_one_root_licence() {
    let ws = workspace();
    for (dir, m) in members() {
        let license = field(&m, &ws, "license").and_then(Value::as_str);
        assert_eq!(license, Some("MIT"), "{dir}: license");
        assert!(package(&m).get("license-file").is_none(), "{dir}: license-file");
        for entry in std::fs::read_dir(root().join(&dir)).unwrap() {
            let f = entry.unwrap().file_name().to_string_lossy().to_uppercase();
            assert!(!f.starts_with("LICENSE") && !f.starts_with("COPYING"), "{dir}: own licence file {f}");
        }
    }
    let licence = std::fs::read_to_string(root().join("LICENSE")).unwrap();
    assert!(licence.starts_with("MIT License"), "root LICENSE is MIT");
}

#[test]
fn every_crate_has_publishing_metadata() {
    let ws = workspace();
    for (dir, m) in members() {
        let desc = field(&m, &ws, "description").and_then(Value::as_str).unwrap_or_default();
        assert!(!desc.is_empty(), "{dir}: description");
        assert_eq!(field(&m, &ws, "homepage").and_then(Value::as_str), Some(HOMEPAGE), "{dir}: homepage");
        let readme = field(&m, &ws, "readme").and_then(Value::as_str).unwrap_or_else(|| panic!("{dir}: readme"));
        // An inherited readme is relative to the workspace root, an own one to the crate.
        let inherited = package(&m)["readme"].get("workspace").is_some();
        let base = if inherited { root() } else { root().join(&dir) };
        assert!(base.join(readme).is_file(), "{dir}: readme {readme} does not exist");
        let keywords = field(&m, &ws, "keywords").and_then(Value::as_array).unwrap_or_else(|| panic!("{dir}: keywords"));
        assert!((1..=5).contains(&keywords.len()), "{dir}: crates.io takes 1 to 5 keywords");
        for k in keywords {
            let k = k.as_str().unwrap();
            assert!(k.len() <= 20 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "{dir}: keyword {k:?}");
        }
        let categories = field(&m, &ws, "categories").and_then(Value::as_array).unwrap_or_else(|| panic!("{dir}: categories"));
        assert!((1..=5).contains(&categories.len()), "{dir}: categories");
    }
}

#[test]
fn the_gate_crates_are_not_described_as_a_privacy_proxy() {
    let ws = workspace();
    for (dir, m) in members() {
        let n = name(&m);
        if n == "cloakpipe-cli" || n == "cloakpipe-mcp" {
            let desc = field(&m, &ws, "description").and_then(Value::as_str).unwrap().to_lowercase();
            assert!(!desc.contains("privacy proxy"), "{dir}: {desc}");
            assert!(!desc.contains("privacy tools"), "{dir}: {desc}");
            assert!(desc.contains("gate"), "{dir}: {desc}");
        }
    }
}

#[test]
fn only_the_internal_crates_are_unpublished() {
    for (dir, m) in members() {
        let n = name(&m);
        let publish = package(&m).get("publish").and_then(Value::as_bool);
        if UNPUBLISHED.contains(&n.as_str()) {
            assert_eq!(publish, Some(false), "{dir}: publish = false");
        } else {
            assert_eq!(publish, None, "{dir}: is published");
        }
    }
}

/// `cargo publish` needs a version on every normal and build path
/// dependency. Dev-dependencies may stay path-only: cargo strips them.
#[test]
fn every_path_dependency_has_the_workspace_version() {
    let ws = workspace();
    let version = ws["workspace"]["package"]["version"].as_str().unwrap();
    for (dir, m) in members() {
        let mut tables = vec![m.get("dependencies"), m.get("build-dependencies")];
        if let Some(targets) = m.get("target").and_then(Value::as_table) {
            for t in targets.values() {
                tables.push(t.get("dependencies"));
                tables.push(t.get("build-dependencies"));
            }
        }
        for table in tables.into_iter().flatten() {
            for (dep, spec) in table.as_table().unwrap() {
                if spec.get("path").is_some() {
                    assert_eq!(
                        spec.get("version").and_then(Value::as_str),
                        Some(version),
                        "{dir}: path dependency {dep} needs version = \"{version}\""
                    );
                }
            }
        }
    }
}
