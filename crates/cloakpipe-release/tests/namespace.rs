//! Format identifiers live in the `cloakpipe.co` namespace. Objects written
//! before the rename carry `cloakpipe.dev` identifiers; readers keep accepting
//! them and hash them exactly as they were hashed when issued.

use cloakpipe_release::namespace::{self, Namespace};
use cloakpipe_release::{diff, parse_path, parse_str, Format, IssueCode};
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn pinned(name: &str) -> String {
    std::fs::read_to_string(testdata(name)).unwrap().trim().to_string()
}

#[test]
fn current_identifiers_use_the_cloakpipe_co_namespace() {
    assert_eq!(namespace::NAMESPACE, "cloakpipe.co");
    assert_eq!(namespace::API_VERSION, "cloakpipe.co/v1alpha1");
    assert_eq!(namespace::AGENT_RELEASE_HASH_DOMAIN, "cloakpipe.co/agent-release/v1");
    assert_eq!(namespace::EVALUATION_RUN_HASH_DOMAIN, "cloakpipe.co/evaluation-run/v1");
    assert_eq!(namespace::CERTIFICATION_POLICY_HASH_DOMAIN, "cloakpipe.co/certification-policy/v1");
    assert_eq!(namespace::RELEASE_AUDIT_PACK_SIGNING_DOMAIN, "cloakpipe.co/release-audit-pack/v1alpha1");
    assert_eq!(
        namespace::AGENT_RELEASE_PREDICATE_TYPE,
        "https://cloakpipe.co/attestations/agent-release/v1alpha1"
    );
    assert_eq!(
        namespace::CERTIFICATION_PREDICATE_TYPE,
        "https://cloakpipe.co/attestations/certification/v1alpha1"
    );
    assert_eq!(namespace::AGENT_RELEASE_SCHEMA_ID, "https://cloakpipe.co/schemas/agent-release/v1alpha1.json");

    // The crate-level aliases are the current values.
    assert_eq!(cloakpipe_release::API_VERSION, namespace::API_VERSION);
    assert_eq!(cloakpipe_release::HASH_DOMAIN, namespace::AGENT_RELEASE_HASH_DOMAIN);
    assert_eq!(cloakpipe_release::PREDICATE_TYPE, namespace::AGENT_RELEASE_PREDICATE_TYPE);
}

#[test]
fn legacy_identifiers_are_the_exact_pre_rename_values() {
    assert_eq!(namespace::LEGACY_NAMESPACE, "cloakpipe.dev");
    assert_eq!(namespace::LEGACY_API_VERSION, "cloakpipe.dev/v1alpha1");
    assert_eq!(namespace::LEGACY_AGENT_RELEASE_HASH_DOMAIN, "cloakpipe.dev/agent-release/v1");
    assert_eq!(namespace::LEGACY_EVALUATION_RUN_HASH_DOMAIN, "cloakpipe.dev/evaluation-run/v1");
    assert_eq!(namespace::LEGACY_CERTIFICATION_POLICY_HASH_DOMAIN, "cloakpipe.dev/certification-policy/v1");
    assert_eq!(namespace::LEGACY_RELEASE_AUDIT_PACK_SIGNING_DOMAIN, "cloakpipe.dev/release-audit-pack/v1alpha1");
    assert_eq!(
        namespace::LEGACY_AGENT_RELEASE_PREDICATE_TYPE,
        "https://cloakpipe.dev/attestations/agent-release/v1alpha1"
    );
    assert_eq!(
        namespace::LEGACY_CERTIFICATION_PREDICATE_TYPE,
        "https://cloakpipe.dev/attestations/certification/v1alpha1"
    );
    assert_eq!(
        namespace::LEGACY_AGENT_RELEASE_SCHEMA_ID,
        "https://cloakpipe.dev/schemas/agent-release/v1alpha1.json"
    );
}

#[test]
fn namespace_enum_maps_every_identifier() {
    for ns in [Namespace::Current, Namespace::Legacy] {
        let d = ns.domain();
        assert_eq!(ns.api_version(), format!("{d}/v1alpha1"));
        assert_eq!(ns.agent_release_hash_domain(), format!("{d}/agent-release/v1"));
        assert_eq!(ns.evaluation_run_hash_domain(), format!("{d}/evaluation-run/v1"));
        assert_eq!(ns.certification_policy_hash_domain(), format!("{d}/certification-policy/v1"));
        assert_eq!(ns.release_audit_pack_signing_domain(), format!("{d}/release-audit-pack/v1alpha1"));
        assert_eq!(ns.agent_release_predicate_type(), format!("https://{d}/attestations/agent-release/v1alpha1"));
        assert_eq!(ns.certification_predicate_type(), format!("https://{d}/attestations/certification/v1alpha1"));
        assert_eq!(ns.agent_release_schema_id(), format!("https://{d}/schemas/agent-release/v1alpha1.json"));
    }
    assert_eq!(Namespace::Current.domain(), namespace::NAMESPACE);
    assert_eq!(Namespace::Legacy.domain(), namespace::LEGACY_NAMESPACE);
}

#[test]
fn both_namespaces_of_the_supported_api_version_are_accepted() {
    assert!(namespace::is_known_api_version("cloakpipe.co/v1alpha1"));
    assert!(namespace::is_known_api_version("cloakpipe.dev/v1alpha1"));
    assert_eq!(Namespace::of_api_version("cloakpipe.co/v1alpha1"), Some(Namespace::Current));
    assert_eq!(Namespace::of_api_version("cloakpipe.dev/v1alpha1"), Some(Namespace::Legacy));
}

#[test]
fn unsupported_versions_and_other_domains_fail_closed() {
    for bad in [
        "cloakpipe.co/v2",
        "cloakpipe.dev/v2",
        "cloakpipe.co/v0",
        "cloakpipe.dev/v9",
        "cloakpipe.com/v1alpha1",
        "example.com/v1alpha1",
        "evil.cloakpipe.co/v1alpha1",
        "https://cloakpipe.co/v1alpha1",
        "CLOAKPIPE.CO/v1alpha1",
        "cloakpipe.co/v1alpha1 ",
        "v1alpha1",
        "",
    ] {
        assert!(!namespace::is_known_api_version(bad), "{bad:?}");
        assert_eq!(Namespace::of_api_version(bad), None, "{bad:?}");
    }
}

#[test]
fn predicate_types_accept_both_namespaces_only() {
    for ok in [
        "https://cloakpipe.co/attestations/agent-release/v1alpha1",
        "https://cloakpipe.dev/attestations/agent-release/v1alpha1",
    ] {
        assert!(namespace::is_known_agent_release_predicate_type(ok), "{ok}");
        assert!(!namespace::is_known_certification_predicate_type(ok), "{ok}");
    }
    for ok in [
        "https://cloakpipe.co/attestations/certification/v1alpha1",
        "https://cloakpipe.dev/attestations/certification/v1alpha1",
    ] {
        assert!(namespace::is_known_certification_predicate_type(ok), "{ok}");
        assert!(!namespace::is_known_agent_release_predicate_type(ok), "{ok}");
    }
    for bad in [
        "https://cloakpipe.co/attestations/certification/v2",
        "https://cloakpipe.dev/attestations/certification/v2",
        "https://cloakpipe.com/attestations/certification/v1alpha1",
        "http://cloakpipe.co/attestations/certification/v1alpha1",
        "",
    ] {
        assert!(!namespace::is_known_certification_predicate_type(bad), "{bad:?}");
        assert!(!namespace::is_known_agent_release_predicate_type(bad), "{bad:?}");
    }
}

#[test]
fn hash_domain_follows_the_manifest_api_version() {
    assert_eq!(Namespace::for_hashing("cloakpipe.dev/v1alpha1"), Namespace::Legacy);
    assert_eq!(Namespace::for_hashing("cloakpipe.co/v1alpha1"), Namespace::Current);
    // Unsupported versions are rejected by validation; hashing them is
    // defined (current domain) so `manifest_hash` stays total.
    assert_eq!(Namespace::for_hashing("cloakpipe.dev/v2"), Namespace::Current);
}

#[test]
fn new_manifests_are_in_the_cloakpipe_co_namespace() {
    for f in ["support-agent-184.yaml", "support-agent-184.json", "support-agent-185.yaml", "edge-cases.json"] {
        let r = parse_path(&testdata(f)).unwrap();
        assert_eq!(r.api_version, "cloakpipe.co/v1alpha1", "{f}");
        assert_eq!(r.validate(), vec![], "{f}");
    }
}

#[test]
fn legacy_manifest_validates_and_keeps_its_issued_hash() {
    let r = parse_path(&testdata("support-agent-184.legacy.yaml")).unwrap();
    assert_eq!(r.api_version, "cloakpipe.dev/v1alpha1", "never rewritten on read");
    assert_eq!(r.validate(), vec![]);
    // Hash issued by CloakPipe <= 0.10 for this exact manifest.
    assert_eq!(pinned("support-agent-184.legacy.hash"), "sha256:ae7bc9e404c194c9fcf80d95cafe4c322e4e9f69595c693ffb48441647d03c32");
    assert_eq!(r.manifest_hash().to_string(), pinned("support-agent-184.legacy.hash"));
    let canonical = String::from_utf8(r.canonical_bytes()).unwrap();
    assert!(canonical.contains("\"apiVersion\":\"cloakpipe.dev/v1alpha1\""), "{canonical}");
}

#[test]
fn legacy_and_current_manifests_hash_differently_but_diff_as_comparable() {
    let legacy = parse_path(&testdata("support-agent-184.legacy.yaml")).unwrap();
    let current = parse_path(&testdata("support-agent-184.yaml")).unwrap();
    assert_ne!(legacy.manifest_hash(), current.manifest_hash());
    let d = diff(&legacy, &current);
    assert!(d.comparable, "the same format version in either namespace is comparable");
    assert!(!d.same_hash);
    assert!(d.changes.is_empty(), "{:?}", d.changes);
}

#[test]
fn unsupported_versions_in_either_namespace_are_rejected_by_validate() {
    let src = std::fs::read_to_string(testdata("support-agent-184.yaml")).unwrap();
    for bad in ["cloakpipe.co/v2", "cloakpipe.dev/v2", "cloakpipe.com/v1alpha1"] {
        let r = parse_str(&src.replace("cloakpipe.co/v1alpha1", bad), Format::Yaml).unwrap();
        assert!(r.validate().iter().any(|i| i.code == IssueCode::UnsupportedApiVersion), "{bad}");
    }
}

#[test]
fn statement_for_a_legacy_manifest_uses_the_current_predicate_type_and_legacy_hash() {
    let r = parse_path(&testdata("support-agent-184.legacy.yaml")).unwrap();
    let s = r.intoto_statement();
    assert_eq!(s["predicateType"], namespace::AGENT_RELEASE_PREDICATE_TYPE);
    assert_eq!(s["predicate"]["apiVersion"], "cloakpipe.dev/v1alpha1");
    let digest = s["subject"][0]["digest"]["sha256"].as_str().unwrap();
    assert_eq!(format!("sha256:{digest}"), pinned("support-agent-184.legacy.hash"));
}
