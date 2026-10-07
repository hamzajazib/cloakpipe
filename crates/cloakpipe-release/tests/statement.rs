//! The release manifest is published as an in-toto v1 Statement so it can be
//! signed and verified with standard supply-chain tooling.

use cloakpipe_release::parse_path;
use std::path::PathBuf;

#[test]
fn statement_binds_subject_digest_to_manifest_hash() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/support-agent-184.yaml");
    let r = parse_path(&path).unwrap();
    let s = r.intoto_statement();

    assert_eq!(s["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(s["predicateType"], "https://cloakpipe.co/attestations/agent-release/v1alpha1");
    assert_eq!(s["subject"][0]["name"], "agent-release:support-agent@184");

    let digest = s["subject"][0]["digest"]["sha256"].as_str().unwrap();
    assert_eq!(format!("sha256:{digest}"), r.manifest_hash().to_string());

    // The predicate is the full manifest, so a verifier can recompute the hash.
    assert_eq!(s["predicate"]["metadata"]["agent"], "support-agent");
    assert_eq!(s["predicate"]["spec"]["model"]["ref"], "model:openai/gpt-5@2026-08-01");
}
