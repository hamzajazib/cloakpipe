mod common;
#[test]
#[ignore]
fn write_heads() {
    let d = common::fixtures_dir();
    std::fs::write(d.join("head-honest.json"), common::head_bytes(&common::HONEST)).unwrap();
    std::fs::write(d.join("head-future.json"), common::head_bytes(&common::FUTURE)).unwrap();
    let b = common::bundle_for(&common::HONEST);
    cloakpipe_verify::verify::verify_all(&b).unwrap();
    cloakpipe_verify::anchor::verify_inclusion_proofs(&b).unwrap();
}
