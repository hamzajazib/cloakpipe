//! Evidence records can be bound to the exact Agent Release that produced them.

use cloakpipe_ledger::{canonicalize, chain, RecordBuilder, RELEASE_HASH_KEY};

const RELEASE: [u8; 32] = [0xae; 32];

#[test]
fn release_hash_round_trips() {
    let r = RecordBuilder::new().release(RELEASE).build().unwrap();
    assert_eq!(r.release_hash(), Some(RELEASE));
    assert!(r.metadata.contains_key(RELEASE_HASH_KEY));
}

#[test]
fn records_without_a_release_report_none() {
    let r = RecordBuilder::new().build().unwrap();
    assert_eq!(r.release_hash(), None);
}

#[test]
fn release_hash_is_covered_by_the_record_hash() {
    let ts = chrono::Utc::now();
    let a = RecordBuilder::new().ts(ts).release(RELEASE).build().unwrap();
    let b = RecordBuilder::new().ts(ts).release([0xaf; 32]).build().unwrap();
    let none = RecordBuilder::new().ts(ts).build().unwrap();

    let canon = String::from_utf8(canonicalize(&a)).unwrap();
    assert!(canon.contains(&format!("{RELEASE_HASH_KEY}=hash:{}", "ae".repeat(32))), "{canon}");

    let h = chain::hash_record;
    assert_ne!(h(&a), h(&b), "a different release must produce a different record hash");
    assert_ne!(h(&a), h(&none), "binding a release must change the record hash");
}

#[test]
fn records_without_a_release_keep_their_existing_encoding() {
    // Backwards compatibility: no new bytes unless a release is bound, so
    // already-issued bundles still verify.
    let r = RecordBuilder::new().build().unwrap();
    let canon = String::from_utf8(canonicalize(&r)).unwrap();
    assert!(canon.ends_with("\nmetadata="), "{canon}");
}

#[test]
fn release_lifecycle_events_have_stable_tags() {
    use cloakpipe_ledger::Hop;
    // Tags are part of the signed canonical bytes: never rename them.
    assert_eq!(Hop::ReleaseRegistered.tag(), "release_registered");
    assert_eq!(Hop::ReleasePromoted.tag(), "release_promoted");
    assert_eq!(Hop::ReleaseCertified.tag(), "release_certified");
    assert_eq!(Hop::CertificationRevoked.tag(), "certification_revoked");
}

#[test]
fn release_lifecycle_events_canonicalise_with_their_release() {
    use cloakpipe_ledger::Hop;
    let r = RecordBuilder::new().hop(Hop::ReleasePromoted).release(RELEASE).build().unwrap();
    let canon = String::from_utf8(canonicalize(&r)).unwrap();
    assert!(canon.contains("\nhop=release_promoted\n"), "{canon}");
    assert!(canon.contains(&format!("{RELEASE_HASH_KEY}=hash:{}", "ae".repeat(32))), "{canon}");
}
