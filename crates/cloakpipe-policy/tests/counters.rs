//! Persistent call counters: sliding 1h / 24h windows per release and tool,
//! kept in SQLite so they survive a restart.

use cloakpipe_policy::{Counters, Window};

const NOW: i64 = 1_793_111_400;

fn w(last_1h: i64, last_24h: i64) -> Window {
    Window { last_1h, last_24h }
}

#[test]
fn windows_slide() {
    let c = Counters::in_memory().unwrap();
    c.record("support-agent", "send_email", NOW - 90_000).unwrap(); // older than 24h
    c.record("support-agent", "send_email", NOW - 7_200).unwrap(); // 2h ago
    c.record("support-agent", "send_email", NOW - 3_600).unwrap(); // exactly 1h ago: out of the hour
    c.record("support-agent", "send_email", NOW - 100).unwrap();
    c.record("support-agent", "send_email", NOW).unwrap();
    let snap = c.snapshot("support-agent", ["send_email", "read_ticket"], NOW).unwrap();
    assert_eq!(snap["send_email"], w(2, 4));
    // Every tool asked for is present, at zero when it has no calls.
    assert_eq!(snap["read_ticket"], w(0, 0));
    assert_eq!(snap.len(), 2);
}

#[test]
fn releases_are_counted_apart() {
    let c = Counters::in_memory().unwrap();
    c.record("support-agent", "send_email", NOW).unwrap();
    c.record("billing-agent", "send_email", NOW).unwrap();
    c.record("billing-agent", "send_email", NOW).unwrap();
    assert_eq!(c.snapshot("support-agent", ["send_email"], NOW).unwrap()["send_email"], w(1, 1));
    assert_eq!(c.snapshot("billing-agent", ["send_email"], NOW).unwrap()["send_email"], w(2, 2));
}

#[test]
fn a_recorded_call_can_be_withdrawn() {
    let c = Counters::in_memory().unwrap();
    let id = c.record("support-agent", "send_email", NOW).unwrap();
    c.record("support-agent", "send_email", NOW).unwrap();
    c.forget(id).unwrap();
    assert_eq!(c.snapshot("support-agent", ["send_email"], NOW).unwrap()["send_email"], w(1, 1));
}

#[test]
fn counters_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    {
        let c = Counters::open(&path).unwrap();
        for i in 0..7 {
            c.record("support-agent", "send_email", NOW - i).unwrap();
        }
    }
    let c = Counters::open(&path).unwrap();
    assert_eq!(c.snapshot("support-agent", ["send_email"], NOW).unwrap()["send_email"], w(7, 7));
}

#[test]
fn old_calls_are_pruned() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let c = Counters::open(&path).unwrap();
    c.record("support-agent", "send_email", NOW - 200_000).unwrap();
    c.record("support-agent", "send_email", NOW).unwrap();
    assert_eq!(c.stored_calls().unwrap(), 1, "calls older than the longest window are dropped on record");
}

#[test]
fn an_unopenable_store_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(Counters::open(dir.path().join("missing-dir").join("state.db")).is_err());
}
