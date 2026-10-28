//! The events log (`mcp-proxy --events-log events.jsonl`): one line of
//! [`GateEvent::to_json`] per event, appended (an existing file is never
//! truncated), written on a background thread.

use super::delivery::{Queue, DEFAULT_CAPACITY};
use super::{EventSink, GateEvent};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

/// An [`EventSink`] appending to a JSONL file.
pub struct JsonlSink {
    queue: Queue<GateEvent>,
}

impl JsonlSink {
    /// Open (or create) `path` for appending: an unwritable path fails here,
    /// at start-up, not on the first event.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let mut file: File = OpenOptions::new().create(true).append(true).open(path)?;
        let shown = path.display().to_string();
        let queue = Queue::spawn("events-log", DEFAULT_CAPACITY, 256, move |batch: Vec<GateEvent>| {
            let mut lines = String::new();
            for event in &batch {
                lines.push_str(&event.to_json().to_string());
                lines.push('\n');
            }
            if let Err(e) = file.write_all(lines.as_bytes()).and_then(|_| file.flush()) {
                eprintln!("warning: cloakpipe events log {shown}: {} event(s) not written: {e}", batch.len());
            }
        });
        Ok(Self { queue })
    }

    /// Events dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.queue.dropped()
    }
}

impl EventSink for JsonlSink {
    fn emit(&self, event: &GateEvent) {
        self.queue.push(event.clone());
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.queue.flush(timeout)
    }
}
