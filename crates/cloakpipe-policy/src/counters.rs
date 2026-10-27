//! Persistent call counters for `context.counters`.
//!
//! One row per forwarded call (release name, tool, unix seconds) in a
//! SQLite table, so the windows survive a restart and a rate-limit policy
//! cannot be reset by restarting the gate. They are keyed by the release
//! *name*, not the manifest digest, so publishing a new version does not
//! reset them either. Rows older than the longest window (24h) are pruned
//! as calls are recorded.

use rusqlite::{params, Connection, OpenFlags};
use std::collections::BTreeMap;
use std::path::Path;

/// The longest window, in seconds.
const DAY: i64 = 24 * 3600;
const HOUR: i64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("counter store: {0}")]
pub struct CounterError(pub String);

impl From<rusqlite::Error> for CounterError {
    fn from(e: rusqlite::Error) -> Self {
        CounterError(e.to_string())
    }
}

/// Calls forwarded in the last hour and the last day (`(now - window, now]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Window {
    pub last_1h: i64,
    pub last_24h: i64,
}

/// The counter store.
pub struct Counters {
    conn: Connection,
}

impl std::fmt::Debug for Counters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Counters").finish_non_exhaustive()
    }
}

impl Counters {
    /// Open (creating if needed) the store at `path`. Its directory must exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CounterError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path.as_ref(), flags)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    /// A store that lives as long as this value (tests).
    pub fn in_memory() -> Result<Self, CounterError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, CounterError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS gate_calls (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                release TEXT    NOT NULL,
                tool    TEXT    NOT NULL,
                at      INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS gate_calls_by_release ON gate_calls (release, at);",
        )?;
        Ok(Self { conn })
    }

    /// Record a forwarded call; returns its id (for [`Self::forget`]).
    pub fn record(&self, release: &str, tool: &str, at_unix: i64) -> Result<i64, CounterError> {
        self.conn.execute("DELETE FROM gate_calls WHERE at <= ?1", params![at_unix - DAY])?;
        self.conn.execute("INSERT INTO gate_calls (release, tool, at) VALUES (?1, ?2, ?3)", params![release, tool, at_unix])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Withdraw a recorded call that was not forwarded after all.
    pub fn forget(&self, id: i64) -> Result<(), CounterError> {
        self.conn.execute("DELETE FROM gate_calls WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// The windows at `now_unix` for each of `tools` (zero when it has no calls).
    pub fn snapshot<'a>(
        &self,
        release: &str,
        tools: impl IntoIterator<Item = &'a str>,
        now_unix: i64,
    ) -> Result<BTreeMap<String, Window>, CounterError> {
        let mut out: BTreeMap<String, Window> = tools.into_iter().map(|t| (t.to_string(), Window::default())).collect();
        let mut stmt = self.conn.prepare_cached(
            "SELECT tool, SUM(CASE WHEN at > ?3 THEN 1 ELSE 0 END), COUNT(*)
             FROM gate_calls WHERE release = ?1 AND at > ?2 AND at <= ?4 GROUP BY tool",
        )?;
        let rows = stmt.query_map(params![release, now_unix - DAY, now_unix - HOUR, now_unix], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
        })?;
        for row in rows {
            let (tool, last_1h, last_24h) = row?;
            if let Some(w) = out.get_mut(&tool) {
                *w = Window { last_1h, last_24h };
            }
        }
        Ok(out)
    }

    /// How many calls are stored (all releases).
    pub fn stored_calls(&self) -> Result<i64, CounterError> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM gate_calls", [], |r| r.get(0))?)
    }
}
