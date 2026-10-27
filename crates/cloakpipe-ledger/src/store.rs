//! Durable append-only storage for [`LedgerRecord`].
//!
//! Uses SQLite (one file per ledger) for simplicity — same engine as the
//! vault. Each insert is a single transaction; records are never updated
//! or deleted.
//!
//! The gate's decision entries ([`crate::decision`]) live in their own
//! `decisions` table: one chain per ledger file, each entry signed as it is
//! appended.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use thiserror::Error;

use crate::chain::{compute_hash, GENESIS_HASH};
use crate::decision::{DecisionDraft, DecisionEntry, GENESIS};
use crate::epoch::{receipt_kind, EpochHead, StoredEpoch, EPOCH_GENESIS, EPOCH_KIND};
use cloakpipe_anchor::receipt::ExternalReceipt;
use crate::gate_key::GateKey;
use crate::record::LedgerRecord;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serde_json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("record's stored seq does not match expected next seq {expected}")]
    SeqOutOfOrder { expected: u64 },
    #[error("record's prev_hash does not match head record_hash")]
    PrevHashMismatch,
    #[error("record's stored record_hash does not match recomputed hash")]
    RecordHashMismatch,
    #[error("decision entry {0} is corrupt: {1}")]
    CorruptDecision(u64, String),
    #[error("epoch {0} is corrupt: {1}")]
    CorruptEpoch(u64, String),
    #[error("no epoch {0}")]
    NoEpoch(u64),
}

/// A record that has been durably stored, paired with its DB row id.
#[derive(Debug, Clone)]
pub struct StoredRecord {
    pub id: i64,
    pub record: LedgerRecord,
}

/// Append-only store. One connection per ledger file; cheap to clone via
/// [`Connection::clone`] — but each thread should ideally own one.
pub struct LedgerStore {
    conn: Connection,
}

impl LedgerStore {
    /// Opens or creates a ledger at `path`. Enables WAL for concurrent
    /// appends and reasonable crash safety.
    ///
    /// Several processes or threads may open one ledger at once (the gate,
    /// its anchoring thread, `cloakpipe operations reconcile`). Setting up a
    /// new file (switching it to WAL, creating tables) can then fail
    /// transiently even with a busy timeout, so setup is retried for up to
    /// ten seconds.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match Self::open_once(path) {
                Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(e, _)))
                    if matches!(
                        e.code,
                        rusqlite::ErrorCode::DatabaseBusy
                            | rusqlite::ErrorCode::DatabaseLocked
                            | rusqlite::ErrorCode::SystemIoFailure
                    ) && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                result => return result,
            }
        }
    }

    fn open_once(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        // The gate, its anchoring thread and `cloakpipe operations
        // reconcile` may open and write at once: wait for locks, including
        // the one switching a new file to WAL.
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS records (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id    TEXT NOT NULL,
                seq          INTEGER NOT NULL,
                record_hash  TEXT NOT NULL,
                prev_hash    TEXT NOT NULL,
                record_json  TEXT NOT NULL,
                UNIQUE(tenant_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_records_tenant_seq
              ON records(tenant_id, seq);
            CREATE TABLE IF NOT EXISTS decisions (
                seq         INTEGER PRIMARY KEY,
                entry_hash  TEXT NOT NULL,
                prev_hash   TEXT NOT NULL,
                entry_json  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS epochs (
                epoch         INTEGER PRIMARY KEY,
                first_seq     INTEGER NOT NULL,
                last_seq      INTEGER NOT NULL,
                epoch_json    TEXT NOT NULL,
                anchors_json  TEXT NOT NULL DEFAULT '[]',
                last_error    TEXT
            );
            "#,
        )?;
        Ok(())
    }

    /// Returns the (seq, record_hash) tail of the chain for `tenant_id`,
    /// or `(None, GENESIS_HASH)` if empty.
    pub fn head(&self, tenant_id: &uuid::Uuid) -> Result<(Option<u64>, [u8; 32]), StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, record_hash FROM records
             WHERE tenant_id = ?1
             ORDER BY seq DESC LIMIT 1",
        )?;
        let mut rows = stmt.query([tenant_id.to_string()])?;
        if let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let hash_hex: String = row.get(1)?;
            let hash = decode_hex_32(&hash_hex)
                .ok_or_else(|| StoreError::PrevHashMismatch)?;
            Ok((Some(seq as u64), hash))
        } else {
            Ok((None, GENESIS_HASH))
        }
    }

    /// Append a record after linking it into the chain. Verifies the
    /// supplied `prev_hash` matches the current head.
    pub fn append(&mut self, tenant_id: &uuid::Uuid, record: &mut LedgerRecord) -> Result<i64, StoreError> {
        let (head_seq_opt, head_hash) = self.head(tenant_id)?;
        let expected_seq = head_seq_opt.map(|s| s + 1).unwrap_or(0);
        if record.seq != expected_seq {
            return Err(StoreError::SeqOutOfOrder {
                expected: expected_seq,
            });
        }
        record.prev_hash = head_hash;
        record.record_hash = compute_hash(record);

        // Sanity: the hash we just computed matches what we are about to
        // store. (compute_hash is deterministic, so this is a tautology —
        // but it documents the contract.)
        let recomputed = compute_hash(record);
        if recomputed != record.record_hash {
            return Err(StoreError::RecordHashMismatch);
        }

        let json = serde_json::to_string(record)?;
        let mut stmt = self.conn.prepare(
            "INSERT INTO records (tenant_id, seq, record_hash, prev_hash, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        let res = stmt.insert(params![
            tenant_id.to_string(),
            record.seq as i64,
            hex_lower(&record.record_hash),
            hex_lower(&record.prev_hash),
            json
        ])?;
        Ok(res)
    }

    /// Read all records for a tenant, in seq order.
    pub fn records_for_tenant(&self, tenant_id: &uuid::Uuid) -> Result<Vec<StoredRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, seq, record_json FROM records
             WHERE tenant_id = ?1
             ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([tenant_id.to_string()], |row| {
            let id: i64 = row.get(0)?;
            let seq: i64 = row.get(1)?;
            let json: String = row.get(2)?;
            Ok((id, seq, json))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, _seq, json) = row?;
            let record: LedgerRecord = serde_json::from_str(&json)?;
            out.push(StoredRecord { id, record });
        }
        Ok(out)
    }
}

impl LedgerStore {
    /// Chain `draft` onto the decision chain, sign it with `key` and store
    /// it, in one write transaction (so concurrent writers never fork the
    /// chain). Returns the stored entry.
    pub fn append_decision(&mut self, draft: DecisionDraft, key: &GateKey) -> Result<DecisionEntry, StoreError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let head: Option<(i64, String)> = tx
            .query_row("SELECT seq, entry_hash FROM decisions ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let (seq, prev) = match head {
            Some((seq, hash)) => (seq as u64 + 1, hash),
            None => (0, GENESIS.to_string()),
        };
        let mut entry = DecisionEntry::link(draft, seq, &prev, key.keyid());
        let digest: [u8; 32] = decode_hex_32(&entry.entry_hash).expect("entry_hash is 64 hex chars");
        entry.sig = hex_lower(&key.sign(&digest));
        tx.execute(
            "INSERT INTO decisions (seq, entry_hash, prev_hash, entry_json) VALUES (?1, ?2, ?3, ?4)",
            params![seq as i64, entry.entry_hash, entry.prev_hash, entry.to_json_line()],
        )?;
        tx.commit()?;
        Ok(entry)
    }

    /// Every decision entry, in seq order.
    pub fn decisions(&self) -> Result<Vec<DecisionEntry>, StoreError> {
        self.decisions_from(0)
    }

    /// The decision entries from `seq` on, in seq order.
    pub fn decisions_from(&self, seq: u64) -> Result<Vec<DecisionEntry>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT seq, entry_json FROM decisions WHERE seq >= ?1 ORDER BY seq ASC")?;
        let rows = stmt.query_map([seq as i64], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, json) = row?;
            let entry: DecisionEntry =
                serde_json::from_str(&json).map_err(|e| StoreError::CorruptDecision(seq as u64, e.to_string()))?;
            out.push(entry);
        }
        Ok(out)
    }
}

impl LedgerStore {
    /// The seq of the newest decision entry, `None` when there is none.
    pub fn decision_head_seq(&self) -> Result<Option<u64>, StoreError> {
        let seq: Option<i64> = self.conn.query_row("SELECT MAX(seq) FROM decisions", [], |r| r.get(0))?;
        Ok(seq.map(|s| s as u64))
    }

    /// The decision entries `first..=last`, in seq order.
    pub fn decisions_between(&self, first: u64, last: u64) -> Result<Vec<DecisionEntry>, StoreError> {
        Ok(self.decisions_from(first)?.into_iter().take_while(|e| e.seq <= last).collect())
    }

    /// The first seq no epoch covers yet (0 before the first epoch).
    pub fn next_unsealed_seq(&self) -> Result<u64, StoreError> {
        let last: Option<i64> = self.conn.query_row("SELECT MAX(last_seq) FROM epochs", [], |r| r.get(0))?;
        Ok(last.map(|l| l as u64 + 1).unwrap_or(0))
    }

    /// Seal every decision entry no epoch covers yet into the next epoch,
    /// signed with `key`, in one write transaction. `None` when there is
    /// nothing new.
    pub fn seal_epoch(&mut self, key: &GateKey, now: chrono::DateTime<chrono::Utc>) -> Result<Option<EpochHead>, StoreError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prev: Option<(i64, i64, String)> = tx
            .query_row("SELECT epoch, last_seq, epoch_json FROM epochs ORDER BY epoch DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        let (epoch, first_seq, prev_epoch) = match prev {
            None => (0u64, 0u64, EPOCH_GENESIS.to_string()),
            Some((n, last, json)) => {
                let head: EpochHead =
                    serde_json::from_str(&json).map_err(|e| StoreError::CorruptEpoch(n as u64, e.to_string()))?;
                (n as u64 + 1, last as u64 + 1, head.epoch_hash)
            }
        };
        let tail: Option<(i64, String)> = tx
            .query_row("SELECT seq, entry_hash FROM decisions ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((last_seq, entries_head)) = tail.filter(|(seq, _)| *seq as u64 >= first_seq) else {
            return Ok(None);
        };
        let mut head = EpochHead {
            kind: EPOCH_KIND.to_string(),
            epoch,
            first_seq,
            last_seq: last_seq as u64,
            entries_head,
            prev_epoch,
            sealed_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            signer: key.keyid(),
            epoch_hash: String::new(),
            sig: String::new(),
        };
        head.epoch_hash = head.compute_hash();
        let digest = decode_hex_32(&head.epoch_hash).expect("epoch_hash is 64 hex chars");
        head.sig = hex_lower(&key.sign(&digest));
        tx.execute(
            "INSERT INTO epochs (epoch, first_seq, last_seq, epoch_json) VALUES (?1, ?2, ?3, ?4)",
            params![epoch as i64, first_seq as i64, last_seq, serde_json::to_string(&head)?],
        )?;
        tx.commit()?;
        Ok(Some(head))
    }

    /// Every epoch, in order, with its anchors.
    pub fn epochs(&self) -> Result<Vec<StoredEpoch>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT epoch, epoch_json, anchors_json, last_error FROM epochs ORDER BY epoch ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (n, head, anchors, last_error) = row?;
            let corrupt = |e: serde_json::Error| StoreError::CorruptEpoch(n as u64, e.to_string());
            out.push(StoredEpoch {
                head: serde_json::from_str(&head).map_err(corrupt)?,
                anchors: serde_json::from_str(&anchors).map_err(corrupt)?,
                last_error,
            });
        }
        Ok(out)
    }

    /// Add `receipts` to epoch `epoch` (a receipt of a kind it already
    /// holds replaces nothing: the first one is kept) and record `error`,
    /// the outcome of this attempt (`None`: it succeeded in full).
    pub fn add_epoch_anchors(
        &mut self,
        epoch: u64,
        receipts: Vec<ExternalReceipt>,
        error: Option<String>,
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let json: Option<String> = tx
            .query_row("SELECT anchors_json FROM epochs WHERE epoch = ?1", [epoch as i64], |r| r.get(0))
            .optional()?;
        let json = json.ok_or(StoreError::NoEpoch(epoch))?;
        let mut anchors: Vec<ExternalReceipt> =
            serde_json::from_str(&json).map_err(|e| StoreError::CorruptEpoch(epoch, e.to_string()))?;
        for r in receipts {
            if !anchors.iter().any(|a| receipt_kind(a) == receipt_kind(&r)) {
                anchors.push(r);
            }
        }
        tx.execute(
            "UPDATE epochs SET anchors_json = ?1, last_error = ?2 WHERE epoch = ?3",
            params![serde_json::to_string(&anchors)?, error, epoch as i64],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn fresh() -> (tempfile::TempDir, LedgerStore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        (dir, store)
    }

    fn rec(seq: u64, tenant: Uuid) -> LedgerRecord {
        RecordBuilder::new()
            .seq(seq)
            .tenant(tenant)
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap()
    }

    #[test]
    fn head_starts_at_genesis_for_new_ledger() {
        let (_dir, store) = fresh();
        let t = Uuid::new_v4();
        let (seq, hash) = store.head(&t).unwrap();
        assert_eq!(seq, None);
        assert_eq!(hash, GENESIS_HASH);
    }

    #[test]
    fn append_links_chain_correctly() {
        let (_dir, mut store) = fresh();
        let t = Uuid::new_v4();
        for i in 0..3 {
            let mut r = rec(i, t);
            store.append(&t, &mut r).unwrap();
        }
        let rows = store.records_for_tenant(&t).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].record.prev_hash, GENESIS_HASH);
        assert_eq!(rows[1].record.prev_hash, rows[0].record.record_hash);
        assert_eq!(rows[2].record.prev_hash, rows[1].record.record_hash);
    }

    #[test]
    fn append_rejects_wrong_seq() {
        let (_dir, mut store) = fresh();
        let t = Uuid::new_v4();
        let mut r = rec(7, t);
        let err = store.append(&t, &mut r).unwrap_err();
        assert!(matches!(err, StoreError::SeqOutOfOrder { expected: 0 }));
    }

    #[test]
    fn two_tenants_have_independent_chains() {
        let (_dir, mut store) = fresh();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        store.append(&t1, &mut rec(0, t1)).unwrap();
        store.append(&t2, &mut rec(0, t2)).unwrap();
        store.append(&t1, &mut rec(1, t1)).unwrap();
        store.append(&t2, &mut rec(1, t2)).unwrap();
        let r1 = store.records_for_tenant(&t1).unwrap();
        let r2 = store.records_for_tenant(&t2).unwrap();
        assert_eq!(r1.len(), 2);
        assert_eq!(r2.len(), 2);
        // Independent genesis -> tail hashes differ across tenants.
        assert_ne!(r1[0].record.record_hash, r2[0].record.record_hash);
    }

    #[test]
    fn persisted_records_replay_through_chain_verifier() {
        let (_dir, mut store) = fresh();
        let t = Uuid::new_v4();
        for i in 0..10 {
            let mut r = rec(i, t);
            store.append(&t, &mut r).unwrap();
        }
        let rows: Vec<LedgerRecord> = store
            .records_for_tenant(&t)
            .unwrap()
            .into_iter()
            .map(|s| s.record)
            .collect();
        crate::chain::verify_chain(&rows).unwrap();
    }
}