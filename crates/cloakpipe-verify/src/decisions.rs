//! Decision ledger entries (`cloakpipe.decision/v1`), verified offline with
//! the gate's public key(s).
//!
//! An entry is a flat JSON object. Checked here, with this crate's own
//! code (no `cloakpipe-ledger`):
//!
//! - `kind` is `cloakpipe.decision/v1`;
//! - `seq` increases by one from the first entry, and each `prev_hash` is
//!   the previous entry's `entry_hash` (64 zeros before seq 0; a range that
//!   starts later is anchored at its first `prev_hash`);
//! - `entry_hash` = SHA-256(`cloakpipe.decision.v1` `\n` canonical JSON of
//!   the entry without `entry_hash` and `sig`), canonical JSON being sorted
//!   keys and no whitespace, so every member is covered;
//! - `sig` is an Ed25519 signature over the 32 bytes of `entry_hash` by the
//!   trusted key whose keyid (`ed25519:` + 16 hex chars of SHA-256 of the
//!   public key) the entry's `signer` names.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const DECISION_KIND: &str = "cloakpipe.decision/v1";
pub const DECISION_HASH_DOMAIN: &str = "cloakpipe.decision.v1";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecisionError {
    #[error("line {line}: not a JSON object: {msg}")]
    Malformed { line: usize, msg: String },
    #[error("no trusted gate public key given")]
    NoKeys,
    #[error("entry {seq}: kind is not {DECISION_KIND}")]
    Kind { seq: u64 },
    #[error("entry {index}: missing or invalid field `{field}`")]
    Field { index: usize, field: &'static str },
    #[error("seq gap: expected {expected}, found {actual}")]
    SeqGap { expected: u64, actual: u64 },
    #[error("entry {seq}: prev_hash does not match the previous entry_hash")]
    PrevHash { seq: u64 },
    #[error("entry {seq}: entry_hash does not match its content")]
    EntryHash { seq: u64 },
    #[error("entry {seq}: signer {signer} is not a trusted gate key")]
    UnknownSigner { seq: u64, signer: String },
    #[error("entry {seq}: signature does not verify")]
    BadSignature { seq: u64 },
}

/// What a verified run of entries says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionSummary {
    pub entries: usize,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// Whether the run starts at seq 0 (otherwise it is anchored at its
    /// first `prev_hash`).
    pub from_genesis: bool,
    /// `entry_hash` of the last entry (the genesis hash when empty).
    pub head: String,
    /// Tool call decisions (`call` and `replay` events).
    pub allowed: usize,
    pub denied: usize,
    pub approvals_required: usize,
    /// Entries recorded in shadow mode.
    pub shadow: usize,
    pub committed_outcomes: usize,
    pub failed_outcomes: usize,
    pub unknown_outcomes: usize,
    /// Operator reconciliations.
    pub reconciled: usize,
}

/// `entries.jsonl`: one entry per non-empty line.
pub fn parse_jsonl(text: &str) -> Result<Vec<Value>, DecisionError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value =
            serde_json::from_str(line).map_err(|e| DecisionError::Malformed { line: i + 1, msg: e.to_string() })?;
        if !v.is_object() {
            return Err(DecisionError::Malformed { line: i + 1, msg: "not an object".into() });
        }
        out.push(v);
    }
    Ok(out)
}

/// The keyid `release keygen` gives an Ed25519 public key.
pub fn keyid(public: &[u8; 32]) -> String {
    format!("ed25519:{}", &hex::encode(Sha256::digest(public))[..16])
}

/// `entry_hash` of an entry as JSON.
pub fn entry_hash(entry: &Value) -> [u8; 32] {
    let mut covered = entry.clone();
    if let Some(o) = covered.as_object_mut() {
        o.remove("entry_hash");
        o.remove("sig");
    }
    let mut bytes = format!("{DECISION_HASH_DOMAIN}\n").into_bytes();
    canonical(&covered, &mut bytes);
    Sha256::digest(&bytes).into()
}

/// Sorted keys, no whitespace, serde_json's string escaping.
pub(crate) fn canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(o) => {
            let sorted: BTreeMap<&String, &Value> = o.iter().collect();
            out.push(b'{');
            for (i, (k, x)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_string(k).unwrap_or_default().into_bytes());
                out.push(b':');
                canonical(x, out);
            }
            out.push(b'}');
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical(x, out);
            }
            out.push(b']');
        }
        other => out.extend(serde_json::to_string(other).unwrap_or_default().into_bytes()),
    }
}

/// Verify a run of entries in order against the trusted gate public keys.
pub fn verify_decisions(entries: &[Value], trusted: &[[u8; 32]]) -> Result<DecisionSummary, DecisionError> {
    if trusted.is_empty() {
        return Err(DecisionError::NoKeys);
    }
    let keys: BTreeMap<String, VerifyingKey> = trusted
        .iter()
        .filter_map(|k| VerifyingKey::from_bytes(k).ok().map(|vk| (keyid(k), vk)))
        .collect();
    let mut s = DecisionSummary { head: GENESIS.to_string(), ..Default::default() };
    let mut prev: Option<(u64, String)> = None;
    for (index, e) in entries.iter().enumerate() {
        let str_field = |field: &'static str| e.get(field).and_then(Value::as_str).ok_or(DecisionError::Field { index, field });
        let seq = e.get("seq").and_then(Value::as_u64).ok_or(DecisionError::Field { index, field: "seq" })?;
        if e.get("kind").and_then(Value::as_str) != Some(DECISION_KIND) {
            return Err(DecisionError::Kind { seq });
        }
        let prev_hash = str_field("prev_hash")?;
        match &prev {
            None => {
                s.first_seq = Some(seq);
                s.from_genesis = seq == 0;
                if seq == 0 && prev_hash != GENESIS {
                    return Err(DecisionError::PrevHash { seq });
                }
            }
            Some((p_seq, p_hash)) => {
                if seq != p_seq + 1 {
                    return Err(DecisionError::SeqGap { expected: p_seq + 1, actual: seq });
                }
                if prev_hash != p_hash {
                    return Err(DecisionError::PrevHash { seq });
                }
            }
        }
        let recorded = str_field("entry_hash")?;
        let computed = entry_hash(e);
        if recorded != hex::encode(computed) {
            return Err(DecisionError::EntryHash { seq });
        }
        let signer = str_field("signer")?;
        let Some(vk) = keys.get(signer) else {
            return Err(DecisionError::UnknownSigner { seq, signer: signer.to_string() });
        };
        let sig = hex::decode(str_field("sig")?).ok().and_then(|b| <[u8; 64]>::try_from(b).ok());
        let ok = sig.is_some_and(|sig| vk.verify(&computed, &Signature::from_bytes(&sig)).is_ok());
        if !ok {
            return Err(DecisionError::BadSignature { seq });
        }
        tally(&mut s, e);
        s.entries += 1;
        s.last_seq = Some(seq);
        s.head = recorded.to_string();
        prev = Some((seq, recorded.to_string()));
    }
    Ok(s)
}

fn tally(s: &mut DecisionSummary, e: &Value) {
    let field = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("");
    if field("mode") == "shadow" {
        s.shadow += 1;
    }
    match field("event") {
        "call" | "replay" => match field("decision") {
            "allow" => s.allowed += 1,
            "deny" => s.denied += 1,
            "require_approval" => s.approvals_required += 1,
            _ => {}
        },
        "reconcile" => s.reconciled += 1,
        _ => {}
    }
    // A replay answers from a commit already counted; a reconciliation is
    // counted as such.
    if !matches!(field("event"), "reconcile" | "replay") {
        match field("outcome") {
            "committed" => s.committed_outcomes += 1,
            "failed" => s.failed_outcomes += 1,
            "unknown" => s.unknown_outcomes += 1,
            _ => {}
        }
    }
}
