//! The gate's audit pack (`cloakpipe ledger export`): everything an auditor
//! needs to check the decision ledger offline, in one plain tar.
//!
//! ```text
//! pack.json                     signed pack manifest (cloakpipe.audit-pack/v1)
//! entries.jsonl                 decision entries, one per line, in seq order
//! gate.pub.json                 {"keyid", "publicKey"} of the gate signing key
//! manifests.json                the manifest and policy digests the entries name
//! anchors/epoch-<n>.json        {"epoch": <epoch head>, "anchors": [<receipts>]}
//! ```
//!
//! `pack.json` lists every other file with its `sha256:` digest, the seq
//! range, the time range asked for and the epochs included. Its
//! `pack_hash` = SHA-256(`cloakpipe.audit-pack.v1` `\n` canonical JSON of
//! the manifest without `pack_hash` and `sig`), and `sig` is Ed25519 over
//! those 32 bytes by the gate key named in `signer`.
//!
//! A time range (`since` / `until`, on entry `ts`) widens to whole epochs:
//! every epoch with an entry in the range is included with all its entries,
//! so each epoch can be checked against the entries it seals. Entries after
//! the last epoch (not yet anchored) are included as they are.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

use crate::decision::canonical_json;
use crate::gate_key::GateKey;
use crate::store::{LedgerStore, StoreError};

/// The `kind` of a pack manifest.
pub const PACK_KIND: &str = "cloakpipe.audit-pack/v1";

/// Domain separator of `pack_hash`.
pub const PACK_HASH_DOMAIN: &str = "cloakpipe.audit-pack.v1";

#[derive(Debug, Error)]
pub enum ExportError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("no decision entries in the requested range")]
    Empty,
    #[error("entry {0} has an unreadable ts")]
    BadTime(u64),
}

/// Which entries to export, by entry time (inclusive).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackRange {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// An exported pack.
#[derive(Debug, Clone)]
pub struct Pack {
    pub tar: Vec<u8>,
    pub entries: usize,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// The epochs included.
    pub epochs: Vec<u64>,
}

/// The path of epoch `n` in a pack.
pub fn epoch_file(n: u64) -> String {
    format!("anchors/epoch-{n:08}.json")
}

fn sha256_ref(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

fn rfc3339(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// `pack_hash` of a pack manifest.
pub fn pack_hash(manifest: &Value) -> [u8; 32] {
    let mut covered = manifest.clone();
    if let Some(o) = covered.as_object_mut() {
        o.remove("pack_hash");
        o.remove("sig");
    }
    let mut bytes = format!("{PACK_HASH_DOMAIN}\n").into_bytes();
    canonical_json(&covered, &mut bytes);
    Sha256::digest(&bytes).into()
}

/// Build the pack for `range` from `store`, signed with `key`.
pub fn export_pack(store: &LedgerStore, key: &GateKey, range: &PackRange, now: DateTime<Utc>) -> Result<Pack, ExportError> {
    let all = store.decisions()?;
    let epochs = store.epochs()?;
    let ranged = range.since.is_some() || range.until.is_some();
    let mut selected = Vec::new();
    for e in &all {
        let ts = DateTime::parse_from_rfc3339(&e.ts).map_err(|_| ExportError::BadTime(e.seq))?.with_timezone(&Utc);
        if range.since.is_none_or(|s| ts >= s) && range.until.is_none_or(|u| ts <= u) {
            selected.push(e.seq);
        }
    }
    let bounds = match (selected.first(), selected.last()) {
        (Some(&lo), Some(&hi)) => {
            // Widen to whole epochs.
            let (mut lo, mut hi) = (lo, hi);
            for ep in &epochs {
                if ep.head.first_seq <= hi && ep.head.last_seq >= lo {
                    lo = lo.min(ep.head.first_seq);
                    hi = hi.max(ep.head.last_seq);
                }
            }
            Some((lo, hi))
        }
        _ if ranged => return Err(ExportError::Empty),
        _ => None,
    };
    let entries: Vec<_> = match bounds {
        Some((lo, hi)) => all.into_iter().filter(|e| e.seq >= lo && e.seq <= hi).collect(),
        None => Vec::new(),
    };
    let included: Vec<_> = match bounds {
        Some((lo, hi)) => epochs.into_iter().filter(|ep| ep.head.first_seq <= hi && ep.head.last_seq >= lo).collect(),
        None => Vec::new(),
    };

    let jsonl: String = entries.iter().map(|e| format!("{}\n", e.to_json_line())).collect();
    let gate = json!({ "keyid": key.keyid(), "publicKey": key.public_hex() });
    let digests = |f: fn(&crate::decision::DecisionEntry) -> Option<&String>| -> Vec<String> {
        entries.iter().filter_map(f).cloned().collect::<BTreeSet<_>>().into_iter().collect()
    };
    let manifests = json!({
        "releases": digests(|e| e.release.as_ref()),
        "policy_versions": digests(|e| e.policy_version.as_ref()),
        "policy_digests": digests(|e| e.policy_digest.as_ref()),
    });
    let mut files: Vec<(String, Vec<u8>)> = vec![
        ("entries.jsonl".into(), jsonl.into_bytes()),
        ("gate.pub.json".into(), pretty(&gate)),
        ("manifests.json".into(), pretty(&manifests)),
    ];
    for ep in &included {
        let body = json!({ "epoch": ep.head, "anchors": ep.anchors });
        files.push((epoch_file(ep.head.epoch), pretty(&body)));
    }

    let mut manifest = json!({
        "kind": PACK_KIND,
        "created_at": rfc3339(&now),
        "range": {
            "since": range.since.as_ref().map(rfc3339),
            "until": range.until.as_ref().map(rfc3339),
            "first_seq": entries.first().map(|e| e.seq),
            "last_seq": entries.last().map(|e| e.seq),
        },
        "entries": entries.len(),
        "epochs": included.iter().map(|e| e.head.epoch).collect::<Vec<_>>(),
        "files": files.iter().map(|(n, d)| (n.clone(), Value::String(sha256_ref(d)))).collect::<serde_json::Map<_, _>>(),
        "signer": key.keyid(),
    });
    let h = pack_hash(&manifest);
    manifest["pack_hash"] = Value::String(hex::encode(h));
    manifest["sig"] = Value::String(hex::encode(key.sign(&h)));
    files.insert(0, ("pack.json".into(), pretty(&manifest)));

    let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    let tar = cloakpipe_verify::ustar::write(&refs, now.timestamp().max(0) as u64);
    Ok(Pack {
        tar,
        entries: entries.len(),
        first_seq: entries.first().map(|e| e.seq),
        last_seq: entries.last().map(|e| e.seq),
        epochs: included.iter().map(|e| e.head.epoch).collect(),
    })
}

fn pretty(v: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec_pretty(v).expect("JSON serializes");
    out.push(b'\n');
    out
}
