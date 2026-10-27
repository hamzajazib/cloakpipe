//! Anchoring epochs (`cloakpipe.epoch/v1`): the decision chain sealed in
//! numbered, signed ranges that are anchored externally.
//!
//! Epoch `n` covers decision entries `first_seq..=last_seq`. Epoch 0 starts
//! at seq 0, and each later epoch starts right after the previous one, so
//! together they cover the chain without gaps or overlap. An epoch head is
//! a flat JSON object:
//!
//! - `kind`: `cloakpipe.epoch/v1`; `epoch` (from 0, no gaps)
//! - `first_seq`, `last_seq`; `entries_head`: the `entry_hash` of entry
//!   `last_seq`, which commits to every entry before it through the chain
//! - `prev_epoch`: the previous epoch's `epoch_hash` ([`EPOCH_GENESIS`] for
//!   epoch 0)
//! - `sealed_at` (RFC 3339 UTC), `signer` (`ed25519:<keyid>`)
//! - `epoch_hash` = SHA-256(`cloakpipe.epoch.v1` `\n` canonical JSON of the
//!   head without `epoch_hash` and `sig`), and `sig`, Ed25519 over the 32
//!   bytes of `epoch_hash` by the gate signing key
//!
//! The anchored artifact ([`EpochHead::artifact`]) is the canonical JSON of
//! the whole signed head: an RFC 3161 TSA stamps its SHA-256, and Rekor logs
//! it signed by the gate key. Receipts are kept with the epoch in the ledger
//! database, so verification later needs no network.

use cloakpipe_anchor::receipt::ExternalReceipt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::decision::canonical_json;

/// The `kind` of an epoch head.
pub const EPOCH_KIND: &str = "cloakpipe.epoch/v1";

/// Domain separator of `epoch_hash`.
pub const EPOCH_HASH_DOMAIN: &str = "cloakpipe.epoch.v1";

/// `prev_epoch` of epoch 0.
pub const EPOCH_GENESIS: &str = crate::decision::GENESIS;

/// A sealed, signed epoch head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochHead {
    pub kind: String,
    pub epoch: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub entries_head: String,
    pub prev_epoch: String,
    pub sealed_at: String,
    pub signer: String,
    pub epoch_hash: String,
    pub sig: String,
}

impl EpochHead {
    /// The `epoch_hash` these fields hash to (hex).
    pub fn compute_hash(&self) -> String {
        hex::encode(epoch_hash_of(&serde_json::to_value(self).expect("an epoch serializes")))
    }

    /// The bytes anchored externally: canonical JSON of the signed head.
    pub fn artifact(&self) -> Vec<u8> {
        let mut out = Vec::new();
        canonical_json(&serde_json::to_value(self).expect("an epoch serializes"), &mut out);
        out
    }

    /// How receipts name this epoch: `epoch-<n>`.
    pub fn id(&self) -> String {
        format!("epoch-{}", self.epoch)
    }
}

/// `epoch_hash` of a head given as JSON: every member except `epoch_hash`
/// and `sig` is covered.
pub fn epoch_hash_of(head: &Value) -> [u8; 32] {
    let mut covered = head.clone();
    if let Some(o) = covered.as_object_mut() {
        o.remove("epoch_hash");
        o.remove("sig");
    }
    let mut bytes = format!("{EPOCH_HASH_DOMAIN}\n").into_bytes();
    canonical_json(&covered, &mut bytes);
    Sha256::digest(&bytes).into()
}

/// An epoch as stored: its head, the anchors obtained so far and the last
/// anchoring error (cleared once an attempt succeeds in full).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpoch {
    pub head: EpochHead,
    pub anchors: Vec<ExternalReceipt>,
    pub last_error: Option<String>,
}

impl StoredEpoch {
    /// The anchor kinds held (`rekor`, `rfc3161`), sorted, once each.
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut kinds: Vec<&'static str> = self.anchors.iter().map(receipt_kind).collect();
        kinds.sort();
        kinds.dedup();
        kinds
    }
}

/// `rfc3161` or `rekor`.
pub fn receipt_kind(r: &ExternalReceipt) -> &'static str {
    match r {
        ExternalReceipt::Rfc3161 { .. } => "rfc3161",
        ExternalReceipt::Rekor { .. } => "rekor",
    }
}
