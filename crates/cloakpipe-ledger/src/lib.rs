//! CloakPipe Ledger — verifiable evidence records.
//!
//! The ledger's **P0 invariant** is that no record field can carry a raw PII
//! value. Records describe *what happened* using only types, counts, hashes,
//! and references. The raw identifier never leaves the vault.
//!
//! ## Design
//!
//! - [`LedgerRecord`] is the canonical record; [`RecordBuilder`] is the only
//!   way to construct one.
//! - [`canonicalize`] produces a deterministic byte representation so any
//!   third party can re-derive `record_hash`.
//! - [`hash_chain`] links each record to its predecessor per tenant.
//! - [`Signer`] signs records with Ed25519 (ML-DSA-65 pluggable later per
//!   ADR-004).
//!
//! The verifier (`cloakpipe-verify`, M2) reads the same schema.
//!
//! The tool gate records its decisions as a separate record kind,
//! [`decision`] (`cloakpipe.decision/v1`): one entry per decision,
//! hash-chained and signed one by one with the gate signing key
//! ([`gate_key`]), in its own table of the same ledger database.

pub mod canonical;
pub mod chain;
pub mod anchoring;
pub mod audit_pack;
pub mod decision;
pub mod epoch;
pub mod export;
pub mod gate_key;
pub mod record;
pub mod sign;
pub mod store;

pub use canonical::canonicalize;
pub use decision::{Decision, DecisionDraft, DecisionEntry, Event, Mode, Outcome};
pub use gate_key::GateKey;
pub use chain::{hash_record, ChainLinkError, GENESIS_HASH};
pub use record::{
    Action, ActionKind, ConfidenceBucket, Detection, Detector, Egress, Hop, Identity, MetadataValue,
    Policy, PolicyDecision, RecordBuilder, RecordError, RELEASE_HASH_KEY,
};
pub use sign::{Ed25519Signer, Signature, Signer, SignedRecord};
pub use store::{LedgerStore, StoredRecord};