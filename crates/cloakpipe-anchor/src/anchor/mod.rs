//! Pluggable anchor backends.
//!
//! An anchor backend takes a signed batch head and returns an
//! [`AnchorReceipt`](crate::receipt::AnchorReceipt) that can be
//! verified offline. The [`BackendKind`] tag is what the verifier
//! pattern-matches on to decide which verifier to run.
//!
//! In-process implementations ship today:
//! - [`TsaBackend`] — RFC-3161 timestamp authority.
//! - [`LogBackend`] — generic transparency log (the protocol shape
//!   Rekor v2 / Trillian-Tessera expose — same wire format, simpler
//!   test harness).
//!
//! External anchors (real services, verified before a receipt is
//! returned):
//! - [`rfc3161::TsaClient`] — any RFC 3161 TSA over HTTP (freetsa.org by
//!   default, DigiCert documented).
//! - [`rekor::RekorClient`] — Sigstore Rekor v1 API, `hashedrekord`.

use crate::batch::SignedBatchHead;
use crate::receipt::{AnchorReceipt, BackendKind};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("submit failed: {0}")]
    Submit(String),
    /// The anchor answered, but its answer does not verify.
    #[error("anchor response rejected: {0}")]
    Rejected(String),
}

/// A pluggable anchor backend.
///
/// Sync trait on purpose: the test backends are in-process; a real
/// HTTP TSA client is a thin wrapper around a sync HTTP call. We can
/// layer an async facade on top later if needed.
pub trait Backend: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn submit(&self, head: &SignedBatchHead) -> Result<AnchorReceipt, AnchorError>;
}

pub mod log;
pub mod rekor;
pub mod rfc3161;
pub mod tsa;

pub use log::LogBackend;
pub use tsa::{InProcessTsa, TsaBackend};

// Silence unused warning for an internal helper kept for future
// shared state if we want a registry of backends.
#[allow(dead_code)]
type BackendRegistry = Mutex<Vec<Arc<dyn Backend>>>;