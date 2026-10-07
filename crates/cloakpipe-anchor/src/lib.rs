//! CloakPipe Anchor — external anchoring for evidence bundles.
//!
//! Per docs/v2/05-SYSTEM_DESIGN.md §2:
//!
//! "Publish signed batch heads to a transparency log and/or trusted
//! timestamp authority *outside operator control* so history cannot
//! be rewritten undetectably."
//!
//! ## Components
//!
//! - [`merkle`] — pure-SHA-256 Merkle tree over record hashes, with
//!   inclusion-proof generation and verification.
//! - [`batch`] — batch head construction (signed Merkle root +
//!   metadata).
//! - [`anchor`] — pluggable anchor backend. Phase 1 ships:
//!   - [`anchor::TsaBackend`] — RFC-3161 timestamp authority (with a
//!     fully-tested in-process TSA implementation).
//!   - [`anchor::LogBackend`] — generic transparency-log backend
//!     (Rekor v2 / Trillian-Tessera shaped; in-process test harness).
//!   - [`anchor::rfc3161::TsaClient`] — a real RFC 3161 TSA over HTTP.
//!   - [`anchor::rekor::RekorClient`] — Sigstore Rekor (v1 API).
//! - [`receipt`] — typed [`receipt::AnchorReceipt`] (in-process) and
//!   [`receipt::ExternalReceipt`] (RFC 3161 / Rekor) receipts.
//!
//! External receipts are verified with `cloakpipe-verify` (the standalone
//! auditor code) before they are returned. See `docs/ANCHORING.md`.
//!
//! ## Why standalone
//!
//! Like `cloakpipe-verify`, this crate defines its own types for the
//! wire format. The producer (M2's bundle exporter) consumes these
//! types; the verifier reads them. No dependency on `cloakpipe-ledger`;
//! it depends on `cloakpipe-verify` (never the reverse) to check external
//! anchors with exactly the code auditors run.

pub mod anchor;
pub mod batch;
pub mod merkle;
pub mod receipt;