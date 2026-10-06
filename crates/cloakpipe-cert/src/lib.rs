//! Agent Release certification (Phase B).
//!
//! - [`model`]: evaluation runs, certification policies and decisions, with
//!   canonical hashes so every input to a decision is pinned.
//! - [`import`]: turn external results (JUnit XML, native JSON) into
//!   [`model::EvaluationRun`]s.
//! - [`policy`]: the deterministic certification decision.
//! - [`statement`]: signed, scoped, expiring certification attestations
//!   (in-toto v1 in a DSSE envelope) and their offline verification.
//!
//! The contract is specified in `docs/CERTIFICATION.md`.

pub mod import;
pub mod model;
pub mod policy;
pub mod statement;

pub use model::*;
