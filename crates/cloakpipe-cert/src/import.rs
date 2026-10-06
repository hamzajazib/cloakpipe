//! Import external evaluation results as [`EvaluationRun`]s.
//!
//! Contract (see docs/CERTIFICATION.md §Import):
//!
//! **JUnit XML** (`from_junit`) — the de-facto CI format (pytest, Jest, Go,
//! JUnit, cargo-nextest):
//! - Accepts a `<testsuites>` root with any number of `<testsuite>` children,
//!   or a bare `<testsuite>` root. Nested `<testsuite>` elements are walked.
//! - Each `<testcase>` becomes one [`CaseResult`] with
//!   `id = "{classname}::{name}"`, or just `name` when `classname` is absent
//!   or empty.
//! - Status: a `<failure>` child → `Fail`; `<error>` → `Error`; `<skipped>` →
//!   `Skipped`; otherwise `Pass`. If several are present, precedence is
//!   error > failure > skipped.
//! - `time="<seconds>"` → `duration_ms` (rounded to nearest ms); absent or
//!   unparseable → `None`.
//! - Case-level `<properties><property name=… value=…/></properties>`:
//!   `cloakpipe.critical` = `true`/`false`; `cloakpipe.score` = f64;
//!   `cloakpipe.metric.<name>` = f64 → `metrics[<name>]`. Non-finite or
//!   unparseable numeric values are an error. Unknown properties are ignored.
//! - A case is also critical if its id matches any pattern in
//!   `ImportMeta::critical`: a pattern ending in `*` is a prefix match,
//!   otherwise an exact match.
//! - Duplicate case ids → `ImportError::Invalid`. Malformed XML →
//!   `ImportError::Xml`. Zero test cases is allowed (the decision reports it).
//! - Run fields (`runId`, `release`, `suite`, `covers`, `dataset`,
//!   `evaluators`) come from [`ImportMeta`]; `source = {kind: junit, tool}`.
//! - The resulting run must pass [`EvaluationRun::validate`], else
//!   `ImportError::Invalid` with the issues.
//! - Never panics on any input.
//!
//! **Native JSON** (`from_json`): the [`EvaluationRun`] JSON format itself
//! (camelCase, unknown fields rejected), validated with
//! [`EvaluationRun::validate`].

use crate::model::{EvaluationRun, EvaluatorRef, SuiteRef};

/// Run-level metadata a JUnit file does not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportMeta {
    pub run_id: String,
    /// `sha256:<hex>` manifest hash of the evaluated release.
    pub release: String,
    pub suite: SuiteRef,
    pub covers: Vec<String>,
    pub dataset: Option<String>,
    pub evaluators: Vec<EvaluatorRef>,
    /// Name of the producing tool, e.g. `pytest`.
    pub tool: Option<String>,
    /// Case-id patterns marking cases critical (`prefix*` or exact).
    pub critical: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("malformed XML: {0}")]
    Xml(String),
    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid evaluation run: {}", .0.join("; "))]
    Invalid(Vec<String>),
}

pub fn from_junit(_xml: &str, _meta: &ImportMeta) -> Result<EvaluationRun, ImportError> {
    todo!("implement per the module contract")
}

pub fn from_json(_json: &str) -> Result<EvaluationRun, ImportError> {
    todo!("implement per the module contract")
}
