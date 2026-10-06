//! The certification decision.
//!
//! Contract (see docs/CERTIFICATION.md §Decision). `decide` is a pure,
//! deterministic function: the same input always yields an identical
//! `Decision` (including reason order), regardless of the order of runs or
//! cases in the input. It never panics.
//!
//! Checks, in this order (all are evaluated; any reason ⇒ `Blocked`):
//!
//! 1. **Input validity** — every candidate and baseline run must pass
//!    `EvaluationRun::validate`, and the policy `CertificationPolicy::validate`;
//!    each problem → `InvalidInput` (invalid runs are then ignored by the
//!    remaining checks).
//! 2. **Release binding** — a candidate run whose `release` ≠ input `release`
//!    → `ReleaseMismatch` (and the run is ignored by the remaining checks).
//!    Baseline runs may be for any release.
//! 3. **Required assurance** — each name in `required_suites` must appear in
//!    the `covers` of at least one remaining candidate run, else
//!    `MissingSuite` (reason.suite = the assurance suite name).
//! 4. Per remaining candidate run (keyed by run suite name; if two runs share
//!    a suite name, both are checked independently):
//!    - zero executed cases (all skipped or none) → `NoCases`;
//!    - coverage = executed / total < `rules.minCoverage` → `CoverageBelowMinimum`;
//!    - `rules.minPassRate`: pass rate < min → `PassRateBelowMinimum`;
//!    - `rules.maxPassRateRegression`: if a baseline run with the same suite
//!      name exists, baseline pass rate − candidate pass rate > max →
//!      `PassRateRegression` (no baseline ⇒ check skipped);
//!    - critical cases (`critical: true`) whose status is Fail/Error:
//!      **new** if the baseline run for the suite does not have a failing
//!      case with that id (absent baseline or absent case counts as new),
//!      otherwise **persisting**. New critical failures above
//!      `rules.maxNewCriticalFailures` (counted across all runs) → one
//!      `NewCriticalFailure` reason per new failing case; persisting ones →
//!      one `PersistingCriticalFailure` each when
//!      `rules.blockPersistingCriticalFailures`.
//! 5. **Metrics** — for each `MetricRule`, over the executed cases of every
//!    remaining candidate run whose suite name matches `rule.suite` (all runs
//!    when `None`) that carry the metric: aggregate (mean; p50/p95 by
//!    nearest-rank on the sorted values; min; max) and compare. Violation →
//!    `MetricThreshold` with `observed` and `required`. No values ⇒ rule
//!    skipped.
//!
//! Comparisons use the exact thresholds (no epsilon): pass rate exactly equal
//! to `minPassRate` passes.
//!
//! The returned `Decision`: `release` and `policy` (`PolicyRef`) as given;
//! `requiredSuites` sorted and de-duplicated; `runs` / `baselineRuns` are
//! `RunRef`s of all input runs sorted by (suite, runId, hash); `summaries` one
//! per remaining candidate run sorted by (suite, then runId); `reasons` sorted
//! by (code, suite, case, message). `outcome = Certified` iff `reasons` is
//! empty.

use crate::model::{CertificationPolicy, Decision, EvaluationRun};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub struct DecisionInput<'a> {
    /// `sha256:<hex>` manifest hash of the candidate release.
    pub release: &'a str,
    /// Assurance suites the release must have evidence for (from
    /// `cloakpipe_release::diff` and/or policy).
    pub required_suites: &'a BTreeSet<String>,
    pub runs: &'a [EvaluationRun],
    pub baseline_runs: &'a [EvaluationRun],
    pub policy: &'a CertificationPolicy,
}

pub fn decide(_input: &DecisionInput<'_>) -> Decision {
    todo!("implement per the module contract")
}
