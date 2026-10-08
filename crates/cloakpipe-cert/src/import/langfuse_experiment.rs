//! Langfuse experiment + experiment items → [`EvaluationRun`] (contract in
//! the `import` module docs).

use super::scores::ScoreRules;
use super::{ImportError, ImportMeta};
use crate::model::EvaluationRun;

/// Import a Langfuse experiment and its items (with their scores) as an
/// [`EvaluationRun`] (see the `import` module docs).
pub fn from_langfuse_experiment(
    _experiment_json: &str,
    _items_json: &str,
    _meta: &ImportMeta,
    _rules: &ScoreRules,
) -> Result<EvaluationRun, ImportError> {
    Err(ImportError::Invalid(vec!["not implemented".into()]))
}
