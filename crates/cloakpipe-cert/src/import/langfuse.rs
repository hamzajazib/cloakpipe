//! Langfuse dataset run + scores → [`EvaluationRun`] (contract in the
//! `import` module docs).

use super::scores::{CaseScores, ScoreRules, J};
use super::{build_run, ImportError, ImportMeta};
use crate::model::{EvaluationRun, SourceKind};
use std::collections::{BTreeMap, BTreeSet};

/// A dataset run item: one case.
struct Item {
    case_id: String,
    trace_id: String,
    observation_id: Option<String>,
}

/// Import a Langfuse dataset run and its scores as an [`EvaluationRun`] (see
/// the `import` module docs).
pub fn from_langfuse(
    run_json: &str,
    scores_json: &str,
    meta: &ImportMeta,
    rules: &ScoreRules,
) -> Result<EvaluationRun, ImportError> {
    let run = J::parse(run_json)?;
    let scores_doc = J::parse(scores_json)?;
    let mut issues = rules.issues();

    let items = read_items(&run).map_err(|e| ImportError::Invalid(vec![e]))?;
    let dataset_name = match run.get("datasetName") {
        Ok(Some(J::Str(name))) if !name.trim().is_empty() => Some(name.clone()),
        _ => None,
    };

    let mut parsed = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match read_item(item) {
            Ok(item) => parsed.push(item),
            Err(e) => issues.push(format!("datasetRunItems[{i}]: {e}")),
        }
    }

    // Scores by trace id, de-duplicated by score id (pages may overlap).
    let mut by_trace: BTreeMap<&str, Vec<(String, &J)>> = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
    for (label, score) in score_objects(&scores_doc, &mut issues) {
        if !matches!(score, J::Obj(_)) {
            issues.push(format!("{label}: expected a score object, found {}", score.kind()));
            continue;
        }
        let fields = (score.get("id"), score.get("traceId"));
        match fields {
            (Err(e), _) | (_, Err(e)) => issues.push(format!("{label}: {e}")),
            (Ok(id), Ok(trace)) => {
                if let Some(J::Str(id)) = id {
                    if !seen_ids.insert(id.as_str()) {
                        continue;
                    }
                }
                // Scores without a trace (session or dataset-run scores) cannot join.
                if let Some(J::Str(trace)) = trace {
                    by_trace.entry(trace.as_str()).or_default().push((label, score));
                }
            }
        }
    }

    let mut cases = Vec::with_capacity(parsed.len());
    for item in parsed {
        let mut scores = CaseScores::new(format!("case {:?}", item.case_id));
        for (label, score) in by_trace.get(item.trace_id.as_str()).into_iter().flatten() {
            let mut problem = |what: String| issues.push(scores.issue(format_args!("{label}: {what}")));
            match score.get("observationId") {
                Ok(None) => {}
                Ok(Some(J::Str(obs))) if item.observation_id.as_deref() == Some(obs.as_str()) => {}
                Ok(Some(J::Str(_))) => continue,
                Ok(Some(other)) => {
                    problem(format!("observationId: expected a string or null, found {}", other.kind()));
                    continue;
                }
                Err(e) => {
                    problem(e);
                    continue;
                }
            }
            let data_type = match score.get("dataType") {
                Ok(None) => "NUMERIC",
                Ok(Some(J::Str(t))) => t.as_str(),
                Ok(Some(other)) => {
                    problem(format!("dataType: expected a string, found {}", other.kind()));
                    continue;
                }
                Err(e) => {
                    problem(e);
                    continue;
                }
            };
            if data_type == "CATEGORICAL" {
                continue;
            }
            let name = match score.get("name") {
                Ok(Some(J::Str(name))) if !name.is_empty() => name,
                Ok(other) => {
                    problem(format!("name: expected a non-empty string, found {}", other.map_or("null", J::kind)));
                    continue;
                }
                Err(e) => {
                    problem(e);
                    continue;
                }
            };
            let value = match (data_type, score.get("value")) {
                (_, Err(e)) => Err(e),
                ("NUMERIC", Ok(Some(J::Num(v)))) => Ok(*v),
                ("BOOLEAN", Ok(Some(J::Num(v)))) if *v == 0.0 || *v == 1.0 => Ok(*v),
                ("NUMERIC", Ok(other)) => {
                    Err(format!("value: expected a number, found {}", other.map_or("null", J::kind)))
                }
                ("BOOLEAN", Ok(other)) => Err(format!(
                    "value: expected 0 or 1 for a BOOLEAN score, found {}",
                    other.map_or("null".to_string(), |v| match v {
                        J::Num(n) => n.to_string(),
                        v => v.kind().to_string(),
                    })
                )),
                (other, _) => Err(format!("unsupported dataType {other:?}")),
            };
            match value {
                Ok(v) => {
                    if scores.name(name, &mut issues) {
                        scores.value(name, v, &mut issues);
                    }
                }
                Err(e) => problem(e),
            }
        }
        let critical = meta.is_critical(&item.case_id);
        cases.push(scores.into_case(item.case_id, critical, false, rules, BTreeMap::new(), None));
    }

    let dataset = meta.dataset.clone().or(dataset_name);
    build_run(meta, SourceKind::Langfuse, dataset, cases, issues)
}

fn read_items(run: &J) -> Result<&[J], String> {
    let found = match run {
        J::Obj(_) => run.get("datasetRunItems")?,
        other => return Err(format!("expected a dataset run object with datasetRunItems, found {}", other.kind())),
    };
    match found {
        Some(J::Arr(items)) => Ok(items),
        other => Err(format!("datasetRunItems: expected an array, found {}", other.map_or("nothing", J::kind))),
    }
}

fn read_item(item: &J) -> Result<Item, String> {
    if !matches!(item, J::Obj(_)) {
        return Err(format!("expected an object, found {}", item.kind()));
    }
    let string = |key: &str| match item.get(key)? {
        Some(J::Str(s)) if !s.trim().is_empty() => Ok(s.clone()),
        other => Err(format!("{key}: expected a non-empty string, found {}", other.map_or("null", J::kind))),
    };
    let case_id = string("datasetItemId")?;
    let trace_id = string("traceId")?;
    let observation_id = match item.get("observationId")? {
        None => None,
        Some(J::Str(s)) => Some(s.clone()),
        Some(other) => return Err(format!("observationId: expected a string or null, found {}", other.kind())),
    };
    Ok(Item { case_id, trace_id, observation_id })
}

/// Score objects from a scores page `{"data": [...]}`, a bare array of
/// scores, or an array of pages; each with a label naming it in issues.
fn score_objects<'a>(doc: &'a J, issues: &mut Vec<String>) -> Vec<(String, &'a J)> {
    let mut out = Vec::new();
    match doc {
        J::Obj(_) => page_scores("scores".into(), doc, &mut out, issues),
        J::Arr(elements) => {
            for (i, element) in elements.iter().enumerate() {
                let label = format!("scores[{i}]");
                match element {
                    J::Obj(entries) if entries.iter().any(|(k, _)| k == "data") => {
                        page_scores(label, element, &mut out, issues)
                    }
                    J::Obj(_) => out.push((label, element)),
                    other => {
                        issues.push(format!("{label}: expected a score or a page of scores, found {}", other.kind()))
                    }
                }
            }
        }
        other => issues.push(format!("scores: expected a page of scores or an array, found {}", other.kind())),
    }
    out
}

/// The scores of one page `{"data": [...], "meta": {...}}`.
fn page_scores<'a>(label: String, page: &'a J, out: &mut Vec<(String, &'a J)>, issues: &mut Vec<String>) {
    match page.get("data") {
        Ok(Some(J::Arr(scores))) => {
            out.extend(scores.iter().enumerate().map(|(i, s)| (format!("{label}.data[{i}]"), s)))
        }
        Ok(other) => {
            issues.push(format!("{label}.data: expected an array, found {}", other.map_or("nothing", J::kind)))
        }
        Err(e) => issues.push(format!("{label}: {e}")),
    }
}
