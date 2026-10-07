//! Braintrust experiment export → [`EvaluationRun`] (contract in the
//! `import` module docs).

use super::scores::{json_error, CaseScores, ScoreRules, J};
use super::{build_run, secs_to_ms, ImportError, ImportMeta};
use crate::model::{CaseResult, EvaluationRun, SourceKind};
use std::collections::BTreeMap;

/// Import a Braintrust experiment export as an [`EvaluationRun`] (see the
/// `import` module docs).
pub fn from_braintrust(json: &str, meta: &ImportMeta, rules: &ScoreRules) -> Result<EvaluationRun, ImportError> {
    let events = read_events(json)?;
    let mut issues = rules.issues();
    let mut cases = Vec::new();
    for (label, event) in &events {
        if !matches!(event, J::Obj(_)) {
            issues.push(format!("{label}: expected an event object, found {}", event.kind()));
            continue;
        }
        match read_event(label, event, meta, rules) {
            Ok(Some(case)) => cases.push(case),
            Ok(None) => {}
            Err(problems) => issues.extend(problems),
        }
    }
    build_run(meta, SourceKind::Braintrust, meta.dataset.clone(), cases, issues)
}

/// The events of `json`, each with a label naming it in issues.
fn read_events(json: &str) -> Result<Vec<(String, J)>, ImportError> {
    let whole = match J::parse(json) {
        Ok(doc) => doc,
        Err(err) => return read_jsonl(json, err),
    };
    let indexed = |items: Vec<J>| items.into_iter().enumerate().map(|(i, e)| (format!("events[{i}]"), e)).collect();
    match whole {
        J::Arr(items) => Ok(indexed(items)),
        // A lone event object: JSONL with one line.
        J::Obj(_) if !has_key(&whole, "events") => Ok(vec![("line 1".into(), whole)]),
        J::Obj(_) => match whole.get("events").map_err(|e| ImportError::Invalid(vec![e]))? {
            Some(J::Arr(items)) => Ok(indexed(items.clone())),
            other => Err(ImportError::Invalid(vec![format!(
                "events: expected an array, found {}",
                other.map_or("null", J::kind)
            )])),
        },
        other => Err(ImportError::Invalid(vec![format!(
            "expected {{\"events\": [...]}}, an array of events or JSONL, found {}",
            other.kind()
        )])),
    }
}

fn has_key(obj: &J, key: &str) -> bool {
    matches!(obj, J::Obj(entries) if entries.iter().any(|(k, _)| k == key))
}

/// One event per non-blank line. If not even the first line parses, the
/// input was not JSONL either: report the whole-document error.
fn read_jsonl(json: &str, whole: serde_json::Error) -> Result<Vec<(String, J)>, ImportError> {
    let json = json.strip_prefix('\u{feff}').unwrap_or(json);
    let mut events = Vec::new();
    for (i, line) in json.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match J::parse(line) {
            Ok(event) => events.push((format!("line {}", i + 1), event)),
            Err(_) if events.is_empty() => return Err(ImportError::Json(whole)),
            Err(e) => return Err(json_error(format_args!("JSONL line {}: {e}", i + 1))),
        }
    }
    if events.is_empty() {
        return Err(ImportError::Json(whole));
    }
    Ok(events)
}

/// The case of a root-span event; `None` for any other span.
fn read_event(
    label: &str,
    event: &J,
    meta: &ImportMeta,
    rules: &ScoreRules,
) -> Result<Option<CaseResult>, Vec<String>> {
    let at = |e: String| vec![format!("{label}: {e}")];
    let get = |key: &str| event.get(key).map_err(at);

    // ── Is it a root span? ──
    let is_root = match get("is_root")? {
        None => false,
        Some(J::Bool(b)) => *b,
        Some(other) => return Err(at(format!("is_root: expected a bool, found {}", other.kind()))),
    };
    let has_parents = match get("span_parents")? {
        None => false,
        Some(J::Arr(parents)) => !parents.is_empty(),
        Some(other) => return Err(at(format!("span_parents: expected an array, found {}", other.kind()))),
    };
    let same_span = match (get("span_id")?, get("root_span_id")?) {
        (Some(J::Str(a)), Some(J::Str(b))) => a == b,
        _ => false,
    };
    if !(is_root || !has_parents || same_span) {
        return Ok(None);
    }

    // ── Identity ──
    let mut issues = Vec::new();
    let metadata = match get("metadata")? {
        None => None,
        Some(m @ J::Obj(_)) => Some(m),
        Some(other) => return Err(at(format!("metadata: expected an object, found {}", other.kind()))),
    };
    let meta_get = |key: &str| match metadata {
        Some(m) => m.get(key).map_err(|e| at(format!("metadata: {e}"))),
        None => Ok(None),
    };
    let candidates = [
        ("metadata.cloakpipe_case_id", meta_get("cloakpipe_case_id")?),
        ("metadata.case_id", meta_get("case_id")?),
        ("dataset_record_id", get("dataset_record_id")?),
    ];
    let Some((field, value)) = candidates.into_iter().find_map(|(f, v)| v.map(|v| (f, v))) else {
        return Err(at(
            "no stable case id: set metadata.cloakpipe_case_id or metadata.case_id, or log from a dataset \
             (dataset_record_id); row ids differ between runs"
                .into(),
        ));
    };
    let id = match value {
        J::Str(s) if !s.trim().is_empty() => s.clone(),
        other => return Err(at(format!("{field}: expected a non-empty string, found {}", describe(other)))),
    };
    let mut scores = CaseScores::new(format!("{label} (case {id:?})"));

    // ── Critical ──
    let critical_flag = match metadata.map(|m| has_key(m, "critical")) {
        Some(true) => match meta_get("critical")? {
            Some(J::Bool(b)) => *b,
            other => {
                let found = other.map_or("null", J::kind);
                issues.push(scores.issue(format_args!("metadata.critical: expected true or false, found {found}")));
                false
            }
        },
        _ => false,
    };
    let critical = critical_flag || meta.is_critical(&id);

    // ── Error ──
    let error = get("error")?.is_some_and(|e| !e.is_empty());

    // ── Scores ──
    match get("scores")? {
        None => {}
        Some(J::Obj(entries)) => {
            for (name, value) in entries {
                if !scores.name(name, &mut issues) {
                    continue;
                }
                match value {
                    J::Null => {}
                    J::Num(v) => scores.value(name, *v, &mut issues),
                    other => issues.push(
                        scores.issue(format_args!("score {name:?}: expected a number or null, found {}", other.kind())),
                    ),
                }
            }
        }
        Some(other) => issues.push(scores.issue(format_args!("scores: expected an object, found {}", other.kind()))),
    }

    // ── Metrics ──
    let mut metrics = BTreeMap::new();
    let mut duration_ms = None;
    match get("metrics")? {
        None => {}
        Some(m @ J::Obj(_)) => {
            let num = |key: &str| match m.get(key) {
                Ok(Some(J::Num(v))) => Ok(Some(*v)),
                Ok(_) => Ok(None),
                Err(e) => Err(scores.issue(format_args!("metrics: {e}"))),
            };
            match (num("start"), num("end")) {
                (Ok(Some(start)), Ok(Some(end))) if end >= start => duration_ms = secs_to_ms(end - start),
                (Err(e), _) | (_, Err(e)) => issues.push(e),
                _ => {}
            }
            for (key, metric) in [
                ("prompt_tokens", "tokens.prompt"),
                ("completion_tokens", "tokens.completion"),
                ("tokens", "tokens.total"),
            ] {
                match num(key) {
                    Ok(Some(v)) => {
                        metrics.insert(metric.to_string(), v);
                    }
                    Ok(None) => {}
                    Err(e) => issues.push(e),
                }
            }
        }
        Some(other) => issues.push(scores.issue(format_args!("metrics: expected an object, found {}", other.kind()))),
    }

    if !issues.is_empty() {
        return Err(issues);
    }
    Ok(Some(scores.into_case(id, critical, error, rules, metrics, duration_ms)))
}

fn describe(v: &J) -> String {
    match v {
        J::Str(s) => format!("{s:?}"),
        other => other.kind().to_string(),
    }
}
