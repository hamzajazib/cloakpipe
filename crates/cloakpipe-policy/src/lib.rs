//! Cedar policies for the CloakPipe tool gate.
//!
//! A v1 manifest may reference a Cedar policy file (`policy:`). The gate
//! evaluates it for every call that passed the tool contract, with:
//!
//! - **principal** `Release::"<release name>"`;
//! - **action** `Action::"<tool name>"` (the spec's `Tool::"<tool name>"`
//!   spelling is accepted in policies and means the same);
//! - **resource** `Call::"<call fingerprint>"`, whose `args` attribute holds
//!   the call's arguments as a Cedar record;
//! - **context** `{ task: <the trusted task context>, counters: { <tool>_1h,
//!   <tool>_24h, ... }, time: { unix, hour_utc, weekday } }`.
//!
//! Arguments and the task context map from JSON as: string -> String,
//! boolean -> Bool, integral number -> Long, other number -> `decimal` (at
//! most four fractional digits), array -> Set, object -> Record; `null`
//! members are left out. Values are built directly, never through Cedar's
//! JSON entity format, so an argument can not forge an entity reference
//! (`__entity`) or an extension value (`__extn`). A number Cedar cannot hold
//! is an [`PolicyError::Input`] error.
//!
//! `counters` has, for every tool the manifest declares, the number of calls
//! to it the gate forwarded for this release in the hour and the day before
//! this call ([`Counters`]). `time.weekday` is the ISO weekday (1 = Monday ..
//! 7 = Sunday), `time.hour_utc` 0..23.
//!
//! Decisions ([`PolicyDecision`]): no satisfied permit, or any satisfied
//! forbid, is `Deny` (with the satisfied forbids' ids); when every satisfied
//! permit carries `@approval("<route>")` the call needs an approval receipt
//! (`RequireApproval`, with the routes); otherwise `Allow`. Any evaluation
//! error is [`PolicyError::Evaluation`]: the gate fails closed.
//!
//! A policy's id is its `@id("...")` annotation when it has one, else Cedar's
//! positional `policyN`.

use cedar_policy::{
    AuthorizationError, Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicyId,
    PolicySet, Request, RestrictedExpression,
};
use chrono::{Datelike, TimeZone, Timelike};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

mod counters;

pub use counters::{CounterError, Counters, Window};

/// The annotation that names a policy.
pub const ID_ANNOTATION: &str = "id";
/// The annotation that makes a permit require an approval receipt; its value
/// is a routing string for the approval broker.
pub const APPROVAL_ANNOTATION: &str = "approval";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The policy file is not valid Cedar (or uses templates, or repeats an id).
    #[error("invalid Cedar policy: {0}")]
    Parse(String),
    /// The call could not be expressed as a Cedar request. Never carries
    /// argument values.
    #[error("the call cannot be evaluated: {0}")]
    Input(String),
    /// Evaluating these policies failed (a type error, a missing attribute,
    /// ...). Cedar's messages can quote values, so only the ids are kept.
    #[error("policy evaluation failed in {}", policies.join(", "))]
    Evaluation { policies: Vec<String> },
}

/// The outcome of evaluating one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Permitted; `policies` are the satisfied permits.
    Allow { policies: Vec<String> },
    /// Permitted only with an approval receipt: every satisfied permit
    /// (`policies`) carries `@approval`; `approvers` are their values.
    RequireApproval { approvers: Vec<String>, policies: Vec<String> },
    /// Refused; `policies` are the satisfied forbids (empty: nothing permits).
    Deny { policies: Vec<String> },
}

/// One call, as the gate presents it to the policy.
#[derive(Debug, Clone, Copy)]
pub struct CallInput<'a> {
    /// The release name (the principal).
    pub release: &'a str,
    /// The tool (the action).
    pub tool: &'a str,
    /// The call fingerprint (the resource id).
    pub fingerprint: &'a str,
    /// The raw arguments (`resource.args`); `None` is an empty record.
    pub args: Option<&'a Value>,
    /// The trusted task context (`context.task`); `None` is an empty record.
    pub task: Option<&'a Value>,
    /// Calls forwarded per tool, by window (`context.counters`).
    pub counters: &'a BTreeMap<String, Window>,
    /// Seconds since the Unix epoch (`context.time`).
    pub now_unix: i64,
}

/// A parsed policy set, ready to evaluate calls.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl PolicyEngine {
    /// Parse Cedar source. Templates and repeated ids are refused.
    pub fn parse(src: &str) -> Result<Self, PolicyError> {
        let src = tool_as_action(src);
        let parsed = PolicySet::from_str(&src).map_err(|e| PolicyError::Parse(render_parse_error(&e)))?;
        if parsed.templates().next().is_some() {
            return Err(PolicyError::Parse("policy templates (?principal / ?resource slots) are not supported".into()));
        }
        let mut policies = PolicySet::new();
        for p in parsed.policies() {
            let p = match p.annotation(ID_ANNOTATION) {
                Some(id) if id.trim().is_empty() => return Err(PolicyError::Parse("an @id annotation is empty".into())),
                Some(id) => p.new_id(PolicyId::new(id)),
                None => p.clone(),
            };
            let id = p.id().to_string();
            policies.add(p).map_err(|_| PolicyError::Parse(format!("two policies have the id {id:?}")))?;
        }
        Ok(Self { policies, authorizer: Authorizer::new() })
    }

    /// The policies' ids, sorted.
    pub fn policy_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.policies.policies().map(|p| p.id().to_string()).collect();
        ids.sort();
        ids
    }

    /// Evaluate one call.
    pub fn evaluate(&self, call: &CallInput<'_>) -> Result<PolicyDecision, PolicyError> {
        let principal = uid("Release", call.release)?;
        let action = uid("Action", call.tool)?;
        let resource = uid("Call", call.fingerprint)?;
        let args = match call.args {
            None | Some(Value::Null) => RestrictedExpression::new_record([]).map_err(input)?,
            Some(v) => to_cedar(v, "args")?,
        };
        let call_entity = Entity::new(resource.clone(), HashMap::from([("args".to_string(), args)]), HashSet::new())
            .map_err(|_| PolicyError::Input("the arguments are not valid Cedar values".into()))?;
        let entities = Entities::from_entities([call_entity, Entity::new_no_attrs(principal.clone(), HashSet::new())], None)
            .map_err(|_| PolicyError::Input("the call entities are not valid".into()))?;
        let context = Context::from_pairs([
            ("task".to_string(), match call.task {
                None | Some(Value::Null) => RestrictedExpression::new_record([]).map_err(input)?,
                Some(v) => to_cedar(v, "task context")?,
            }),
            ("counters".to_string(), counters_record(call.counters)?),
            ("time".to_string(), time_record(call.now_unix)?),
        ])
        .map_err(|_| PolicyError::Input("the context is not a valid Cedar record".into()))?;
        let request = Request::new(principal, action, resource, context, None)
            .map_err(|_| PolicyError::Input("the request is not valid".into()))?;
        let response = self.authorizer.is_authorized(&request, &self.policies, &entities);
        let diagnostics = response.diagnostics();
        let errored: BTreeSet<String> = diagnostics
            .errors()
            .map(|e| match e {
                AuthorizationError::PolicyEvaluationError(e) => e.policy_id().to_string(),
            })
            .collect();
        if !errored.is_empty() {
            return Err(PolicyError::Evaluation { policies: errored.into_iter().collect() });
        }
        let satisfied: BTreeSet<String> = diagnostics.reason().map(PolicyId::to_string).collect();
        let satisfied: Vec<String> = satisfied.into_iter().collect();
        if response.decision() == Decision::Deny {
            return Ok(PolicyDecision::Deny { policies: satisfied });
        }
        let mut approvers = Vec::new();
        for id in &satisfied {
            match self.policies.annotation(&PolicyId::new(id), APPROVAL_ANNOTATION) {
                Some(route) => {
                    if !route.is_empty() && !approvers.iter().any(|a| a == route) {
                        approvers.push(route.to_string());
                    }
                }
                None => return Ok(PolicyDecision::Allow { policies: satisfied }),
            }
        }
        Ok(PolicyDecision::RequireApproval { approvers, policies: satisfied })
    }
}

fn input(_: impl std::fmt::Display) -> PolicyError {
    PolicyError::Input("a record could not be built".into())
}

fn uid(ty: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let ty = EntityTypeName::from_str(ty).map_err(|_| PolicyError::Input(format!("bad entity type {ty}")))?;
    Ok(EntityUid::from_type_name_and_id(ty, EntityId::new(id)))
}

/// A JSON value as a Cedar value (see the crate docs for the mapping).
/// `what` names it in errors; values never appear in them.
fn to_cedar(v: &Value, what: &str) -> Result<RestrictedExpression, PolicyError> {
    Ok(match v {
        Value::String(s) => RestrictedExpression::new_string(s.clone()),
        Value::Bool(b) => RestrictedExpression::new_bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                RestrictedExpression::new_long(i)
            } else if n.is_u64() {
                return Err(PolicyError::Input(format!("a number in the {what} is too large for Cedar")));
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.fract() == 0.0 && f >= i64::MIN as f64 && f < i64::MAX as f64 {
                    RestrictedExpression::new_long(f as i64)
                } else {
                    // Cedar decimals: at most four fractional digits, |x| < 2^63 / 10^4.
                    let s = format!("{f}");
                    let fraction = s.split_once('.').map_or(0, |(_, frac)| frac.len());
                    if !f.is_finite() || fraction > 4 || f.abs() >= 922_337_203_685_477.0 {
                        return Err(PolicyError::Input(format!(
                            "a number in the {what} is neither an integer nor a decimal with at most four fractional digits"
                        )));
                    }
                    RestrictedExpression::new_decimal(s)
                }
            }
        }
        Value::Array(items) => RestrictedExpression::new_set(
            items.iter().filter(|i| !i.is_null()).map(|i| to_cedar(i, what)).collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Object(map) => RestrictedExpression::new_record(
            map.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| Ok((k.clone(), to_cedar(v, what)?)))
                .collect::<Result<Vec<_>, PolicyError>>()?,
        )
        .map_err(input)?,
        Value::Null => return Err(PolicyError::Input(format!("the {what} is null"))),
    })
}

fn counters_record(counters: &BTreeMap<String, Window>) -> Result<RestrictedExpression, PolicyError> {
    let mut fields = Vec::with_capacity(counters.len() * 2);
    for (tool, w) in counters {
        fields.push((format!("{tool}_1h"), RestrictedExpression::new_long(w.last_1h)));
        fields.push((format!("{tool}_24h"), RestrictedExpression::new_long(w.last_24h)));
    }
    // Two tools could collide (`a_1h` the tool vs `a` + `_1h`): an error.
    RestrictedExpression::new_record(fields).map_err(|_| PolicyError::Input("two counter names collide".into()))
}

fn time_record(now_unix: i64) -> Result<RestrictedExpression, PolicyError> {
    let t = chrono::Utc
        .timestamp_opt(now_unix, 0)
        .single()
        .ok_or_else(|| PolicyError::Input("the time is out of range".into()))?;
    RestrictedExpression::new_record([
        ("unix".to_string(), RestrictedExpression::new_long(now_unix)),
        ("hour_utc".to_string(), RestrictedExpression::new_long(i64::from(t.hour()))),
        ("weekday".to_string(), RestrictedExpression::new_long(i64::from(t.weekday().number_from_monday()))),
    ])
    .map_err(input)
}

/// Accept the spec's `Tool::"name"` for actions: rewrite each `Tool::"`
/// that is not inside a string literal or a comment, and not part of a
/// longer path (`Ns::Tool::"`), to `Action::"`.
fn tool_as_action(src: &str) -> String {
    const FROM: &str = "Tool::\"";
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut start = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                // Skip the string literal, honouring escapes.
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'T' if src[i..].starts_with(FROM)
                && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || bytes[i - 1] == b':')) =>
            {
                out.push_str(&src[start..i]);
                out.push_str("Action::");
                // Continue at the opening quote, so the literal is skipped.
                i += FROM.len() - 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    out.push_str(&src[start.min(src.len())..]);
    out
}

/// Cedar's parse errors, with their source snippets.
fn render_parse_error(e: &cedar_policy::ParseErrors) -> String {
    let mut msg = e.to_string();
    for (n, err) in e.iter().enumerate().skip(1) {
        msg.push_str(&format!("; ({}) {err}", n + 1));
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::tool_as_action;

    #[test]
    fn tool_spelling_is_rewritten_outside_strings_and_comments() {
        assert_eq!(tool_as_action(r#"action == Tool::"a""#), r#"action == Action::"a""#);
        assert_eq!(tool_as_action(r#"[Tool::"a",Tool::"b"]"#), r#"[Action::"a",Action::"b"]"#);
        assert_eq!(tool_as_action(r#"x == "Tool::\"a\"""#), r#"x == "Tool::\"a\"""#);
        assert_eq!(tool_as_action("// Tool::\"a\"\nTool::\"b\""), "// Tool::\"a\"\nAction::\"b\"");
        assert_eq!(tool_as_action(r#"Ns::Tool::"a" MyTool::"b""#), r#"Ns::Tool::"a" MyTool::"b""#);
        assert_eq!(tool_as_action(r#"Tool::"Tool::\"x\"""#), r#"Action::"Tool::\"x\"""#);
        assert_eq!(tool_as_action("ünïcode Tool::\"é\""), "ünïcode Action::\"é\"");
    }
}
