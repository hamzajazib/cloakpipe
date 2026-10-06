//! Runtime tool gate (Phase C): may this Agent Release call this tool now?
//!
//! The MCP interceptor asks [`ToolGate::check`] before forwarding each
//! `tools/call`. A call is allowed only when
//!
//! 1. the tool is declared in the release manifest (`spec.tools`, by name:
//!    `tool:refund@4` declares `refund`), and
//! 2. the release holds a certification that verifies offline *now*
//!    ([`cloakpipe_cert::statement::verify`]: trusted signer, not revoked,
//!    inside its validity window, about this release, `certified` decision)
//!    for the gate's environment.
//!
//! Without a certification every call is refused: the gate fails closed.
//! `warn` mode reports the same verdicts but lets calls through.

use cloakpipe_cert::statement::{verify, Envelope, Status, VerifyContext};
use cloakpipe_release::{AgentRelease, Reference};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Refuse calls that fail the gate.
    Enforce,
    /// Forward them, but report the violation.
    Warn,
}

/// Why a call fails the gate. `code()` is stable and safe to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The manifest does not declare this tool.
    UndeclaredTool,
    /// No certification was supplied.
    Uncertified,
    /// The certification does not certify the release now; carries the
    /// verification status (`expired`, `revoked`, `invalid`, ...) or
    /// `blocked` for a verified BLOCKED decision.
    NotCertified(String),
    /// Certified, but for another environment.
    WrongEnvironment(String),
}

impl Denial {
    pub fn code(&self) -> String {
        match self {
            Denial::UndeclaredTool => "undeclared_tool".into(),
            Denial::Uncertified => "uncertified".into(),
            Denial::NotCertified(status) => status.clone(),
            Denial::WrongEnvironment(_) => "wrong_environment".into(),
        }
    }
}

pub struct ToolGate {
    pub mode: GateMode,
    release: String,
    environment: String,
    tools: BTreeSet<String>,
    certification: Option<Envelope>,
    verify: VerifyContext,
}

impl ToolGate {
    /// `verify` carries the trusted keys and revocations; its `now` and
    /// `expected_release` are set per check.
    pub fn new(
        mode: GateMode,
        manifest: &AgentRelease,
        environment: &str,
        certification: Option<Envelope>,
        verify: VerifyContext,
    ) -> Self {
        let tools = manifest
            .spec
            .tools
            .iter()
            .filter_map(|t| Reference::parse(&t.reference).ok())
            .map(|r| r.name)
            .collect();
        Self {
            mode,
            release: manifest.manifest_hash().to_string(),
            environment: environment.to_string(),
            tools,
            certification,
            verify,
        }
    }

    /// The release's manifest hash (`sha256:<hex>`).
    pub fn release(&self) -> &str {
        &self.release
    }

    /// Check one call to `tool` at RFC 3339 time `now`.
    pub fn check(&self, tool: &str, now: &str) -> Result<(), Denial> {
        if !self.tools.contains(tool) {
            return Err(Denial::UndeclaredTool);
        }
        let Some(envelope) = &self.certification else { return Err(Denial::Uncertified) };
        let ctx = VerifyContext {
            now: now.to_string(),
            expected_release: Some(self.release.clone()),
            ..self.verify.clone()
        };
        let report = verify(envelope, &ctx);
        if !report.certified {
            let status = match report.status {
                // Verified, but the decision it attests is a block.
                Status::Valid | Status::ValidWithLimitations => "blocked".to_string(),
                other => serde_json::to_value(other)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_ascii_lowercase))
                    .unwrap_or_else(|| "invalid".into()),
            };
            return Err(Denial::NotCertified(status));
        }
        // Signed and verified: its scope can be trusted.
        match certified_environment(envelope) {
            Some(env) if env == self.environment => Ok(()),
            Some(env) => Err(Denial::WrongEnvironment(env)),
            None => Err(Denial::NotCertified("invalid".into())),
        }
    }
}

/// `predicate.certification.environment` of a (verified) envelope.
fn certified_environment(envelope: &Envelope) -> Option<String> {
    use base64::prelude::*;
    let payload = BASE64_STANDARD.decode(&envelope.payload).ok()?;
    let statement: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    statement.pointer("/predicate/certification/environment")?.as_str().map(str::to_string)
}
