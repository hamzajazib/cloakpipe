//! in-toto v1 Statement wrapper, so a release manifest can be signed and
//! verified with standard supply-chain tooling (DSSE, Sigstore, SLSA
//! verifiers). The predicate is the full manifest; a verifier recomputes the
//! subject digest from it.

use crate::manifest::AgentRelease;
use serde_json::{json, Value};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://cloakpipe.dev/attestations/agent-release/v1alpha1";

impl AgentRelease {
    pub fn intoto_statement(&self) -> Value {
        json!({
            "_type": STATEMENT_TYPE,
            "subject": [{
                "name": format!("agent-release:{}@{}", self.metadata.agent, self.metadata.version),
                "digest": { "sha256": self.manifest_hash().hex() },
            }],
            "predicateType": PREDICATE_TYPE,
            "predicate": self,
        })
    }
}
