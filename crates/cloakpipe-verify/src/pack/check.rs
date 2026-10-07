//! Verifier side: every check of docs/AUDIT_PACK.md §Verification.
//!
//! Checks never stop at the first problem: the report lists every failure,
//! so a reviewer sees the whole picture. The pack passes iff there are none.

use super::*;
use crate::{anchor, verify as chain};
use base64::prelude::*;
use chrono::{DateTime, SecondsFormat, Utc};
use cloakpipe_cert::statement::{self, Certification, Status, VerifyContext};
use cloakpipe_cert::Outcome;
use cloakpipe_release::ReleaseHash;
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};

/// What verification depends on besides the pack. Each role has its own
/// trust anchors, and one key may not hold two roles: otherwise the exporter
/// could certify its own promotions, or a runtime ledger key (on a less
/// protected proxy host) could sign governance history.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Trusted exporter keys (`--trust`): the pack signature.
    pub trusted: Vec<TrustedKey>,
    /// Trusted ledger signer keys (`--ledger-trust`), matched by public key.
    pub ledger_trusted: Vec<TrustedKey>,
    /// Trusted certification issuers (`--cert-trust`).
    pub cert_trusted: Vec<TrustedKey>,
    /// The verification time (`--now`).
    pub now: DateTime<Utc>,
}

/// The outcome of verifying a pack.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackReport {
    /// True iff `failures` is empty.
    pub ok: bool,
    /// `sha256:<hex>` recomputed from the manifest.
    pub release: Option<String>,
    pub agent: Option<String>,
    pub version: Option<String>,
    /// Recomputed pack digest.
    pub digest: Option<String>,
    /// Key id of the trusted exporter whose signature verified.
    pub signer: Option<String>,
    pub exporter: Option<String>,
    pub created_at: Option<String>,
    pub now: String,
    pub failures: Vec<String>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub runs: Vec<RunSummary>,
    pub certifications: Vec<CertSummary>,
    pub ledger: Vec<LedgerSummary>,
    /// Where the release is (or was) deployed, from the governance events.
    pub environments: Vec<EnvironmentStatus>,
    /// Everything that happened to the release, in time order.
    pub timeline: Vec<TimelineEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    pub run_id: String,
    /// `name@version`.
    pub suite: String,
    pub hash: String,
    pub cases: u64,
    pub passed: u64,
    pub failed: u64,
    pub errored: u64,
    pub skipped: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertSummary {
    /// sha256 hex of the statement payload (what revocations name).
    pub statement_digest: Option<String>,
    /// Status at `now`, with the pack's revocations applied.
    pub status: Status,
    pub outcome: Option<Outcome>,
    pub environment: Option<String>,
    pub issuer: Option<String>,
    pub issued_at: Option<String>,
    pub valid_until: Option<String>,
    /// Valid (possibly with limitations) and a certified decision, at `now`.
    pub certified: bool,
    pub revoked_at: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerSummary {
    pub bundle_id: Option<String>,
    pub records: u64,
    /// Hops whose signed bytes bind them to this release.
    pub release_hops: u64,
    /// Hops bound to another release or to none (kept for the chain proof).
    pub other_hops: u64,
    pub release_hops_by_type: BTreeMap<String, u64>,
    pub first_hop_at: Option<String>,
    pub last_hop_at: Option<String>,
    pub chain_tip: Option<String>,
    pub signer_key_id: Option<String>,
    pub anchor_receipts: u64,
    pub inclusion_proofs: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentStatus {
    pub environment: String,
    /// The release is still the environment's pointer per the events.
    pub live: bool,
    /// When it was last promoted there (or superseded, if never promoted).
    pub since: String,
    /// `certified`, `break_glass`, `not_required`, `uncertified` (a failure)
    /// or `unknown` (superseded without a promotion in the pack).
    pub basis: String,
    pub actor: String,
    /// When it was superseded, if it was.
    pub until: Option<String>,
    /// For the certified environment: some certification for it is valid now.
    pub certified_now: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TimelineEntry {
    pub at: String,
    /// `registered`, `promoted`, `superseded`, `certification_issued`,
    /// `certification_expired`, `certification_revoked`, `sentinel_breach`,
    /// `runtime_first_hop`, `runtime_last_hop`.
    pub event: String,
    pub detail: String,
}

// ── Shared helpers (also used by the builder) ───────────────────────────

/// RFC 3339 `date-time` (chrono also accepts a space separator, which the
/// RFC does not).
pub(crate) fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    if !matches!(value.as_bytes().get(10), Some(b'T' | b't')) {
        return None;
    }
    DateTime::parse_from_rfc3339(value).ok().map(|t| t.with_timezone(&Utc))
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn decode_statement(e: &Envelope) -> Result<(Vec<u8>, Value), String> {
    let payload = BASE64_STANDARD.decode(&e.payload).map_err(|_| "payload is not standard base64".to_string())?;
    let value = serde_json::from_slice(&payload).map_err(|e| format!("payload is not JSON: {e}"))?;
    Ok((payload, value))
}

/// The release an envelope's statement is about (`sha256:<hex>`).
pub(crate) fn subject_release(e: &Envelope) -> Result<String, String> {
    let (_, st) = decode_statement(e)?;
    let hex = st["subject"][0]["digest"]["sha256"].as_str().ok_or("statement has no subject digest")?;
    let release: ReleaseHash =
        format!("sha256:{hex}").parse().map_err(|_| format!("subject digest {hex:?} is not 64 lowercase hex"))?;
    Ok(release.to_string())
}

fn decode_certification(e: &Envelope) -> Option<(String, Certification)> {
    let (payload, st) = decode_statement(e).ok()?;
    let cert = Certification::deserialize(st.get("predicate")?.get("certification")?).ok()?;
    Some((hex::encode(Sha256::digest(&payload)), cert))
}

/// The release a ledger record is bound to, read from its canonical bytes.
struct Hop {
    hop: String,
    ts: String,
    release: Option<String>,
}

const RECORD_LINES: [&str; 11] = [
    "seq=",
    "ts=",
    "tenant_id=",
    "hop=",
    "detections=",
    "actions=",
    "policy=",
    "identities=",
    "egress=",
    "prev_hash=",
    "metadata=",
];

/// Parse the fields a pack needs from a record's canonical bytes (the
/// `cloakpipe-ledger` encoding). Anything that does not read one way only
/// is an error: an unexpected line layout, or metadata that is not exactly
/// the ledger's `key=type:value;` entries (see [`parse_metadata`]).
fn parse_hop(canonical: &str) -> Result<Hop, String> {
    let lines: Vec<&str> = canonical.split('\n').collect();
    if lines.len() != RECORD_LINES.len() || lines.iter().zip(RECORD_LINES).any(|(l, p)| !l.starts_with(p)) {
        return Err("canonical bytes are not the 11-line record encoding".into());
    }
    let release = parse_metadata(&lines[10]["metadata=".len()..])?;
    Ok(Hop { hop: lines[3]["hop=".len()..].to_string(), ts: lines[1]["ts=".len()..].to_string(), release })
}

/// Parse a record's metadata line and return its release binding.
///
/// The ledger writes a `BTreeMap` as `key=type:value;` entries, keys in
/// strictly increasing byte order, and refuses keys and opaque ids that
/// contain `;` or `=` (or whitespace). Under those rules a line splits into
/// entries one way only, so the binding read here is exactly
/// `LedgerRecord::release_hash()`: the entry whose key is `release_hash`,
/// which must be a `hash`. Anything else fails rather than being guessed.
fn parse_metadata(meta: &str) -> Result<Option<String>, String> {
    if meta.is_empty() {
        return Ok(None);
    }
    let body = meta.strip_suffix(';').ok_or("metadata does not end with `;`")?;
    let is_hex64 = |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut release = None;
    let mut previous: Option<&str> = None;
    for entry in body.split(';') {
        let malformed = || format!("metadata entry {entry:?} is not `key=type:value`");
        let (key, typed) = entry.split_once('=').ok_or_else(malformed)?;
        let (kind, value) = typed.split_once(':').ok_or_else(malformed)?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!("metadata key {key:?} is not a plain name"));
        }
        if previous.is_some_and(|p| p >= key) {
            return Err(format!("metadata key {key:?} is out of order or repeated"));
        }
        previous = Some(key);
        let well_typed = match kind {
            "bool" => value == "true" || value == "false",
            "int" => value.parse::<i64>().is_ok_and(|i| i.to_string() == value),
            "hash" => is_hex64(value),
            "id" => !value.contains('=') && !value.chars().any(char::is_whitespace),
            _ => false,
        };
        if !well_typed {
            return Err(format!("metadata entry {entry:?} is not a valid {kind:?} value"));
        }
        if key == RELEASE_HASH_KEY {
            if kind != "hash" {
                return Err(format!("metadata release_hash is a {kind:?}, not a hash: ambiguous release binding"));
            }
            release = Some(format!("sha256:{value}"));
        }
    }
    Ok(release)
}

/// `cloakpipe_ledger::RELEASE_HASH_KEY` (this crate does not depend on the
/// ledger).
const RELEASE_HASH_KEY: &str = "release_hash";

/// Record the `(tenant, seq)` of every record of export `index`; the first
/// one already seen in an earlier export is reported as an overlap.
pub(crate) fn overlap(seen: &mut BTreeMap<(String, u64), usize>, index: usize, bundle: &Bundle) -> Option<String> {
    let mut found = None;
    for r in &bundle.records {
        if let Some(j) = seen.insert((r.tenant_id.clone(), r.seq), index) {
            if j != index && found.is_none() {
                found = Some(format!(
                    "overlaps ledgerExports[{j}] (record {}#{}): include each hop once, in one export",
                    r.tenant_id, r.seq
                ));
            }
        }
    }
    found
}

/// How many records of `bundle` are bound to `release`.
pub(crate) fn release_binding_count(bundle: &Bundle, release: &str) -> Result<u64, String> {
    let mut n = 0;
    for r in &bundle.records {
        let hop = parse_hop(&r.canonical_bytes).map_err(|e| format!("record #{}: {e}", r.seq))?;
        n += u64::from(hop.release.as_deref() == Some(release));
    }
    Ok(n)
}

// ── Verification ────────────────────────────────────────────────────────

/// Verify a pack file's bytes (strict JSON: no duplicate keys, no integers
/// beyond 2^53).
pub fn verify_pack_bytes(bytes: &[u8], opts: &VerifyOptions) -> PackReport {
    match strict::parse(bytes) {
        Ok(doc) => verify_pack(&doc, opts),
        Err(e) => {
            let mut c = Checker::new(opts);
            c.fail(format!("pack: {e}"));
            c.finish()
        }
    }
}

/// Verify a parsed pack document. Prefer [`verify_pack_bytes`]: a `Value`
/// has already lost any duplicate keys of the original text.
pub fn verify_pack(doc: &Value, opts: &VerifyOptions) -> PackReport {
    let mut c = Checker::new(opts);
    c.check(doc);
    c.finish()
}

struct Checker<'a> {
    opts: &'a VerifyOptions,
    report: PackReport,
    timeline: Vec<(DateTime<Utc>, TimelineEntry)>,
}

/// A certification decoded from the pack, for consistency checks.
struct PackCert<'a> {
    envelope: &'a Envelope,
    /// sha256 hex of the decoded payload (what revocations name).
    digest: Option<String>,
    certification: Option<Certification>,
}

impl<'a> Checker<'a> {
    fn new(opts: &'a VerifyOptions) -> Self {
        let report = PackReport {
            now: rfc3339(opts.now),
            limitations: vec![GOVERNANCE_LIMITATION.to_string()],
            ..Default::default()
        };
        Checker { opts, report, timeline: Vec::new() }
    }

    fn fail(&mut self, msg: impl Into<String>) {
        self.report.failures.push(msg.into());
    }

    fn warn(&mut self, msg: impl Into<String>) {
        self.report.warnings.push(msg.into());
    }

    fn at(&mut self, at: DateTime<Utc>, event: &str, detail: String) {
        self.timeline.push((at, TimelineEntry { at: rfc3339(at), event: event.into(), detail }));
    }

    fn finish(mut self) -> PackReport {
        self.timeline.sort_by_key(|(t, _)| *t);
        self.report.timeline = self.timeline.into_iter().map(|(_, e)| e).collect();
        self.report.ok = self.report.failures.is_empty();
        self.report
    }

    fn check(&mut self, doc: &Value) {
        if let Err(e) = strict::check_numbers(doc) {
            self.fail(format!("pack: {e}"));
        }
        self.check_roles();
        let Some(obj) = doc.as_object() else {
            return self.fail("pack: not a JSON object");
        };
        let (Some(api), Some(kind), Some(spec)) = (obj.get("apiVersion"), obj.get("kind"), obj.get("spec")) else {
            return self.fail("pack: apiVersion, kind and spec are required");
        };
        self.check_signature(api, kind, spec, obj.get("digest"), obj.get("signature"));

        let pack: ReleaseAuditPack = match serde_json::from_value(doc.clone()) {
            Ok(p) => p,
            Err(e) => return self.fail(format!("pack: malformed: {e}")),
        };
        if !cloakpipe_release::namespace::is_known_api_version(&pack.api_version) {
            self.fail(format!(
                "pack: apiVersion {:?} is not {PACK_API_VERSION:?} (or legacy {:?})",
                pack.api_version,
                cloakpipe_release::namespace::LEGACY_API_VERSION
            ));
        }
        if pack.kind != PACK_KIND {
            self.fail(format!("pack: kind {:?} is not {PACK_KIND:?}", pack.kind));
        }
        self.check_spec(&pack.spec);
    }

    /// No public key is trusted for two roles.
    fn check_roles(&mut self) {
        let roles = [
            ("exporter (--trust)", &self.opts.trusted),
            ("ledger signer (--ledger-trust)", &self.opts.ledger_trusted),
            ("certification issuer (--cert-trust)", &self.opts.cert_trusted),
        ];
        let mut owner: BTreeMap<[u8; 32], &str> = BTreeMap::new();
        let mut clashes = Vec::new();
        for (role, keys) in roles {
            for k in keys {
                match owner.get(&k.public_key) {
                    Some(other) if *other != role => clashes.push(format!(
                        "trust: key {} is trusted for more than one role ({other} and {role}); \
                         each role needs its own key",
                        keyid(&k.public_key)
                    )),
                    _ => {
                        owner.insert(k.public_key, role);
                    }
                }
            }
        }
        for c in clashes {
            self.fail(c);
        }
    }

    /// The digest recomputes and a trusted exporter key signed it.
    fn check_signature(
        &mut self,
        api: &Value,
        kind: &Value,
        spec: &Value,
        digest: Option<&Value>,
        sig: Option<&Value>,
    ) {
        let input = match signing_input(api, kind, spec) {
            Ok(i) => i,
            Err(e) => return self.fail(format!("pack: {e}")),
        };
        let computed = digest_of(&input);
        match digest.and_then(Value::as_str) {
            Some(d) if d == computed => {}
            Some(d) => self.fail(format!("pack: digest {d} does not match the signed content ({computed})")),
            None => self.fail("pack: digest is missing"),
        }
        self.report.digest = Some(computed);

        let sig: Option<PackSignature> = sig.and_then(|s| serde_json::from_value(s.clone()).ok());
        let Some(sig) = sig else {
            return self.fail("pack: signature must be {\"keyid\", \"sig\"}");
        };
        let candidates: Vec<&TrustedKey> = self.opts.trusted.iter().filter(|k| k.keyid == sig.keyid).collect();
        if candidates.is_empty() {
            return self.fail(format!("pack: signature keyid {:?} is not trusted (--trust)", sig.keyid));
        }
        let signature =
            BASE64_STANDARD.decode(&sig.sig).ok().and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok());
        let Some(signature) = signature else {
            return self.fail("pack: signature is not a base64 64-byte Ed25519 signature");
        };
        let verifies = candidates.iter().any(|k| {
            VerifyingKey::from_bytes(&k.public_key).is_ok_and(|vk| vk.verify_strict(&input, &signature).is_ok())
        });
        if verifies {
            self.report.signer = Some(sig.keyid);
        } else {
            self.fail(format!("pack: signature does not verify under trusted key {:?}", sig.keyid));
        }
    }

    fn check_spec(&mut self, spec: &PackSpec) {
        let now = self.opts.now;
        self.report.exporter = Some(spec.exporter.clone());
        self.report.created_at = Some(spec.created_at.clone());
        if spec.exporter.trim().is_empty() {
            self.fail("spec.exporter: must not be empty");
        }
        let created_at = parse_time(&spec.created_at);
        match created_at {
            None => self.fail(format!("spec.createdAt: {:?} is not RFC 3339", spec.created_at)),
            Some(t) if t > now => {
                self.fail(format!("spec.createdAt {} is after now ({})", spec.created_at, rfc3339(now)))
            }
            Some(_) => {}
        }
        if spec.governance.attested_by != ATTESTED_BY_EXPORTER {
            self.fail(format!(
                "spec.governance.attestedBy: {:?} is not {ATTESTED_BY_EXPORTER:?} (the only attestation this version defines)",
                spec.governance.attested_by
            ));
        }
        for l in &spec.limitations {
            if !self.report.limitations.contains(l) {
                self.report.limitations.push(l.clone());
            }
        }

        let release = self.check_manifest(&spec.release);
        let run_hashes = self.check_runs(&spec.evaluation_runs, &release);
        let revocations = self.check_events(&spec.governance.events, &release, created_at, &spec.release.manifest);
        let certs = self.check_certifications(&spec.certifications, &release, &run_hashes, &revocations);
        self.check_promotions(&spec.governance.events, &certs, &release, &revocations);
        self.check_sentinels(&spec.governance.events, &certs, &release, &revocations);
        let mut seen = BTreeMap::new();
        for (i, bundle) in spec.ledger_exports.iter().enumerate() {
            if let Some(problem) = overlap(&mut seen, i, bundle) {
                self.fail(format!("ledgerExports[{i}]: {problem}"));
            }
            self.check_ledger(i, bundle, &release);
        }
    }

    /// The release hash recomputes from a certifiable manifest. Returns the
    /// recomputed hash, which every other section must be bound to.
    fn check_manifest(&mut self, section: &ReleaseSection) -> String {
        let m = &section.manifest;
        let computed = m.manifest_hash().to_string();
        if section.hash != computed {
            self.fail(format!("release.hash {} does not recompute from the manifest ({computed})", section.hash));
        }
        for issue in m.validate() {
            self.fail(format!("release.manifest is not certifiable: {issue}"));
        }
        self.report.release = Some(computed.clone());
        self.report.agent = Some(m.metadata.agent.clone());
        self.report.version = Some(m.metadata.version.clone());
        computed
    }

    fn check_runs(&mut self, runs: &[EvaluationRun], release: &str) -> BTreeSet<String> {
        let mut hashes = BTreeSet::new();
        for (i, run) in runs.iter().enumerate() {
            for issue in run.validate() {
                self.fail(format!("evaluationRuns[{i}]: {issue}"));
            }
            if run.release != release {
                self.fail(format!("evaluationRuns[{i}] ({}): release {} is not this release", run.run_id, run.release));
            }
            let hash = run.run_hash();
            if !hashes.insert(hash.clone()) {
                self.fail(format!("evaluationRuns[{i}]: duplicate of run {hash}"));
            }
            let count =
                |f: fn(&cloakpipe_cert::CaseStatus) -> bool| run.cases.iter().filter(|c| f(&c.status)).count() as u64;
            use cloakpipe_cert::CaseStatus as S;
            self.report.runs.push(RunSummary {
                run_id: run.run_id.clone(),
                suite: format!("{}@{}", run.suite.name, run.suite.version),
                hash,
                cases: run.cases.len() as u64,
                passed: count(|s| *s == S::Pass),
                failed: count(|s| *s == S::Fail),
                errored: count(|s| *s == S::Error),
                skipped: count(|s| *s == S::Skipped),
            });
        }
        hashes
    }

    /// Per-event validity, order and timeline entries. Returns revocations:
    /// statement digest → time.
    fn check_events(
        &mut self,
        events: &[GovernanceEvent],
        release: &str,
        created_at: Option<DateTime<Utc>>,
        manifest: &AgentRelease,
    ) -> BTreeMap<String, DateTime<Utc>> {
        let now = self.opts.now;
        let mut revocations = BTreeMap::new();
        let mut previous: Option<DateTime<Utc>> = None;
        let mut registrations = 0;
        for (i, event) in events.iter().enumerate() {
            let label = format!("governance.events[{i}] ({})", event.kind());
            if event.actor().trim().is_empty() {
                self.fail(format!("{label}: actor must not be empty"));
            }
            let Some(at) = parse_time(event.at()) else {
                self.fail(format!("{label}: at {:?} is not RFC 3339", event.at()));
                continue;
            };
            if previous.is_some_and(|p| at < p) {
                self.fail(format!("{label}: out of order ({} is before the previous event)", event.at()));
            }
            previous = Some(previous.map_or(at, |p| p.max(at)));
            if at > now {
                self.fail(format!("{label}: at {} is after now ({})", event.at(), rfc3339(now)));
            }
            if created_at.is_some_and(|c| at > c) {
                self.fail(format!("{label}: at {} is after spec.createdAt", event.at()));
            }
            let actor = event.actor();
            match event {
                GovernanceEvent::ReleaseRegistered { agent, version, .. } => {
                    registrations += 1;
                    if registrations > 1 {
                        self.fail(format!("{label}: the release is registered more than once"));
                    } else if i != 0 {
                        self.fail(format!("{label}: the registration must be the first event"));
                    }
                    if *agent != manifest.metadata.agent || *version != manifest.metadata.version {
                        self.fail(format!(
                            "{label}: registered {agent} v{version} does not match the manifest ({} v{})",
                            manifest.metadata.agent, manifest.metadata.version
                        ));
                    }
                    self.at(at, "registered", format!("{agent} v{version} by {actor}"));
                }
                GovernanceEvent::ReleasePromoted { environment, from_release, break_glass, reason, .. } => {
                    self.check_environment(&label, environment);
                    if *break_glass && reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                        self.fail(format!("{label}: a break_glass promotion needs a non-empty reason"));
                    }
                    if let Some(from) = from_release {
                        match from.parse::<ReleaseHash>() {
                            Err(_) => {
                                self.fail(format!("{label}: fromRelease {from:?} is not a sha256:<hex> release hash"))
                            }
                            Ok(h) if h.to_string() == release => {
                                self.fail(format!("{label}: fromRelease is this release"))
                            }
                            Ok(_) => {}
                        }
                    }
                    // The timeline entry is added by check_promotions, which
                    // knows the basis.
                }
                GovernanceEvent::ReleaseSuperseded { environment, to_release, .. } => {
                    self.check_environment(&label, environment);
                    match to_release.parse::<ReleaseHash>() {
                        Err(_) => {
                            self.fail(format!("{label}: toRelease {to_release:?} is not a sha256:<hex> release hash"))
                        }
                        Ok(h) if h.to_string() == release => self.fail(format!("{label}: toRelease is this release")),
                        Ok(_) => {}
                    }
                    self.at(at, "superseded", format!("{environment} moved to {to_release} by {actor}"));
                }
                GovernanceEvent::CertificationRevoked { statement_digest, reason, .. } => {
                    let well_formed = statement_digest.len() == 64
                        && statement_digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                    if !well_formed {
                        self.fail(format!("{label}: statementDigest {statement_digest:?} is not 64 lowercase hex"));
                    }
                    if reason.trim().is_empty() {
                        self.fail(format!("{label}: reason must not be empty"));
                    }
                    if revocations.insert(statement_digest.clone(), at).is_some() {
                        self.fail(format!("{label}: statement {statement_digest} is revoked more than once"));
                    }
                    let short = statement_digest.get(..12).unwrap_or(statement_digest);
                    self.at(at, "certification_revoked", format!("statement {short}… by {actor}: {reason}"));
                }
                GovernanceEvent::SentinelBreach {
                    sentinel,
                    environment,
                    metric,
                    op,
                    threshold,
                    value,
                    calls,
                    action,
                    ..
                } => {
                    if sentinel.trim().is_empty() || metric.trim().is_empty() {
                        self.fail(format!("{label}: sentinel and metric must not be empty"));
                    }
                    self.check_environment(&label, environment);
                    if !threshold.is_finite() || !value.is_finite() {
                        self.fail(format!("{label}: threshold and value must be finite"));
                    }
                    let (breaches, sym) = match op {
                        SentinelOp::Gt => (value > threshold, ">"),
                        SentinelOp::Lt => (value < threshold, "<"),
                    };
                    if !breaches {
                        self.fail(format!("{label}: value {value} does not breach {metric} {sym} {threshold}"));
                    }
                    if *calls == 0 {
                        self.fail(format!("{label}: calls must be at least 1"));
                    }
                    let act = match action {
                        SentinelAction::Alert => "alert",
                        SentinelAction::Revoke => "revoke",
                    };
                    self.at(
                        at,
                        "sentinel_breach",
                        format!("{sentinel} in {environment}: {metric} {value} {sym} {threshold} over {calls} call(s); action {act}"),
                    );
                }
            }
        }
        if registrations == 0 {
            self.fail("governance: there is no release_registered event (it must be the first event)");
        }
        revocations
    }

    /// One of [`KNOWN_ENVIRONMENTS`], spelled exactly.
    fn check_environment(&mut self, label: &str, environment: &str) {
        if !KNOWN_ENVIRONMENTS.contains(&environment) {
            self.fail(format!("{label}: environment {environment:?} is not one of {}", KNOWN_ENVIRONMENTS.join(", ")));
        }
    }

    fn cert_context(&self, now: &str, release: &str, revoked: BTreeSet<String>) -> VerifyContext {
        VerifyContext {
            trusted: self.opts.cert_trusted.clone(),
            revoked_statements: revoked,
            revoked_keys: BTreeSet::new(),
            now: now.to_string(),
            expected_release: Some(release.to_string()),
            required_runs: None,
        }
    }

    fn check_certifications<'p>(
        &mut self,
        envelopes: &'p [Envelope],
        release: &str,
        run_hashes: &BTreeSet<String>,
        revocations: &BTreeMap<String, DateTime<Utc>>,
    ) -> Vec<PackCert<'p>> {
        let now = rfc3339(self.opts.now);
        let all_revoked: BTreeSet<String> = revocations.keys().cloned().collect();
        let mut digests = BTreeSet::new();
        let mut certs = Vec::new();
        for (i, envelope) in envelopes.iter().enumerate() {
            let label = format!("certifications[{i}]");
            let report = statement::verify(envelope, &self.cert_context(&now, release, all_revoked.clone()));
            if report.status == Status::Invalid {
                self.fail(format!("{label}: INVALID: {}", report.reasons.join("; ")));
            }
            if let Some(d) = &report.statement_digest {
                if !digests.insert(d.clone()) {
                    self.fail(format!("{label}: duplicate of statement {d}"));
                }
            }
            let decoded = decode_certification(envelope);
            if let Some((digest, c)) = &decoded {
                if let (Some(revoked), Some(issued)) = (revocations.get(digest), parse_time(&c.issued_at)) {
                    if *revoked < issued {
                        self.fail(format!(
                            "{label}: revoked at {} (governance), before it was issued ({})",
                            rfc3339(*revoked),
                            c.issued_at
                        ));
                    }
                }
                for r in &c.decision.runs {
                    if !run_hashes.contains(&r.hash) {
                        self.fail(format!("{label}: cites run {:?} ({}) which is not in the pack", r.run_id, r.hash));
                    }
                }
                if let Some(t) = parse_time(&c.issued_at) {
                    let outcome = match c.decision.outcome {
                        Outcome::Certified => "CERTIFIED",
                        Outcome::Blocked => "BLOCKED",
                    };
                    self.at(
                        t,
                        "certification_issued",
                        format!(
                            "{outcome} for {} by {}, valid until {} (statement {}…)",
                            c.environment,
                            c.issuer,
                            c.valid_until,
                            &digest[..12]
                        ),
                    );
                }
                if let Some(t) = parse_time(&c.valid_until).filter(|t| *t <= self.opts.now) {
                    self.at(
                        t,
                        "certification_expired",
                        format!("{} certification {}… expired", c.environment, &digest[..12]),
                    );
                }
            }
            let revoked_at = report.statement_digest.as_ref().and_then(|d| revocations.get(d)).map(|t| rfc3339(*t));
            let c = decoded.as_ref().map(|(_, c)| c);
            self.report.certifications.push(CertSummary {
                statement_digest: report.statement_digest.clone(),
                status: report.status,
                outcome: report.outcome,
                environment: c.map(|c| c.environment.clone()),
                issuer: c.map(|c| c.issuer.clone()),
                issued_at: c.map(|c| c.issued_at.clone()),
                valid_until: c.map(|c| c.valid_until.clone()),
                certified: report.certified,
                revoked_at,
                reasons: report.reasons.clone(),
            });
            let (digest, certification) = decoded.map_or((None, None), |(d, c)| (Some(d), Some(c)));
            certs.push(PackCert { envelope, digest, certification });
        }
        for digest in revocations.keys() {
            if !digests.contains(digest) {
                self.fail(format!("governance: revocation of statement {digest}, which is not in the pack"));
            }
        }
        certs
    }

    /// Some certification for `environment` certifies this release at `at`
    /// (signature, validity window, revocations up to `at`).
    fn certified_at(
        &self,
        certs: &[PackCert],
        environment: &str,
        at: DateTime<Utc>,
        release: &str,
        revocations: &BTreeMap<String, DateTime<Utc>>,
    ) -> bool {
        let revoked: BTreeSet<String> = revocations.iter().filter(|(_, t)| **t <= at).map(|(d, _)| d.clone()).collect();
        let ctx = self.cert_context(&rfc3339(at), release, revoked);
        certs.iter().any(|c| {
            c.certification.as_ref().is_some_and(|cert| cert.environment == environment)
                && statement::verify(c.envelope, &ctx).certified
        })
    }

    /// A promotion into the certified environment needs a certification
    /// valid at that moment, or break-glass. Also derives environment status.
    fn check_promotions(
        &mut self,
        events: &[GovernanceEvent],
        certs: &[PackCert],
        release: &str,
        revocations: &BTreeMap<String, DateTime<Utc>>,
    ) {
        let mut envs: BTreeMap<String, EnvironmentStatus> = BTreeMap::new();
        for (i, event) in events.iter().enumerate() {
            let Some(at) = parse_time(event.at()) else { continue };
            match event {
                GovernanceEvent::ReleasePromoted { actor, environment, break_glass, reason, .. } => {
                    let certified = environment == CERTIFIED_ENVIRONMENT
                        && self.certified_at(certs, environment, at, release, revocations);
                    let reason = reason.as_deref().unwrap_or("").trim();
                    let basis = if certified {
                        "certified"
                    } else if *break_glass {
                        "break_glass"
                    } else if environment == CERTIFIED_ENVIRONMENT {
                        self.fail(format!(
                            "governance.events[{i}] (release_promoted): promotion to {environment} at {} by {actor} \
                             has no certification valid at that time and is not break_glass",
                            event.at()
                        ));
                        "uncertified"
                    } else {
                        "not_required"
                    };
                    let mut detail = format!("to {environment} by {actor}");
                    match basis {
                        "certified" => detail.push_str(" (certified)"),
                        "break_glass" => {
                            detail.push_str(&format!(" — BREAK-GLASS: {reason}"));
                            if environment == CERTIFIED_ENVIRONMENT {
                                self.warn(format!(
                                    "break-glass promotion to {environment} at {} by {actor} without a valid certification: {reason}",
                                    event.at()
                                ));
                            }
                        }
                        "uncertified" => detail.push_str(" — NO VALID CERTIFICATION"),
                        _ => {}
                    }
                    self.at(at, "promoted", detail);
                    envs.insert(
                        environment.clone(),
                        EnvironmentStatus {
                            environment: environment.clone(),
                            live: true,
                            since: rfc3339(at),
                            basis: basis.into(),
                            actor: actor.clone(),
                            until: None,
                            certified_now: false,
                        },
                    );
                }
                GovernanceEvent::ReleaseSuperseded { actor, environment, .. } => {
                    let e = envs.entry(environment.clone()).or_insert_with(|| EnvironmentStatus {
                        environment: environment.clone(),
                        since: rfc3339(at),
                        basis: "unknown".into(),
                        actor: actor.clone(),
                        ..Default::default()
                    });
                    e.live = false;
                    e.until = Some(rfc3339(at));
                }
                _ => {}
            }
        }
        let now = self.opts.now;
        for e in envs.values_mut() {
            e.certified_now = self.certified_at(certs, &e.environment, now, release, revocations);
        }
        // A truthful history, so not a failure: but a reviewer must not read
        // PASS as "production runs a certified release".
        for e in envs.values().filter(|e| e.environment == CERTIFIED_ENVIRONMENT && e.live && !e.certified_now) {
            self.report.warnings.push(format!(
                "the release is live in {} with no certification valid now (revoked, expired or never certified)",
                e.environment
            ));
        }
        self.report.environments = envs.into_values().collect();
    }

    /// A `sentinel_breach` with action `revoke` revoked every certification
    /// for its environment that was valid at the breach: each must have a
    /// `certification_revoked` event. Its time is not compared with the
    /// breach's: CloakPipe Cloud revokes before it records the breach, and a
    /// breach folded into its window's row keeps that row's earlier time.
    fn check_sentinels(
        &mut self,
        events: &[GovernanceEvent],
        certs: &[PackCert],
        release: &str,
        revocations: &BTreeMap<String, DateTime<Utc>>,
    ) {
        for (i, event) in events.iter().enumerate() {
            let GovernanceEvent::SentinelBreach { sentinel, environment, action: SentinelAction::Revoke, .. } = event
            else {
                continue;
            };
            let Some(at) = parse_time(event.at()) else { continue };
            // Valid at the breach, revocations aside.
            let ctx = self.cert_context(&rfc3339(at), release, BTreeSet::new());
            for c in certs {
                let for_env = c.certification.as_ref().is_some_and(|cert| &cert.environment == environment);
                let Some(digest) = c.digest.as_ref().filter(|_| for_env) else { continue };
                if statement::verify(c.envelope, &ctx).certified && !revocations.contains_key(digest) {
                    self.fail(format!(
                        "governance.events[{i}] (sentinel_breach): sentinel {sentinel} revoked {environment} at {} \
                         but certification {}… valid then has no certification_revoked event",
                        event.at(),
                        &digest[..12]
                    ));
                }
            }
        }
    }

    /// A signed v4 ledger export from a trusted signer, with at least one
    /// hop bound to this release.
    fn check_ledger(&mut self, i: usize, b: &Bundle, release: &str) {
        let label = format!("ledgerExports[{i}]");
        let mut summary = LedgerSummary {
            bundle_id: b.manifest.as_ref().map(|m| m.bundle_id.clone()),
            records: b.records.len() as u64,
            anchor_receipts: b.anchor_receipts.len() as u64,
            ..Default::default()
        };
        if b.format_version < crate::bundle::MIN_BUNDLE_VERSION_FOR_CHAIN_TIP {
            self.fail(format!(
                "{label}: must be a v4 export (manifest signs the chain tip), got format_version {}",
                b.format_version
            ));
            self.report.ledger.push(summary);
            return;
        }
        match chain::verify_all(b) {
            Ok(s) => summary.chain_tip = Some(s.chain_tip),
            Err(e) => self.fail(format!("{label}: chain: {e}")),
        }
        if let Err(e) = anchor::verify_anchors(b) {
            self.fail(format!("{label}: anchors: {e}"));
        }
        match anchor::verify_inclusion_proofs(b) {
            Ok(n) => summary.inclusion_proofs = n as u64,
            Err(e) => self.fail(format!("{label}: inclusion proofs: {e}")),
        }
        if let Err(e) = anchor::verify_manifest(b) {
            self.fail(format!("{label}: manifest: {e}"));
        }
        if let Some(m) = &b.manifest {
            let key_id = &m.signature.key_id;
            summary.signer_key_id = Some(key_id.clone());
            let declared = b
                .signer_public_keys
                .iter()
                .find(|k| &k.key_id == key_id)
                .and_then(|k| hex::decode(&k.public_key).ok())
                .filter(|k| k.len() == 32);
            let trusted = declared.is_some_and(|d| self.opts.ledger_trusted.iter().any(|t| t.public_key[..] == d[..]));
            if !trusted {
                self.fail(format!("{label}: ledger signer {key_id:?} is not trusted (--ledger-trust)"));
            }
        }

        let (mut first, mut last): (Option<DateTime<Utc>>, Option<DateTime<Utc>>) = (None, None);
        for r in &b.records {
            let hop = match parse_hop(&r.canonical_bytes) {
                Ok(h) => h,
                Err(e) => {
                    self.fail(format!("{label}: record #{}: {e}", r.seq));
                    continue;
                }
            };
            if hop.release.as_deref() != Some(release) {
                summary.other_hops += 1;
                continue;
            }
            summary.release_hops += 1;
            *summary.release_hops_by_type.entry(hop.hop).or_default() += 1;
            match parse_time(&hop.ts) {
                Some(t) => {
                    first = Some(first.map_or(t, |f| f.min(t)));
                    last = Some(last.map_or(t, |l| l.max(t)));
                }
                None => self.fail(format!("{label}: record #{}: ts {:?} is not RFC 3339", r.seq, hop.ts)),
            }
        }
        if summary.release_hops == 0 {
            self.fail(format!("{label}: contains no hop bound to this release"));
        }
        let name = summary.bundle_id.clone().unwrap_or_else(|| format!("export {i}"));
        if let Some(f) = first {
            summary.first_hop_at = Some(rfc3339(f));
            self.at(
                f,
                "runtime_first_hop",
                format!("{name}: first of {} runtime hop(s) for this release", summary.release_hops),
            );
        }
        if let Some(l) = last.filter(|_| summary.release_hops > 1) {
            summary.last_hop_at = Some(rfc3339(l));
            self.at(l, "runtime_last_hop", format!("{name}: last runtime hop for this release"));
        } else {
            summary.last_hop_at = summary.first_hop_at.clone();
        }
        self.report.ledger.push(summary);
    }
}

// ── Human summary ───────────────────────────────────────────────────────

impl PackReport {
    /// The human summary `cloakpipe-verify release-pack` prints. The first
    /// word is `PASS` or `FAIL`.
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        let unknown = "(unknown)".to_string();
        let verdict = if self.ok { "PASS" } else { "FAIL" };
        s.push_str(&format!("{verdict}  release audit pack for {}\n", self.release.as_ref().unwrap_or(&unknown)));
        if let (Some(a), Some(v)) = (&self.agent, &self.version) {
            s.push_str(&format!("  release      {a} v{v}\n"));
        }
        s.push_str(&format!(
            "  pack         {}  signed by {}  exporter {}  created {}\n",
            self.digest.as_ref().unwrap_or(&unknown),
            self.signer.as_deref().map_or("(no trusted signature)".to_string(), |k| format!("{k} (trusted)")),
            self.exporter.as_ref().unwrap_or(&unknown),
            self.created_at.as_ref().unwrap_or(&unknown),
        ));
        s.push_str(&format!("  verified at  {}\n", self.now));
        for r in &self.runs {
            s.push_str(&format!(
                "  run          {} {}: {} case(s), {} passed, {} failed, {} errored, {} skipped\n",
                r.run_id, r.suite, r.cases, r.passed, r.failed, r.errored, r.skipped
            ));
        }
        for c in &self.certifications {
            let outcome = match c.outcome {
                Some(Outcome::Certified) => "certified",
                Some(Outcome::Blocked) => "blocked",
                None => "?",
            };
            let status =
                serde_json::to_value(c.status).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
            s.push_str(&format!(
                "  certification {status} {outcome} {} until {} by {}{}\n",
                c.environment.as_deref().unwrap_or("?"),
                c.valid_until.as_deref().unwrap_or("?"),
                c.issuer.as_deref().unwrap_or("?"),
                c.revoked_at.as_ref().map(|t| format!(", revoked {t}")).unwrap_or_default(),
            ));
        }
        for l in &self.ledger {
            let types: Vec<String> = l.release_hops_by_type.iter().map(|(k, v)| format!("{k}={v}")).collect();
            s.push_str(&format!(
                "  ledger       {}: {} record(s), {} for this release [{}], {} other; signer {}; {} anchor receipt(s)\n",
                l.bundle_id.as_deref().unwrap_or("?"),
                l.records,
                l.release_hops,
                types.join(" "),
                l.other_hops,
                l.signer_key_id.as_deref().unwrap_or("?"),
                l.anchor_receipts,
            ));
        }
        if !self.environments.is_empty() {
            s.push_str("ENVIRONMENTS\n");
            for e in &self.environments {
                let state = if e.live { "LIVE" } else { "superseded" };
                let until = e.until.as_ref().map(|u| format!(" until {u}")).unwrap_or_default();
                let now = if e.environment == CERTIFIED_ENVIRONMENT && e.live && !e.certified_now {
                    "; NO certification valid now"
                } else {
                    ""
                };
                s.push_str(&format!("  {:<12} {state} since {}{until} ({}){now}\n", e.environment, e.since, e.basis));
            }
        }
        s.push_str("TIMELINE\n");
        for t in &self.timeline {
            s.push_str(&format!("  {}  {:<22} {}\n", t.at, t.event, t.detail));
        }
        s.push_str("LIMITATIONS\n");
        for l in &self.limitations {
            s.push_str(&format!("  - {l}\n"));
        }
        if !self.warnings.is_empty() {
            s.push_str("WARNINGS\n");
            for w in &self.warnings {
                s.push_str(&format!("  - {w}\n"));
            }
        }
        if !self.failures.is_empty() {
            s.push_str("FAILURES\n");
            for f in &self.failures {
                s.push_str(&format!("  - {f}\n"));
            }
        }
        s.push_str(&if self.ok { "OK\n".to_string() } else { format!("FAIL  {} problem(s)\n", self.failures.len()) });
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(meta: &str) -> String {
        format!(
            "seq=0\nts=2026-10-03T10:00:00Z\ntenant_id=x\nhop=llm_prompt\ndetections=\nactions=\npolicy=(a|b|c|allow)\n\
             identities=(x|-|u|r)\negress=(d|00)\nprev_hash=00\nmetadata={meta}"
        )
    }

    #[test]
    fn release_binding_is_read_one_way_only() {
        let hex = "ab".repeat(32);
        let bound = |meta: &str| parse_hop(&canon(meta)).map(|h| h.release);
        assert_eq!(bound(""), Ok(None));
        assert_eq!(bound(&format!("release_hash=hash:{hex};")), Ok(Some(format!("sha256:{hex}"))));
        assert_eq!(
            bound(&format!("a=int:-1;gate=id:undeclared_tool;release_hash=hash:{hex};z=bool:true;")),
            Ok(Some(format!("sha256:{hex}")))
        );
        // Other keys that merely contain `release_hash` are other keys.
        assert_eq!(bound(&format!("prev_release_hash=hash:{hex};")), Ok(None));
        assert_eq!(bound("gate=id:;"), Ok(None));
        assert_eq!(
            bound(&format!("prev_release_hash=hash:{hex};release_hash=hash:{hex};")),
            Ok(Some(format!("sha256:{hex}")))
        );
        for bad in [
            // Not `key=type:value;` entries in strictly increasing key order.
            format!("release_hash=hash:{hex}"),
            format!("release_hash=hash:{hex};release_hash=hash:{hex};"),
            format!("z=int:1;release_hash=hash:{hex};"),
            format!("=int:1;release_hash=hash:{hex};"),
            format!("gate=id:x=y;release_hash=hash:{hex};"),
            format!("gate=str:x;release_hash=hash:{hex};"),
            format!("gate;release_hash=hash:{hex};"),
            "a=int:01;".to_string(),
            "a=int:;".to_string(),
            "a=bool:yes;".to_string(),
            format!("a=hash:{};", "AB".repeat(32)),
            "a=hash:ab;".to_string(),
            // A binding that is not a hash.
            format!("release_hash=id:{hex};"),
            ";".to_string(),
        ] {
            assert!(parse_hop(&canon(&bad)).is_err(), "{bad}");
        }
        assert!(parse_hop("seq=0\nts=x").is_err());
        assert!(parse_hop(&canon("").replace("hop=", "hop\n=")).is_err());
    }

    #[test]
    fn timestamps_need_the_t_separator() {
        assert!(parse_time("2026-10-01T00:00:00Z").is_some());
        assert!(parse_time("2026-10-01T05:30:00+05:30").is_some());
        assert!(parse_time("2026-10-01 00:00:00Z").is_none());
        assert!(parse_time("").is_none());
    }
}
