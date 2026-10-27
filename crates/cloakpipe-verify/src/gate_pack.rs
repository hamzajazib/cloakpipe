//! The gate's audit pack (`audit-pack.tar`, from `cloakpipe ledger
//! export`), verified offline with this crate's own code. Nothing in the
//! pack is trusted to vouch for itself: the gate key can be pinned
//! (otherwise the pack's own key is used and the report says so), and
//! anchors are checked only against the auditor's TSA roots and Rekor key.
//!
//! Layout (see `cloakpipe-ledger`'s `audit_pack` for the producer):
//!
//! ```text
//! pack.json                     signed pack manifest (cloakpipe.audit-pack/v1)
//! entries.jsonl                 decision entries (cloakpipe.decision/v1)
//! gate.pub.json                 {"keyid", "publicKey"} of the gate signing key
//! manifests.json                {"releases", "policy_versions", "policy_digests"}
//! anchors/epoch-<n>.json        {"epoch": <cloakpipe.epoch/v1 head>, "anchors": [...]}
//! ```
//!
//! Checks:
//!
//! - **pack**: `pack.json` lists every other file with its SHA-256 and no
//!   file is unlisted; its `pack_hash` (SHA-256 of `cloakpipe.audit-pack.v1`
//!   `\n` + canonical JSON without `pack_hash` and `sig`) is signed by a
//!   trusted gate key; its counts and seq range match the entries.
//! - **entries**: [`crate::decisions::verify_decisions`]: chain, seq gaps,
//!   entry hashes, per-entry signatures.
//! - **epochs**: each head's `epoch_hash` (SHA-256 of `cloakpipe.epoch.v1`
//!   `\n` + canonical JSON without `epoch_hash` and `sig`) is signed by a
//!   trusted gate key; its `entries_head` is the `entry_hash` of its
//!   `last_seq`, and all its entries are in the pack; epoch n+1 starts at
//!   the seq after epoch n and names epoch n's hash as `prev_epoch`.
//! - **anchors**: the anchored artifact is the canonical JSON of the epoch
//!   head. An RFC 3161 token must stamp its SHA-256 and chain to a trusted
//!   root; a Rekor entry must log it, signed by the gate key, with a valid
//!   inclusion proof under the trusted log key. Neither the head's
//!   `sealed_at` nor any of its entries may be stamped later than an
//!   anchor's time (plus the allowed clock skew).
//! - **gaps**: a missing epoch number, entries no epoch covers before or
//!   between epochs, an epoch without any anchor. Entries after the last
//!   epoch are reported as the unanchored tail; they fail only with
//!   [`PackTrust::require_anchors`].

use crate::decisions::{canonical, keyid, parse_jsonl, verify_decisions, DecisionSummary};
use crate::rekor::{verify_rekor_entry, RekorKey};
use crate::rfc3161::{verify_timestamp_response, TrustedRoots};
use crate::time::{parse_rfc3339_secs, rfc3339_from_unix};
use crate::ustar;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const PACK_KIND: &str = "cloakpipe.audit-pack/v1";
pub const PACK_HASH_DOMAIN: &str = "cloakpipe.audit-pack.v1";
pub const EPOCH_KIND: &str = "cloakpipe.epoch/v1";
pub const EPOCH_HASH_DOMAIN: &str = "cloakpipe.epoch.v1";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What the auditor brings.
#[derive(Debug, Clone, Default)]
pub struct PackTrust {
    /// Pinned gate public keys. Empty: the key in the pack is used (which
    /// proves integrity, not who produced the pack).
    pub gate_keys: Vec<[u8; 32]>,
    /// Roots an RFC 3161 token must chain to; `None` fails every token.
    pub tsa_roots: Option<TrustedRoots>,
    /// The Rekor log key; `None` fails every Rekor entry.
    pub rekor_key: Option<RekorKey>,
    /// How far an entry or seal time may run ahead of an anchor's time.
    pub clock_skew_secs: i64,
    /// Fail when entries after the last epoch are not anchored.
    pub require_anchors: bool,
}

impl PackTrust {
    /// Trust inputs from PEM bytes (`--tsa-root`, `--rekor-key`), each
    /// replacing the compiled-in public default ([`crate::trust`]) when
    /// given; default clock skew 60 s.
    pub fn from_pem(tsa_root_pem: Option<&[u8]>, rekor_key_pem: Option<&[u8]>) -> Result<Self, String> {
        let tsa_roots = match tsa_root_pem {
            Some(p) => TrustedRoots::from_pem(p).map_err(|e| format!("--tsa-root: {e}"))?,
            None => crate::trust::default_tsa_roots(),
        };
        let rekor_key = match rekor_key_pem {
            Some(p) => RekorKey::from_pem(p).map_err(|e| format!("--rekor-key: {e}"))?,
            None => crate::trust::default_rekor_key(),
        };
        Ok(Self { gate_keys: vec![], tsa_roots: Some(tsa_roots), rekor_key: Some(rekor_key), clock_skew_secs: 60, require_anchors: false })
    }
}

/// What a pack says, and what is wrong with it.
#[derive(Debug, Clone, Default)]
pub struct PackReport {
    pub files: usize,
    /// The keyid of the key the pack is checked against.
    pub gate_key: Option<String>,
    pub pinned: bool,
    pub pack_ok: bool,
    pub entries: usize,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// `None` when the entries verify.
    pub entries_error: Option<String>,
    pub epochs: usize,
    /// The seq range the epochs cover.
    pub anchored: Option<(u64, u64)>,
    pub rfc3161_ok: usize,
    pub rfc3161_total: usize,
    pub rekor_ok: usize,
    pub rekor_total: usize,
    pub gaps: Vec<String>,
    pub unanchored_tail: Option<(u64, u64)>,
    pub denials: usize,
    pub approvals_required: usize,
    pub approvals_granted: usize,
    pub unknown_side_effects: usize,
    pub reconciled: usize,
    pub manifests: Vec<String>,
    pub failures: Vec<String>,
    pub require_anchors: bool,
}

impl PackReport {
    /// Nothing failed and nothing is missing.
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
            && self.gaps.is_empty()
            && self.entries_error.is_none()
            && !(self.require_anchors && self.unanchored_tail.is_some())
    }

    /// The report as printed by `cloakpipe verify`.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let key = match (&self.gate_key, self.pinned) {
            (Some(k), true) => format!("{k} (pinned)"),
            (Some(k), false) => format!("{k} (from the pack, not pinned: pin it with --key)"),
            (None, _) => "no usable gate key".to_string(),
        };
        out.push_str(&format!(
            "pack: {} files, signed by {key}, {}\n",
            self.files,
            if self.pack_ok { "OK" } else { "FAIL" }
        ));
        let range = match (self.first_seq, self.last_seq) {
            (Some(a), Some(b)) => format!(" (seq {a}..{b})"),
            _ => String::new(),
        };
        match &self.entries_error {
            None => out.push_str(&format!("entries: {}{range}, chain OK, signatures OK\n", self.entries)),
            Some(e) => out.push_str(&format!("entries: {}{range}, FAIL: {e}\n", self.entries)),
        }
        if self.epochs == 0 {
            out.push_str("anchors: none\n");
        } else {
            let covered = self.anchored.map(|(a, b)| format!(" (seq {a}..{b})")).unwrap_or_default();
            let status = |ok: usize, total: usize, what: &str| match (ok, total) {
                (_, 0) => "none".to_string(),
                (ok, total) if ok == total => format!("OK ({ok}/{total}{what})"),
                (ok, total) => format!("FAIL ({ok}/{total}{what})"),
            };
            out.push_str(&format!(
                "anchors: {} epoch{}{covered}, RFC3161 {}, Rekor {}\n",
                self.epochs,
                if self.epochs == 1 { "" } else { "s" },
                status(self.rfc3161_ok, self.rfc3161_total, ""),
                status(self.rekor_ok, self.rekor_total, " inclusion proofs"),
            ));
        }
        if self.gaps.is_empty() {
            out.push_str("gaps: none\n");
        } else {
            out.push_str(&format!("gaps: {}\n", self.gaps.join("; ")));
        }
        if let Some((a, b)) = self.unanchored_tail {
            out.push_str(&format!("unanchored: seq {a}..{b} (after the last epoch)\n"));
        }
        out.push_str(&format!(
            "denials: {}, approvals: {} required, {} granted, unknown side effects: {}, reconciled: {}\n",
            self.denials, self.approvals_required, self.approvals_granted, self.unknown_side_effects, self.reconciled
        ));
        if !self.manifests.is_empty() {
            out.push_str(&format!("manifests: {}\n", self.manifests.join(", ")));
        }
        for f in &self.failures {
            out.push_str(&format!("FAIL: {f}\n"));
        }
        if self.require_anchors && self.unanchored_tail.is_some() {
            out.push_str("FAIL: entries after the last epoch are not anchored (--require-anchors)\n");
        }
        out.push_str(if self.ok() { "result: OK\n" } else { "result: FAIL\n" });
        out
    }
}

/// `pack_hash` of a pack manifest given as JSON.
pub fn pack_hash(manifest: &Value) -> [u8; 32] {
    domain_hash(PACK_HASH_DOMAIN, manifest, &["pack_hash", "sig"])
}

/// `epoch_hash` of an epoch head given as JSON.
pub fn epoch_hash(head: &Value) -> [u8; 32] {
    domain_hash(EPOCH_HASH_DOMAIN, head, &["epoch_hash", "sig"])
}

fn domain_hash(domain: &str, v: &Value, without: &[&str]) -> [u8; 32] {
    let mut covered = v.clone();
    if let Some(o) = covered.as_object_mut() {
        for k in without {
            o.remove(*k);
        }
    }
    let mut bytes = format!("{domain}\n").into_bytes();
    canonical(&covered, &mut bytes);
    Sha256::digest(&bytes).into()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out).ok()?;
    Some(out)
}

fn signed_by(keys: &BTreeMap<String, VerifyingKey>, signer: &str, digest: &[u8; 32], sig_hex: &str) -> Result<(), String> {
    let vk = keys.get(signer).ok_or_else(|| format!("signer {signer} is not a trusted gate key"))?;
    let sig = hex::decode(sig_hex).ok().and_then(|b| <[u8; 64]>::try_from(b).ok()).ok_or("signature is not 64 hex bytes")?;
    vk.verify(digest, &Signature::from_bytes(&sig)).map_err(|_| "signature does not verify".to_string())
}

/// Verify an audit pack. Never panics on hostile input; everything wrong
/// ends up in the report.
pub fn verify_pack(tar: &[u8], trust: &PackTrust) -> PackReport {
    let mut r = PackReport { require_anchors: trust.require_anchors, ..Default::default() };
    let files = match ustar::read(tar) {
        Ok(f) => f,
        Err(e) => {
            r.failures.push(format!("not an audit pack: {e}"));
            return r;
        }
    };
    r.files = files.len();
    let by_name: BTreeMap<&str, &[u8]> = files.iter().map(|f| (f.name.as_str(), f.data.as_slice())).collect();
    let json = |name: &str| -> Result<Value, String> {
        let data = by_name.get(name).ok_or_else(|| format!("{name} is missing"))?;
        serde_json::from_slice(data).map_err(|e| format!("{name}: not JSON: {e}"))
    };

    // The gate key(s) everything must be signed by.
    let pack_key = json("gate.pub.json").and_then(|g| {
        let public = g.get("publicKey").and_then(Value::as_str).and_then(hex32).ok_or("gate.pub.json: no publicKey")?;
        if g.get("keyid").and_then(Value::as_str) != Some(keyid(&public).as_str()) {
            return Err("gate.pub.json: keyid does not match publicKey".to_string());
        }
        Ok(public)
    });
    let trusted: Vec<[u8; 32]> = if trust.gate_keys.is_empty() {
        r.pinned = false;
        match &pack_key {
            Ok(k) => vec![*k],
            Err(e) => {
                r.failures.push(e.clone());
                vec![]
            }
        }
    } else {
        r.pinned = true;
        if let Ok(k) = &pack_key {
            if !trust.gate_keys.contains(k) {
                r.failures.push(format!("gate.pub.json names {}, which is not a pinned key", keyid(k)));
            }
        }
        trust.gate_keys.clone()
    };
    let keys: BTreeMap<String, VerifyingKey> =
        trusted.iter().filter_map(|k| VerifyingKey::from_bytes(k).ok().map(|vk| (keyid(k), vk))).collect();
    r.gate_key = trusted.first().map(keyid);

    // pack.json: listed files, signature.
    let manifest = match json("pack.json") {
        Ok(m) => m,
        Err(e) => {
            r.failures.push(e);
            Value::Null
        }
    };
    r.pack_ok = check_manifest(&manifest, &by_name, &keys, &mut r.failures);
    // With several keys pinned (a rotation), report the one that signed
    // pack.json, not merely the first one given.
    if let Some(signer) = manifest.get("signer").and_then(Value::as_str).filter(|s| keys.contains_key(*s)) {
        r.gate_key = Some(signer.to_string());
    }

    // Entries.
    let entries = match by_name.get("entries.jsonl").map(|d| std::str::from_utf8(d)) {
        Some(Ok(text)) => match parse_jsonl(text) {
            Ok(v) => v,
            Err(e) => {
                r.entries_error = Some(e.to_string());
                vec![]
            }
        },
        Some(Err(_)) => {
            r.entries_error = Some("entries.jsonl is not UTF-8".into());
            vec![]
        }
        None => {
            r.entries_error = Some("entries.jsonl is missing".into());
            vec![]
        }
    };
    r.entries = entries.len();
    r.first_seq = entries.first().and_then(|e| e.get("seq")).and_then(Value::as_u64);
    r.last_seq = entries.last().and_then(|e| e.get("seq")).and_then(Value::as_u64);
    if r.entries_error.is_none() {
        match verify_decisions(&entries, &trusted) {
            Ok(s) => tally(&mut r, &s, &entries),
            Err(e) => r.entries_error = Some(e.to_string()),
        }
    }
    if manifest.is_object() {
        let range = &manifest["range"];
        if manifest.get("entries").and_then(Value::as_u64) != Some(entries.len() as u64)
            || range.get("first_seq").and_then(Value::as_u64) != r.first_seq
            || range.get("last_seq").and_then(Value::as_u64) != r.last_seq
        {
            r.failures.push("pack.json: entry count or seq range does not match entries.jsonl".into());
        }
    }

    // Manifest digests.
    match json("manifests.json") {
        Ok(m) => {
            let listed: BTreeSet<String> = m
                .get("releases")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default();
            let named: BTreeSet<String> =
                entries.iter().filter_map(|e| e.get("release").and_then(Value::as_str)).map(String::from).collect();
            if listed != named {
                r.failures.push("manifests.json: releases do not match the entries".into());
            }
            r.manifests = listed.into_iter().collect();
        }
        Err(e) => r.failures.push(e),
    }

    // Epochs and anchors.
    let by_seq: BTreeMap<u64, &Value> =
        entries.iter().filter_map(|e| Some((e.get("seq")?.as_u64()?, e))).collect();
    let mut epoch_files: Vec<(u64, &str)> = files
        .iter()
        .filter_map(|f| {
            let n = f.name.strip_prefix("anchors/epoch-")?.strip_suffix(".json")?;
            Some((n.parse().ok()?, f.name.as_str()))
        })
        .collect();
    epoch_files.sort();
    if let Some(listed) = manifest.get("epochs").and_then(Value::as_array) {
        let listed: Vec<u64> = listed.iter().filter_map(Value::as_u64).collect();
        if listed != epoch_files.iter().map(|(n, _)| *n).collect::<Vec<_>>() {
            r.failures.push("pack.json: the epochs listed are not the epoch files present".into());
        }
    }
    r.epochs = epoch_files.len();
    let mut prev: Option<(u64, u64, String)> = None;
    for (n, name) in &epoch_files {
        let body = match json(name) {
            Ok(b) => b,
            Err(e) => {
                r.failures.push(e);
                continue;
            }
        };
        let Some(head) = check_epoch(*n, &body, &keys, &by_seq, &mut r.failures) else { continue };
        // Continuity with what came before.
        match &prev {
            None => {
                if *n == 0 && (head.first_seq != 0 || head.prev_epoch != GENESIS) {
                    r.failures.push("epoch 0 does not start the chain (first_seq 0, prev_epoch genesis)".into());
                }
                if let Some(first) = r.first_seq.filter(|f| *f < head.first_seq) {
                    r.gaps.push(format!("seq {first}..{} not covered by any epoch", head.first_seq - 1));
                }
            }
            Some((p_n, p_last, p_hash)) => {
                if *n != p_n + 1 {
                    r.gaps.push(if *n == p_n + 2 {
                        format!("epoch {} is missing", p_n + 1)
                    } else {
                        format!("epochs {}..{} are missing", p_n + 1, n - 1)
                    });
                } else if head.prev_epoch != *p_hash {
                    r.failures.push(format!("epoch {n} does not link to epoch {p_n} (prev_epoch)"));
                }
                if head.first_seq > p_last + 1 {
                    r.gaps.push(format!("seq {}..{} not covered by any epoch", p_last + 1, head.first_seq - 1));
                } else if head.first_seq != p_last + 1 {
                    r.failures.push(format!("epoch {n} overlaps epoch {p_n}"));
                }
            }
        }
        r.anchored = Some((r.anchored.map_or(head.first_seq, |(a, _)| a), head.last_seq));
        check_anchors(*n, &body, &head, &keys, &by_seq, trust, &mut r);
        prev = Some((*n, head.last_seq, head.epoch_hash.clone()));
    }
    if let Some(last) = r.last_seq {
        let after = prev.as_ref().map_or(r.first_seq.unwrap_or(0), |(_, l, _)| l + 1);
        if after <= last {
            r.unanchored_tail = Some((after, last));
        }
    }
    r
}

fn check_manifest(
    m: &Value,
    files: &BTreeMap<&str, &[u8]>,
    keys: &BTreeMap<String, VerifyingKey>,
    failures: &mut Vec<String>,
) -> bool {
    let before = failures.len();
    if !m.is_object() {
        return false;
    }
    if m.get("kind").and_then(Value::as_str) != Some(PACK_KIND) {
        failures.push(format!("pack.json: kind is not {PACK_KIND}"));
    }
    let listed = m.get("files").and_then(Value::as_object).cloned().unwrap_or_default();
    for (name, data) in files {
        if *name == "pack.json" {
            continue;
        }
        match listed.get(*name).and_then(Value::as_str) {
            None => failures.push(format!("{name} is not listed in pack.json")),
            Some(d) if d != format!("sha256:{}", hex::encode(Sha256::digest(data))) => {
                failures.push(format!("{name} does not match its digest in pack.json"))
            }
            Some(_) => {}
        }
    }
    for name in listed.keys() {
        if !files.contains_key(name.as_str()) {
            failures.push(format!("{name} is listed in pack.json but missing"));
        }
    }
    let h = pack_hash(m);
    if m.get("pack_hash").and_then(Value::as_str) != Some(hex::encode(h).as_str()) {
        failures.push("pack.json: pack_hash does not match its content".into());
    }
    let signer = m.get("signer").and_then(Value::as_str).unwrap_or_default();
    let sig = m.get("sig").and_then(Value::as_str).unwrap_or_default();
    if let Err(e) = signed_by(keys, signer, &h, sig) {
        failures.push(format!("pack.json: {e}"));
    }
    failures.len() == before
}

/// The fields of an epoch head the checks use.
struct Head {
    first_seq: u64,
    last_seq: u64,
    prev_epoch: String,
    epoch_hash: String,
    sealed_at: i64,
    signer: String,
}

fn check_epoch(
    n: u64,
    body: &Value,
    keys: &BTreeMap<String, VerifyingKey>,
    by_seq: &BTreeMap<u64, &Value>,
    failures: &mut Vec<String>,
) -> Option<Head> {
    let v = &body["epoch"];
    let s = |k: &str| v.get(k).and_then(Value::as_str);
    let u = |k: &str| v.get(k).and_then(Value::as_u64);
    let fail = |failures: &mut Vec<String>, m: String| {
        failures.push(format!("epoch {n}: {m}"));
        None
    };
    if s("kind") != Some(EPOCH_KIND) {
        return fail(failures, format!("kind is not {EPOCH_KIND}"));
    }
    let (Some(epoch), Some(first_seq), Some(last_seq)) = (u("epoch"), u("first_seq"), u("last_seq")) else {
        return fail(failures, "missing epoch / first_seq / last_seq".into());
    };
    let (Some(entries_head), Some(prev_epoch), Some(sealed_at), Some(signer), Some(recorded), Some(sig)) =
        (s("entries_head"), s("prev_epoch"), s("sealed_at"), s("signer"), s("epoch_hash"), s("sig"))
    else {
        return fail(failures, "missing a field".into());
    };
    if epoch != n || first_seq > last_seq {
        return fail(failures, "number or seq range is inconsistent".into());
    }
    let h = epoch_hash(v);
    if recorded != hex::encode(h) {
        return fail(failures, "epoch_hash does not match its content".into());
    }
    if let Err(e) = signed_by(keys, signer, &h, sig) {
        return fail(failures, e);
    }
    let Some(sealed_at) = parse_rfc3339_secs(sealed_at) else {
        return fail(failures, "sealed_at is not a time".into());
    };
    if (first_seq..=last_seq).any(|q| !by_seq.contains_key(&q)) {
        return fail(failures, format!("entries {first_seq}..{last_seq} are not all in the pack"));
    }
    if by_seq.get(&last_seq).and_then(|e| e.get("entry_hash")).and_then(Value::as_str) != Some(entries_head) {
        return fail(failures, format!("entries_head is not the hash of entry {last_seq}"));
    }
    Some(Head {
        first_seq,
        last_seq,
        prev_epoch: prev_epoch.to_string(),
        epoch_hash: recorded.to_string(),
        sealed_at,
        signer: signer.to_string(),
    })
}

fn check_anchors(
    n: u64,
    body: &Value,
    head: &Head,
    keys: &BTreeMap<String, VerifyingKey>,
    by_seq: &BTreeMap<u64, &Value>,
    trust: &PackTrust,
    r: &mut PackReport,
) {
    let mut artifact = Vec::new();
    canonical(&body["epoch"], &mut artifact);
    let subject: [u8; 32] = Sha256::digest(&artifact).into();
    let id = format!("epoch-{n}");
    let anchors = body.get("anchors").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut verified = 0usize;
    for a in &anchors {
        let kind = a.get("kind").and_then(Value::as_str).unwrap_or_default();
        let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or_default();
        let named = s("batch_id") == id && s("subject_hash") == hex::encode(subject);
        let time: Result<(i64, &str), String> = match kind {
            "rfc3161" => {
                r.rfc3161_total += 1;
                let roots: Option<&TrustedRoots> = trust.tsa_roots.as_ref();
                let tsr = base64::engine::general_purpose::STANDARD.decode(s("tsr")).ok();
                let nonce = hex::decode(s("nonce")).ok();
                match (named, roots, tsr, nonce) {
                    (false, ..) => Err("RFC 3161 anchor names another epoch or subject".into()),
                    (_, None, ..) => Err("RFC 3161 anchor: no TSA root to check it against (--tsa-root)".into()),
                    (_, _, None, _) | (_, _, _, None) => Err("RFC 3161 anchor: unreadable token or nonce".into()),
                    (true, Some(roots), Some(tsr), Some(nonce)) => verify_timestamp_response(&tsr, &subject, &nonce, roots)
                        .map(|t| {
                            r.rfc3161_ok += 1;
                            (t.gen_time_unix, "rfc3161")
                        })
                        .map_err(|e| format!("RFC 3161 anchor: {e}")),
                }
            }
            "rekor" => {
                r.rekor_total += 1;
                let signer = keys.get(&head.signer).map(|k| k.to_bytes());
                match (named, &trust.rekor_key, signer) {
                    (false, ..) => Err("Rekor anchor names another epoch or subject".into()),
                    (_, None, _) => Err("Rekor anchor: no Rekor key to check it against (--rekor-key)".into()),
                    (_, _, None) => Err("Rekor anchor: the epoch signer is not a trusted gate key".into()),
                    (true, Some(key), Some(signer)) => {
                        let entry = a.get("entry").cloned().unwrap_or(Value::Null);
                        verify_rekor_entry(s("entry_uuid"), &entry, key, &artifact, &signer)
                            .map(|v| {
                                r.rekor_ok += 1;
                                (v.integrated_time, "rekor")
                            })
                            .map_err(|e| format!("Rekor anchor: {e}"))
                    }
                }
            }
            other => Err(format!("unknown anchor kind `{other}`")),
        };
        match time {
            Err(e) => r.failures.push(format!("epoch {n}: {e}")),
            Ok((at, kind)) => {
                verified += 1;
                let limit = at + trust.clock_skew_secs;
                let late = |t: i64| t > limit;
                if late(head.sealed_at) {
                    r.failures.push(format!(
                        "epoch {n}: sealed at {} after its anchor ({kind} at {})",
                        rfc3339_from_unix(head.sealed_at),
                        rfc3339_from_unix(at)
                    ));
                }
                for q in head.first_seq..=head.last_seq {
                    let ts = by_seq.get(&q).and_then(|e| e.get("ts")).and_then(Value::as_str).and_then(parse_rfc3339_secs);
                    match ts {
                        Some(t) if late(t) => {
                            r.failures.push(format!(
                                "epoch {n}: entry {q} is stamped {} after its anchor ({kind} at {})",
                                rfc3339_from_unix(t),
                                rfc3339_from_unix(at)
                            ));
                            break;
                        }
                        Some(_) => {}
                        None => {
                            r.failures.push(format!("epoch {n}: entry {q} has no readable ts"));
                            break;
                        }
                    }
                }
            }
        }
    }
    if anchors.is_empty() {
        r.gaps.push(format!("epoch {n} is not anchored"));
    } else if verified == 0 {
        r.gaps.push(format!("epoch {n} has no anchor that verifies"));
    }
}

fn tally(r: &mut PackReport, s: &DecisionSummary, entries: &[Value]) {
    r.denials = s.denied;
    r.approvals_required = s.approvals_required;
    r.unknown_side_effects = s.unknown_outcomes;
    r.reconciled = s.reconciled;
    r.approvals_granted = entries
        .iter()
        .filter(|e| {
            e.get("event").and_then(Value::as_str) == Some("call")
                && e.get("decision").and_then(Value::as_str) == Some("allow")
                && e.get("approval").is_some_and(|a| !a.is_null())
        })
        .count();
}
