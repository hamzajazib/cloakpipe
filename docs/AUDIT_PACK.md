# Release audit packs

A **release audit pack** is the one artefact a client's security reviewer
gets for an Agent Release: one signed JSON file with the manifest, the
evaluation evidence, the certifications, the governance history and the
runtime evidence ledger for that exact release. It verifies offline, with
no network access and no CloakPipe account.

- Rust: [`crates/cloakpipe-verify/src/pack`](../crates/cloakpipe-verify/src/pack)
  (`PackBuilder` to produce, `verify_pack_bytes` to check)
- Producer CLI: `cloakpipe release audit-pack`
- Verifier CLI: `cloakpipe-verify release-pack`

## Why one JSON file

A directory or tarball needs a manifest of its own, a rule for files that
are present but not listed, and a canonical archive encoding before it can be
signed. Every section here is already JSON (manifests, runs, DSSE envelopes,
ledger bundles), so one JSON document signed over its RFC 8785 (JCS) form
has a single canonical byte representation, opens in any tool, and leaves
nothing outside the signature. The cost is size: ledger exports are
embedded whole (see [Ledger](#ledger)).

## Format (`cloakpipe.dev/v1alpha1`, `ReleaseAuditPack`)

```json
{
  "apiVersion": "cloakpipe.dev/v1alpha1",
  "kind": "ReleaseAuditPack",
  "spec": {
    "createdAt": "2026-10-07T12:00:00Z",
    "exporter": "cloakpipe-cloud:acme",
    "release": { "hash": "sha256:<hex>", "manifest": { "apiVersion": "cloakpipe.dev/v1alpha1", "kind": "AgentRelease", "...": "..." } },
    "evaluationRuns": [ { "kind": "EvaluationRun", "release": "sha256:<hex>", "...": "..." } ],
    "certifications": [ { "payloadType": "application/vnd.in-toto+json", "payload": "<base64>", "signatures": [ { "keyid": "...", "sig": "..." } ] } ],
    "governance": {
      "attestedBy": "exporter",
      "events": [
        { "type": "release_registered", "at": "...", "actor": "ci:acme/support", "agent": "support-agent", "version": "184" },
        { "type": "release_promoted", "at": "...", "actor": "alice@acme", "environment": "production",
          "fromRelease": "sha256:<hex>", "breakGlass": false, "reason": "optional" },
        { "type": "release_superseded", "at": "...", "actor": "...", "environment": "production", "toRelease": "sha256:<hex>" },
        { "type": "certification_revoked", "at": "...", "actor": "sentinel:block-rate", "statementDigest": "<64 hex>", "reason": "..." },
        { "type": "sentinel_breach", "at": "...", "actor": "sentinel:block-rate", "sentinel": "block-rate",
          "environment": "production", "metric": "guardrail_block_rate", "op": "gt", "threshold": 0.2,
          "value": 0.4, "calls": 50, "action": "revoke" }
      ]
    },
    "ledgerExports": [ { "format": "cloakpipe.bundle", "format_version": 4, "...": "..." } ],
    "limitations": [ "Governance events (...) are attested only by the exporter's pack signature; ..." ]
  },
  "digest": "sha256:<hex>",
  "signature": { "keyid": "ed25519:<16 hex>", "sig": "<base64>" }
}
```

| Field | Content |
|---|---|
| `spec.release` | The manifest ([AGENT_RELEASE.md](AGENT_RELEASE.md)) and its `sha256:` hash. |
| `spec.evaluationRuns` | Native `EvaluationRun`s ([CERTIFICATION.md](CERTIFICATION.md)) of this release. |
| `spec.certifications` | DSSE envelopes from `release certify` or CloakPipe Cloud, blocked decisions included. |
| `spec.governance.events` | Control-plane history, in non-decreasing `at` order. `at` is RFC 3339; `actor` is non-empty. `fromRelease`, `reason` are optional; `breakGlass` defaults to `false`. `op` is `gt`/`lt`, `action` `alert`/`revoke`. |
| `spec.ledgerExports` | Signed `cloakpipe.bundle` v4 exports (`cloakpipe-ledger::export`), unmodified. |
| `spec.limitations` | Caveats; the builder always includes the governance limitation below. |

Every object defined by the pack rejects unknown fields; event `type` is a
closed set.

**Signing input** = `"cloakpipe.dev/release-audit-pack/v1alpha1"` ‖ `"\n"` ‖
`JCS({"apiVersion", "kind", "spec"})`. `digest` = `"sha256:"` + hex SHA-256 of
the signing input. `signature.sig` = standard base64 of the Ed25519 signature
of the signing input by the exporter key; `keyid` = `"ed25519:"` + first 16
hex chars of SHA-256(public key) (the `release keygen` key id).

## Governance events are exporter-attested only

Registrations, promotions, revocations and sentinel breaches are records of
the exporter's control plane. Nobody else signed them: the pack signature
proves the exporter vouched for them, not that `alice@acme` really pressed
the button. The pack says so (`governance.attestedBy: "exporter"`, the only
value this version accepts, and a `limitations` entry) and the verifier
prints it in every report. Certifications and ledger hops, by contrast, are
signed by their own issuers and verified against their own trust anchors.

## Verification

```
cloakpipe-verify release-pack PACK --trust KEYFILE... [--cert-trust KEYFILE]... [--now RFC3339] [--json]
```

- `--trust`: exporter and ledger signer public keys (`release keygen` files;
  `{"keyid", "publicKey"}` is enough, a declared `keyid` must match). At
  least one is required.
- `--cert-trust`: certification issuers. Default: the `--trust` keys.
- `--now`: verification time (default: the clock). Everything is offline.
- Exit **0** pass, **1** failed (any check below), **2** usage or an
  unreadable pack or key file. `--json` prints the report.

Checks (all run; the report lists every failure):

1. **Document**: valid JSON, no duplicate keys, no integer beyond ±(2^53−1)
   (it has no exact JCS form), `apiVersion`/`kind` as above, no unknown
   fields.
2. **Pack signature**: `digest` recomputes; `signature` verifies under a
   `--trust` key with that `keyid`.
3. **Manifest**: certifiable, and `release.hash` recomputes from it. Every
   other section is checked against the recomputed hash.
4. **Runs**: valid, `release` is this release, no duplicates.
5. **Certifications**: each verifies (`cloakpipe_cert::statement::verify`)
   against `--cert-trust` with subject = this release; `INVALID` fails the
   pack, while `EXPIRED`/`REVOKED` are reported as history. Every run a
   decision cites must be in the pack (baseline runs are not required, they
   belong to another release). No duplicate statements.
6. **Events**: in time order, not after `createdAt`, `createdAt` not after
   `now`; `release_registered` matches the manifest's agent and version (at
   most once); `release_superseded.toRelease` is another release;
   `certification_revoked` names a statement in the pack, once;
   `sentinel_breach.value` really breaches `op threshold`, `calls ≥ 1`.
7. **Promotion consistency**: a `release_promoted` into `production` needs a
   certification for `production` that is certified at that instant
   (signature, validity window, revocations up to then). Otherwise it must
   be `breakGlass: true` with a non-empty `reason`, which passes with a
   warning; anything else fails.
8. **Ledger**: each export is v4 (the manifest signs the chain tip), its chain,
   batch signatures, anchor receipts, inclusion proofs and manifest verify
   (the existing `chain`/`sigs`/`anchors`/`proofs`/`manifest` checks), its
   manifest signer is a `--trust` key, and at least one hop is bound to this
   release.

The human summary starts with `PASS` or `FAIL`, then the release, signer,
runs, certifications, ledger, **environment status** (live/superseded, since
when, on what basis, whether a production certification is valid now) and a
**timeline** (registration, promotions, certification issuance/expiry,
revocations, sentinel breaches, first and last runtime hop).

### Ledger

A hash chain cannot be cut to one release's hops without breaking its
proof, so exports are embedded whole. The verifier reads each hop's release
binding from its signed canonical bytes (`metadata=…release_hash=hash:<hex>;`)
and reports hops bound to this release and the `other` hops kept for the
chain. A binding that does not read one way only (`release_hash=` more than
once, e.g. another key ending in `release_hash`, or not a `hash:<64 hex>;`
entry) fails the pack. Anchor receipts travel inside the exports and are
verified there; the pack itself is not anchored.

## Producing a pack

CLI, from local files:

```
cloakpipe release audit-pack --manifest release.yaml --run run.json... \
    --certification release.cert.dsse.json... --ledger-export ledger.json... \
    --events events.json --key exporter.key.json --out release.audit-pack.json \
    [--exporter ID] [--now RFC3339] [--limitation TEXT]...
```

`events.json` is a JSON array of events as above (any order; they are
sorted). Exit 0 written (prints the digest), 1 an input that could never
verify, 2 usage or I/O.

Rust (CloakPipe Cloud):

```rust
use cloakpipe_verify::pack::{GovernanceEvent, PackBuilder};

let pack = PackBuilder::new(manifest /* AgentRelease */, "cloakpipe-cloud:acme", created_at_rfc3339)
    .runs(runs)                       // Vec<cloakpipe_cert::EvaluationRun>
    .certifications(envelopes)        // Vec<cloakpipe_cert::statement::Envelope>
    .events(events)                   // Vec<GovernanceEvent>, any order
    .ledger_export_json(bundle_json)? // serde_json::Value of a ledger export
    .build(&signing_key)?;            // ed25519_dalek::SigningKey
let json = pack.to_json_pretty();
```

`build` refuses what could never verify (`BuildError`): an empty exporter,
an uncertifiable manifest, a run or certification for another release, a
non-RFC 3339 time or an event after `createdAt`, a ledger export without a
hop for this release. It does not check certification signatures or
promotion consistency, which need the verifier's trust anchors.

## What a pack does not prove

- That governance events happened as recorded (exporter-attested only).
- That the pack is complete: an exporter can leave out runs,
  certifications, events or whole ledger exports. A ledger export is
  complete only up to its own signed chain tip.
- Anything the included certifications do not claim (see
  [CERTIFICATION.md](CERTIFICATION.md#what-a-certification-does-not-claim)).
