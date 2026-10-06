# Agent Release certification

Certification turns evaluation evidence about one exact Agent Release into a
deterministic decision and a signed, scoped, expiring attestation that anyone
can verify offline.

```
release manifest ─┐
evaluation runs ──┼─> decide(policy) ─> Decision ─> sign ─> DSSE(in-toto) ─> verify(now, trust, revocations)
baseline runs  ───┘
```

Crate: [`crates/cloakpipe-cert`](../crates/cloakpipe-cert). Each module's doc
comment is the normative contract:

| Module | Contract |
|---|---|
| `model` | `EvaluationRun`, `CertificationPolicy`, `Decision`; canonical hashes (`cloakpipe.dev/evaluation-run/v1`, `cloakpipe.dev/certification-policy/v1`, RFC 8785, same scheme as release manifests). |
| `import` | JUnit XML and native JSON → `EvaluationRun`. |
| `policy` | `decide()`: input validity, release binding, required assurance, coverage, pass rate, regression vs baseline, critical failures (new vs persisting), metric thresholds. Pure and deterministic. |
| `statement` | in-toto v1 Statement in a DSSE envelope signed with Ed25519; verification statuses `VALID`, `VALID_WITH_LIMITATIONS`, `INCOMPLETE`, `EXPIRED`, `REVOKED`, `INVALID`. |

## CLI

All commands are offline and deterministic given their inputs (`--now` pins
time). Exit codes: **0** ok / certified, **1** invalid input, BLOCKED
decision or attestation that does not certify, **2** usage or I/O error.

### `cloakpipe release keygen [--out FILE]`

Generates an Ed25519 signing key and prints
`{"keyid", "publicKey", "privateKey"}` (hex; `privateKey` is the 32-byte
seed). `keyid = "ed25519:" + first 16 hex chars of SHA-256(public key)`.
With `--out`, the full key is written to `FILE` with mode `0600` (an existing
file is never overwritten) and only `keyid` and `publicKey` are printed —
publish those to verifiers.

### `cloakpipe eval import`

```
cloakpipe eval import --junit FILE --release <manifest | sha256:hex>
    --suite NAME@VERSION --covers a,b [--critical PATTERN]...
    [--run-id ID] [--tool NAME] [--dataset REF] [--out FILE]
```

Turns a JUnit XML report into a native `EvaluationRun` (rules in `import`)
on stdout or in `--out`. A manifest path must be certifiable and is replaced
by its hash. `--run-id` defaults to `NAME@VERSION`; `--critical` takes
`prefix*` or exact case ids. An invalid report or run exits 1 with the
issues on stderr.

### `cloakpipe release certify`

```
cloakpipe release certify MANIFEST --policy FILE --run FILE...
    [--baseline MANIFEST --baseline-run FILE...] [--require a,b]
    --environment ENV --issuer ID [--key KEYFILE] [--now RFC3339]
    [--limitation TEXT]... [--out FILE] [--json]
```

- **Required suites** = `cloakpipe_release::diff(baseline, candidate).required_suites`
  ∪ `--require`. Without `--baseline` only `--require` applies; an empty
  set is allowed but warned about on stderr.
- **Decision**: `policy::decide` over the candidate's manifest hash, the
  runs, the baseline runs and the policy (YAML, or JSON when the file ends
  in `.json`). Structurally invalid runs or policies become `invalid_input`
  reasons; unparseable files exit 1.
- **Signing** (`--key`): a `Certification` with `issuedAt = --now` (default:
  current UTC), `validUntil = issuedAt + policy.validityDays`, the
  manifest's agent, `--environment`, `--issuer` and `--limitation`s, signed
  into a DSSE envelope written to `--out` (default
  `<manifest stem>.cert.dsse.json` in the working directory). BLOCKED
  decisions are signed too: an attestation of a block.
- **Output**: `CERTIFIED` or `BLOCKED`, the release hash, the policy, the
  required suites, then one line per reason. `--json` prints
  `{"decision", "envelope"?, "envelopePath"?}`.
- Exit 0 iff the decision is `certified`.

### `cloakpipe release verify-cert`

```
cloakpipe release verify-cert ENVELOPE [--trust KEYFILE]... [--trust-key KEYID=PUBHEX]...
    [--release <manifest | sha256:hex>] [--require-run HASH]...
    [--revoked-statement HEX]... [--revoked-key KEYID]... [--now RFC3339] [--json]
```

Runs `statement::verify` and prints the status (`VALID`,
`VALID_WITH_LIMITATIONS`, `INCOMPLETE`, `EXPIRED`, `REVOKED`, `INVALID`), the
decision outcome, release, statement digest and reasons (`--json`: the
`Report`). Key files from `keygen` are accepted as trust anchors; only their
public part is used and a declared `keyid` must match the key. Exit 0 iff
`report.certified` (valid, possibly with limitations, *and* a certified
decision).

### End to end

```sh
cloakpipe release keygen --out key.json
cloakpipe eval import --junit report.xml --release release.yaml \
  --suite support-critical@23 --covers privacy,functional --critical 'privacy::*' --out run.json
cloakpipe release certify release.yaml --policy policy.yaml --run run.json \
  --baseline previous.yaml --baseline-run previous-run.json \
  --environment production --issuer ci:acme/support --key key.json
cloakpipe release verify-cert release.cert.dsse.json --trust key.json --release release.yaml
```

## GitHub Action

[`.github/actions/certify`](../.github/actions/certify) wraps `release certify`
for workflows: it installs the CLI (`cargo install --git
https://github.com/rohansx/cloakpipe … cloakpipe-cli --locked` at
`cloakpipe-ref`), certifies, writes a job summary and sets the outputs
`outcome`, `envelope` and `decision`. The `signing-key` input takes the
contents of a `keygen` key file from a secret; it is written to a `0600`
temp file for the step and removed afterwards. The action uploads nothing.

```yaml
- id: cert
  uses: rohansx/cloakpipe/.github/actions/certify@main
  with:
    manifest: release.yaml
    policy: certification-policy.yaml
    runs: |
      runs/support-critical.json
    baseline-manifest: releases/previous.yaml
    baseline-runs: |
      runs/previous/support-critical.json
    environment: production
    signing-key: ${{ secrets.CLOAKPIPE_CERT_KEY }}
```

See the action's [README](../.github/actions/certify/README.md) for all
inputs. The `certification-gate` CI job exercises the CLI and the action on
the fixtures in `crates/cloakpipe-cli/tests/fixtures/certification/`.

## Runtime: the MCP tool gate

`cloakpipe mcp-proxy` enforces certification where an agent acts: its tool
calls. With `--manifest`, each `tools/call` passes only if

1. the tool is declared in the manifest's `spec.tools` (`tool:refund@4`
   declares `refund`), and
2. `--certification` verifies offline at the moment of the call: trusted
   signer (`--trust` / `--trust-key`), not revoked (`--revoked-statement`),
   inside its validity window, about this manifest's release, a `certified`
   decision, for `--environment` (default `production`).

```
cloakpipe mcp-proxy --upstream "npx -y @acme/crm-mcp" \
  --manifest release.yaml --certification release.cert.dsse.json \
  --trust-key "$KEYID=$PUBHEX" --environment production
```

`--gate enforce` (default): a refused call never reaches the upstream tool.
The agent receives JSON-RPC error `-32001` with
`data: {reason, tool, release}` (notifications get no reply). Reasons:
`undeclared_tool`, `uncertified` (no `--certification`), `wrong_environment`,
`blocked`, or the verification status (`expired`, `revoked`, `invalid`, …).
The refusal is recorded as a release-bound `mcp_tool_call` hop with action
`block` and `gate_denial=<reason>`. `--gate warn` forwards the call, logs the
violation and marks the hop `gate_violation=<reason>`.

The gate fails closed: `--manifest` without a certification refuses every
call, and `--certification` without `--manifest`, an unreadable envelope or a
`CLOAKPIPE_RELEASE` that names another release refuse to start. The manifest
also binds every evidence hop to its release. MCP server identity
(`spec.mcpServers`) is not checked: the gate fronts the one upstream it was
started with.

## What a certification does not claim

A valid certification proves that a named issuer applied a named policy to
named evaluation runs of an exact release and reached the stated decision. It
does not prove the evaluators measured the right property, that the suites are
representative, or that the release is safe outside the certified scope and
validity window.
