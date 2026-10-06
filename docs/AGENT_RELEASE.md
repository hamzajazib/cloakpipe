# Agent Release manifests

An **Agent Release** is the complete, immutable set of behaviour-affecting
components deployed as one unit. CloakPipe evaluates, certifies, enforces and
records evidence against the release's **manifest hash**, so a passing test of
one configuration can never certify a different one.

- Schema: [`schemas/agent-release.schema.json`](../schemas/agent-release.schema.json)
- Rust: [`crates/cloakpipe-release`](../crates/cloakpipe-release)
- Reference hash implementation (Python, stdlib only): [`tools/release_hash_reference.py`](../tools/release_hash_reference.py)

## Manifest

```yaml
apiVersion: cloakpipe.dev/v1alpha1
kind: AgentRelease
metadata:
  agent: support-agent        # identity — hashed
  version: "184"              # human release number — not hashed
  labels: {team: support}     # bookkeeping — not hashed
spec:
  code: {repository: acme/support, commit: 8fd29ac}
  prompts: [{ref: prompt:support-answer@31}]      # ordered
  model: {ref: model:openai/gpt-5@2026-08-01}
  parameters: {temperature: 0.2, max_tokens: 1200}
  tools: [{ref: tool:lookup-customer@7}, {ref: tool:refund@4}]
  mcpServers: [{ref: mcp:crm@12}]
  retrieval: {ref: retrieval:support@22}
  policies: [{ref: policy:support-prod@11}]
  runtime: {image: registry/agent@sha256:<64 hex>, region: in-south}
  dependencies: [{name: orchestrator, version: 2.4.1}]
  featureFlags: {}
```

References are `<kind>:<name>@<version>`, where `version` is an immutable token
(`31`, `2.4.1`, `2026-08-01`) or a digest (`sha256:<64 hex>`). A release is
**certifiable** only if every reference is immutable: unversioned references
and environment aliases (`@latest`, `@production`, `@staging`, …) are rejected,
the commit must be a hex SHA, and the runtime image must be pinned by digest.

## Hash

```
manifest_hash = "sha256:" + hex(SHA-256("cloakpipe.dev/agent-release/v1" || "\n" || JCS(view)))
```

`view` contains `apiVersion`, `kind`, `metadata.agent` and the full `spec`,
with every string NFC-normalised, references flattened to strings, unordered
collections (`tools`, `mcpServers`, `policies`, `dependencies`) sorted, prompt
order preserved, and an absent `retrieval` as `null`. `JCS` is RFC 8785.

Consequences: YAML and JSON forms of the same manifest hash identically;
re-registering identical behaviour under a new release number yields the same
hash; any material change yields a different one.

## CLI

```bash
cloakpipe release validate release.yaml        # exit 1 with field paths if not certifiable
cloakpipe release hash release.yaml            # prints sha256:… ; refuses invalid manifests
cloakpipe release diff old.yaml new.yaml       # material changes + required assurance (--json)
cloakpipe release inspect release.yaml --json  # in-toto v1 Statement for signing
cloakpipe release register release.yaml        # register with CloakPipe Cloud (CI)
```

`register` validates locally first, then POSTs to
`$CLOAKPIPE_API_URL/v1/agents/<agent>/releases` with `$CLOAKPIPE_API_KEY`. It
prints the release hash, the baseline it was compared against, the required
assurance and the evidence ledger sequence (`--json` for the raw response).
Exit codes: 0 registered or already registered, 1 manifest rejected, 2
configuration, network or server error.

`diff` maps each changed component to the minimum assurance it needs before
certification (e.g. a model change requires functional, tool-use, safety,
privacy, regression, performance and cost suites) and flags changes to tools,
MCP servers or policies as requiring approval.

## Evidence binding

Set `CLOAKPIPE_RELEASE=sha256:…` when running `cloakpipe mcp-proxy`; every
ledger hop then carries `release_hash` inside its signed, hash-chained bytes.
A malformed value stops the interceptor from starting.
