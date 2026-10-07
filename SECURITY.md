# Security Policy

CloakPipe produces and verifies security evidence (release hashes,
certifications, ledger records, anchors, audit packs) and handles sensitive
data in its privacy proxy. We take reports seriously.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request.**

Report privately through
[GitHub Security Advisories](https://github.com/rohansx/cloakpipe/security/advisories/new).
Include:

- the affected crate, command or format, and the commit or version;
- a description of the impact (for example: a tampered artifact that still
  verifies, PII reaching a ledger record or upstream provider, a gate bypass);
- steps or a minimal input to reproduce.

We aim to acknowledge reports within a few working days, keep you informed
while we investigate, and credit you in the advisory unless you prefer
otherwise. Please give us a reasonable window to release a fix before any
public disclosure.

## Scope

Particularly in scope:

- `cloakpipe-verify` accepting an artifact it should reject (fail-open
  behaviour, signature or hash bypass, back-dating past an anchor);
- certification decisions or the MCP tool gate admitting what the policy or
  manifest should refuse;
- raw PII appearing in ledger records, audit logs or upstream requests that the
  configured detectors are documented to catch;
- weaknesses in key handling, vault encryption or canonicalization.

Detection misses on new kinds of PII are generally quality issues rather than
vulnerabilities; please open a regular issue for those, without real personal
data.

The documented limitations in [`docs/`](docs) (for example, that governance
events in an audit pack are exporter-attested, or that offline verification
does not check CRL/OCSP) are known and by design.

## Supported versions

CloakPipe is in developer preview. Fixes land on `main` and in the next tagged
release; older releases are not patched separately.
