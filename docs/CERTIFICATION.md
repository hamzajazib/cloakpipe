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

## What a certification does not claim

A valid certification proves that a named issuer applied a named policy to
named evaluation runs of an exact release and reached the stated decision. It
does not prove the evaluators measured the right property, that the suites are
representative, or that the release is safe outside the certified scope and
validity window.
