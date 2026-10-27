# Legacy documents

CloakPipe is a self-hosted policy-enforcement gate for AI agent tool calls
([README](../../README.md)). These documents describe earlier directions of
the project and are kept, marked legacy, for existing users and for history.
Nothing here is needed to run the gate.

| Document | What it covers | Status |
|---|---|---|
| [CERTIFICATION.md](CERTIFICATION.md) | Evaluation import (JUnit, Braintrust, Langfuse), certification policies, signed certifications, the GitHub Action | Behind the `certification` cargo feature, off by default |
| [AUDIT_PACK.md](AUDIT_PACK.md) | The release audit pack of the certification pipeline (`release audit-pack`, `cloakpipe-verify release-pack`) | Behind `certification` / `release-pack` |
| [AGENT_RELEASE.md](AGENT_RELEASE.md) | The AgentRelease manifest and its canonical hash | Accepted by the gate for one more release, with a deprecation warning; use [MANIFEST.md](../MANIFEST.md) |
| [ARCHITECTURE.md](ARCHITECTURE.md), [TECH.md](TECH.md), [PLAN.md](PLAN.md) | The 2025 PII privacy proxy design and plan | Historical; some of it was never built |

Build with the legacy commands:

```bash
cargo install --git https://github.com/rohansx/cloakpipe cloakpipe-cli --locked --features certification
```
