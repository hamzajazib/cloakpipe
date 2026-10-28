# Threat model

What the gate defends against, what it assumes, and what it does not do.
This describes the code in this repository, not plans; where something is
planned, it says so.

## The system

```
 orchestrator ──task context──┐
                              v
 agent (model) ──tools/call──> cloakpipe mcp-proxy ──allowed calls──> MCP tool server ──> real systems
                               │  manifest + Cedar policy (files)
                               │  approval receipts, approver public keys
                               │  operations.db, state.db (SQLite)
                               └─> ledger.db ──epochs──> RFC 3161 TSA, Sigstore Rekor
                                        │
                                        └─ ledger export ──> audit-pack.tar ──> cloakpipe verify (auditor, offline)
```

## Who is trusted for what

| Party | Trusted to | Not trusted to |
|---|---|---|
| The model and the agent loop | nothing | choose tools, arguments, operation ids or task ids |
| Content the agent reads (tickets, web pages, tool results) | nothing | anything; this is where prompt injection comes from |
| The orchestrator | write a correct task context (`--task-context`) | (the gate cannot check it) |
| The manifest and policy authors | say what is allowed | (the gate enforces what they wrote, mistakes included) |
| Approvers | hold their keys and approve deliberately | approve anything outside the contract and policy (approval never widens them) |
| The operator of the gate's host | run the gate and keep its keys | rewrite history after the fact, once it is anchored |
| The tool server | perform the calls it receives | (its results are passed back unchecked) |
| TSA and Rekor | timestamp and log honestly | (two independent services; the verifier checks their signatures and Rekor inclusion proofs) |

## In scope

These are the attacks the gate is built to stop or expose. Each has tests.

**Prompt injection that leads to an out-of-contract call.** The injected
`send_email` to `attacker@evil.example` is refused because the recipient
must equal a task-context value the model cannot write
(`scope_mismatch`). A tool the release never declared is refused
(`undeclared_tool`) however the model was persuaded to call it.

**Argument smuggling.** Arguments are closed by default
(`undeclared_argument`), typed, length- and range-bounded, and checked
against anchored patterns. The gate refuses, as `fail_closed`, JSON-RPC
it cannot read unambiguously: unparseable messages, batches, and member
names that are not the canonical ones. A refusal names the rule and the
argument's path, never its value, so probing it leaks nothing.

**Cross-task and cross-tenant calls.** `one_of_context` binds an
argument to the task the orchestrator assigned; a well-formed id of another
customer is `scope_mismatch`.

**Approval abuse.** A receipt is bound to the call's fingerprint (the
manifest digest, the tool and every argument), to the task id, and to a
validity window capped by the manifest's `ttl`. A receipt for a 350 refund
does not authorise 3,500, another ticket, or the same call next week. An
approval never lets through what the contract or policy refuses.

**Duplicate side effects.** A side-effecting call is recorded before it
is forwarded. A retry of a completed call is answered from the store; a
retry of a call whose outcome is unknown (the tool died mid-call) is refused
as `reconcile_before_retry` until an operator settles it. The operation id
comes from the gate, never from the model.

**Rate-limit reset by restart.** Cedar counters are in SQLite and keyed by
release name, so restarting the gate or shipping a new version does not
reset them.

**Failures that would open the gate.** A manifest or policy that does not
load stops the gate at start-up. A policy evaluation error, an unreadable
counter or operations store, or a ledger write that fails refuses the call
(`fail_closed`); the call is not forwarded.

**Editing or deleting history.** Each ledger entry is hash-chained to the
previous one and signed. `cloakpipe verify` with the pinned gate key detects
an edited, reordered or removed entry. With anchoring on, each epoch head is
timestamped by an RFC 3161 TSA and logged in Sigstore Rekor; the verifier
checks both offline and reports missing epochs and uncovered ranges as gaps,
so the operator cannot back-date or rewrite anchored history even with the
gate key.

**Raw values in evidence.** The ledger holds no argument values, results
or raw fingerprints; `args_fingerprint` is keyed (HMAC) with a key derived
from the gate key, so a holder of the ledger cannot test guesses of
low-entropy arguments against it.

## Out of scope, or not yet defended

**Injections that stay inside the contract.** If the manifest allows the
agent to email the customer anything up to 4,000 characters, an injection
can make it send the customer something wrong. The gate decides on the call,
not on intent; it does not read prompts, outputs or message bodies. Tight
contracts and policies narrow this; nothing removes it.

**Bypassing the gate.** The gate only sees calls that go through it. An
agent with a shell, network access or other credentials for the same
systems can act without it. Deploy it so that it is the only path: the tool
server's credentials should exist only in the gate's child process.

**A malicious or compromised tool server.** Results are passed back to
the agent unchanged (apart from the opt-in PII transform), so a tool can
inject instructions into the model. Tool descriptions in `tools/list` are
passed through, but not unchecked (since v0.13.0). A tool whose
definition changes during a session is hidden and refused (`tool_drift`).
With a tools lock (`cloakpipe tools pin`, `mcp-proxy --tools-lock`), so is
any tool that does not match the definition you reviewed. Pinning catches a
description that changes. It does not judge whether the description you
pinned was honest, and it does not touch results.

**A wrong task context.** The gate trusts the orchestrator. If the
orchestrator puts the attacker's address in the task context, the gate
allows it.

**A compromised gate host.** Root on the gate's machine can stop the gate,
edit its manifest, read its keys and sign new entries. Anchoring limits the
damage to history after the last anchored epoch; entries in that
unanchored tail could be dropped or rewritten without detection. Keep
anchoring intervals short. Keys in a KMS or HSM are planned
([KEYS.md](KEYS.md#kms-and-hsm)).

**Completeness.** A verified pack proves that the entries it holds were
written in that order by that key and (when anchored) existed by the anchor
time. It does not prove that every action in the world went through the
gate, or that a gate run with `--no-ledger` never happened.

**Shadow mode.** With `--mode shadow` every call is forwarded; it is for
trying a manifest, not for protection.

**Denial of service.** An agent that loops on refused calls fills the
ledger; there is no budget or loop detection yet (planned).

**Verification limits.** Offline verification does not check certificate
revocation (CRL/OCSP) for TSA certificates, or Rekor log consistency between
checkpoints. Without `--key`, the verifier trusts the key inside the pack,
which only shows internal consistency.

**Clock.** Counters, `context.time` and receipt expiry use the gate
host's clock. A host whose clock can be moved can widen time-based rules.
Anchor times come from the TSA and Rekor, not from the host.

**Approver key compromise.** A stolen approver key can approve calls the
contract and policy allow until it is removed from `--approver-key`; there
is no revocation list.

**PII detection.** The opt-in PII transform and the PII proxy use regex
and heuristics (NER with the `ner` feature). They miss entities; measure
them on your data.

**The HTTP transports.** The gate speaks MCP over stdio and Streamable
HTTP (since v0.13.0): `--listen` serves agents over
HTTP, `--upstream-url` fronts an HTTP MCP server. Only traffic sent through
the gate is gated: an agent that can reach the MCP server directly goes
around it, so put the server where only the gate can reach it. The
listener checks `Origin` (against DNS rebinding) and, with
`--listen-token-file`, a bearer token on every `/mcp` request; without a
token, anyone who can reach the listener can use the gate's tools, so a
non-loopback bind without one draws a warning (and the Docker entrypoint
refuses it). The token is a shared secret, not a per-agent identity, and
TLS is left to a reverse proxy in front. Tools called through an LLM
provider's native tool calling without MCP are not gated (planned).

## Reporting

Please report vulnerabilities privately; see [SECURITY.md](../SECURITY.md).
