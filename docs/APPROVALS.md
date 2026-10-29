# Approvals through a broker

A call the manifest holds for approval is refused as `approval_required`
until a signed receipt for that exact call is in the gate's approvals
directory ([MANIFEST.md](MANIFEST.md#approval),
[ACTION_BOUNDARY.md](ACTION_BOUNDARY.md#approval-receipts)). You can make
receipts by hand with `cloakpipe approve`, or let an **approval broker**
route the request to a human and hand the receipt back. CloakPipe Cloud is
one such broker. The protocol below is open: any service that implements
it works the same way, and the gate trusts it no further than the approver
keys you pin.

```
 agent ──tools/call──> gate ──refused: approval_required──> agent (retries later)
                        │  └─ POST /approvals (background, signed) ──> broker ──> a human (Slack, a dashboard, ...)
                        │                                                     │ approves: broker signs a receipt
                        └── poller: GET /approvals?since= (signed) <──────────┘
                              verify locally ──> approvals/<fingerprint>.approval.json
 agent ──same tools/call──> gate finds the receipt, verifies it again ──> tool
```

- **The decision path never waits on the network.** Filing the request is
  queued; the poller runs on its own thread. The agent retries; the gate
  finds the receipt on disk exactly as it would one made by
  `cloakpipe approve`.
- **The gate verifies every receipt twice**: the poller before it writes
  one (signature by a pinned approver key, release, tool, task id,
  fingerprint, `approval.ttl`), and the gate again on the call. A receipt
  that does not verify is never written; it is logged and raises an
  `approval.mismatch` event.
- **If the broker is down**, nothing changes but that approvals do not
  arrive: a call that needs one stays refused, so it expires to deny.

## Running it

```bash
cloakpipe approvals keys --approvals-url https://broker.example/v1/gates/$GATE_ID \
  --approvals-secret-file gate.secret --out approver-keys
cloakpipe mcp-proxy --upstream "python3 mock_upstream.py" --manifest cloakpipe.manifest.yaml \
  --task-context task-context.json \
  --approvals approvals --approver-key approver-keys/<keyid>.approver.json \
  --approvals-url https://broker.example/v1/gates/$GATE_ID --approvals-secret-file gate.secret
```

| Flag | Meaning |
|---|---|
| `--approvals-url URL` | The gate's base URL at the broker. Needs `--approvals`, at least one `--approver-key`, `--approvals-secret-file`, and a task context with a `taskId` (every receipt is signed for it). |
| `--approvals-secret-file FILE` | The HMAC secret both directions are signed with. The webhook secret file (`--webhook-secret-file`) may be reused. |
| `--approvals-poll-interval DURATION` | How often finished requests are fetched: `5s` (default), `1m`, ... |

`cloakpipe approvals keys` fetches the broker's approver public keys and
writes each as an `--approver-key` file. Review them before you pin them:
they decide who can approve.

The refusal tells the agent what is going on:

```json
{"jsonrpc":"2.0","id":4,"error":{"code":-32001,"message":"tool call refused by CloakPipe: approval_required","data":{"reason":"approval_required","tool":"issue_refund","release":"sha256:…","approvers":["slack:#support-leads"],"fingerprint":"sha256:…","approval_request":"requested","hint":"approval requested; retry the same call after approval"}}}
```

`data.approval_request` is `requested` (filed now, or being filed),
`pending` (the broker has it; nobody decided yet) or `denied`. The reason
stays `approval_required`; it is only `approval_denied` once an approver
denied the call.

## What the broker sees

The request carries the call's fingerprint, the release (name, version,
digest), the tool, the manifest's approver routes, the task id, the ttl,
the decision ledger seq, and **only** the argument values the manifest
opts in to with `approval.show`:

```yaml
approval:
  when: "amount > 100"
  approvers: ["slack:#support-leads"]
  ttl: 15m
  show: [amount]          # the approver sees the amount; ticket_id and note never leave the host
```

`show` lists top-level arguments the tool declares; the default is none.
Keep it short. A fingerprint is SHA-256 over the manifest digest, the tool
and every argument, so a broker that knows the other arguments' likely
values can test guesses against it: treat a fingerprint as revealing,
at most, low-entropy arguments of the call, and `show` as revealing what it
lists. "Approve with an edit" (an approver changing an argument) is not
possible: the broker never sees the arguments it would have to fingerprint.

## Denied and expired

| The broker reports | The gate |
|---|---|
| `approved` | verifies the receipt and writes `<fingerprint hex>.approval.json` atomically; the retry is forwarded |
| `denied` | refuses that exact call as `approval_denied` until the denial's `not_after` (else the request's ttl): in memory, and as a marker `<fingerprint hex>.denied.json` it honours after a restart. No new request is filed meanwhile. Any other arguments are another call. |
| `expired` (nobody decided in time) | nothing is written; the call stays `approval_required`, and the next retry files a new request |

`approval_expired` keeps its meaning: a receipt past its `notAfter`.

## The protocol (v1)

Everything is JSON over HTTPS, under the gate's base URL `<url>` (e.g.
`https://broker.example/v1/gates/<gate id>`).

**Signing.** Every request carries
`CloakPipe-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>." + signed)>`,
exactly as gate webhooks are signed ([EVENTS.md](EVENTS.md)). `signed` is
the exact body of a `POST`, and for a `GET` the string `GET <target>`,
where `<target>` is the request's path and query as sent, percent-encoded
as on the wire (`GET /v1/gates/g1/approvals?since=c-42`; no `?` without a
query). A broker should reject a `t` more than five minutes from its clock.
`cloakpipe events verify-signature` checks a header.

### `POST <url>/approvals`: file a request

```json
{
  "schema": "cloakpipe.approval-request/v1",
  "fingerprint": "sha256:5e2b…",
  "release": "support-agent",
  "version": "2026.10.3",
  "release_digest": "sha256:c558…",
  "tool": "issue_refund",
  "approvers": ["slack:#support-leads"],
  "task_id": "t-981",
  "ttl_secs": 900,
  "requested_at": "2026-10-29T10:00:00Z",
  "expires_at": "2026-10-29T10:15:00Z",
  "ledger_seq": 12,
  "shown": { "amount": 350 }
}
```

`ttl_secs` is the tool's `approval.ttl` (900 when it sets none);
`expires_at` is when the request lapses. `ledger_seq` names the decision
ledger entry of the refusal (null without a ledger). A broker must store no
argument value other than those in `shown`, and should be idempotent per
`fingerprint`: filing an open request again returns it. Reply with any 2xx,
e.g. `{"request_id": "…", "status": "pending"}`; the gate retries a 429,
a 5xx or a connection error, and files the request again on the agent's
next retry if every try failed.

### `GET <url>/approvals?since=<cursor>`: finished requests

```json
{
  "cursor": "c-43",
  "approvals": [
    { "request_id": "…", "fingerprint": "sha256:5e2b…", "status": "approved", "envelope": { "payloadType": "application/vnd.in-toto+json", "payload": "…", "signatures": [ … ] } },
    { "request_id": "…", "fingerprint": "sha256:9a1c…", "status": "denied", "decided_at": "2026-10-29T10:03:00Z", "not_after": "2026-10-29T10:15:00Z" },
    { "request_id": "…", "fingerprint": "sha256:77d0…", "status": "expired" }
  ]
}
```

Requests that finished after `cursor`, in order, and the cursor to ask
from next (opaque to the gate). Without `since`, the broker may return
whatever it still holds; the gate skips what it already has. `not_after`
on a denial is optional.

**The receipt** (`envelope`) is a DSSE envelope made with
[`cloakpipe-receipt`](../crates/cloakpipe-receipt)'s `sign_approval`, the
same as `cloakpipe approve` makes: the subject's digest is the request's
fingerprint, and the predicate's `release` is `release_digest`, `tool` and
`taskId` are the request's, `operationId` is any valid operation id (a
fresh UUID v4 is fine), `approver` is the signing key's keyid, and
`notAfter - approvedAt` is at most `ttl_secs`. Sign each approver with a
key of their own.

### `GET <url>/approver-keys`: the approver public keys

```json
{ "keys": [ { "keyid": "ed25519:3f1a9c0b5d2e7a41", "publicKey": "<64 hex chars>" } ] }
```

The format `--approver-key` reads. `keyid` is `ed25519:` and the first 16
hex characters of SHA-256 over the 32-byte public key;
`cloakpipe approvals keys` refuses a key whose keyid is not its own, and
writes nothing then. List a rotated-out key until its receipts have
expired.

## Trust

The broker holds approver keys, so it can approve anything the contract
and the Cedar policy already allow; it can never widen them, and every
receipt names its approver and is recorded by digest in the decision
ledger. Pin only keys you mean to trust, one per approver, and remove a
key from `--approver-key` to revoke it ([KEYS.md](KEYS.md#approver-keys),
[THREAT_MODEL.md](THREAT_MODEL.md)). Beyond what those keys can sign, a
broker can only withhold approvals or report denials, and both refuse.
Nothing the broker sends reaches the approvals directory unless it
verifies, and only a 64-hex fingerprint ever becomes a file name.
