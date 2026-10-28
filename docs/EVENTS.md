# Events: webhooks, OpenTelemetry and the events log

> Since v0.13.0.

The gate's second job, after stopping an out-of-contract call, is telling
a human about it. `cloakpipe mcp-proxy` raises a **gate event** for every
decision that deserves attention and can deliver it three ways:

- an append-only JSONL file (`--events-log`)
- HMAC-signed webhooks, raw JSON or formatted for Slack or Discord
  (`--webhook`)
- OpenTelemetry spans over OTLP/HTTP, one per tool-call decision, allows
  included (`--otel-endpoint`)

Delivery is off the decision path. Events go on a bounded queue drained
by a background thread. A slow or dead endpoint never delays a decision or
changes it.

## What is in an event

| kind | when |
|---|---|
| `decision.deny` | a call was refused (enforce mode), including `fail_closed` |
| `approval.requested` | a call needs an approval receipt and has none |
| `approval.mismatch` | a receipt was presented that does not cover this exact call (other arguments, release or tool, or a bad signature) |
| `shadow.finding` | shadow mode forwarded a call that enforce mode would have refused |
| `side_effect.replayed` | a retry of a completed side effect was answered from the operations store |
| `side_effect.unknown` | a forwarded side effect never got its reply: reconcile it |
| `anchor.failed` | anchoring a ledger epoch failed (`reason` is `rfc3161` or `rekor`) |
| `tool.drift` | an upstream tool no longer matches its pin in the tools lock, or changed during the session (`reason` is `tool_drift`): once when the gate finds it, then with each refused call |

An expired approval receipt is a `decision.deny` with reason
`approval_expired`.

Each event is one JSON object with `"schema": "cloakpipe.event/v1"` and
these members: `kind`, `fingerprint`, `ts`, `release`, `release_digest`,
`policy_version` (the Cedar policy digest), `tool`, `reason`, `path` (the
contract path of an argument denial, such as `/to`), `server` (the
upstream server of a `tool.drift` event, else `null`), `decision`, `mode`,
`operation_id`, `ledger_seq` and `entry_hash`. The last two name the
decision ledger entry the event follows (`null` for a `tool.drift` raised
when the gate finds the drift, before any call).

The **fingerprint** is `sha256:` plus the hex SHA-256 of
`kind|reason|tool|path|policy_version`, with an absent member counted as
an empty string (for `tool.drift`, `tool` is `<server>/<tool>`). The same failure gets the same fingerprint on every run
and every gate, so an alerting pipeline can group repeats into one issue.
A policy change is a new issue.

An event never carries an argument value, a tool result or a credential.
The injected `send_email` in Example 2 produces this event, and the
attacker's address appears nowhere in it:

```json
{
  "schema": "cloakpipe.event/v1",
  "kind": "decision.deny",
  "fingerprint": "sha256:…",
  "ts": "2026-10-28T09:14:03Z",
  "release": "support-agent",
  "release_digest": "sha256:…",
  "policy_version": "sha256:…",
  "tool": "send_email",
  "reason": "scope_mismatch",
  "path": "/to",
  "server": null,
  "decision": "deny",
  "mode": "enforce",
  "operation_id": null,
  "ledger_seq": 2,
  "entry_hash": "1d5b7808…"
}
```

## The flags

They all need `--manifest`, because without a gate there are no events.
They are checked before anything starts. An unreadable secret, a
non-HTTP URL or an unwritable log path refuses to start, with exit code 2.

```bash
cloakpipe mcp-proxy \
  --manifest cloakpipe.manifest.yaml \
  --upstream "python3 server.py" \
  --events-log ~/.cloakpipe/events.jsonl \
  --webhook https://alerts.example.com/cloakpipe \
  --webhook-secret-file ~/.cloakpipe/webhook.secret \
  --otel-endpoint http://localhost:4318
```

| flag | |
|---|---|
| `--events-log PATH` | append each event to PATH as one JSON line; an existing file is never truncated |
| `--webhook URL` | POST each event to URL; repeatable |
| `--webhook-secret-file FILE` | sign webhook payloads with this secret (one trailing newline is ignored) |
| `--webhook-format generic\|slack\|discord` | payload shape for every `--webhook` (default `generic`) |
| `--otel-endpoint URL` | OTLP/HTTP collector base URL; spans go to `URL/v1/traces` |
| `--otel` | use `$OTEL_EXPORTER_OTLP_ENDPOINT` as the endpoint |

`OTEL_EXPORTER_OTLP_ENDPOINT` on its own exports nothing. Pass `--otel` to
use it, so a variable set for some other program never starts sending
decisions from the gate.

## Webhooks

Every webhook request is a `POST` with `Content-Type: application/json`
and these headers:

- `CloakPipe-Event: <kind>`
- `CloakPipe-Fingerprint: <fingerprint>`
- `CloakPipe-Signature: t=<unix seconds>,v1=<hex>` when a secret is set

With the `generic` format the body is the event object above. Without a
secret the payload is unsigned, and the gate warns about it at start-up.

### Delivery

- Each `--webhook` has its own queue and thread. A queue holds 1024
  events. When it is full, new events are dropped and counted, with a
  warning on stderr for the first drop and every 100th after that.
- Each event gets up to three tries, with 5 s timeout each and a backoff
  of 0.5 s and then 1 s. A connection error, a timeout, a `429` or a `5xx`
  is retried. Any other non-2xx status is final.
- Each try is signed again with a fresh `t`.
- When the proxy stops, it waits up to 5 s for queued events to be
  delivered, then exits.

### Verifying the signature

```text
v1 = hex( HMAC-SHA256( secret, "<t>" + "." + <raw request body> ) )
```

To check a request, a receiver should:

1. Split the header on `,` and read `t` and every `v1`.
2. Compute `v1` over the **raw** body bytes. Re-serialized JSON will not
   match.
3. Compare it in constant time with each `v1` in the header. Any match is
   enough, which lets you rotate secrets.
4. Reject a `t` more than about five minutes from your clock, so that an
   old request cannot be replayed.

`cloakpipe events verify-signature` does exactly this, and you can test
your own receiver's code against it. This computes a signature with
`openssl` and checks it:

<!-- check-docs: run signature -->
```bash
printf 'whsec-example-secret' > webhook.secret
printf '{"kind":"decision.deny","reason":"scope_mismatch"}' > body.json
t=$(date +%s)
v1=$(printf '%s.%s' "$t" "$(cat body.json)" | openssl dgst -sha256 -hmac "$(cat webhook.secret)" | sed 's/^.* //')
cloakpipe events verify-signature --secret-file webhook.secret --header "t=$t,v1=$v1" --body-file body.json
```

<!-- check-docs: expect signature -->
```text
signature ok
```

A tampered body or a different secret exits with code 1 and the message
`signature does not match the body`. A timestamp outside `--tolerance`
seconds (default 300) also exits with code 1. `--tolerance 0` turns the
age check off.

### Slack

1. In Slack, create an app with **Incoming Webhooks** turned on, add a
   webhook to the channel you want, and copy its URL.
2. Send a sample event to check the wiring:

   ```bash
   cloakpipe events test --webhook "$SLACK_WEBHOOK_URL" --webhook-format slack
   ```

3. Run the gate with the same flags:

   ```bash
   cloakpipe mcp-proxy --manifest cloakpipe.manifest.yaml --upstream "python3 server.py" \
     --webhook "$SLACK_WEBHOOK_URL" --webhook-format slack
   ```

Each message is a Block Kit message. A header gives the kind and tool,
such as "Tool call denied: send_email". Fields follow for the reason,
tool, contract path, release, mode, ledger seq and operation. A context
line shows the fingerprint and the release digest. Slack ignores the
signature header, so a secret is optional here.

### Discord

Create a webhook under the channel's **Integrations** settings, then run
with `--webhook "$DISCORD_WEBHOOK_URL" --webhook-format discord`. Each
event becomes one embed with the same fields, colour-coded: red for a
refusal, amber for something that needs a human, blue for a replay. The
fingerprint goes in the footer.

`cloakpipe events test` sends a sample `decision.deny` in any of the three
formats. It exits 0 on a 2xx response and 1 otherwise.

## OpenTelemetry

`--otel-endpoint http://collector:4318` exports one span named
`cloakpipe.decision` for every tool-call decision, allows included, as
OTLP/HTTP JSON. Spans are sent in batches from a background thread. The
resource's `service.name` is `cloakpipe-gate`, and each span is its own
trace.

| attribute | value |
|---|---|
| `cloakpipe.decision` | `allow`, `deny` or `require_approval` |
| `cloakpipe.reason` | the reason code (`ok` for an allow) |
| `cloakpipe.tool` | the tool |
| `cloakpipe.path` | the contract path of an argument denial |
| `cloakpipe.release` | the release name |
| `cloakpipe.manifest_digest` | the manifest digest |
| `cloakpipe.policy_digest` | the Cedar policy digest, if there is one |
| `cloakpipe.mode` | `enforce` or `shadow` |
| `cloakpipe.forwarded` | whether the call reached the tool |
| `cloakpipe.operation_id` | the side-effect operation, if any |
| `cloakpipe.ledger.seq`, `cloakpipe.ledger.entry_hash` | the decision's ledger entry |
| `cloakpipe.event`, `cloakpipe.fingerprint` | the event the decision raised, if any |

A refused call is an error span (status code 2). Spans carry no argument
values. The span's duration is the time the gate took to decide, ledger
write included.

## Library use

The sinks are in `cloakpipe_mcp::events` and are re-exported from the
crate root: `JsonlSink`, `WebhookSink`, `OtelSink`. You can also implement
the `EventSink` trait yourself. `emit` gets each event, the default no-op
`decision` gets every tool-call decision, and `flush` is called when the
proxy stops. All three are called on the decision path, so they must
queue the work and return straight away.

## Not built yet

- a different secret or format for each webhook (today one
  `--webhook-format` and one secret apply to every `--webhook`)
- delivery that survives a restart. The queue is in memory, but the signed
  decision ledger keeps every decision.

A hosted plane that groups events into issues, routes them, sends approval
cards and escalates is not part of this repository.
