# Policies: Cedar in the gate

A manifest's contract says what each argument may hold. Some rules are not
about one argument: "at most 50 emails an hour", "refunds over 100 need a
lead, over 500 never", "no deploys on Friday evening". Those go in a
[Cedar](https://www.cedarpolicy.com) policy file that the manifest names:

```yaml
release: support-agent
version: 2026.10.3
policy: ./policies/support.cedar   # relative to the manifest's directory
```

The gate uses the official `cedar-policy` crate (4.x), schema-less.

- Rust: [`crates/cloakpipe-policy`](../crates/cloakpipe-policy)
- Example: [`examples/support-agent/policies/support.cedar`](../examples/support-agent/policies/support.cedar),
  [`examples/filesystem/policies/readonly.cedar`](../examples/filesystem/policies/readonly.cedar)

## Where Cedar sits

For every `tools/call` the gate decides in this order, and the first stage
that refuses wins:

1. **Contract** (the manifest's `tools`). Cedar never sees a call that
   failed it, so a policy can rely on declared types and bounds.
2. **Cedar** (only when the manifest has `policy:`).
3. **Approval** (the manifest's `approval`, or a Cedar `@approval`).
4. **Operations** (side-effect tracking).

With no `policy:`, step 2 is skipped and the gate is contract-only.

## The request

| Cedar | Value |
|---|---|
| `principal` | `Release::"<release>"`, the manifest's `release` name |
| `action` | `Action::"<tool>"`, the tool name from `tools/call`. `Tool::"<tool>"` is accepted as a spelling of the same thing. |
| `resource` | `Call::"<fingerprint>"`, with the call's arguments as the record `resource.args` |
| `context.task` | the trusted task context (`--task-context`), as a record |
| `context.counters` | for every tool the manifest declares, `<tool>_1h` and `<tool>_24h` (see [Counters](#counters)) |
| `context.time` | `unix` (seconds), `hour_utc` (0 to 23), `weekday` (ISO: 1 = Monday to 7 = Sunday), at the gate's clock |

JSON maps to Cedar values as: string to String, boolean to Bool, integer
to Long, any other number to `decimal` (at most four fractional digits),
array to Set, object to Record. `null` members are left out. A number Cedar
cannot hold refuses the call as `fail_closed`. Values are built directly,
never through Cedar's JSON entity format, so an argument cannot smuggle in
an entity reference or an extension value.

Because Cedar compares Longs, declare amounts as `type: integer` (whole
cents or units) when a policy compares them. A `decimal` argument has to be
compared with Cedar's decimal methods (`.lessThan(decimal("100.00"))`).

A tool name that is not a plain identifier (`crm.patch`, `send-email`) is
still a valid action id (`Action::"crm.patch"`), but its counters must be
read with index syntax: `context.counters["send-email_1h"]`.

## Decisions

| Cedar's answer | Gate decision | Reason |
|---|---|---|
| no satisfied `permit` | deny | `policy_denied` (with `policies: []`) |
| any satisfied `forbid` | deny | `policy_denied`, with the `@id`s of the satisfied forbids in `policies` |
| permitted, but every satisfied permit has `@approval` | require approval | `approval_required` (unless a valid receipt is present) |
| permitted | allow | continue with the approval and operation checks |
| an evaluation error (wrong type, missing attribute) | deny | `fail_closed` |

A policy's id is its `@id("...")` annotation, or Cedar's positional
`policy0`, `policy1`, ... when it has none. Give every policy an `@id`: it
is what the agent, and you, see in a refusal.

Default deny means **every tool needs a permit**. The usual shape is one
broad permit per tool and narrow forbids on top:

```cedar
@id("send-email")
permit (principal == Release::"support-agent", action == Action::"send_email", resource);

@id("email-rate-limit")
forbid (principal, action == Action::"send_email", resource)
when { context.counters.send_email_1h >= 50 };
```

An evaluation error refuses the call rather than skipping the policy. Guard
optional attributes with `has`:

```cedar
@id("no-cc-outside")
forbid (principal, action == Action::"send_email", resource)
when { resource.args has cc && !(resource.args.cc like "*@ourcompany.com") };
```

## Approval

`@approval("<route>")` on a permit makes the calls it permits need a signed
approval receipt, exactly as the manifest's `approval:` does:

```cedar
@id("refund-large")
@approval("slack:#support-leads")
permit (principal == Release::"support-agent", action == Action::"issue_refund", resource)
when { resource.args.amount > 100 && resource.args.amount <= 500 };
```

If any satisfied permit has no `@approval`, the call does not need one from
Cedar. If the manifest's `approval.when` also holds, the call needs one
anyway; either source is enough, and the routes of both are merged into the
refusal's `approvers` list. Receipts are bound to the manifest digest, not
the policy digest: editing only the policy does not invalidate receipts
already signed.

## Counters

`context.counters.<tool>_1h` and `<tool>_24h` are the number of calls to
that tool the gate **forwarded** for this release name in the last hour and
the last 24 hours, before the current call. They are kept in a SQLite state
database:

- `--state-db <file>`, else `$CLOAKPIPE_STATE_DB`, else
  `$CLOAKPIPE_HOME/state.db` (`~/.cloakpipe/state.db`);
- keyed by the release **name**, so a new manifest version does not reset
  them, and stored on disk, so neither does restarting the gate;
- a call is counted when it is forwarded. A refused call, a retry answered
  from the operations store, and a call whose ledger write failed are not
  counted; in shadow mode every forwarded call is;
- rows older than 24 hours are pruned as calls are recorded.

Counters are per gate (per state database). Two gates on two machines each
count their own calls; there is no shared budget yet.

## Try it

Copy the example, add a freeze and a policy with a type error, and send one
refund and one email:

<!-- check-docs: run policy cwd=examples/support-agent -->
```bash
cd examples/support-agent
export CLOAKPIPE_HOME=$(mktemp -d)
cat >> policies/support.cedar <<'EOF'

@id("refund-freeze")
forbid (principal, action == Action::"issue_refund", resource)
when { context.time.unix > 0 };

@id("type-error")
forbid (principal, action == Action::"send_email", resource)
when { resource.args.ticket_id > 3 };
EOF
cloakpipe manifest validate cloakpipe.manifest.yaml
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_refund","arguments":{"ticket_id":"T-1042","amount":40}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"ticket_id":"T-1042","to":"dana@customer.example","subject":"Hi","body":"Hello"}}}' \
| cloakpipe mcp-proxy --upstream "python3 mock_upstream.py" --manifest cloakpipe.manifest.yaml \
    --task-context task-context.json --operations-db "$CLOAKPIPE_HOME/operations.db"
```

<!-- check-docs: expect policy -->
```text
policy sha256:…  ./policies/support.cedar  7 Cedar policies
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"tool call refused by CloakPipe: policy_denied","data":{"reason":"policy_denied","tool":"issue_refund","release":"sha256:…","policies":["refund-freeze"]}}}
{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"tool call refused by CloakPipe: fail_closed","data":{"reason":"fail_closed","tool":"send_email","release":"sha256:…"}}}
```
<!-- check-docs: absent policy upstream received -->

`type-error` compares a string with a number, which is a Cedar evaluation
error, so the email is refused as `fail_closed` even though `send-email`
permits it. The gate's log names the policy (`policy evaluation failed in
type-error`); the agent only sees the reason. A policy file that does not
parse stops the gate at start-up, and `cloakpipe manifest validate` reports
it with its line.

## What Cedar does not see

- The model's prompt or output, and the tool's result: the gate decides on
  the call alone.
- Anything outside the task context, the counters and the clock. There are
  no entity stores, no group memberships and no `in` hierarchies beyond what
  you put in the task context.
- Other gates' counters.

The policy digest (SHA-256 of the file's bytes) is recorded in every ledger
entry as `policy_digest`, so an auditor can tell which policy decided each
call.
