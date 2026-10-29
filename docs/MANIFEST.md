# Manifest reference: `cloakpipe.manifest.yaml`

The manifest is the one file the gate enforces: which tools an agent
release may call, what each call may carry, which calls change the world,
and which need a human's signature. `cloakpipe mcp-proxy --manifest <file>`
loads it at start-up; anything it does not declare is refused.

- JSON Schema: [`schemas/cloakpipe.manifest.schema.json`](../schemas/cloakpipe.manifest.schema.json)
- Rust: [`crates/cloakpipe-release/src/v1.rs`](../crates/cloakpipe-release/src/v1.rs)
- Worked example: [`examples/support-agent/cloakpipe.manifest.yaml`](../examples/support-agent/cloakpipe.manifest.yaml)
- Policies (`policy:`): [POLICY.md](POLICY.md)

## A complete example

Save this as `crm/cloakpipe.manifest.yaml` in a checkout of the repository
(the commands below borrow the support-agent example's stub tool server):

<!-- check-docs: file manifest crm/cloakpipe.manifest.yaml -->
```yaml
release: crm-agent
version: "1.4"
tools:
  lookup_customer:
    args:
      customer_id: { type: string, pattern: "C-[0-9]{6}", required: true }
  update_stage:
    args:
      customer_id: { type: string, pattern: "C-[0-9]{6}", one_of_context: ["account.customer_ids"], required: true }
      stage: { type: string, enum: [lead, qualified, won, lost], required: true }
      note: { type: string, max_len: 280 }
    effect: write
    idempotency_key: "{customer_id}:{stage}"
    approval:
      when: "stage == 'won' || stage == 'lost'"
      approvers: ["slack:#sales-ops"]
      ttl: 1h
```

<!-- check-docs: run manifest cwd=examples/support-agent -->
```bash
cd crm
cloakpipe manifest validate cloakpipe.manifest.yaml
cloakpipe manifest hash cloakpipe.manifest.yaml
```

<!-- check-docs: expect manifest -->
```text
valid  sha256:… crm-agent@1.4  2 tools
sha256:…
```

`validate` exits 0 when the gate would load the file, 1 when it would
refuse to start, and 2 on a usage or I/O error.

The task context the orchestrator writes for this task, `crm/task-context.json`:

<!-- check-docs: file manifest crm/task-context.json -->
```json
{"taskId": "t-77", "account": {"customer_ids": ["C-000001", "C-000002"]}}
```

Seven calls an agent might make, and what the gate answers:

<!-- check-docs: run manifest -->
```bash
call() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$@"; }
{
  call 1 lookup_customer '{"customer_id":"C-000001","debug":"true"}'
  call 2 lookup_customer '{}'
  call 3 lookup_customer '{"customer_id":"C-1"}'
  call 4 update_stage '{"customer_id":"C-000009","stage":"lead"}'
  call 5 update_stage '{"customer_id":"C-000001","stage":"won"}'
  call 6 update_stage '{"customer_id":"C-000001","stage":"qualified"}'
  call 7 update_stage '{"customer_id":"C-000001","stage":"qualified","note":"again"}'
} | cloakpipe mcp-proxy --upstream "python3 ../examples/support-agent/mock_upstream.py" \
      --manifest cloakpipe.manifest.yaml --task-context task-context.json \
      --operations-db operations.db 2>/dev/null
```

<!-- check-docs: expect manifest -->
```text
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"tool call refused by CloakPipe: undeclared_argument","data":{"reason":"undeclared_argument","tool":"lookup_customer","release":"sha256:…"}}}
{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"tool call refused by CloakPipe: argument_missing","data":{"reason":"argument_missing","tool":"lookup_customer","release":"sha256:…","path":"/customer_id"}}}
{"jsonrpc":"2.0","id":3,"error":{"code":-32001,"message":"tool call refused by CloakPipe: argument_invalid","data":{"reason":"argument_invalid","tool":"lookup_customer","release":"sha256:…","path":"/customer_id"}}}
{"jsonrpc":"2.0","id":4,"error":{"code":-32001,"message":"tool call refused by CloakPipe: scope_mismatch","data":{"reason":"scope_mismatch","tool":"update_stage","release":"sha256:…","path":"/customer_id"}}}
{"jsonrpc":"2.0","id":5,"error":{"code":-32001,"message":"tool call refused by CloakPipe: approval_required","data":{"reason":"approval_required","tool":"update_stage","release":"sha256:…","approvers":["slack:#sales-ops"],"fingerprint":"sha256:…"}}}
{"jsonrpc":"2.0","id":6,"result":{"content":[{"type":"text","text":"update_stage: done"}]}}
{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"tool call refused by CloakPipe: operation_conflict","data":{"reason":"operation_conflict","tool":"update_stage","release":"sha256:…","operationId":"op-…"}}}
```

1. `debug` is not declared: `undeclared_argument`. The refusal does not
   name the argument, so a probing model learns nothing from it.
2. `customer_id` is `required: true`.
3. `C-1` does not match the anchored `pattern`.
4. `C-000009` is a well-formed id, but not one of this task's customers.
5. Moving a deal to `won` needs a signed approval; the refusal carries the
   route and the fingerprint the approval must be for.
6. Allowed, and tracked as the operation whose idempotency key renders as
   `C-000001:qualified`.
7. The same idempotency key with different arguments (a `note`) is a
   conflict, not a second update.

## Top level

| Key | Required | Meaning |
|---|---|---|
| `release` | yes | The agent release's name. It is the Cedar `principal` (`Release::"<release>"`), it keys the persistent call counters, and it goes into operation ids derived from `idempotency_key`. |
| `version` | yes | A string or a number. Quote it when YAML would read it as a number you did not mean (`"1.10"`). |
| `policy` | no | A path to a Cedar policy file, relative to the manifest's directory. See [POLICY.md](POLICY.md). |
| `tools` | no | A map from tool name (exactly as in `tools/call`) to its rules. A manifest with no tools refuses every call. |

Unknown keys are errors, at every level.

## Tools

| Key | Meaning |
|---|---|
| `args` | The arguments a call may carry, by name. **Closed:** a declared tool with no `args` accepts no arguments, and any argument not listed is refused as `undeclared_argument` (the refusal does not name it). |
| `side_effect` | `true`: the call changes state outside the agent. It becomes a tracked operation (see [Operations](ACTION_BOUNDARY.md#operations-identity-and-outcome-states)), and the gate needs `--operations-db`. |
| `effect` | `read`, `write` or `irreversible`. `write` and `irreversible` are side effects; `side_effect: true` means `write`. Setting both keys so that they disagree is an error. |
| `idempotency_key` | Side-effecting tools only. A template that names the operation, so that a retry is recognised as the same operation. |
| `approval` | The call needs a signed approval receipt for its exact arguments. |

A tool that is not declared is refused as `undeclared_tool`.

## Argument constraints

Each argument is optional unless it has `required: true`. A missing required
argument is `argument_missing`. A value that breaks a constraint is
`argument_invalid`, with the JSON pointer of the offending value as `path`.

| Key | Applies to | Meaning |
|---|---|---|
| `type` | any | `string`, `number`, `integer`, `boolean`, `object` or `array`. |
| `pattern` | string | A regex the **whole** string must match (it is anchored for you). |
| `enum` | any | The value must equal one of these. |
| `const` | any | The value must equal this. |
| `min_len`, `max_len` | string, array | Length in Unicode scalar values, or number of items. |
| `min`, `max` | number, integer | Inclusive bounds. |
| `items` | array | A constraint every item must meet. |
| `properties` | object | The object's members, each with its own constraint. Closed: other members are refused. |
| `required` | any | `true`: the argument (or member) must be present. |
| `one_of_context` | string | Dotted paths into the trusted task context (a `task.` prefix is accepted). The value must equal one of the values found there; each may be a string or an array of strings. |
| `or_pattern` | string | With `one_of_context`: a regex (unanchored search) that also lets a value through. |

A constraint must restrict something, and its keys must fit its `type`
(`min` on a string is an error at load time).

### Binding arguments to the task (`one_of_context`)

The **task context** is a JSON object your orchestrator writes for the task
the agent is working on, and passes to the gate with `--task-context
<file>` (or `CLOAKPIPE_TASK_CONTEXT`). The model never writes it. With

```json
{"taskId": "t-1042", "ticket": {"id": "T-1042", "customer_email": "dana@customer.example"}}
```

`to: { type: string, one_of_context: ["ticket.customer_email"], or_pattern: "@ourcompany\\.com$" }`
lets `send_email` write only to Dana or to an internal address:

- equal to a value at one of the paths: allowed;
- otherwise, if `or_pattern` matches: allowed;
- otherwise `scope_mismatch` (with the `path` of the argument), or
  `task_context_missing` when none of the paths exists in the task context.

`taskId` is also what approval receipts are bound to, and what derived
operation ids are scoped to.

## `idempotency_key`

A template over the call's arguments and the task context:

| Placeholder | Renders as |
|---|---|
| `{path}` | the argument at that dotted path |
| `{task.path}` | the task-context value at that path |
| `{sha256(path)}` | the lowercase hex SHA-256 of what `{path}` would render |

A string renders as itself, any other value as its RFC 8785 (JCS) JSON;
everything else in the template is literal text. A placeholder whose
argument is absent from the call refuses it as `argument_missing`. Every placeholder must name a declared
argument (or a `task.` path); this is checked at load. The operation id is
`op-` followed by the first 32 hex digits of HMAC-SHA256 under the
operations database's own random key, over the release name, the tool and
the rendered key. The model never supplies it, and the same rendered key
under the same release is the same operation even after a redeploy. Two
calls that render the same key but carry different arguments are refused as
`operation_conflict`.

Without a template, the operation id is derived from the task id and the
call's fingerprint, so the same call in the same task is the same operation.

## `approval`

```yaml
approval:
  when: "amount > 100 && currency == 'EUR'"
  approvers: ["slack:#support-leads", "pagerduty:refunds"]
  ttl: 15m
  show: [amount]
```

| Key | Meaning |
|---|---|
| `when` | Approval is needed only when this holds. Without `when`, every call needs approval. |
| `approvers` | Free-form routing strings. The gate does not contact anyone; it puts them in the `approval_required` refusal with the call `fingerprint`, so your approval flow knows where to send the request. |
| `ttl` | The longest validity a receipt may have (`notAfter - approvedAt`): `30s`, `15m`, `1h30m`, `1d`. A receipt valid for longer is `approval_invalid`. |
| `show` | Top-level arguments (declared under `args`) whose values an approval broker may see in a request, so the approver can decide: `[amount, ticket_id]`. Scalar values only: an argument declared `type: object` or `type: array` is refused, and an object or array value of an untyped argument is left out. Default: none, and no other value is ever sent. Keep it short: see [APPROVALS.md](APPROVALS.md#what-the-broker-sees). |

The `when` language is deliberately small. Comparisons `path OP literal`,
with `OP` one of `>`, `>=`, `<`, `<=`, `==`, `!=` and a literal that is a
number, a quoted string (`'EUR'` or `"EUR"`), `true` or `false`; joined with
`&&` and `||`, grouped with parentheses. Paths are declared arguments. It is
parsed at load, so a typo stops the gate at start-up. A comparison that
meets a missing value or a value of another type **holds**, so a malformed
call needs approval instead of slipping past it.

A Cedar permit annotated `@approval("<route>")` can also require approval
([POLICY.md](POLICY.md#approval)); either one is enough, and their routes
are merged.

Receipts are signed with `cloakpipe approve` and checked against the keys
given with `--approver-key`. How receipts are bound to one exact call, and
what makes one invalid or expired:
[ACTION_BOUNDARY.md](ACTION_BOUNDARY.md#approval-receipts). Approver keys:
[KEYS.md](KEYS.md#approver-keys). To have a broker route the request to a
human and fetch the receipt back (`mcp-proxy --approvals-url`), see
[APPROVALS.md](APPROVALS.md).

## Digests

- The **manifest digest** is `sha256:` over the RFC 8785 (JCS) form of the
  parsed document. Comments, formatting and key order do not change it; any
  rule does. Every ledger entry records it (`release`, `policy_version`),
  and approval receipts are bound to it.
- The **policy digest** is the SHA-256 of the policy file's bytes, recorded
  as `policy_digest` in every ledger entry.

## Errors at a glance

| Reason | Stage | Meaning |
|---|---|---|
| `undeclared_tool` | contract | The tool is not in `tools`. |
| `undeclared_argument` | contract | An argument is not listed under the tool's `args`. |
| `argument_missing` | contract | A `required: true` argument is absent. |
| `argument_invalid` | contract | A value breaks its constraint (`path` says which). |
| `scope_mismatch` | contract | A `one_of_context` value is not one the task allows. |
| `task_context_missing` | contract | A path the call needs is not in the task context (or there is no `taskId` where one is needed). |
| `policy_denied` | Cedar | See [POLICY.md](POLICY.md). |
| `approval_required`, `approval_invalid`, `approval_expired` | approval | No receipt; a receipt that fails a check; a receipt past `notAfter`. |
| `approval_denied` | approval | An approver denied this exact call through an approval broker, and the denial still holds ([APPROVALS.md](APPROVALS.md#denied-and-expired)). |
| `operation_conflict`, `reconcile_before_retry` | operations | See [ACTION_BOUNDARY.md](ACTION_BOUNDARY.md#states). |
| `fail_closed` | any | Something could not be evaluated or recorded; the call is refused. |

## The legacy format

The two-file AgentRelease + ToolContract format of 0.11
([docs/legacy/AGENT_RELEASE.md](legacy/AGENT_RELEASE.md)) is still accepted
for one release: a manifest with a top-level `apiVersion` is read as legacy,
with a deprecation warning on stderr, and takes its contracts from
`--tool-contract`. Passing `--tool-contract` with a v1 manifest is an
error.
