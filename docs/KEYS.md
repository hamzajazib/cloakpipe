# Keys

Every key CloakPipe uses, where it lives, who needs which part, and how to
rotate it. Today all keys are files on the gate's machine; keys held in a
KMS or an HSM are on the [roadmap](#kms-and-hsm).

| Key | Kind | Default location | Used for | Who gets the public part |
|---|---|---|---|---|
| [Gate signing key](#the-gate-signing-key) | Ed25519 | `$CLOAKPIPE_HOME/gate.key` | Signing every decision entry, epoch head, Rekor entry and audit pack; keying argument fingerprints | Auditors |
| [Approver keys](#approver-keys) | Ed25519 | wherever approvers keep them | Signing approval receipts | The gate (`--approver-key`) |
| [Anchoring roots](#anchoring-roots) | X.509 roots, a Rekor public key | built into the binaries | Checking RFC 3161 tokens and Rekor entries | (they are public) |
| [Operations key](#local-secrets) | 32 random bytes | inside the operations database | Deriving operation ids | Nobody |
| [Vault key](#local-secrets) | AES-256 | `CLOAKPIPE_VAULT_KEY` | `--transform pii` only | Nobody |

All Ed25519 key files use one JSON format, made by `cloakpipe release
keygen`: `{"keyid", "publicKey", "privateKey"}` in hex, where `keyid` is
`ed25519:` and the first 16 hex digits of the SHA-256 of the public key.
`keygen --out <file>` writes the pair with mode `0600`, never overwrites a
file, and prints only the public part, which is itself a valid key file for
anything that only verifies.

## The gate signing key

`cloakpipe mcp-proxy` finds its key in this order:

1. `--signing-key <file>`
2. `CLOAKPIPE_SIGNING_KEY=<file>`
3. `$CLOAKPIPE_HOME/gate.key` (`CLOAKPIPE_HOME` defaults to `~/.cloakpipe`),
   created on first use with mode `0600`. The gate then prints the public
   key once on stderr.

It signs:

- each decision entry (Ed25519 over the 32-byte `entry_hash`; the entry's
  `signer` is the keyid);
- each anchoring epoch head, and the Rekor `hashedrekord` entry for it
  (Ed25519ph);
- the `pack.json` of an audit pack (`cloakpipe ledger export`).

It also keys the argument fingerprints in the ledger: `args_fingerprint`
is HMAC-SHA256 under a key derived from the private key, so only its holder
can test whether an entry is about a given call.

Give auditors the public part, through a channel they trust (not inside
the pack they are checking):

<!-- check-docs: run keys cwd=examples/support-agent -->
```bash
cd examples/support-agent
export CLOAKPIPE_HOME=$(mktemp -d)
cloakpipe release keygen --out gate-2026-10.key > gate-2026-10.pub.json
call='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"export_customers","arguments":{}}}'
echo "$call" | cloakpipe mcp-proxy --upstream "python3 mock_upstream.py" --manifest cloakpipe.manifest.yaml \
  --operations-db "$CLOAKPIPE_HOME/operations.db" --signing-key gate-2026-10.key > /dev/null
cloakpipe ledger public-key --signing-key gate-2026-10.key
```

<!-- check-docs: expect keys -->
```text
"keyid": "ed25519:…",
"publicKey": "…"
```

`cloakpipe verify audit-pack.tar --key <file or hex>` pins it. Without
`--key`, the verifier uses the key the pack itself carries and says
`not pinned`: that only shows the pack is consistent with itself, not that
your gate wrote it.

### Rotation

A rotation is a restart with another key. The chain continues, because
`prev_hash` links entries whatever signed them, and each entry names its
signer. Auditors pin every key the period used:

<!-- check-docs: run keys -->
```bash
cloakpipe release keygen --out gate-2026-11.key > gate-2026-11.pub.json
echo "$call" | cloakpipe mcp-proxy --upstream "python3 mock_upstream.py" --manifest cloakpipe.manifest.yaml \
  --operations-db "$CLOAKPIPE_HOME/operations.db" --signing-key gate-2026-11.key > /dev/null
cloakpipe ledger export --out audit-pack.tar --signing-key gate-2026-11.key
cloakpipe verify audit-pack.tar --key gate-2026-10.pub.json --key gate-2026-11.pub.json
```

<!-- check-docs: expect keys -->
```text
pack: 4 files, signed by ed25519:… (pinned), OK
entries: 2 (seq 0..1), chain OK, signatures OK
result: OK
```

With only the new key pinned, the old entries fail (`signer ... is not a
trusted gate key`), as they should.

- Rotate on a schedule (for example, monthly) and whenever someone who could
  read the key file leaves. Publish each public key with the dates it was in
  use.
- The argument-fingerprint key changes with the gate key, so the same call
  before and after a rotation has different `args_fingerprint` values.
- Keep old private keys only as long as you need to answer "was this entry
  about that call?"; verification needs only the public parts.

### If the gate key leaks

Whoever holds it can sign entries, epochs and packs that verify. They
cannot change anything already anchored: an epoch's head is timestamped by
the TSA and logged in Rekor, so a rewritten history no longer matches its
anchors. Entries after the last anchored epoch have no such protection.
So:

1. Stop the gate, rotate to a new key, and restart.
2. Tell auditors the leaked key's keyid and the time of the leak. Entries
   signed by it after that time are suspect.
3. Run with anchoring (`--anchor-every`, `--anchor-interval`) so that the
   unprotected tail is short.

## Approver keys

Approvers sign receipts with their own Ed25519 keys; the gate needs only
the public parts:

<!-- check-docs: run keys -->
```bash
cloakpipe release keygen --out approver-dana.json > approver-dana.pub.json
echo '{"ticket_id":"T-1042","amount":350}' > refund.json
cloakpipe approve --manifest cloakpipe.manifest.yaml --tool issue_refund --args refund.json \
  --task-context task-context.json --key approver-dana.json --expires 15m --out approvals
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_refund","arguments":{"ticket_id":"T-1042","amount":350}}}' \
| cloakpipe mcp-proxy --upstream "python3 mock_upstream.py" --manifest cloakpipe.manifest.yaml \
    --task-context task-context.json --operations-db "$CLOAKPIPE_HOME/operations.db" \
    --approvals approvals --approver-key approver-dana.pub.json
```

<!-- check-docs: expect keys -->
```text
upstream received: issue_refund {"amount": 350, "ticket_id": "T-1042"}
```

- One key per person (or per approving system), so a receipt says who
  approved. `--approver-key` is repeatable.
- To revoke an approver, remove their key from `--approver-key` and restart
  the gate. Receipts they already signed stop verifying at once; there is no
  revocation list.
- Receipts are short-lived by design (`--expires`, capped by the manifest's
  `approval.ttl`), which limits what a stolen approver key can do to calls
  the contract and policy already allow, until it is removed.

## Anchoring roots

Anchors are checked against trust inputs that are never read from the
evidence itself:

| Input | Default | Override |
|---|---|---|
| RFC 3161 TSA roots | the freetsa.org and DigiCert roots built into `cloakpipe-verify` (`crates/cloakpipe-verify/trust/`) | `--tsa-root <pem>` on `mcp-proxy` and on `verify` |
| Rekor public key | rekor.sigstore.dev's key, built in | `--rekor-key <pem>` on `mcp-proxy` and on `verify` |

Auditors should compare the fingerprints of these roots with the ones the
services publish, out of band, rather than trust the copy in a binary the
operator gave them. A private TSA or Rekor instance works the same way: pass
its root or key to both the gate and the verifier. The roots change rarely;
when a service rotates its key, verify old epochs with the old root and new
ones with the new root (`--tsa-root` takes several roots in one PEM file).

## Local secrets

- The **operations key** lives in the operations database
  (`operation_id_key`), 32 bytes from the OS CSPRNG, created with the
  database. It makes operation ids unguessable from the ledger. Protect the
  database like a credential (mode `0600`, not on shared storage): it also
  holds the stored results of side-effecting calls.
- The **vault key** (`CLOAKPIPE_VAULT_KEY`, 64 hex characters) encrypts the
  pseudonym vault of `--transform pii` and the PII proxy. Without it an
  ephemeral key is used and mappings do not survive a restart.

## KMS and HSM

Not yet. Every private key above is a file the gate process reads. Planned:
gate and approver keys held in a cloud KMS or a PKCS#11 HSM, so the gate
can sign without ever holding the key bytes, and so a host compromise
cannot copy the key. Until then, run the gate as a dedicated user, keep
`CLOAKPIPE_HOME` on a local disk readable only by that user, and rotate as
described above.
