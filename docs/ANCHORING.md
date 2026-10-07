# External anchoring

An evidence bundle proves its records were not edited *after it was
signed*. Anchoring proves *when* it was signed, with evidence from someone
other than the operator, so history cannot be rewritten or back-dated
undetectably.

CloakPipe anchors a **batch head** (a signed Merkle root over the bundle's
records) at two independent services:

| Anchor | What it proves | Default endpoint | Trust input for verification |
|---|---|---|---|
| RFC 3161 timestamp | A TSA signed the head's SHA-256 at `genTime` | `https://freetsa.org/tsr` | the TSA's root certificate (`--tsa-root`) |
| Sigstore Rekor (v1 API) | A public append-only log integrated the head at `integratedTime`, at a position covered by a signed tree head | `https://rekor.sigstore.dev` | the log's public key (`--rekor-key`) |

Receipts carry the complete raw evidence (the DER `TimeStampResp`, the Rekor
entry verbatim), so verification is entirely offline and never trusts the
bundle to say who the TSA or log is.

The older in-process receipt kinds (`tsa`, `log`: an Ed25519 stand-in TSA
and log whose public keys travel in the bundle) still verify as before. They
prove nothing about time to an outside party and should be treated as test
fixtures.

## Producing an anchored bundle

```bash
# 1. Export a bundle (any exporter; for a demo, the fixture exporter writes
#    the operator key too).
cargo run -p cloakpipe-ledger --bin ledger-export-fixture -- bundle.json --key-out key.json

# 2. Trust inputs. Verify fingerprints out of band.
curl -sS https://freetsa.org/files/cacert.pem -o freetsa-root.pem
curl -sS https://rekor.sigstore.dev/api/v1/log/publicKey -o rekor.pub

# 3. Seal and anchor.
cloakpipe anchor bundle.json --key key.json \
  --tsa-root freetsa-root.pem --rekor-key rekor.pub --out anchored.json
```

`cloakpipe anchor`:

1. checks `--key` is the key that signed the bundle's manifest;
2. builds one batch head over all records (Merkle root of the record hashes,
   `signed_time` = now, signed by the operator key) and a Merkle inclusion
   proof per record;
3. sends `SHA-256(head JSON)` to the TSA in a DER `TimeStampReq` with a fresh
   128-bit nonce and `certReq = TRUE`;
4. submits a `hashedrekord` entry to Rekor: the artifact is the head JSON,
   hashed SHA-512 and signed **Ed25519ph** by the operator key (Rekor only
   accepts Ed25519 over a SHA-512 prehash), with the key as PKIX PEM. A 409
   (entry exists) is resolved by fetching the existing entry;
5. verifies both answers offline (below) and refuses to continue otherwise;
6. attaches the receipts, re-signs the manifest (refs
   `rfc3161:<batch>:<nonce>`, `rekor:<batch>:<uuid>`), re-verifies the whole
   bundle as an auditor would, and only then writes `--out`.

Options: `--tsa-url` (DigiCert: `http://timestamp.digicert.com` with root
*DigiCert Trusted Root G4*), `--rekor-url`, `--no-tsa`, `--no-rekor`,
`--batch-id`, `--timeout-secs`. Each enabled anchor requires its trust input.
Exit codes: 0 anchored, 1 refused / anchor failed (nothing written), 2 usage
or I/O.

Each Rekor submission is **public and permanent**. It contains a hash of the
head, a signature and the operator's public key; no record content.

## Verifying

```bash
cloakpipe-verify anchors anchored.json --tsa-root freetsa-root.pem --rekor-key rekor.pub
cloakpipe-verify all     anchored.json --tsa-root freetsa-root.pem --rekor-key rekor.pub [--trust-key ID=HEX]
```

Fail-closed rules:

- A bundle carrying `rfc3161` (`rekor`) receipts **fails** without
  `--tsa-root` (`--rekor-key`). Missing trust is never a skip.
- Supplying a trust input means "this bundle must be anchored there": every
  batch head needs a verified receipt of that kind, every record must lie in
  a batch head with a valid inclusion proof. An unanchored bundle fails.
- **Back-dating**: no record `ts` and no head `signed_time` may be later than
  the anchored time (`genTime` / `integratedTime`, compared in whole
  seconds). A record claimed after its anchor was written after the fact.
- A receipt whose subject is not the SHA-256 of the head as it appears in the
  bundle fails (a changed head is not covered by its anchor).

### RFC 3161 checks

1. `PKIStatus` granted (0) or grantedWithMods (1), token present.
2. CMS `SignedData` over `id-ct-TSTInfo`, exactly one `SignerInfo`, signed
   attributes present.
3. `contentType` = `id-ct-TSTInfo`; `messageDigest` = digest of the TSTInfo;
   ESS `signingCertificate` (SHA-1) / `signingCertificateV2` (default
   SHA-256), when present, match the signer certificate: its hash and, when
   `issuerSerial` is given, its serial and its issuer (as a directory name).
4. Signature over the DER signed attributes: RSA PKCS#1 v1.5 (>= 2048 bits)
   or ECDSA P-256 / P-384, with SHA-256/384/512. Anything else (RSA-PSS,
   SHA-1 signatures, other curves) is rejected.
5. TSTInfo version 1, SHA-256 message imprint equal to the head hash, nonce
   equal to the request nonce.
6. Signer certificate: critical extended key usage of exactly
   `id-kp-timeStamping`; key usage (if present) allows signing.
7. Path from the signer, through certificates carried in the token, to a
   `--tsa-root` certificate: every signature checks; every issuer, **the
   `--tsa-root` certificate included**, is a CA (`basicConstraints CA:TRUE`)
   within its path length, may sign certificates (`keyCertSign` if key usage
   is present) and, if it restricts its extended key usage, allows
   `timeStamping` (or any purpose); every certificate (root included) is
   valid **at `genTime`**; and no certificate on the path, root included,
   has a critical extension the verifier does not understand. Pinning a
   non-CA certificate as `--tsa-root` therefore does not make it an issuer.
   The one exception is pinning the TSA's own signer certificate, which is
   trusted directly (it still needs the timeStamping EKU of step 6).
   Certificates in the token are never trusted as roots.

No revocation (CRL/OCSP) checking is done: that needs the network. Pin a
specific root and re-check revocation out of band if you need it.

### Rekor checks

1. `logID` = SHA-256 of the supplied key's DER SubjectPublicKeyInfo.
2. SignedEntryTimestamp: ECDSA P-256 / SHA-256 by the log key over
   `{"body":…,"integratedTime":…,"logID":…,"logIndex":…}` (canonical JSON).
3. Body: `hashedrekord` 0.0.1, `sha512` = SHA-512 of the head JSON, public
   key = the head signer's Ed25519 key from `signer_public_keys`, and a valid
   Ed25519ph signature over the head JSON.
4. Entry UUID ends with the RFC 6962 leaf hash `SHA-256(0x00 || body)`.
5. RFC 6962 inclusion proof from that leaf to `rootHash` at `treeSize`
   (RFC 9162 §2.1.3.2).
6. The checkpoint (signed note) carried with the proof is signed by the log
   key (key hint = first 4 bytes of the log ID) and names the same tree size
   and root.

Consistency between checkpoints (that the log did not fork) is not checked
offline; a monitor or witness does that.

## Wire format

```json
{ "kind": "rfc3161", "batch_id": "…", "subject_hash": "<hex sha256 of head JSON>",
  "tsa_url": "https://freetsa.org/tsr", "nonce": "<hex>", "tsr": "<base64 DER TimeStampResp>" }
{ "kind": "rekor", "batch_id": "…", "subject_hash": "<hex>",
  "rekor_url": "https://rekor.sigstore.dev", "entry_uuid": "<hex>",
  "entry": { "body": "…", "integratedTime": 0, "logID": "…", "logIndex": 0,
             "verification": { "signedEntryTimestamp": "…", "inclusionProof": { … } } } }
```

`tsa_url` / `rekor_url` are informational; verification never fetches them.

## Trust inputs used by the tests

Committed in `crates/cloakpipe-verify/tests/fixtures/anchoring/` (see its
README for SHA-256 fingerprints):

- `freetsa-root.pem` — freetsa.org root CA (RSA-4096; the TSA signs with
  ECDSA P-384 / SHA-512).
- `digicert-trusted-root-g4.pem` — DigiCert Trusted Root G4 (RSA chain via
  an intermediate).
- `rekor.pub` — rekor.sigstore.dev, log ID
  `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d`.

## Tests

- Offline (every CI run): recorded real responses from freetsa.org, DigiCert
  and rekor.sigstore.dev, captured with `tools/capture_anchor_fixtures.sh`
  (OpenSSL 3 + curl, independent of CloakPipe's own clients). They cover
  success, wrong roots/keys, byte flips in the token, certificates, proof,
  checkpoint and body, missing trust inputs, uncovered heads and records, and
  back-dating. The clients are tested against a local server replaying the
  recordings; the Rekor request we build is byte-identical to the body Rekor
  stored for the OpenSSL submission.
- Live (`CLOAKPIPE_LIVE_ANCHOR=1`, the `live-anchor` CI job on pushes):
  `cargo test -p cloakpipe-anchor --test live` anchors fresh heads at all
  three services and checks the served Rekor key still matches the committed
  one; the job then runs `ledger-export-fixture` → `cloakpipe anchor` →
  `cloakpipe-verify all` end to end.

To re-record after changing the deterministic test heads:

```bash
cargo test -p cloakpipe-verify --test anchoring_fixtures -- --ignored write_heads
OPENSSL=/path/to/openssl3 tools/capture_anchor_fixtures.sh
```

## Dependencies

Verification uses the RustCrypto 0.7-generation stack (`der`, `spki`,
`x509-cert` 0.2, `cms` 0.2, `rsa` 0.9, `p256`/`p384` 0.13, `sha1`/`sha2`
0.10), the newest set with stable releases of every crate (`cms` 0.3 and
`rsa` 0.10 are pre-releases). `rsa` 0.9 carries RUSTSEC-2023-0071 (a timing
side channel in *private-key* operations); only public-key verification is
used here.
