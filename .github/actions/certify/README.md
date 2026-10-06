# CloakPipe certify action

Certifies an Agent Release against a CloakPipe `CertificationPolicy`, using
evaluation runs as evidence, and signs the decision as a DSSE-wrapped in-toto
attestation. The decision is deterministic and the attestation verifies
offline (`cloakpipe release verify-cert`). See
[docs/CERTIFICATION.md](../../../docs/CERTIFICATION.md).

The action installs the CLI (`cargo install --git … cloakpipe-cli --locked`),
runs `cloakpipe release certify`, writes a job summary, and sets outputs. It
uploads nothing; upload the envelope yourself if you want to keep it.

## One-time setup

```sh
cloakpipe release keygen --out certify-key.json   # mode 0600; prints keyid + publicKey
gh secret set CLOAKPIPE_CERT_KEY < certify-key.json
```

Publish the printed `keyid` and `publicKey` to whoever verifies your
certifications; keep `certify-key.json` out of the repository.

## Usage

```yaml
jobs:
  certify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      # … run your evaluation suites, producing JUnit XML …

      - name: Import evaluation results
        run: |
          cloakpipe eval import --junit reports/support-critical.xml \
            --release release.yaml --suite support-critical@23 \
            --covers privacy,functional --critical 'privacy::*' \
            --tool pytest --out runs/support-critical.json

      - id: cert
        uses: rohansx/cloakpipe/.github/actions/certify@main
        with:
          manifest: release.yaml
          policy: certification-policy.yaml
          runs: |
            runs/support-critical.json
          baseline-manifest: releases/previous.yaml   # optional: required suites from the diff
          baseline-runs: |
            runs/previous/support-critical.json
          require: privacy
          environment: production
          signing-key: ${{ secrets.CLOAKPIPE_CERT_KEY }}

      - uses: actions/upload-artifact@v4
        if: always() && steps.cert.outputs.envelope != ''
        with:
          name: certification
          path: ${{ steps.cert.outputs.envelope }}
```

The `eval import` step needs the CLI on `PATH` before the action runs; either
install it in an earlier step or run the action first with `runs` produced by
your own tooling.

## Inputs

| Input | Required | Description |
|---|---|---|
| `manifest` | yes | Candidate release manifest; must be certifiable. |
| `policy` | yes | `CertificationPolicy` (YAML or JSON). |
| `runs` | yes | Newline-separated `EvaluationRun` JSON paths. |
| `baseline-manifest` | no | Baseline release; `diff(baseline, candidate)` sets the required suites. |
| `baseline-runs` | no | Newline-separated baseline `EvaluationRun` JSON paths. |
| `require` | no | Extra required assurance suites, comma-separated. |
| `environment` | yes | Certification scope, e.g. `production`. |
| `issuer` | no | Defaults to `github:<owner/repo>/<workflow>@<ref>`. |
| `signing-key` | no | Key file contents from `keygen` (a secret). Empty: decide without signing. |
| `out` | no | Envelope path; default `<manifest stem>.cert.dsse.json`. |
| `fail-on-blocked` | no | Fail the step on BLOCKED (default `true`). |
| `install` | no | `false` to use a `cloakpipe` already on `PATH` (default `true`). |
| `cloakpipe-ref` | no | Branch, tag or commit to install from (default `main`). |

## Outputs

| Output | Description |
|---|---|
| `outcome` | `certified` or `blocked`. |
| `envelope` | Path of the signed envelope (empty when unsigned). |
| `decision` | Path of the `{decision, envelope?}` JSON. |

The signing key is written to a `0600` file under `$RUNNER_TEMP`, removed when
the step ends, and never printed.
