#!/usr/bin/env bash
# Dependency boundaries, checked with default features and normal (non-dev,
# non-build) edges only: `cargo tree -p <crate> -e normal`.
#
# 1. The gate's runtime dependency tree must not contain the certification
#    pipeline. cloakpipe-mcp (the gate itself) verifies certifications only
#    when built with its legacy `certification` feature, off by default.
# 2. The default `cloakpipe` binary is the lean gate: no ONNX Runtime or
#    tokenizers (`ner` feature), no RAG crates (`rag`) and no certification
#    (`certification`). `--features full` turns them all on.
set -euo pipefail

status=0

# check <crate> <forbidden crate>...
check() {
  local crate=$1
  shift
  # A failing `cargo tree` (unknown crate, resolve error) fails the check.
  local tree
  tree=$(cargo tree -q -p "$crate" -e normal --prefix none)
  for forbidden in "$@"; do
    if grep -q "^${forbidden} " <<<"$tree"; then
      echo "FAIL: $crate depends on $forbidden:"
      cargo tree -q -p "$crate" -e normal -i "$forbidden" || true
      status=1
    else
      echo "ok: $crate has no $forbidden in its normal dependency tree"
    fi
  done
}

for crate in cloakpipe-mcp cloakpipe-receipt cloakpipe-verify cloakpipe-anchor cloakpipe-ledger; do
  check "$crate" cloakpipe-cert
done

lean=(ort ort-sys tokenizers ureq cloakpipe-cert cloakpipe-tree cloakpipe-vector)
for crate in cloakpipe-cli cloakpipe-proxy; do
  check "$crate" "${lean[@]}"
done

exit "$status"
