#!/usr/bin/env bash
# Build RFC 3161 tokens from a throwaway local PKI, for path-validation
# tests that no public TSA can exercise (a non-CA trust anchor, an unknown
# critical extension on the root, an intermediate restricted to another
# extended key usage). One control chain is valid, so each negative case
# differs from it in exactly one property.
#
#   OPENSSL=/path/to/openssl3 tools/make_local_tsa_fixtures.sh [OUT_DIR]
#
# Every token stamps head-honest.json with a fresh nonce; the keys are
# discarded. Output: <case>-root.pem, <case>.tsr, <case>.nonce.
set -euo pipefail

FIX=crates/cloakpipe-verify/tests/fixtures/anchoring
OUT=${1:-$FIX/local}
OPENSSL=${OPENSSL:-openssl}
"$OPENSSL" version | grep -q '^OpenSSL 3' || { echo "need OpenSSL 3 (set OPENSSL=)"; exit 1; }
mkdir -p "$OUT"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

key() { "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/$1.key" 2>/dev/null; }

# self_signed name subject extensions...
self_signed() {
  local name=$1 subj=$2; shift 2
  key "$name"
  local args=()
  for e in "$@"; do args+=(-addext "$e"); done
  "$OPENSSL" req -new -x509 -key "$work/$name.key" -subj "$subj" -days 36500 -sha256 \
    -set_serial 0x$("$OPENSSL" rand -hex 8) "${args[@]}" -out "$work/$name.pem" 2>/dev/null
}

# issue name subject issuer extfile-body
issue() {
  local name=$1 subj=$2 issuer=$3 ext=$4
  key "$name"
  "$OPENSSL" req -new -key "$work/$name.key" -subj "$subj" -out "$work/$name.csr" 2>/dev/null
  printf '%b\n' "$ext" > "$work/$name.ext"
  "$OPENSSL" x509 -req -in "$work/$name.csr" -CA "$work/$issuer.pem" -CAkey "$work/$issuer.key" \
    -set_serial 0x$("$OPENSSL" rand -hex 8) -days 36500 -sha256 -extfile "$work/$name.ext" \
    -out "$work/$name.pem" 2>/dev/null
}

TSA_EXT='basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping'

# stamp case signer chain-file
stamp() {
  local name=$1 signer=$2 chain=$3
  cat > "$work/$name.cnf" <<CNF
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial = $work/$name.serial
signer_digest = sha256
default_policy = 1.3.6.1.4.1.4146.2.3
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
CNF
  echo 01 > "$work/$name.serial"
  "$OPENSSL" ts -query -data "$FIX/head-honest.json" -sha256 -cert -out "$work/$name.tsq" 2>/dev/null
  "$OPENSSL" ts -query -in "$work/$name.tsq" -text 2>/dev/null \
    | sed -n 's/^Nonce: 0x//p' | tr 'A-F' 'a-f' | tr -d '\n' > "$OUT/$name.nonce"
  "$OPENSSL" ts -reply -config "$work/$name.cnf" -queryfile "$work/$name.tsq" \
    -signer "$work/$signer.pem" -inkey "$work/$signer.key" -chain "$chain" -out "$OUT/$name.tsr" 2>/dev/null
}

CA_EXT=(basicConstraints=critical,CA:TRUE keyUsage=critical,keyCertSign,cRLSign)

# Control: CA root -> TSA.
self_signed ca-root "/CN=Local Test Root CA" "${CA_EXT[@]}"
issue ca-tsa "/CN=Local Test TSA" ca-root "$TSA_EXT"
: > "$work/empty.pem"
stamp ca ca-tsa "$work/empty.pem"
cp "$work/ca-root.pem" "$OUT/ca-root.pem"

# The trust anchor is not a CA.
self_signed nonca-root "/CN=Local Test Not A CA" basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature
issue nonca-tsa "/CN=Local Test TSA" nonca-root "$TSA_EXT"
stamp nonca nonca-tsa "$work/empty.pem"
cp "$work/nonca-root.pem" "$OUT/nonca-root.pem"

# The trust anchor carries an unknown critical extension.
self_signed critroot-root "/CN=Local Test Root Critical" "${CA_EXT[@]}" 1.3.6.1.4.1.55555.1=critical,DER:0500
issue critroot-tsa "/CN=Local Test TSA" critroot-root "$TSA_EXT"
stamp critroot critroot-tsa "$work/empty.pem"
cp "$work/critroot-root.pem" "$OUT/critroot-root.pem"

# An intermediate restricted to code signing issues the TSA.
self_signed ekuint-root "/CN=Local Test Root EKU" "${CA_EXT[@]}"
issue ekuint-int "/CN=Local Test CodeSigning CA" ekuint-root \
  'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\nextendedKeyUsage=codeSigning'
issue ekuint-tsa "/CN=Local Test TSA" ekuint-int "$TSA_EXT"
stamp ekuint ekuint-tsa "$work/ekuint-int.pem"
cp "$work/ekuint-root.pem" "$OUT/ekuint-root.pem"

# Control for the intermediate: the same shape, restricted to timeStamping.
self_signed tsint-root "/CN=Local Test Root TS" "${CA_EXT[@]}"
issue tsint-int "/CN=Local Test TimeStamping CA" tsint-root \
  'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\nextendedKeyUsage=timeStamping'
issue tsint-tsa "/CN=Local Test TSA" tsint-int "$TSA_EXT"
stamp tsint tsint-tsa "$work/tsint-int.pem"
cp "$work/tsint-root.pem" "$OUT/tsint-root.pem"

ls "$OUT"
