#!/usr/bin/env bash
# Re-record the external-anchoring fixtures from the live services.
#
# Uses only OpenSSL 3 and curl, independent of CloakPipe's own clients, so the
# recordings double as an interop check: requests built by OpenSSL, responses
# verified by cloakpipe-verify.
#
#   tools/capture_anchor_fixtures.sh [OUT_DIR]
#
# Inputs are the batch heads written by
#   cargo test -p cloakpipe-verify --test anchoring_fixtures -- --ignored write_heads
# Each recorded Rekor entry is public and permanent; it contains only hashes,
# a signature and the test operator's public key.
set -euo pipefail

OUT=${1:-crates/cloakpipe-verify/tests/fixtures/anchoring}
OPENSSL=${OPENSSL:-openssl}
FREETSA=${FREETSA:-https://freetsa.org/tsr}
DIGICERT=${DIGICERT:-http://timestamp.digicert.com}
REKOR=${REKOR:-https://rekor.sigstore.dev}

"$OPENSSL" version | grep -q '^OpenSSL 3' || { echo "need OpenSSL 3 (set OPENSSL=)"; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Test operator key: Ed25519 seed 0x42 * 32 (common::OPERATOR_SEED).
printf '302e020100300506032b657004220420%s' "$(printf '42%.0s' {1..32})" | xxd -r -p > "$work/op.der"
"$OPENSSL" pkey -inform DER -in "$work/op.der" -out "$work/op.pem"
"$OPENSSL" pkey -in "$work/op.pem" -pubout -out "$work/op.pub.pem"

tsa() { # name url head
  local name=$1 url=$2 head=$3
  "$OPENSSL" ts -query -data "$head" -sha256 -cert -out "$work/$name.tsq" 2>/dev/null
  "$OPENSSL" ts -query -in "$work/$name.tsq" -text 2>/dev/null \
    | sed -n 's/^Nonce: 0x//p' | tr 'A-F' 'a-f' | tr -d '\n' > "$OUT/$name.nonce"
  curl -sS --fail -m 60 -H 'Content-Type: application/timestamp-query' \
    --data-binary @"$work/$name.tsq" "$url" -o "$OUT/$name.tsr"
  "$OPENSSL" ts -reply -in "$OUT/$name.tsr" -text 2>/dev/null | grep -E 'Status:|Time stamp:'
}

rekor() { # name head
  local name=$1 head=$2 sig hash pk
  "$OPENSSL" pkeyutl -sign -inkey "$work/op.pem" -rawin -in "$head" \
    -pkeyopt instance:Ed25519ph -out "$work/$name.sig"
  sig=$(base64 < "$work/$name.sig" | tr -d '\n')
  hash=$("$OPENSSL" dgst -sha512 -r "$head" | cut -d' ' -f1)
  pk=$(base64 < "$work/op.pub.pem" | tr -d '\n')
  printf '{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha512","value":"%s"}},"signature":{"content":"%s","publicKey":{"content":"%s"}}}}' \
    "$hash" "$sig" "$pk" > "$work/$name.req.json"
  curl -sS --fail -m 60 -X POST -H 'Content-Type: application/json' \
    --data @"$work/$name.req.json" "$REKOR/api/v1/log/entries" -o "$OUT/$name.json"
  echo "$name: $(head -c 120 "$OUT/$name.json")"
}

tsa freetsa-honest "$FREETSA" "$OUT/head-honest.json"
tsa freetsa-future "$FREETSA" "$OUT/head-future.json"
tsa digicert-honest "$DIGICERT" "$OUT/head-honest.json"
rekor rekor-honest "$OUT/head-honest.json"
rekor rekor-future "$OUT/head-future.json"

# Trust inputs.
curl -sS --fail -m 60 https://freetsa.org/files/cacert.pem -o "$OUT/freetsa-root.pem"
curl -sS --fail -m 60 https://cacerts.digicert.com/DigiCertTrustedRootG4.crt -o "$work/g4.der"
"$OPENSSL" x509 -inform DER -in "$work/g4.der" -out "$OUT/digicert-trusted-root-g4.pem"
curl -sS --fail -m 60 "$REKOR/api/v1/log/publicKey" -o "$OUT/rekor.pub"
cp "$work/op.pub.pem" "$OUT/operator.pub.pem"
for p in freetsa-root.pem digicert-trusted-root-g4.pem; do
  "$OPENSSL" x509 -in "$OUT/$p" -noout -subject -fingerprint -sha256
done
