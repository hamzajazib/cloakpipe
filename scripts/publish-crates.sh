#!/usr/bin/env bash
# Publishes every publishable workspace crate whose version is not on
# crates.io yet, so a partly published release can be re-run. crates.io
# rate-limits new crates (HTTP 429); those runs wait and try again.
set -euo pipefail

api="${CRATES_IO_API:-https://crates.io/api/v1}"
attempts="${PUBLISH_ATTEMPTS:-8}"
retry_secs="${PUBLISH_RETRY_SECS:-600}"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

for attempt in $(seq 1 "$attempts"); do
  excludes=()
  pending=0
  while read -r name version; do
    code=$(curl -s -o /dev/null -w '%{http_code}' \
      -A 'cloakpipe-release (https://github.com/rohansx/cloakpipe)' \
      "$api/crates/$name/$version")
    if [ "$code" = 200 ]; then
      echo "$name $version is already on crates.io"
      excludes+=(--exclude "$name")
    else
      pending=1
    fi
  done < <(cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p["publish"] != []:
        print(p["name"], p["version"])')

  if [ "$pending" = 0 ]; then
    echo "Every crate is on crates.io."
    exit 0
  fi
  if cargo publish --workspace --locked ${excludes[@]+"${excludes[@]}"} 2> >(tee "$log" >&2); then
    exit 0
  fi
  sleep 1 # let the tee above finish writing
  if ! grep -q '429' "$log"; then
    exit 1
  fi
  echo "crates.io rate limit (attempt $attempt/$attempts); retrying in ${retry_secs}s."
  sleep "$retry_secs"
done
echo "::error::crates.io kept rate-limiting after $attempts attempts; re-run the release workflow for this tag."
exit 1
