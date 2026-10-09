#!/usr/bin/env bash
# Fetch one Langfuse experiment and every page of its items (with scores)
# into the two files `cloakpipe eval import --langfuse-experiment FILE
# --langfuse-experiment-items FILE` reads.
#
# Usage:
#   LANGFUSE_HOST=https://cloud.langfuse.com \
#   LANGFUSE_PUBLIC_KEY=pk-lf-... LANGFUSE_SECRET_KEY=sk-lf-... \
#   tools/fetch_langfuse_experiment.sh EXPERIMENT_ID FROM_START_TIME [TO_START_TIME] [OUT_DIR]
#
#   FROM_START_TIME / TO_START_TIME: ISO 8601 (e.g. 2026-10-05T00:00:00Z);
#   FROM must be at or before the experiment's first item. TO defaults to
#   now, fixed once so both requests see the same window: the importer
#   checks the item count against the experiment's itemCount.
#
# Writes OUT_DIR/lf-experiment.json (GET /api/public/experiments?id=...) and
# OUT_DIR/lf-experiment-items.json (an array of every
# GET /api/public/experiment-items page, in fetch order). OUT_DIR defaults
# to the current directory. Requires curl and jq.
#
# Find an experiment id by name:
#   curl -sSfG -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" "$LANGFUSE_HOST/api/public/experiments" \
#     --data-urlencode "fromStartTime=2026-10-01T00:00:00Z" --data-urlencode "name=my-run" | jq '.data[] | {id, name}'
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
  exit 2
fi
: "${LANGFUSE_HOST:?set LANGFUSE_HOST, e.g. https://cloud.langfuse.com}"
: "${LANGFUSE_PUBLIC_KEY:?set LANGFUSE_PUBLIC_KEY}"
: "${LANGFUSE_SECRET_KEY:?set LANGFUSE_SECRET_KEY}"

experiment_id=$1
from=$2
to=${3:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
out=${4:-.}
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

lf() { # PATH [curl -G args...]
  local path=$1
  shift
  # Credentials go through a config on a pipe, not argv (visible in ps).
  curl -sSfG --retry 3 -K <(printf 'user = "%s:%s"\n' "$LANGFUSE_PUBLIC_KEY" "$LANGFUSE_SECRET_KEY") \
    "${LANGFUSE_HOST%/}$path" "$@"
}

lf /api/public/experiments \
  --data-urlencode "id=$experiment_id" \
  --data-urlencode "fromStartTime=$from" \
  --data-urlencode "toStartTime=$to" > "$out/lf-experiment.json"

# Items: 100 per page (the maximum), all of each item's scores up to the
# maximum scoreLimit of 50 (an item with 50 is rejected as possibly cut off).
n=0
cursor=
seen=" "
max_pages=$(($(jq '.data[0].itemCount // 0' "$out/lf-experiment.json") / 100 + 2))
while :; do
  args=(
    --data-urlencode "experimentId=$experiment_id"
    --data-urlencode "fromStartTime=$from"
    --data-urlencode "toStartTime=$to"
    --data-urlencode "fields=core,dataset,scores"
    --data-urlencode "limit=100"
    --data-urlencode "scoreLimit=50"
  )
  [ -n "$cursor" ] && args+=(--data-urlencode "cursor=$cursor")
  n=$((n + 1))
  page=$(printf '%s/page-%06d.json' "$tmp" "$n")
  lf /api/public/experiment-items "${args[@]}" > "$page"
  next=$(jq -r '.meta.cursor // empty' "$page")
  [ -z "$next" ] && break
  case "$seen" in *" $next "*)
    echo "error: page $n returns a cursor already seen" >&2
    exit 1
  esac
  if [ "$n" -ge "$max_pages" ]; then
    echo "error: more than $max_pages pages for the experiment's itemCount; is it still running?" >&2
    exit 1
  fi
  seen="$seen$next "
  cursor=$next
done
jq -s . "$tmp"/page-*.json > "$out/lf-experiment-items.json"

echo "experiment: $(jq -c '.data[0] | {id, name, itemCount, datasetId}' "$out/lf-experiment.json")" >&2
echo "items: $(jq '[.[].data | length] | add' "$out/lf-experiment-items.json") in $n page(s)" >&2
