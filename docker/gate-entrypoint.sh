#!/bin/sh
# The CloakPipe image's entrypoint. With no command, or `gate`, it runs the
# MCP tool-call gate over HTTP:
#
#   cloakpipe mcp-proxy --listen $CLOAKPIPE_LISTEN --manifest $CLOAKPIPE_MANIFEST \
#     --upstream-url $CLOAKPIPE_UPSTREAM_URL ...
#
# built from these variables (unset ones add nothing):
#
#   CLOAKPIPE_UPSTREAM_URL        the upstream MCP server over HTTP, or
#   CLOAKPIPE_UPSTREAM            a stdio command run inside the container
#                                 (one of the two is required)
#   CLOAKPIPE_UPSTREAM_HEADER     one 'Name: value' header for the upstream
#                                 (a value env:VAR is read from VAR)
#   CLOAKPIPE_MANIFEST            default /app/cloakpipe.manifest.yaml (mount it)
#   CLOAKPIPE_LISTEN              default 0.0.0.0:8900
#   CLOAKPIPE_LISTEN_TOKEN_FILE   bearer token file; required unless the
#                                 listener is loopback or
#                                 CLOAKPIPE_INSECURE_NO_TOKEN=1
#   CLOAKPIPE_TOOLS_LOCK          a tools lock (stdio upstream only)
#   CLOAKPIPE_WEBHOOK_URL, CLOAKPIPE_WEBHOOK_SECRET_FILE,
#   CLOAKPIPE_WEBHOOK_FORMAT      (generic, slack or discord)
#   CLOAKPIPE_OTEL_ENDPOINT       OTLP/HTTP endpoint (spans per decision)
#   CLOAKPIPE_EVENTS_LOG          JSONL event log path
#
# Arguments after `gate` are added to the mcp-proxy flags. The gate also
# reads CLOAKPIPE_HOME (ledger and key, /data in the image),
# CLOAKPIPE_OPERATIONS_DB and CLOAKPIPE_TASK_CONTEXT itself.
#
# Any other command goes to cloakpipe unchanged: `docker run IMAGE start`
# runs the PII proxy with the bundled /app/cloakpipe.toml.
set -eu

if [ "$#" -gt 0 ] && [ "$1" != "gate" ]; then
  exec cloakpipe "$@"
fi
[ "$#" -gt 0 ] && shift

fail() {
  echo "cloakpipe-entrypoint: $*" >&2
  exit 2
}

manifest=${CLOAKPIPE_MANIFEST:-/app/cloakpipe.manifest.yaml}
listen=${CLOAKPIPE_LISTEN:-0.0.0.0:8900}

[ -f "$manifest" ] || fail "no manifest at $manifest: mount yours, e.g. -v \"\$PWD/cloakpipe.manifest.yaml:/app/cloakpipe.manifest.yaml:ro\" (or set CLOAKPIPE_MANIFEST)"

if [ -n "${CLOAKPIPE_UPSTREAM_URL:-}" ] && [ -n "${CLOAKPIPE_UPSTREAM:-}" ]; then
  fail "set CLOAKPIPE_UPSTREAM_URL or CLOAKPIPE_UPSTREAM, not both"
fi
if [ -z "${CLOAKPIPE_UPSTREAM_URL:-}" ] && [ -z "${CLOAKPIPE_UPSTREAM:-}" ]; then
  fail "set CLOAKPIPE_UPSTREAM_URL (an MCP server over HTTP) or CLOAKPIPE_UPSTREAM (a stdio command)"
fi

case "$listen" in
  127.*|localhost:*|\[::1\]:*) loopback=1 ;;
  *) loopback=0 ;;
esac
if [ -z "${CLOAKPIPE_LISTEN_TOKEN_FILE:-}" ] && [ "$loopback" = 0 ] && [ "${CLOAKPIPE_INSECURE_NO_TOKEN:-}" != 1 ]; then
  fail "the gate listens on $listen: set CLOAKPIPE_LISTEN_TOKEN_FILE to a file holding a bearer token (or CLOAKPIPE_INSECURE_NO_TOKEN=1 on a private network)"
fi

# Build the flags in front of the arguments given after `gate`.
set -- --listen "$listen" --manifest "$manifest" "$@"
if [ -n "${CLOAKPIPE_UPSTREAM_URL:-}" ]; then
  set -- "$@" --upstream-url "$CLOAKPIPE_UPSTREAM_URL"
  if [ -n "${CLOAKPIPE_UPSTREAM_HEADER:-}" ]; then set -- "$@" --upstream-header "$CLOAKPIPE_UPSTREAM_HEADER"; fi
else
  set -- "$@" --upstream "$CLOAKPIPE_UPSTREAM"
fi
if [ -n "${CLOAKPIPE_LISTEN_TOKEN_FILE:-}" ]; then set -- "$@" --listen-token-file "$CLOAKPIPE_LISTEN_TOKEN_FILE"; fi
if [ -n "${CLOAKPIPE_TOOLS_LOCK:-}" ]; then set -- "$@" --tools-lock "$CLOAKPIPE_TOOLS_LOCK"; fi
if [ -n "${CLOAKPIPE_WEBHOOK_URL:-}" ]; then set -- "$@" --webhook "$CLOAKPIPE_WEBHOOK_URL"; fi
if [ -n "${CLOAKPIPE_WEBHOOK_SECRET_FILE:-}" ]; then set -- "$@" --webhook-secret-file "$CLOAKPIPE_WEBHOOK_SECRET_FILE"; fi
if [ -n "${CLOAKPIPE_WEBHOOK_FORMAT:-}" ]; then set -- "$@" --webhook-format "$CLOAKPIPE_WEBHOOK_FORMAT"; fi
if [ -n "${CLOAKPIPE_OTEL_ENDPOINT:-}" ]; then set -- "$@" --otel-endpoint "$CLOAKPIPE_OTEL_ENDPOINT"; fi
if [ -n "${CLOAKPIPE_EVENTS_LOG:-}" ]; then set -- "$@" --events-log "$CLOAKPIPE_EVENTS_LOG"; fi

exec cloakpipe mcp-proxy "$@"
