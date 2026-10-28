# CloakPipe OSS: the `cloakpipe` binary. By default the image runs the MCP
# tool-call gate over HTTP (docker/gate-entrypoint.sh builds its flags from
# CLOAKPIPE_* variables):
#
#   docker build -t cloakpipe .
#   docker run -p 127.0.0.1:8900:8900 \
#     -v "$PWD/cloakpipe.manifest.yaml:/app/cloakpipe.manifest.yaml:ro" \
#     -v "$PWD/listen.token:/run/secrets/listen.token:ro" \
#     -v cloakpipe-data:/data \
#     -e CLOAKPIPE_UPSTREAM_URL=https://tools.example.com/mcp \
#     -e CLOAKPIPE_LISTEN_TOKEN_FILE=/run/secrets/listen.token \
#     cloakpipe
#
# Agents then connect to http://localhost:8900/mcp with the bearer token.
# The decision ledger, gate key and operations store live in /data. See
# docker/compose.example.yaml for a gate in front of an example upstream.
#
# Any other command runs cloakpipe itself, e.g. the regex PII proxy for LLM
# traffic with the bundled config (docker/cloakpipe.docker.toml binds
# 0.0.0.0:8900, NER off):
#
#   docker run -p 8900:8900 -e OPENAI_API_KEY=sk-... cloakpipe start
#
# The default build is lean; pass cargo features to add NER, RAG tooling or
# legacy certification:
#
#   docker build --build-arg CLOAKPIPE_FEATURES=full -t cloakpipe:full .

FROM rust:1.99-trixie AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# Comma-separated cargo features of cloakpipe-cli: ner, rag, certification, full.
ARG CLOAKPIPE_FEATURES=""
RUN cargo build --release -p cloakpipe-cli ${CLOAKPIPE_FEATURES:+--features "$CLOAKPIPE_FEATURES"}

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates curl libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/cloakpipe /usr/local/bin/cloakpipe
COPY docker/gate-entrypoint.sh /usr/local/bin/cloakpipe-entrypoint
COPY docker/cloakpipe.docker.toml /app/cloakpipe.toml
RUN chmod 0755 /usr/local/bin/cloakpipe-entrypoint && mkdir -p /data
ENV CLOAKPIPE_HOME=/data
ENV CLOAKPIPE_OPERATIONS_DB=/data/operations.db
ENV CLOAKPIPE_LISTEN=0.0.0.0:8900
VOLUME ["/data"]
WORKDIR /app
EXPOSE 8900
# The gate's /health (and the PII proxy's) needs no token.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${CLOAKPIPE_LISTEN##*:}/health" || exit 1
# Gate: CLOAKPIPE_UPSTREAM_URL (or CLOAKPIPE_UPSTREAM), a manifest at
# /app/cloakpipe.manifest.yaml and CLOAKPIPE_LISTEN_TOKEN_FILE are required;
# see docker/gate-entrypoint.sh for the rest. PII proxy (`start`):
# OPENAI_API_KEY, optional CLOAKPIPE_VAULT_KEY.
ENTRYPOINT ["cloakpipe-entrypoint"]
CMD ["gate"]
