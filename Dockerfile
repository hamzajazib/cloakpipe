# CloakPipe OSS: the `cloakpipe` binary (tool-call gate, evidence tooling and
# the regex PII proxy for LLM traffic). The default build is lean; pass cargo
# features to add NER, RAG tooling or legacy certification:
#
#   docker build -t cloakpipe .
#   docker build --build-arg CLOAKPIPE_FEATURES=full -t cloakpipe:full .
#   docker run -p 8900:8900 -e OPENAI_API_KEY=sk-... cloakpipe
#
# The bundled config (docker/cloakpipe.docker.toml) binds 0.0.0.0:8900 and
# leaves NER disabled, so the image runs the regex/heuristic detector with no
# model download. To use the neural detector, build with
# CLOAKPIPE_FEATURES=ner (or full) and mount your own /app/cloakpipe.toml with
# [detection.ner] enabled = true plus the model files.

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
COPY docker/cloakpipe.docker.toml /app/cloakpipe.toml
RUN mkdir -p /data
WORKDIR /app
EXPOSE 8900
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://localhost:8900/health || exit 1
# Required at runtime: OPENAI_API_KEY (upstream provider key CloakPipe forwards).
# Optional: CLOAKPIPE_VAULT_KEY (64-char hex; auto-generated if unset).
CMD ["cloakpipe", "-c", "/app/cloakpipe.toml", "start"]
