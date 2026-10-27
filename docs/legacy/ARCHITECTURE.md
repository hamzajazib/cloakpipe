# CloakPipe — Architecture Document (v2)

> **Legacy.** The 2025 architecture of the PII privacy proxy (CloakTree,
> CloakVector, TEE plans). Kept for history; the current architecture is in
> the [README](../../README.md) and [ACTION_BOUNDARY.md](../ACTION_BOUNDARY.md).

## System Overview

CloakPipe is a Rust privacy middleware for LLM and RAG pipelines. It operates as an HTTP proxy with two retrieval modes (**CloakTree** for structured documents, **CloakVector** for multi-document corpora), five privacy tiers, and optional hardware isolation via TEEs.

```
┌──────────────┐     ┌──────────────────────────────┐     ┌───────────────┐
│  Your App    │────▶│         CloakPipe              │────▶│  LLM Provider │
│  (LangChain, │     │                                │     │  (OpenAI,     │
│   LlamaIndex,│◀────│  detect → anonymize → forward  │◀────│   Anthropic,  │
│   raw SDK)   │     │  rehydrate ← response          │     │   Ollama...)  │
└──────────────┘     └──────────────────────────────┘     └───────────────┘
                              │           │
                     ┌────────▼──┐  ┌─────▼──────────┐
                     │  Encrypted │  │  Tree Index    │
                     │  Vault     │  │  (local JSON)  │
                     │  (mappings)│  │  (CloakTree)   │
                     └───────────┘  └────────────────┘
                              │
                     ┌────────▼──────────┐
                     │  Vector DB         │
                     │  (ADCPE-encrypted  │
                     │   embeddings)      │
                     │  (CloakVector)     │
                     └───────────────────┘
```

---

## Privacy Tiers

CloakPipe offers five tiers, configurable via a single TOML field:

| Tier | Name | Leak Points | Key Property |
|------|------|-------------|--------------|
| 0 | **CloakTree** | 1 (generation only, pseudonymized) | No embedding API, no vector DB |
| 1 | **CloakVector** | 4 (all pseudonymized) | Consistent pseudonymization across pipeline |
| 2 | **CloakVector + ADCPE** | 4 (pseudonymized + vectors encrypted) | Embedding inversion protection |
| 3 | **TEE-Enclosed** | Same as Tier 0-2 but hardware-isolated | Cryptographic attestation |
| 4 | **Full Local** | 0 (air-gap) | Zero external API calls |

---

## Two Retrieval Modes

### CloakTree (Tier 0) — Vectorless Reasoning-Based Retrieval

Eliminates embedding APIs and vector databases entirely. Inspired by PageIndex (VectifyAI, 98.7% FinanceBench accuracy).

```
INGESTION:
  Document (PDF/DOCX/HTML)
        │
        ▼
  Document Parser (structure extraction)
        │
        ▼
  Tree Index Builder
  (hierarchical JSON: titles, summaries, page ranges)
        │
        ▼ (optional: pseudonymize summaries via vault)
  Local JSON file (no external API for indexing)


QUERY:
  User question
        │
        ▼
  Pseudonymize query (vault)
        │
        ▼
  LLM-driven Tree Search
  (LLM reasons over tree structure: titles + summaries)
  (navigates branches like AlphaGo MCTS)
        │
        ▼
  Selected nodes → extract full text (local)
        │
        ▼
  Pseudonymize extracted text (vault)
        │
        ▼
  Send pseudonymized context + query to LLM  ← ONLY external API call
        │
        ▼
  Rehydrate response (vault)
        │
        ▼
  Clean answer to user
```

**Privacy advantage**: The LLM only sees pseudonymized text at one point (generation). No embedding API calls. No vector database. No embedding inversion risk.

**Best for**: Single-document deep analysis — financial reports, legal contracts, medical records, regulatory filings, technical manuals.

**Limitation**: Cannot scale to searching across hundreds/thousands of documents. Falls back to CloakVector for multi-document corpora.

### CloakVector (Tier 1-2) — Pseudonymized Vector RAG

The traditional RAG pipeline with consistent pseudonymization across all stages, plus optional ADCPE vector encryption.

```
INGESTION:
  Document chunks
        │
        ▼
  Detection Engine (regex + NER + custom rules)
        │
        ▼
  Replacer (vault: entity → pseudonym)
        │
        ▼
  POST /v1/embeddings (pseudonymized text → OpenAI)
        │
        ▼
  Embedding vector returned
        │
        ▼ (Tier 2 only)
  ADCPE Encrypt vector
        │
        ▼
  Store in Vector DB (encrypted or pseudonymized embeddings)


QUERY:
  User question
        │
        ▼
  Pseudonymize query (vault)
        │
        ▼
  POST /v1/embeddings (pseudonymized query → OpenAI)
        │
        ▼
  Query embedding returned
        │
        ▼ (Tier 2 only)
  ADCPE Encrypt query vector
        │
        ▼
  Similarity search against (encrypted) vectors
        │
        ▼
  Retrieved pseudonymized context chunks
        │
        ▼
  POST /v1/chat/completions (pseudonymized context + query → LLM)
        │
        ▼
  Rehydrate response (vault)
        │
        ▼
  Clean answer to user
```

**Best for**: Multi-document knowledge bases, unstructured text, email archives, chat logs.

---

## Crate Structure (v2)

```
cloakpipe/
├── Cargo.toml                      # Workspace root
├── crates/
│   ├── cloakpipe-core/             # Detection, replacement, vault, rehydration
│   │   ├── detector/
│   │   │   ├── patterns.rs         # Regex: secrets, amounts, dates, IPs, emails
│   │   │   ├── financial.rs        # Currency, percentages, fiscal terms
│   │   │   ├── custom.rs           # User-defined TOML rules
│   │   │   ├── ner.rs              # ONNX Runtime NER (feature-gated)
│   │   │   └── symbols.rs          # Generative symbol replacement (optional)
│   │   ├── replacer.rs             # Consistent pseudonymization engine
│   │   ├── vault.rs                # AES-256-GCM encrypted mapping vault
│   │   ├── rehydrator.rs           # Response de-anonymization + streaming
│   │   └── bijection.rs            # AlienLM-style token bijection (optional)
│   │
│   ├── cloakpipe-tree/             # CloakTree: vectorless retrieval  [NEW in v2]
│   │   ├── parser.rs               # PDF/DOCX/HTML document parsing
│   │   ├── indexer.rs              # Document → hierarchical tree builder
│   │   ├── tree.rs                 # Tree data structures (Node, Tree, Summary)
│   │   ├── search.rs               # LLM-driven tree search (reasoning nav)
│   │   ├── extractor.rs            # Full text extraction from selected nodes
│   │   └── storage.rs              # Local JSON tree persistence
│   │
│   ├── cloakpipe-vector/           # CloakVector: vector-level privacy  [NEW in v2]
│   │   ├── adcpe.rs                # Distance-preserving vector encryption
│   │   ├── encrypt.rs              # Embedding encryption before DB storage
│   │   └── search.rs               # Encrypted similarity search helpers
│   │
│   ├── cloakpipe-proxy/            # HTTP proxy layer
│   │   ├── server.rs               # axum-based OpenAI-compatible proxy
│   │   ├── streaming.rs            # SSE chunk-level rehydration
│   │   ├── middleware.rs           # Request/response interception
│   │   ├── embeddings.rs          # /v1/embeddings specific handling
│   │   └── routing.rs              # Provider routing + upstream management
│   │
│   ├── cloakpipe-local/            # Local-first mode  [NEW in v2]
│   │   ├── embeddings.rs           # candle-rs local embedding models
│   │   ├── lancedb.rs              # LanceDB integration
│   │   └── inference.rs            # Optional local LLM inference
│   │
│   ├── cloakpipe-tee/              # TEE deployment  [NEW in v2]
│   │   ├── nitro.rs                # AWS Nitro Enclaves integration
│   │   ├── attestation.rs          # Cryptographic attestation handling
│   │   └── kms.rs                  # AWS KMS key management
│   │
│   ├── cloakpipe-audit/            # Compliance and logging
│   │   ├── logger.rs               # Structured JSONL audit logs
│   │   └── reporter.rs             # Compliance report generation
│   │
│   └── cloakpipe-cli/              # CLI interface
│       ├── main.rs                 # Binary entrypoint
│       ├── config.rs               # TOML configuration loading
│       └── commands.rs             # vault, audit, tree, test subcommands
│
├── policies/                       # Detection rule configurations
│   ├── default.toml
│   └── examples/
│       ├── healthcare.toml         # HIPAA-oriented rules
│       ├── finance.toml            # SOX/PCI-DSS rules
│       ├── legal.toml              # Legal privilege rules
│       └── enterprise.toml         # General enterprise
│
└── models/                         # Optional ONNX NER models
    └── ner-english-base.onnx
```

### Crate Dependency Graph (v2)

```
cloakpipe-cli
  ├── cloakpipe-proxy
  │     ├── cloakpipe-core
  │     ├── cloakpipe-tree      [NEW]
  │     ├── cloakpipe-vector    [NEW]
  │     ├── cloakpipe-local     [NEW]
  │     └── cloakpipe-audit
  ├── cloakpipe-tee             [NEW]
  │     └── cloakpipe-core
  └── cloakpipe-core
        └── (no internal deps)
```

`cloakpipe-core` remains dependency-free internally — still compilable to WASM.

---

## Component Architecture

### 1. Detection Engine (`cloakpipe-core::detector`)

Unchanged from v1. Four layers: Pattern Matching → Financial Intelligence → Custom TOML Rules → NER (optional).

New addition in v2: **Generative Symbol Replacement** (`symbols.rs`) as an optional complementary layer. Uses deterministic emoji/symbol sequences instead of pseudonym tokens. Based on EmojiPrompt (NAACL 2025).

New addition in v2: **Token Bijection** (`bijection.rs`) as an advanced optional mode. AlienLM-style vocabulary-scale bijection. Requires API fine-tuning. Separate from the main detection pipeline.

### 2. Vault (`cloakpipe-core::vault`)

Unchanged from v1. AES-256-GCM encryption, `Zeroizing<T>` wrappers, Argon2id key derivation, atomic file writes.

New in v2: **OS keyring integration** via `keyring` crate (macOS Keychain, Linux Secret Service) as alternative to env var key storage.

### 3. CloakTree Engine (`cloakpipe-tree`) [NEW]

```
┌─────────────────────────────────────────────────────┐
│                    CloakTree                          │
│                                                       │
│  parser.rs                                            │
│    PDF → pages/sections (via pdf-extract or similar)  │
│    DOCX → structured content                          │
│    HTML → DOM tree → content sections                 │
│                                                       │
│  indexer.rs                                           │
│    Sections → hierarchical JSON tree                  │
│    Each node: {id, title, summary, pages, children}   │
│    Summary generation: external LLM or local candle   │
│    Summaries are pseudonymized before LLM sees them   │
│                                                       │
│  tree.rs                                              │
│    Node { id, title, summary, pages, children }       │
│    Tree { root, nodes_by_id, metadata }               │
│                                                       │
│  search.rs                                            │
│    Input: user query + tree structure                  │
│    LLM evaluates node relevance (titles + summaries)  │
│    Drills into promising branches                     │
│    Returns: Vec<NodeId> of relevant nodes             │
│                                                       │
│  extractor.rs                                         │
│    NodeIds → full text extraction from source doc      │
│    Applies pseudonymization via vault                  │
│                                                       │
│  storage.rs                                           │
│    Tree serialized as JSON to local disk               │
│    One JSON file per document                          │
└─────────────────────────────────────────────────────┘
```

### 4. ADCPE Vector Encryption (`cloakpipe-vector`) [NEW]

```
┌─────────────────────────────────────────────────────┐
│                  CloakVector Crypto                    │
│                                                       │
│  adcpe.rs                                             │
│    ADCPE key generation (symmetric, 256-bit)          │
│    encrypt_vector(plaintext_vec, key) → encrypted_vec │
│    Property: dist(enc(a), enc(b)) ≈ dist(a, b)       │
│    Approximate — tunable accuracy/privacy tradeoff    │
│                                                       │
│  encrypt.rs                                           │
│    Hooks into proxy embeddings handler                 │
│    After receiving embedding from API:                 │
│      1. Encrypt via ADCPE                             │
│      2. Return encrypted vector to client             │
│    Client stores encrypted vectors in vector DB       │
│                                                       │
│  search.rs                                            │
│    encrypt_query_vector(query_vec, key)               │
│    Encrypted query searches against encrypted corpus   │
│    Similarity scores are approximately preserved       │
└─────────────────────────────────────────────────────┘
```

### 5. Local-First Mode (`cloakpipe-local`) [NEW]

```
┌─────────────────────────────────────────────────────┐
│                   Local-First Mode                     │
│                                                       │
│  embeddings.rs                                        │
│    candle-rs embedding models (BGE, nomic-embed)      │
│    Zero external API calls for embedding              │
│                                                       │
│  lancedb.rs                                           │
│    LanceDB (Rust-native, embedded, zero-config)       │
│    Local vector storage on disk                        │
│    Optional encryption at rest                         │
│                                                       │
│  inference.rs                                         │
│    Local LLM via candle or llama.cpp bindings          │
│    Quantized models (Qwen2.5, DeepSeek, Llama 3)      │
│    Used for: tree generation, tree search, generation  │
│    Complete air-gap: zero external API calls           │
└─────────────────────────────────────────────────────┘
```

### 6. TEE Deployment (`cloakpipe-tee`) [NEW]

```
┌──────────────────────────────────────────────────────────────┐
│                    TEE Deployment                              │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  AWS Nitro Enclave                                        │ │
│  │  (isolated VM, no persistent storage, no network,         │ │
│  │   no interactive login, VSOCK only)                       │ │
│  │                                                            │ │
│  │  CloakPipe binary runs inside                              │ │
│  │    ├── Detection engine                                    │ │
│  │    ├── Vault (in-memory only, keys from KMS)               │ │
│  │    ├── ADCPE encryption                                    │ │
│  │    └── Tree indices (loaded via VSOCK)                      │ │
│  │                                                            │ │
│  │  nitro.rs: VSOCK server for parent instance communication  │ │
│  │  attestation.rs: PCR hash verification with AWS KMS        │ │
│  │  kms.rs: key retrieval only after attestation passes       │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  Flow:                                                         │
│    1. Parent sends document via encrypted VSOCK                │
│    2. Enclave presents attestation to KMS                      │
│    3. KMS verifies PCR hashes, releases vault key              │
│    4. Enclave processes (detect → anonymize → forward)         │
│    5. Enclave returns rehydrated response via VSOCK            │
│                                                                │
│  Even root on parent instance cannot read Enclave memory       │
└──────────────────────────────────────────────────────────────┘
```

### 7. Proxy Server (`cloakpipe-proxy`)

Unchanged core from v1 (axum + tokio). New additions:

- `embeddings.rs`: Dedicated handler for `/v1/embeddings` with ADCPE encryption hook
- Mode routing: proxy checks `mode` config to dispatch to CloakTree or CloakVector pipeline
- Tree endpoints: `POST /v1/tree/build`, `POST /v1/tree/search` (CloakTree-specific)

### 8. Audit Logger (`cloakpipe-audit`)

Unchanged from v1. New addition: compliance report generation for GDPR, HIPAA, SOX frameworks.

---

## Security Boundaries (v2)

```
┌───────────────────────────────────────────────────────────┐
│  TRUSTED ZONE                                              │
│                                                            │
│  ┌────────────────────────────────────────────────────┐   │
│  │  Tier 3: TEE (Nitro Enclave)                       │   │
│  │  Cryptographically attested, memory-isolated        │   │
│  │  Even infrastructure admin cannot access             │   │
│  │                                                      │   │
│  │  CloakPipe + Vault + Tree Indices + ADCPE keys      │   │
│  └────────────────────────────────────────────────────┘   │
│                                                            │
│  Tier 0-2: Local machine                                   │
│  Your App ←→ CloakPipe ←→ Vault (enc) ←→ Trees (JSON)    │
│                                                            │
│  Tier 4: Air-gap                                           │
│  Everything local: embeddings, vectors, LLM inference      │
└───────────────── │ ───────────────────────────────────────┘
                   │
           ────────┼──────── NETWORK ────────
                   │
           ┌───────▼──────────┐
           │  LLM Provider    │  Sees: pseudonyms only (Tier 0-2)
           │                  │        bijected tokens (optional)
           │                  │        nothing (Tier 4)
           └──────────────────┘
                   │
           ┌───────▼──────────┐
           │  Vector DB       │  Stores: ADCPE-encrypted vectors (Tier 2)
           │                  │          pseudonymized vectors (Tier 1)
           │                  │          nothing (Tier 0, 4)
           └──────────────────┘
```

---

## Concurrency Model

Unchanged from v1 for the proxy core. New considerations:

- **CloakTree indexing**: CPU-intensive, runs on `spawn_blocking`. One-time cost per document.
- **CloakTree search**: Async LLM calls for tree navigation. Multiple rounds of LLM reasoning per query.
- **ADCPE encryption**: CPU-bound per-vector operation, runs on `spawn_blocking`. Lightweight (<1ms per vector).
- **Local inference** (candle-rs): Owns its own thread pool. Heavy GPU/CPU usage.

---

## Configuration Architecture (v2)

```
cloakpipe.toml
    │
    ├── [proxy]          → listen addr, upstream URL, timeouts, concurrency
    ├── mode             → "cloaktree" | "cloakvector" | "cloakvector+encrypt" | "tee" | "local"
    ├── [tree]           → CloakTree settings (storage, models, summaries)  [NEW]
    ├── [vault]          → path, encryption, key source, OS keyring option
    ├── [detection]      → toggle built-in detectors
    │     ├── [detection.ner]       → ONNX model, confidence, entity types
    │     ├── [detection.custom]    → user-defined regex patterns
    │     └── [detection.overrides] → preserve/force entity lists
    ├── [vectors]        → ADCPE encryption settings  [NEW]
    ├── [local]          → local embedding model, vector DB, local LLM  [NEW]
    ├── [tee]            → TEE provider, attestation, KMS key  [NEW]
    ├── [audit]          → log path, format, retention
    └── [streaming]      → SSE rehydration settings, buffer size
```
