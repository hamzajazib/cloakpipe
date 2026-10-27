# CloakPipe — Technical Specification (v2)

> **Legacy.** The 2025 technical specification of the PII privacy proxy.
> Parts of it were never built. Kept for history; see the
> [README](../../README.md) for the current product.

## Language & Runtime

**Rust** (2021 edition, MSRV 1.75+) — rationale unchanged from v1.

---

## Dependency Stack (v2)

### Core Dependencies (unchanged from v1)

| Crate | Purpose |
|-------|---------|
| `axum` 0.7+ | HTTP server framework |
| `tokio` 1.x | Async runtime |
| `reqwest` 0.12+ | Upstream HTTP client |
| `serde` / `serde_json` 1.x | Serialization |
| `toml` 0.8+ | Config parsing |
| `regex` 1.x | Pattern detection |
| `aes-gcm` 0.10+ | Vault encryption (AES-256-GCM) |
| `zeroize` 1.x | Cryptographic memory zeroing |
| `argon2` 0.5+ | Key derivation |
| `tracing` / `tracing-subscriber` | Structured logging |
| `uuid` 1.x / `chrono` 0.4+ | Request IDs, timestamps |

### New V2 Dependencies

| Crate | Feature Flag | Purpose | Notes |
|-------|-------------|---------|-------|
| `candle-core` / `candle-nn` | `local` | Pure-Rust ML framework — local embeddings + LLM | HuggingFace's Rust framework |
| `lancedb` | `local` | Embedded vector database | Rust-native, zero-config |
| `ring` | (core) | Cryptographic primitives for ADCPE | Well-audited crypto library |
| `keyring` | (core) | OS-native secure key storage | macOS Keychain, Linux Secret Service |
| `tree-sitter` | `code` | AST parsing for code-aware detection | v0.5+ |
| `aws-nitro-enclaves-nsm-api` | `tee` | Nitro Enclave attestation | TEE mode only |
| `eventsource-stream` | (core) | SSE streaming parsing | For rehydration |
| `pdf-extract` or `lopdf` | `tree` | PDF parsing for CloakTree | Document ingestion |
| `docx-rs` | `tree` | DOCX parsing | Document ingestion |

### Feature Flags (v2)

```toml
[features]
default = []
ner = ["ort", "tokenizers", "ndarray"]         # ONNX NER model support
tree = ["pdf-extract", "docx-rs"]              # CloakTree document parsing
vector-encrypt = ["ring"]                       # ADCPE vector encryption
local = ["candle-core", "candle-nn", "lancedb"] # Local-first mode
tee = ["aws-nitro-enclaves-nsm-api"]           # TEE deployment
code = ["tree-sitter"]                          # Code-aware detection
full = ["ner", "tree", "vector-encrypt", "local", "tee", "code"]
```

Default build: regex detection + vault + proxy. Everything else is opt-in.

---

## Obfuscation Techniques Specification

### Technique 1: Consistent Pseudonymization (Default)

Unchanged from v1. Detection engine → vault mapping → `{CATEGORY}_{SEQUENCE}` tokens.

Works with any LLM API. Zero fine-tuning required. <5ms latency.

### Technique 2: Generative Symbol Replacement (Optional) [NEW]

Based on EmojiPrompt (NAACL 2025).

```
Input:  "Tata Motors reported revenue of Rs 3.4L Cr"
Output: "🔷⚡ reported revenue of 🔢💰🌊"
```

- Deterministic emoji/symbol sequences replace entities
- Preserves grammatical structure and contextual intent
- No fine-tuning required — works with any API
- Lower security than pseudonymization (patterns may be guessable)
- Complementary to pseudonymization: catches contextual phrases regex misses

Implementation: `cloakpipe-core/detector/symbols.rs`

### Technique 3: Token Bijection (Advanced, Optional) [NEW]

Based on AlienLM (arXiv Jan 2026).

```
Vocabulary bijection: token_id → alien_token_id (1:1 mapping)

Input tokens:  [15496, 995, 2237, 18550, ...]  ("Tata Motors reported...")
Alien tokens:  [48721, 5543, 31002, 7891, ...]  (incomprehensible)

Requires: Alien Adaptation Training (AAT) via fine-tuning API
Performance: >81% plaintext-oracle retention
Security: <0.22% token recovery rate under adversarial attacks
```

- Bijection seed is the secret — stored in vault, never transmitted
- Requires OpenAI/Anthropic fine-tuning API access
- Entire prompt becomes incomprehensible to human review or telemetry
- Not compatible with streaming rehydration (response is in alien language, decoded client-side)

Implementation: `cloakpipe-core/bijection.rs`

### Technique 4: ADCPE Vector Encryption [NEW]

Based on Fuchsbauer et al. (2022), IBM implementation guide.

```rust
// Conceptual API
fn encrypt_vector(plaintext: &[f32], key: &AdcpeKey) -> Vec<f32> {
    // Apply distance-comparison-preserving transformation
    // dist(enc(a, key), enc(b, key)) ≈ dist(a, b)
    // But enc(a) cannot be inverted to recover the text that produced a
}

fn encrypt_query(query_vec: &[f32], key: &AdcpeKey) -> Vec<f32> {
    // Same key, same transformation
    // Encrypted query searches against encrypted corpus
}
```

Properties:
- **Approximate** distance preservation — search accuracy degrades slightly
- Tunable privacy-accuracy tradeoff via ADCPE parameters
- Protects against embedding inversion attacks (Zero2Text-class)
- Symmetric encryption — same key for corpus and queries
- Computational overhead: <1ms per vector encryption

Implementation: `cloakpipe-vector/adcpe.rs`

---

## CloakTree Specification [NEW]

### Tree Index Format

```json
{
  "version": 1,
  "document": {
    "source": "annual-report-2025.pdf",
    "pages": 120,
    "indexed_at": "2026-03-05T14:00:00Z"
  },
  "root": {
    "id": "0",
    "title": "ORG_7 Annual Report FY DATE_3",
    "children": [
      {
        "id": "1",
        "title": "Financial Highlights",
        "summary": "ORG_7 reported AMOUNT_12 revenue, up PCT_3 YoY...",
        "pages": [4, 8],
        "children": [
          {
            "id": "1.1",
            "title": "Revenue Breakdown by Segment",
            "summary": "Automotive segment contributed AMOUNT_15...",
            "pages": [5, 6],
            "children": []
          }
        ]
      }
    ]
  }
}
```

### Tree Search Protocol

```
Round 1: LLM sees full tree (titles + summaries at depth 1)
  → LLM selects: node "1" (Financial Highlights)

Round 2: LLM sees children of node "1" (titles + summaries)
  → LLM selects: node "1.2" (EBITDA and Margins)

Round 3: Node "1.2" is a leaf → extract full text from pages [7, 8]

Total LLM calls: 2-4 (depth of tree)
```

Each LLM call sends only titles and summaries (pseudonymized). Full document text is never sent during search — only during final generation.

### Document Parsing

| Format | Parser | Structure Extraction |
|--------|--------|---------------------|
| PDF | `pdf-extract` / `lopdf` | Headings, page boundaries, tables |
| DOCX | `docx-rs` | Heading styles, sections, lists |
| HTML | `scraper` or built-in | DOM headings (h1-h6), sections |
| Markdown | Built-in | ATX headings, sections |

### Tree Generation Models

| Mode | Model | Latency | Quality |
|------|-------|---------|---------|
| External (default) | GPT-4o / Claude via proxy | ~2s per node | High |
| Local | Qwen2.5-7B via candle | ~5s per node | Medium |
| No summaries | None (titles + page ranges only) | Instant | Lower retrieval accuracy |

---

## API Surface (v2)

### Proxied Endpoints (unchanged)

| Endpoint | Method | Behavior |
|----------|--------|----------|
| `/v1/chat/completions` | POST | Anonymize → forward → rehydrate |
| `/v1/embeddings` | POST | Anonymize → forward → (optional ADCPE encrypt) |
| `/v1/completions` | POST | Anonymize → forward → rehydrate |
| `/*` | * | Passthrough |

### CloakTree Endpoints [NEW]

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/tree/build` | POST | Build tree index from uploaded document |
| `/v1/tree/search` | POST | Search a tree index with a query |
| `/v1/tree/list` | GET | List available tree indices |

### Admin Endpoints (expanded)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/_cloakpipe/stats` | GET | Vault stats, uptime, request counts |
| `/_cloakpipe/mode` | GET | Current privacy tier |

---

## Vault Specification (v2 additions)

Unchanged from v1 core. New additions:

### OS Keyring Integration

```rust
// Key storage options (mutually exclusive)
enum KeySource {
    EnvVar(String),           // CLOAKPIPE_VAULT_KEY env var
    Keyring { service: &str }, // OS keyring (macOS Keychain, Linux Secret Service)
    Passphrase(String),        // Interactive passphrase → Argon2id derivation
}
```

### Multi-Vault Support

```toml
# Per-project or per-tenant vault isolation
[vault]
path = "./vaults/"      # Directory mode: one vault file per project/tenant
isolation = "project"    # "project" | "tenant" | "single"
```

---

## Performance Targets (v2)

| Operation | Target | Notes |
|-----------|--------|-------|
| Regex-only detection (1KB) | <2ms p99 | Unchanged |
| Full detection with NER (1KB) | <30ms p99 | Unchanged |
| Vault lookup | <0.1ms p99 | Unchanged |
| ADCPE vector encryption | <1ms per vector | [NEW] |
| CloakTree search (per round) | LLM latency + <5ms overhead | [NEW] |
| CloakTree total query | 2-8s (2-4 LLM calls) | [NEW] |
| Tree index build (per page) | 2-5s (with LLM summaries) | [NEW] One-time cost |
| Local embedding (candle, 1KB) | 10-50ms | [NEW] GPU-dependent |
| SSE chunk rehydration | <0.5ms per chunk | Unchanged |
| Concurrent connections | 1000+ | Unchanged |

---

## Error Handling (v2 additions)

| Failure | Behavior |
|---------|----------|
| All v1 error handling | Unchanged |
| Tree index build failure | Return error, suggest re-indexing |
| Tree search: LLM fails mid-navigation | Return partial results with warning |
| ADCPE encryption failure | Return 500 (fail-closed) |
| Local model load failure | Fall back to external API mode, log warning |
| TEE attestation failure | Refuse to start, log attestation error |
| VSOCK communication error (TEE) | Return 503, retry with backoff |

---

## Testing Strategy (v2 additions)

| Layer | Approach |
|-------|----------|
| All v1 testing | Unchanged |
| CloakTree indexer | Snapshot tests with sample PDFs, golden tree indices |
| CloakTree search | Mock LLM responses, verify correct node selection |
| ADCPE | Property tests: encrypted similarity ≈ plaintext similarity |
| ADCPE | Security tests: encrypted vectors resist inversion |
| Local inference | Integration tests with small quantized models |
| TEE | Mock attestation tests (real TEE testing requires AWS) |
| Bijection | Round-trip tests: bijection → inverse = identity |

### Key invariants to test (expanded):
1. `rehydrate(anonymize(text)) == text` — pseudonymization round-trip
2. `cosine_sim(adcpe(a), adcpe(b)) ≈ cosine_sim(a, b)` — ADCPE distance preservation
3. `inverse_bijection(bijection(tokens)) == tokens` — bijection round-trip
4. CloakTree search returns correct nodes for known queries on test documents

---

## Research References

| Technique | Paper/Source | Key Result |
|-----------|-------------|------------|
| Consistent Pseudonymization | Standard data protection technique (GDPR Art. 4) | Foundation approach |
| PageIndex (CloakTree basis) | VectifyAI, Feb 2026 | 98.7% FinanceBench accuracy |
| AlienLM (Token Bijection) | arXiv 2601.22710, Jan 2026 | 81%+ retention, <0.22% recovery |
| EmojiPrompt (Symbol Replace) | NAACL 2025 | Maintains/enhances task performance |
| ADCPE (Vector Encryption) | Fuchsbauer et al., Springer 2022 | Distance-preserving encryption |
| Zero2Text (Threat Model) | arXiv 2602.01757, Feb 2026 | 1.8x ROUGE-L inversion on OpenAI embeddings |
| LPRAG | ScienceDirect, 2025 | Entity-level perturbation preserves retrieval |
| Nitro Enclaves + LLM | AWS, 2024-2025 | Production zero-trust LLM inference |
