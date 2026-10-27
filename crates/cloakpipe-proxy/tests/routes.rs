//! Which routes the proxy serves in each build. The LLM PII proxy (chat,
//! messages, sessions) is always built; the RAG routes (`/tree/*` and
//! `/v1/embeddings`) only with the `rag` feature.

use cloakpipe_audit::AuditLogger;
use cloakpipe_core::{config::CloakPipeConfig, detector::Detector, vault::Vault};
use cloakpipe_proxy::{server::build_router, state::AppState};
use std::sync::Arc;

const CONFIG: &str = r#"
[proxy]
listen = "127.0.0.1:0"
upstream = "http://127.0.0.1:9"
api_key_env = "OPENAI_API_KEY"
timeout_seconds = 5
max_concurrent = 4
mode = "proxy"

[vault]
path = "vault.enc"
encryption = "aes-256-gcm"

[detection]
secrets = true
financial = true
dates = true
emails = true
phone_numbers = false
ip_addresses = false
urls_internal = false
"#;

/// Serve the router on an ephemeral port and return its base URL.
async fn serve(dir: &std::path::Path) -> String {
    let mut config: CloakPipeConfig = toml::from_str(CONFIG).unwrap();
    config.tree.storage_path = dir.join("trees").to_string_lossy().into_owned();
    let detector = Detector::from_config(&config.detection).unwrap();
    let audit = AuditLogger::new(&dir.join("audit").to_string_lossy(), false).unwrap();
    let state = AppState::new(config, detector, Vault::ephemeral(), audit, "sk-test".into());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, build_router(Arc::new(state))).await.unwrap() });
    format!("http://{addr}")
}

async fn status(base: &str, method: reqwest::Method, path: &str) -> u16 {
    let client = reqwest::Client::new();
    let req = client.request(method, format!("{base}{path}"));
    let req = req.header("content-type", "application/json").body("{}");
    req.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn the_pii_proxy_routes_are_always_served() {
    let dir = tempfile::tempdir().unwrap();
    let base = serve(dir.path()).await;
    assert_eq!(status(&base, reqwest::Method::GET, "/health").await, 200);
    assert_eq!(status(&base, reqwest::Method::GET, "/sessions").await, 200);
    assert_ne!(status(&base, reqwest::Method::POST, "/v1/chat/completions").await, 404);
    assert_ne!(status(&base, reqwest::Method::POST, "/v1/messages").await, 404);
}

#[cfg(not(feature = "rag"))]
#[tokio::test]
async fn rag_routes_need_the_rag_feature() {
    let dir = tempfile::tempdir().unwrap();
    let base = serve(dir.path()).await;
    assert_eq!(status(&base, reqwest::Method::GET, "/tree/list").await, 404);
    assert_eq!(status(&base, reqwest::Method::POST, "/tree/index").await, 404);
    assert_eq!(status(&base, reqwest::Method::POST, "/v1/embeddings").await, 404);
}

#[cfg(feature = "rag")]
#[tokio::test]
async fn rag_routes_are_served_with_the_rag_feature() {
    let dir = tempfile::tempdir().unwrap();
    let base = serve(dir.path()).await;
    assert_ne!(status(&base, reqwest::Method::GET, "/tree/list").await, 404);
    assert_ne!(status(&base, reqwest::Method::POST, "/v1/embeddings").await, 404);
}
