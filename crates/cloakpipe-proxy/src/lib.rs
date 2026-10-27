//! CloakPipe Proxy — OpenAI-compatible HTTP proxy with privacy middleware.
//!
//! Intercepts requests to LLM APIs, detects and pseudonymizes sensitive
//! entities in prompts, forwards the sanitized request, then rehydrates
//! the response before returning it to the caller.

pub mod server;
pub mod handlers;
pub mod state;
pub mod streaming;
/// CloakTree endpoints (`rag` feature).
#[cfg(feature = "rag")]
pub mod tree_handlers;
