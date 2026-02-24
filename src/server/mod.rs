#[cfg(feature = "server")]
pub mod mailbox;

#[cfg(feature = "server")]
use axum::Router;

/// Server configuration.
#[cfg(feature = "server")]
pub struct ServerConfig {
    #[allow(dead_code)]
    pub port: u16,
    #[allow(dead_code)]
    pub bind: String,
    pub max_channels: usize,
    pub channel_ttl_secs: u64,
    pub max_payload_bytes: usize,
    pub rate_limit_per_min: usize,
}

#[cfg(feature = "server")]
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 4443,
            bind: "0.0.0.0".to_string(),
            max_channels: 100,
            channel_ttl_secs: 300,
            max_payload_bytes: 1_048_576,
            rate_limit_per_min: 10,
        }
    }
}

/// Build the axum router for the relay server.
#[cfg(feature = "server")]
pub fn build_router(config: ServerConfig) -> Router {
    use std::sync::Arc;
    let state = Arc::new(mailbox::RelayState::new(
        config.max_channels,
        config.channel_ttl_secs,
        config.max_payload_bytes,
        config.rate_limit_per_min,
    ));

    Router::new()
        .route("/health", axum::routing::get(health))
        .route("/channel/:code", axum::routing::get(mailbox::ws_handler))
        .with_state(state)
}

#[cfg(feature = "server")]
async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "enseal-relay",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
