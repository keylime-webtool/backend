#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use keylime_webtool_backend::api::routes;
use keylime_webtool_backend::config::KeylimeConfig;
use keylime_webtool_backend::keylime::client::KeylimeClient;
use keylime_webtool_backend::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging with RUST_LOG env filter.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    // Load Keylime connection config from environment variables.
    let verifier_url = std::env::var("KEYLIME_VERIFIER_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let registrar_url = std::env::var("KEYLIME_REGISTRAR_URL")
        .unwrap_or_else(|_| "http://localhost:3001".to_string());

    let keylime_config = KeylimeConfig {
        verifier_url,
        registrar_url,
        mtls: None,
        timeout_secs: 30,
        circuit_breaker: Default::default(),
    };

    let keylime_client = KeylimeClient::new(keylime_config)?;

    let state = AppState {
        keylime: Arc::new(keylime_client),
    };

    let app = routes::build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {addr}");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
