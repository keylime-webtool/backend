#![forbid(unsafe_code)]

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use keylime_webtool_backend::api::routes;
use keylime_webtool_backend::config::KeylimeConfig;
use keylime_webtool_backend::keylime::client::KeylimeClient;
use keylime_webtool_backend::models::alert_store::AlertStore;
use keylime_webtool_backend::settings_store;
use keylime_webtool_backend::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging with RUST_LOG env filter.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    // Resolve config file path and load any persisted settings.
    let config_path = settings_store::resolve_config_path();
    let persisted = config_path
        .as_ref()
        .and_then(|p| settings_store::load_persisted_settings(p));

    // Load Keylime connection config: persisted file > env vars > compiled defaults.
    let verifier_url = persisted
        .as_ref()
        .and_then(|s| s.keylime.as_ref())
        .map(|k| k.verifier_url.clone())
        .or_else(|| std::env::var("KEYLIME_VERIFIER_URL").ok())
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    let registrar_url = persisted
        .as_ref()
        .and_then(|s| s.keylime.as_ref())
        .map(|k| k.registrar_url.clone())
        .or_else(|| std::env::var("KEYLIME_REGISTRAR_URL").ok())
        .unwrap_or_else(|| "http://localhost:3001".to_string());

    let mtls = persisted.and_then(|s| s.mtls);

    let keylime_config = KeylimeConfig {
        verifier_url,
        registrar_url,
        mtls,
        timeout_secs: 30,
        circuit_breaker: Default::default(),
    };

    let keylime_client = KeylimeClient::new(keylime_config)?;

    let alert_store = AlertStore::new_with_seed_data();

    let state = AppState::new(keylime_client, alert_store, config_path);

    let app = routes::build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {addr}");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
