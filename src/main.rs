#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use keylime_webtool_backend::api::routes;
use keylime_webtool_backend::config::KeylimeConfig;
use keylime_webtool_backend::keylime::client::KeylimeClient;
use keylime_webtool_backend::repository::{
    CacheBackend, InMemoryCacheBackend, RedisCacheBackend, Repositories, SqliteDb,
};
use keylime_webtool_backend::settings_store;
use keylime_webtool_backend::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config_path = settings_store::resolve_config_path();
    let persisted = config_path
        .as_ref()
        .and_then(|p| settings_store::load_persisted_settings(p));

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

    let repos = match std::env::var("DATABASE_URL") {
        Ok(url) if url.starts_with("sqlite:") => {
            let db = SqliteDb::connect(&url).await?;
            db.init_schema().await?;
            tracing::info!("SQLite database connected: {url}");
            db.repositories()
        }
        Ok(url) => {
            tracing::warn!("Unsupported DATABASE_URL scheme: {url} — using in-memory repos");
            Repositories::in_memory()
        }
        Err(_) => {
            tracing::info!("No DATABASE_URL set, using in-memory repositories");
            Repositories::in_memory()
        }
    };

    let cache: Arc<dyn CacheBackend> = match std::env::var("REDIS_URL") {
        Ok(url) => match RedisCacheBackend::connect(&url).await {
            Ok(c) => {
                tracing::info!("Redis cache connected");
                Arc::new(c)
            }
            Err(e) => {
                tracing::warn!("Redis unavailable, using in-memory cache: {e}");
                Arc::new(InMemoryCacheBackend::new())
            }
        },
        Err(_) => Arc::new(InMemoryCacheBackend::new()),
    };

    let state = AppState::new(
        keylime_client,
        repos.alert,
        repos.attestation,
        repos.policy,
        repos.audit,
        cache,
        config_path,
    );

    let app = routes::build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {addr}");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
