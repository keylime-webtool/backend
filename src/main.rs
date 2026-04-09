#![forbid(unsafe_code)]

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use keylime_webtool_backend::api::routes;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging with RUST_LOG env filter.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    // TODO: load AppConfig from config file / env vars
    // TODO: initialize Database (TimescaleDB) connection pool
    // TODO: initialize Redis Cache
    // TODO: initialize KeylimeClient with mTLS
    // TODO: initialize OidcClient
    // TODO: initialize SessionStore
    // TODO: initialize AuditLogger (resume from last chain tip)
    // TODO: start periodic reconciliation sweep (NFR-020, every 5 min)
    // TODO: start certificate expiry checker background task

    let app = routes::build_router();

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {addr}");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
