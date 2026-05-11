use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

use crate::config::DatabaseConfig;
use crate::error::AppResult;

/// TimescaleDB connection pool.
///
/// TimescaleDB is used for time-series storage of attestation history,
/// audit logs, metrics, and certificate data.
#[cfg(not(tarpaulin_include))]
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

#[cfg(not(tarpaulin_include))]
impl Database {
    /// Create a new database connection pool from config.
    pub async fn connect(config: &DatabaseConfig) -> AppResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.pool_size)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
            .connect(&config.url)
            .await?;

        Ok(Self { pool })
    }

    /// Get a reference to the underlying connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // TODO: add database migrations under migrations/ directory
    // and enable with sqlx::migrate!().run(&self.pool).await
}
