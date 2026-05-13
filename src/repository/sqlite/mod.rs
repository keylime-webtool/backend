mod alert;
mod attestation;
mod audit;
mod policy;

pub use alert::SqliteAlertRepository;
pub use attestation::SqliteAttestationRepository;
pub use audit::SqliteAuditRepository;
pub use policy::SqlitePolicyRepository;

#[cfg(test)]
pub(crate) use alert::insert_alert;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

use std::sync::Arc;

use crate::error::AppResult;
use crate::repository::Repositories;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_agents TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL,
    created_timestamp TEXT NOT NULL,
    acknowledged_timestamp TEXT,
    assigned_to TEXT,
    investigation_notes TEXT,
    root_cause TEXT,
    resolution TEXT,
    auto_resolved INTEGER NOT NULL DEFAULT 0,
    escalation_count INTEGER NOT NULL DEFAULT 0,
    sla_window TEXT,
    source TEXT NOT NULL,
    external_ticket_id TEXT
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    version INTEGER NOT NULL,
    checksum TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    assigned_agents INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    content TEXT
);

CREATE TABLE IF NOT EXISTS policy_changes (
    id TEXT PRIMARY KEY NOT NULL,
    policy_id TEXT NOT NULL,
    drafter TEXT NOT NULL,
    approver TEXT,
    status TEXT NOT NULL,
    previous_version INTEGER NOT NULL,
    proposed_version INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_entries (
    id INTEGER PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_agent TEXT,
    result TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attestation_results (
    id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    success INTEGER NOT NULL,
    failure_type TEXT,
    failure_reason TEXT,
    latency_ms INTEGER NOT NULL,
    verifier_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS correlated_incidents (
    id TEXT PRIMARY KEY NOT NULL,
    failure_ids TEXT NOT NULL DEFAULT '[]',
    correlation_type TEXT NOT NULL,
    suggested_root_cause TEXT,
    recommended_action TEXT,
    created_at TEXT NOT NULL
);
";

pub struct SqliteDb {
    pub(crate) pool: SqlitePool,
}

impl SqliteDb {
    pub async fn connect(url: &str) -> AppResult<Self> {
        let options = SqliteConnectOptions::from_str(url)?.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await?;

        Ok(Self { pool })
    }

    pub async fn init_schema(&self) -> AppResult<()> {
        for statement in SCHEMA.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed).execute(&self.pool).await?;
            }
        }
        Ok(())
    }

    pub fn alert_repo(&self) -> SqliteAlertRepository {
        SqliteAlertRepository::new(self.pool.clone())
    }

    pub fn policy_repo(&self) -> SqlitePolicyRepository {
        SqlitePolicyRepository::new(self.pool.clone())
    }

    pub fn audit_repo(&self) -> SqliteAuditRepository {
        SqliteAuditRepository::new(self.pool.clone())
    }

    pub fn attestation_repo(&self) -> SqliteAttestationRepository {
        SqliteAttestationRepository::new(self.pool.clone())
    }

    pub fn repositories(&self) -> Repositories {
        Repositories {
            alert: Arc::new(self.alert_repo()),
            attestation: Arc::new(self.attestation_repo()),
            policy: Arc::new(self.policy_repo()),
            audit: Arc::new(self.audit_repo()),
        }
    }
}

#[cfg(test)]
pub(crate) async fn test_db() -> SqliteDb {
    let db = SqliteDb::connect("sqlite::memory:").await.unwrap();
    db.init_schema().await.unwrap();
    db
}
