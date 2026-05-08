use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use crate::audit::logger::{AuditEntry, AuditLogger, AuditSeverity};
use crate::error::{AppError, AppResult};
use crate::repository::audit::AuditFilter;
use crate::repository::AuditRepository;

pub struct SqliteAuditRepository {
    pool: SqlitePool,
}

impl SqliteAuditRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn parse_severity(raw: &str) -> AuditSeverity {
    let quoted = format!("\"{raw}\"");
    serde_json::from_str(&quoted).unwrap_or_else(|_| {
        panic!("failed to deserialize severity: {raw}");
    })
}

fn serialize_severity(val: &AuditSeverity) -> String {
    let json = serde_json::to_string(val).expect("severity serialization");
    json.trim_matches('"').to_string()
}

fn row_to_entry(row: &sqlx::sqlite::SqliteRow) -> AuditEntry {
    AuditEntry {
        id: row.get::<i64, _>("id") as u64,
        timestamp: row
            .get::<&str, _>("timestamp")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        severity: parse_severity(row.get::<&str, _>("severity")),
        actor: row.get("actor"),
        action: row.get("action"),
        resource: row.get("resource"),
        source_ip: row.get("source_ip"),
        user_agent: row.get("user_agent"),
        result: row.get("result"),
        previous_hash: row.get("previous_hash"),
        entry_hash: row.get("entry_hash"),
    }
}

#[async_trait]
impl AuditRepository for SqliteAuditRepository {
    async fn append(&self, entry: AuditEntry) -> AppResult<()> {
        let severity = serialize_severity(&entry.severity);
        sqlx::query(
            "INSERT INTO audit_entries (id, timestamp, severity, actor, action, resource, \
             source_ip, user_agent, result, previous_hash, entry_hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.id as i64)
        .bind(entry.timestamp.to_rfc3339())
        .bind(&severity)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.resource)
        .bind(&entry.source_ip)
        .bind(&entry.user_agent)
        .bind(&entry.result)
        .bind(&entry.previous_hash)
        .bind(&entry.entry_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn query(&self, filter: &AuditFilter) -> AppResult<Vec<AuditEntry>> {
        let mut sql = "SELECT * FROM audit_entries WHERE 1=1".to_string();
        let mut binds: Vec<String> = Vec::new();

        if let Some(ref severity) = filter.severity {
            sql.push_str(" AND severity = ?");
            binds.push(severity.clone());
        }
        if let Some(ref action) = filter.action {
            sql.push_str(" AND action = ?");
            binds.push(action.clone());
        }
        if let Some(ref actor) = filter.actor {
            sql.push_str(" AND actor = ?");
            binds.push(actor.clone());
        }
        if let Some(ref start) = filter.start {
            sql.push_str(" AND timestamp >= ?");
            binds.push(start.clone());
        }
        if let Some(ref end) = filter.end {
            sql.push_str(" AND timestamp <= ?");
            binds.push(end.clone());
        }

        sql.push_str(" ORDER BY id ASC");

        let mut query = sqlx::query(&sql);
        for bind in &binds {
            query = query.bind(bind);
        }

        let rows = query.fetch_all(&self.pool).await?;
        Ok(rows.iter().map(row_to_entry).collect())
    }

    async fn verify_chain(&self) -> AppResult<()> {
        let entries = self.query(&AuditFilter::default()).await?;
        AuditLogger::verify_chain(&entries)
            .map_err(|e| AppError::Internal(format!("chain verification failed: {e}")))
    }

    async fn export(&self, filter: &AuditFilter) -> AppResult<Vec<AuditEntry>> {
        self.query(filter).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::logger::{AuditEntryParams, AuditLogger, AuditSeverity};
    use crate::repository::sqlite::test_db;

    #[tokio::test]
    async fn sqlite_append_and_query() {
        let db = test_db().await;
        let repo = db.audit_repo();
        let mut logger = AuditLogger::new(None, 1);

        let entry = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin@example.com",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });

        repo.append(entry).await.unwrap();
        let results = repo.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, "LOGIN");
    }

    #[tokio::test]
    async fn sqlite_verify_chain_valid() {
        let db = test_db().await;
        let repo = db.audit_repo();
        let mut logger = AuditLogger::new(None, 1);

        let e1 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });
        let e2 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Warning,
            actor: "admin",
            action: "UPDATE_POLICY",
            resource: "policy-1",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });

        repo.append(e1).await.unwrap();
        repo.append(e2).await.unwrap();
        assert!(repo.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn sqlite_verify_chain_detects_broken_link() {
        let db = test_db().await;
        let repo = db.audit_repo();
        let mut logger = AuditLogger::new(None, 1);

        let e1 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });
        repo.append(e1).await.unwrap();

        let mut rogue_logger = AuditLogger::new(Some("wrong_hash".into()), 2);
        let rogue = rogue_logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Critical,
            actor: "attacker",
            action: "DELETE",
            resource: "evidence",
            source_ip: "10.0.0.99",
            user_agent: None,
            result: "SUCCESS",
        });
        repo.append(rogue).await.unwrap();

        assert!(repo.verify_chain().await.is_err());
    }

    #[tokio::test]
    async fn sqlite_verify_chain_empty() {
        let db = test_db().await;
        let repo = db.audit_repo();
        assert!(repo.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn sqlite_query_filters_by_action() {
        let db = test_db().await;
        let repo = db.audit_repo();
        let mut logger = AuditLogger::new(None, 1);

        for action in &["LOGIN", "READ", "UPDATE"] {
            let entry = logger.create_entry(AuditEntryParams {
                severity: AuditSeverity::Info,
                actor: "admin",
                action,
                resource: "session",
                source_ip: "10.0.0.1",
                user_agent: None,
                result: "SUCCESS",
            });
            repo.append(entry).await.unwrap();
        }

        let filter = AuditFilter {
            action: Some("LOGIN".into()),
            ..Default::default()
        };
        let results = repo.query(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, "LOGIN");
    }

    #[tokio::test]
    async fn sqlite_query_filters_by_severity() {
        let db = test_db().await;
        let repo = db.audit_repo();
        let mut logger = AuditLogger::new(None, 1);

        for (severity, action) in [
            (AuditSeverity::Info, "LOGIN"),
            (AuditSeverity::Warning, "UPDATE"),
            (AuditSeverity::Critical, "DELETE"),
        ] {
            let entry = logger.create_entry(AuditEntryParams {
                severity,
                actor: "admin",
                action,
                resource: "session",
                source_ip: "10.0.0.1",
                user_agent: None,
                result: "SUCCESS",
            });
            repo.append(entry).await.unwrap();
        }

        let filter = AuditFilter {
            severity: Some("WARNING".into()),
            ..Default::default()
        };
        let results = repo.query(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, "UPDATE");
    }

    #[tokio::test]
    async fn sqlite_query_filters_by_actor() {
        let db = test_db().await;
        let repo = db.audit_repo();
        let mut logger = AuditLogger::new(None, 1);

        for actor in &["admin", "operator", "auditor"] {
            let entry = logger.create_entry(AuditEntryParams {
                severity: AuditSeverity::Info,
                actor,
                action: "LOGIN",
                resource: "session",
                source_ip: "10.0.0.1",
                user_agent: None,
                result: "SUCCESS",
            });
            repo.append(entry).await.unwrap();
        }

        let filter = AuditFilter {
            actor: Some("operator".into()),
            ..Default::default()
        };
        let results = repo.query(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor, "operator");
    }

    #[tokio::test]
    async fn sqlite_export_matches_query() {
        let db = test_db().await;
        let repo = db.audit_repo();
        let mut logger = AuditLogger::new(None, 1);

        let entry = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });
        repo.append(entry).await.unwrap();

        let filter = AuditFilter::default();
        let queried = repo.query(&filter).await.unwrap();
        let exported = repo.export(&filter).await.unwrap();

        assert_eq!(queried.len(), exported.len());
        assert_eq!(queried[0].entry_hash, exported[0].entry_hash);
    }
}
