use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::models::alert::{seed_alerts, Alert, AlertSummary};
use crate::repository::AlertRepository;

pub struct SqliteAlertRepository {
    pool: SqlitePool,
}

impl SqliteAlertRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn parse_enum<T: serde::de::DeserializeOwned>(raw: &str) -> T {
    let quoted = format!("\"{raw}\"");
    serde_json::from_str(&quoted).unwrap_or_else(|_| {
        panic!("failed to deserialize enum value: {raw}");
    })
}

fn serialize_enum<T: serde::Serialize>(val: &T) -> String {
    let json = serde_json::to_string(val).expect("enum serialization");
    json.trim_matches('"').to_string()
}

fn row_to_alert(row: &sqlx::sqlite::SqliteRow) -> Alert {
    let agents_json: String = row.get("affected_agents");
    let affected_agents: Vec<String> = serde_json::from_str(&agents_json).unwrap_or_default();

    Alert {
        id: Uuid::parse_str(row.get::<&str, _>("id")).expect("valid uuid"),
        alert_type: parse_enum(row.get::<&str, _>("alert_type")),
        severity: parse_enum(row.get::<&str, _>("severity")),
        description: row.get("description"),
        affected_agents,
        state: parse_enum(row.get::<&str, _>("state")),
        created_timestamp: row
            .get::<&str, _>("created_timestamp")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        acknowledged_timestamp: row
            .get::<Option<&str>, _>("acknowledged_timestamp")
            .map(|s| s.parse::<DateTime<Utc>>().expect("valid timestamp")),
        assigned_to: row.get("assigned_to"),
        investigation_notes: row.get("investigation_notes"),
        root_cause: row.get("root_cause"),
        resolution: row.get("resolution"),
        auto_resolved: row.get::<i32, _>("auto_resolved") != 0,
        escalation_count: row.get::<i32, _>("escalation_count") as u32,
        sla_window: row.get("sla_window"),
        source: row.get("source"),
        external_ticket_id: row.get("external_ticket_id"),
        mock: row.get::<i32, _>("mock") != 0,
    }
}

#[async_trait]
impl AlertRepository for SqliteAlertRepository {
    async fn list(
        &self,
        severity: Option<&str>,
        state: Option<&str>,
        include_mock: bool,
    ) -> Vec<Alert> {
        let mut sql = "SELECT * FROM alerts WHERE 1=1".to_string();
        if !include_mock {
            sql.push_str(" AND mock = 0");
        }
        if severity.is_some() {
            sql.push_str(" AND severity = ?");
        }
        if state.is_some() {
            sql.push_str(" AND state = ?");
        }

        let mut query = sqlx::query(&sql);
        if let Some(sev) = severity {
            query = query.bind(sev);
        }
        if let Some(st) = state {
            query = query.bind(st);
        }

        query
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default()
            .iter()
            .map(row_to_alert)
            .collect()
    }

    async fn get(&self, id: Uuid) -> Option<Alert> {
        sqlx::query("SELECT * FROM alerts WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()
            .map(|row| row_to_alert(&row))
    }

    async fn summary(&self, include_mock: bool) -> AlertSummary {
        let mock_filter = if include_mock { "" } else { "WHERE mock = 0" };
        let sql = format!(
            "SELECT
                COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
                COUNT(*) FILTER (WHERE severity = 'warning') AS warnings,
                COUNT(*) FILTER (WHERE severity = 'info') AS info,
                COUNT(*) FILTER (WHERE severity = 'critical'
                    AND state NOT IN ('resolved', 'dismissed')) AS active_critical,
                COUNT(*) FILTER (WHERE severity = 'warning'
                    AND state NOT IN ('resolved', 'dismissed')) AS active_warnings
            FROM alerts {mock_filter}",
        );
        let row = sqlx::query(&sql).fetch_one(&self.pool).await;

        match row {
            Ok(r) => {
                let active_critical = r.get::<i64, _>("active_critical") as u64;
                let active_warnings = r.get::<i64, _>("active_warnings") as u64;
                AlertSummary {
                    critical: r.get::<i64, _>("critical") as u64,
                    warnings: r.get::<i64, _>("warnings") as u64,
                    info: r.get::<i64, _>("info") as u64,
                    active_alerts: active_critical + active_warnings,
                    active_critical,
                    active_warnings,
                }
            }
            Err(_) => AlertSummary {
                critical: 0,
                warnings: 0,
                info: 0,
                active_alerts: 0,
                active_critical: 0,
                active_warnings: 0,
            },
        }
    }

    async fn acknowledge(&self, id: Uuid) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT state FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("alert {id} not found"))?;

        let state: &str = row.get("state");
        if state != "new" {
            return Err(format!(
                "cannot acknowledge alert in {state} state \u{2014} must be New"
            ));
        }

        sqlx::query(
            "UPDATE alerts SET state = 'acknowledged', acknowledged_timestamp = ? WHERE id = ?",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(&id_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn investigate(&self, id: Uuid, assigned_to: Option<String>) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT state, acknowledged_timestamp FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("alert {id} not found"))?;

        let state: &str = row.get("state");
        if state != "new" && state != "acknowledged" {
            return Err(format!(
                "cannot investigate alert in {state} state \u{2014} must be New or Acknowledged"
            ));
        }

        let ack_ts: Option<&str> = row.get("acknowledged_timestamp");
        let now = Utc::now().to_rfc3339();
        let ack_value = match ack_ts {
            Some(ts) => ts.to_string(),
            None => now.clone(),
        };

        sqlx::query(
            "UPDATE alerts SET state = 'under_investigation', \
             acknowledged_timestamp = ?, assigned_to = COALESCE(?, assigned_to) WHERE id = ?",
        )
        .bind(&ack_value)
        .bind(&assigned_to)
        .bind(&id_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn resolve(&self, id: Uuid, resolution: Option<String>) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT state FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("alert {id} not found"))?;

        let state: &str = row.get("state");
        if state == "resolved" || state == "dismissed" {
            return Err(format!("alert already in terminal state {state}"));
        }

        sqlx::query(
            "UPDATE alerts SET state = 'resolved', resolution = COALESCE(?, resolution) WHERE id = ?",
        )
        .bind(&resolution)
        .bind(&id_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn dismiss(&self, id: Uuid) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT state FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("alert {id} not found"))?;

        let state: &str = row.get("state");
        if state == "resolved" || state == "dismissed" {
            return Err(format!("alert already in terminal state {state}"));
        }

        sqlx::query("UPDATE alerts SET state = 'dismissed' WHERE id = ?")
            .bind(&id_str)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn seed_if_empty(&self) {
        let count: Result<(i64,), _> = sqlx::query_as("SELECT COUNT(*) FROM alerts")
            .fetch_one(&self.pool)
            .await;
        match count {
            Ok((0,)) => {
                tracing::info!("seeding alerts table with mock data");
                for alert in seed_alerts() {
                    insert_alert(&self.pool, &alert).await;
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("failed to check alerts count for seeding: {e}"),
        }
    }

    async fn escalate(&self, id: Uuid) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT state FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("alert {id} not found"))?;

        let state: &str = row.get("state");
        if state == "resolved" || state == "dismissed" {
            return Err(format!("cannot escalate alert in terminal state {state}"));
        }

        sqlx::query("UPDATE alerts SET escalation_count = escalation_count + 1 WHERE id = ?")
            .bind(&id_str)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

pub(crate) async fn insert_alert(pool: &SqlitePool, alert: &Alert) {
    let agents_json = serde_json::to_string(&alert.affected_agents).unwrap();
    sqlx::query(
        "INSERT INTO alerts (id, alert_type, severity, description, affected_agents, state, \
         created_timestamp, acknowledged_timestamp, assigned_to, investigation_notes, \
         root_cause, resolution, auto_resolved, escalation_count, sla_window, source, \
         external_ticket_id, mock) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(alert.id.to_string())
    .bind(serialize_enum(&alert.alert_type))
    .bind(serialize_enum(&alert.severity))
    .bind(&alert.description)
    .bind(&agents_json)
    .bind(serialize_enum(&alert.state))
    .bind(alert.created_timestamp.to_rfc3339())
    .bind(alert.acknowledged_timestamp.map(|t| t.to_rfc3339()))
    .bind(&alert.assigned_to)
    .bind(&alert.investigation_notes)
    .bind(&alert.root_cause)
    .bind(&alert.resolution)
    .bind(alert.auto_resolved as i32)
    .bind(alert.escalation_count as i32)
    .bind(&alert.sla_window)
    .bind(&alert.source)
    .bind(&alert.external_ticket_id)
    .bind(alert.mock as i32)
    .execute(pool)
    .await
    .expect("insert test alert");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::alert::{AlertSeverity, AlertState, AlertType};
    use crate::repository::sqlite::test_db;
    use std::sync::Arc;

    fn make_alert(id: &str, severity: AlertSeverity, state: AlertState) -> Alert {
        Alert {
            id: Uuid::parse_str(id).unwrap(),
            alert_type: AlertType::AttestationFailure,
            severity,
            description: "test alert".into(),
            affected_agents: vec!["agent-1".into()],
            state,
            created_timestamp: Utc::now(),
            acknowledged_timestamp: None,
            assigned_to: None,
            investigation_notes: None,
            root_cause: None,
            resolution: None,
            auto_resolved: false,
            escalation_count: 0,
            sla_window: None,
            source: "test".into(),
            external_ticket_id: None,
            mock: false,
        }
    }

    async fn seeded_repo() -> (Arc<dyn AlertRepository>, Uuid, Uuid, Uuid) {
        let db = test_db().await;
        let repo = db.alert_repo();

        let id_new = Uuid::parse_str("a0000001-0000-4000-8000-000000000001").unwrap();
        let id_acked = Uuid::parse_str("a0000001-0000-4000-8000-000000000002").unwrap();
        let id_resolved = Uuid::parse_str("a0000001-0000-4000-8000-000000000003").unwrap();

        insert_alert(
            &db.pool,
            &make_alert(
                "a0000001-0000-4000-8000-000000000001",
                AlertSeverity::Critical,
                AlertState::New,
            ),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_alert(
                "a0000001-0000-4000-8000-000000000002",
                AlertSeverity::Warning,
                AlertState::Acknowledged,
            ),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_alert(
                "a0000001-0000-4000-8000-000000000003",
                AlertSeverity::Info,
                AlertState::Resolved,
            ),
        )
        .await;

        (Arc::new(repo), id_new, id_acked, id_resolved)
    }

    #[tokio::test]
    async fn sqlite_list_all() {
        let (repo, _, _, _) = seeded_repo().await;
        let all = repo.list(None, None, true).await;
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn sqlite_filter_by_severity() {
        let (repo, _, _, _) = seeded_repo().await;
        let critical = repo.list(Some("critical"), None, true).await;
        assert_eq!(critical.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_filter_by_state() {
        let (repo, _, _, _) = seeded_repo().await;
        let new = repo.list(None, Some("new"), true).await;
        assert_eq!(new.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_get_existing() {
        let (repo, id_new, _, _) = seeded_repo().await;
        let alert = repo.get(id_new).await;
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
    }

    #[tokio::test]
    async fn sqlite_get_missing() {
        let (repo, _, _, _) = seeded_repo().await;
        let alert = repo.get(Uuid::nil()).await;
        assert!(alert.is_none());
    }

    #[tokio::test]
    async fn sqlite_acknowledge() {
        let (repo, id_new, _, _) = seeded_repo().await;
        repo.acknowledge(id_new).await.unwrap();
        let alert = repo.get(id_new).await.unwrap();
        assert_eq!(alert.state, AlertState::Acknowledged);
        assert!(alert.acknowledged_timestamp.is_some());
    }

    #[tokio::test]
    async fn sqlite_acknowledge_rejects_non_new() {
        let (repo, _, id_acked, _) = seeded_repo().await;
        let result = repo.acknowledge(id_acked).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_investigate_sets_assignee() {
        let (repo, id_new, _, _) = seeded_repo().await;
        repo.investigate(id_new, Some("analyst@test.com".into()))
            .await
            .unwrap();
        let alert = repo.get(id_new).await.unwrap();
        assert_eq!(alert.state, AlertState::UnderInvestigation);
        assert_eq!(alert.assigned_to.as_deref(), Some("analyst@test.com"));
    }

    #[tokio::test]
    async fn sqlite_resolve() {
        let (repo, id_new, _, _) = seeded_repo().await;
        repo.resolve(id_new, Some("fixed".into())).await.unwrap();
        let alert = repo.get(id_new).await.unwrap();
        assert_eq!(alert.state, AlertState::Resolved);
        assert_eq!(alert.resolution.as_deref(), Some("fixed"));
    }

    #[tokio::test]
    async fn sqlite_resolve_rejects_terminal() {
        let (repo, _, _, id_resolved) = seeded_repo().await;
        let result = repo.resolve(id_resolved, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_dismiss() {
        let (repo, id_new, _, _) = seeded_repo().await;
        repo.dismiss(id_new).await.unwrap();
        let alert = repo.get(id_new).await.unwrap();
        assert_eq!(alert.state, AlertState::Dismissed);
    }

    #[tokio::test]
    async fn sqlite_escalate() {
        let (repo, id_new, _, _) = seeded_repo().await;
        repo.escalate(id_new).await.unwrap();
        let alert = repo.get(id_new).await.unwrap();
        assert_eq!(alert.escalation_count, 1);
    }

    #[tokio::test]
    async fn sqlite_summary() {
        let (repo, _, _, _) = seeded_repo().await;
        let summary = repo.summary(true).await;
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.active_critical, 1);
        assert_eq!(summary.active_warnings, 1);
        assert_eq!(summary.active_alerts, 2);
    }

    #[tokio::test]
    async fn sqlite_dismiss_rejects_already_dismissed() {
        let (repo, id_new, _, _) = seeded_repo().await;
        repo.dismiss(id_new).await.unwrap();
        let result = repo.dismiss(id_new).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_escalate_rejects_terminal_state() {
        let (repo, _, _, id_resolved) = seeded_repo().await;
        let result = repo.escalate(id_resolved).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_investigate_rejects_resolved() {
        let (repo, _, _, id_resolved) = seeded_repo().await;
        let result = repo.investigate(id_resolved, None).await;
        assert!(result.is_err());
    }
}
