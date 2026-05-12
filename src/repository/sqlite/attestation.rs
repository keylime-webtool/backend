use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::attestation::{
    AttestationResult, CorrelatedIncident, FailureType, PipelineResult, TimelineBucket,
};
use crate::repository::AttestationRepository;

pub struct SqliteAttestationRepository {
    pool: SqlitePool,
}

impl SqliteAttestationRepository {
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

fn row_to_attestation_result(row: &sqlx::sqlite::SqliteRow) -> AttestationResult {
    AttestationResult {
        id: Uuid::parse_str(row.get::<&str, _>("id")).expect("valid uuid"),
        agent_id: Uuid::parse_str(row.get::<&str, _>("agent_id")).expect("valid uuid"),
        timestamp: row
            .get::<&str, _>("timestamp")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        success: row.get::<i32, _>("success") != 0,
        failure_type: row
            .get::<Option<&str>, _>("failure_type")
            .map(parse_enum::<FailureType>),
        failure_reason: row.get("failure_reason"),
        latency_ms: row.get::<i64, _>("latency_ms") as u64,
        verifier_id: row.get("verifier_id"),
    }
}

fn row_to_incident(row: &sqlx::sqlite::SqliteRow) -> CorrelatedIncident {
    let failure_ids_json: String = row.get("failure_ids");
    let failure_ids: Vec<Uuid> = serde_json::from_str(&failure_ids_json).unwrap_or_default();

    CorrelatedIncident {
        id: Uuid::parse_str(row.get::<&str, _>("id")).expect("valid uuid"),
        failure_ids,
        correlation_type: parse_enum(row.get::<&str, _>("correlation_type")),
        suggested_root_cause: row.get("suggested_root_cause"),
        recommended_action: row.get("recommended_action"),
        created_at: row
            .get::<&str, _>("created_at")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
    }
}

#[async_trait]
impl AttestationRepository for SqliteAttestationRepository {
    async fn store_result(&self, result: &AttestationResult) -> AppResult<()> {
        let failure_type = result.failure_type.as_ref().map(serialize_enum);

        sqlx::query(
            "INSERT INTO attestation_results (id, agent_id, timestamp, success, failure_type, \
             failure_reason, latency_ms, verifier_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(result.id.to_string())
        .bind(result.agent_id.to_string())
        .bind(result.timestamp.to_rfc3339())
        .bind(result.success as i32)
        .bind(&failure_type)
        .bind(&result.failure_reason)
        .bind(result.latency_ms as i64)
        .bind(&result.verifier_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn query_timeline(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        total_successful: u64,
        total_failed: u64,
        total_timed_out: u64,
    ) -> AppResult<Vec<TimelineBucket>> {
        let rows = sqlx::query(
            "SELECT strftime('%Y-%m-%dT%H:00:00+00:00', timestamp) AS hour, \
             SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS successful, \
             SUM(CASE WHEN success = 0 AND (failure_type IS NULL OR failure_type != 'TIMEOUT') \
                 THEN 1 ELSE 0 END) AS failed, \
             SUM(CASE WHEN success = 0 AND failure_type = 'TIMEOUT' \
                 THEN 1 ELSE 0 END) AS timed_out \
             FROM attestation_results \
             WHERE timestamp >= ? AND timestamp <= ? \
             GROUP BY strftime('%Y-%m-%dT%H:00:00+00:00', timestamp) \
             ORDER BY hour ASC",
        )
        .bind(start.to_rfc3339())
        .bind(end.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            let fallback = crate::repository::FallbackAttestationRepository::new();
            return fallback
                .query_timeline(start, end, total_successful, total_failed, total_timed_out)
                .await;
        }

        Ok(rows
            .iter()
            .map(|row| {
                let hour_str: &str = row.get("hour");
                TimelineBucket {
                    hour: hour_str
                        .parse::<DateTime<Utc>>()
                        .expect("valid hour timestamp"),
                    successful: row.get::<i64, _>("successful") as u64,
                    failed: row.get::<i64, _>("failed") as u64,
                    timed_out: row.get::<i64, _>("timed_out") as u64,
                }
            })
            .collect())
    }

    async fn get_pipeline(&self, _agent_id: Uuid) -> AppResult<Vec<PipelineResult>> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn list_failures(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<Vec<AttestationResult>> {
        let rows = sqlx::query(
            "SELECT * FROM attestation_results WHERE success = 0 \
             AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC",
        )
        .bind(start.to_rfc3339())
        .bind(end.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_attestation_result).collect())
    }

    async fn correlate_incidents(&self) -> AppResult<Vec<CorrelatedIncident>> {
        let rows = sqlx::query("SELECT * FROM correlated_incidents ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.iter().map(row_to_incident).collect())
    }

    async fn get_incident(&self, id: Uuid) -> AppResult<Option<CorrelatedIncident>> {
        let row = sqlx::query("SELECT * FROM correlated_incidents WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.as_ref().map(row_to_incident))
    }

    async fn query_counts(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<(u64, u64, u64)> {
        let row = sqlx::query(
            "SELECT \
             SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS successful, \
             SUM(CASE WHEN success = 0 AND (failure_type IS NULL OR failure_type != 'TIMEOUT') \
                 THEN 1 ELSE 0 END) AS failed, \
             SUM(CASE WHEN success = 0 AND failure_type = 'TIMEOUT' \
                 THEN 1 ELSE 0 END) AS timed_out \
             FROM attestation_results \
             WHERE timestamp >= ? AND timestamp <= ?",
        )
        .bind(start.to_rfc3339())
        .bind(end.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        let successful = row.get::<Option<i64>, _>("successful").unwrap_or(0) as u64;
        let failed = row.get::<Option<i64>, _>("failed").unwrap_or(0) as u64;
        let timed_out = row.get::<Option<i64>, _>("timed_out").unwrap_or(0) as u64;
        Ok((successful, failed, timed_out))
    }

    async fn count_agent_failures(
        &self,
        agent_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<u64> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS cnt FROM attestation_results \
             WHERE agent_id = ? AND success = 0 AND timestamp >= ? AND timestamp <= ?",
        )
        .bind(agent_id.to_string())
        .bind(start.to_rfc3339())
        .bind(end.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get::<i64, _>("cnt") as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::attestation::CorrelationType;
    use crate::repository::sqlite::test_db;
    use chrono::Duration;

    fn make_result(success: bool) -> AttestationResult {
        AttestationResult {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            success,
            failure_type: if success {
                None
            } else {
                Some(FailureType::QuoteInvalid)
            },
            failure_reason: if success {
                None
            } else {
                Some("invalid quote".into())
            },
            latency_ms: 42,
            verifier_id: "verifier-1".into(),
        }
    }

    #[tokio::test]
    async fn sqlite_store_and_list_failures() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        repo.store_result(&make_result(true)).await.unwrap();
        repo.store_result(&make_result(false)).await.unwrap();
        repo.store_result(&make_result(false)).await.unwrap();

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let failures = repo.list_failures(start, end).await.unwrap();
        assert_eq!(failures.len(), 2);
        assert!(!failures[0].success);
    }

    #[tokio::test]
    async fn sqlite_query_timeline_with_data() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        for _ in 0..5 {
            repo.store_result(&make_result(true)).await.unwrap();
        }
        for _ in 0..2 {
            repo.store_result(&make_result(false)).await.unwrap();
        }

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let buckets = repo.query_timeline(start, end, 0, 0, 0).await.unwrap();

        assert!(!buckets.is_empty());
        let total_success: u64 = buckets.iter().map(|b| b.successful).sum();
        let total_failed: u64 = buckets.iter().map(|b| b.failed).sum();
        assert_eq!(total_success, 5);
        assert_eq!(total_failed, 2);
    }

    #[tokio::test]
    async fn sqlite_query_timeline_falls_back_when_empty() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        let start = Utc::now() - Duration::hours(24);
        let end = Utc::now();
        let buckets = repo.query_timeline(start, end, 100, 10, 0).await.unwrap();

        assert_eq!(buckets.len(), 24);
        let total_success: u64 = buckets.iter().map(|b| b.successful).sum();
        assert_eq!(total_success, 100);
    }

    #[tokio::test]
    async fn sqlite_store_and_get_incident() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        let incident_id = Uuid::new_v4();
        let failure_ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let failure_ids_json = serde_json::to_string(&failure_ids).unwrap();

        sqlx::query(
            "INSERT INTO correlated_incidents (id, failure_ids, correlation_type, \
             suggested_root_cause, recommended_action, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(incident_id.to_string())
        .bind(&failure_ids_json)
        .bind("temporal")
        .bind("clock drift")
        .bind("sync NTP")
        .bind(Utc::now().to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();

        let incident = repo.get_incident(incident_id).await.unwrap().unwrap();
        assert_eq!(incident.failure_ids.len(), 2);
        assert_eq!(incident.correlation_type, CorrelationType::Temporal);
        assert_eq!(
            incident.suggested_root_cause.as_deref(),
            Some("clock drift")
        );
    }

    #[tokio::test]
    async fn sqlite_correlate_incidents_returns_multiple() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        for (i, cause) in ["clock drift", "network partition"].iter().enumerate() {
            let incident_id = Uuid::new_v4();
            let failure_ids = vec![Uuid::new_v4()];
            let failure_ids_json = serde_json::to_string(&failure_ids).unwrap();
            let created_at = (Utc::now() + Duration::seconds(i as i64)).to_rfc3339();

            sqlx::query(
                "INSERT INTO correlated_incidents (id, failure_ids, correlation_type, \
                 suggested_root_cause, recommended_action, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(incident_id.to_string())
            .bind(&failure_ids_json)
            .bind("temporal")
            .bind(*cause)
            .bind("investigate")
            .bind(&created_at)
            .execute(&db.pool)
            .await
            .unwrap();
        }

        let incidents = repo.correlate_incidents().await.unwrap();
        assert_eq!(incidents.len(), 2);
        assert_eq!(
            incidents[0].suggested_root_cause.as_deref(),
            Some("network partition"),
            "should be ordered by created_at DESC"
        );
    }

    #[tokio::test]
    async fn sqlite_list_failures_empty_when_none_match() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        repo.store_result(&make_result(true)).await.unwrap();
        repo.store_result(&make_result(true)).await.unwrap();

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let failures = repo.list_failures(start, end).await.unwrap();
        assert!(failures.is_empty());
    }

    #[tokio::test]
    async fn sqlite_query_counts() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        for _ in 0..5 {
            repo.store_result(&make_result(true)).await.unwrap();
        }
        for _ in 0..3 {
            repo.store_result(&make_result(false)).await.unwrap();
        }

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let (successful, failed, timed_out) = repo.query_counts(start, end).await.unwrap();
        assert_eq!(successful, 5);
        assert_eq!(failed, 3);
        assert_eq!(timed_out, 0);
    }

    #[tokio::test]
    async fn sqlite_query_counts_empty() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let (successful, failed, timed_out) = repo.query_counts(start, end).await.unwrap();
        assert_eq!(successful, 0);
        assert_eq!(failed, 0);
        assert_eq!(timed_out, 0);
    }

    #[tokio::test]
    async fn sqlite_count_agent_failures() {
        let db = test_db().await;
        let repo = db.attestation_repo();
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        for _ in 0..4 {
            let mut r = make_result(false);
            r.agent_id = agent_a;
            repo.store_result(&r).await.unwrap();
        }
        for _ in 0..2 {
            let mut r = make_result(false);
            r.agent_id = agent_b;
            repo.store_result(&r).await.unwrap();
        }
        let mut r = make_result(true);
        r.agent_id = agent_a;
        repo.store_result(&r).await.unwrap();

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        assert_eq!(
            repo.count_agent_failures(agent_a, start, end)
                .await
                .unwrap(),
            4
        );
        assert_eq!(
            repo.count_agent_failures(agent_b, start, end)
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn sqlite_count_agent_failures_empty() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        assert_eq!(
            repo.count_agent_failures(Uuid::new_v4(), start, end)
                .await
                .unwrap(),
            0
        );
    }

    fn make_timeout_result() -> AttestationResult {
        AttestationResult {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            success: false,
            failure_type: Some(FailureType::Timeout),
            failure_reason: Some("timeout".into()),
            latency_ms: 45,
            verifier_id: "verifier-1".into(),
        }
    }

    #[tokio::test]
    async fn sqlite_query_counts_separates_timeout_from_fail() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        for _ in 0..5 {
            repo.store_result(&make_result(true)).await.unwrap();
        }
        for _ in 0..3 {
            repo.store_result(&make_result(false)).await.unwrap();
        }
        for _ in 0..2 {
            repo.store_result(&make_timeout_result()).await.unwrap();
        }

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let (successful, failed, timed_out) = repo.query_counts(start, end).await.unwrap();
        assert_eq!(successful, 5);
        assert_eq!(failed, 3);
        assert_eq!(timed_out, 2);
    }

    #[tokio::test]
    async fn sqlite_timeline_separates_timeout_from_fail() {
        let db = test_db().await;
        let repo = db.attestation_repo();

        for _ in 0..4 {
            repo.store_result(&make_result(true)).await.unwrap();
        }
        for _ in 0..2 {
            repo.store_result(&make_result(false)).await.unwrap();
        }
        for _ in 0..3 {
            repo.store_result(&make_timeout_result()).await.unwrap();
        }

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let buckets = repo.query_timeline(start, end, 0, 0, 0).await.unwrap();

        let total_success: u64 = buckets.iter().map(|b| b.successful).sum();
        let total_failed: u64 = buckets.iter().map(|b| b.failed).sum();
        let total_timed_out: u64 = buckets.iter().map(|b| b.timed_out).sum();
        assert_eq!(total_success, 4);
        assert_eq!(total_failed, 2);
        assert_eq!(total_timed_out, 3);
    }
}
