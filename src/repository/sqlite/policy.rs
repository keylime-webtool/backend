use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use crate::error::{AppError, AppResult};
use crate::models::policy::{ApprovalStatus, Policy, PolicyChange};
use crate::repository::PolicyRepository;

pub struct SqlitePolicyRepository {
    pool: SqlitePool,
}

impl SqlitePolicyRepository {
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

fn row_to_policy(row: &sqlx::sqlite::SqliteRow) -> Policy {
    Policy {
        id: row.get("id"),
        name: row.get("name"),
        kind: parse_enum(row.get::<&str, _>("kind")),
        version: row.get::<i32, _>("version") as u32,
        checksum: row.get("checksum"),
        entry_count: row.get::<i64, _>("entry_count") as u64,
        assigned_agents: row.get::<i64, _>("assigned_agents") as u64,
        created_at: row
            .get::<&str, _>("created_at")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        updated_at: row
            .get::<&str, _>("updated_at")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        updated_by: row.get("updated_by"),
        content: row.get("content"),
    }
}

fn row_to_policy_change(row: &sqlx::sqlite::SqliteRow) -> PolicyChange {
    PolicyChange {
        id: row.get("id"),
        policy_id: row.get("policy_id"),
        drafter: row.get("drafter"),
        approver: row.get("approver"),
        status: parse_enum(row.get::<&str, _>("status")),
        previous_version: row.get::<i32, _>("previous_version") as u32,
        proposed_version: row.get::<i32, _>("proposed_version") as u32,
        submitted_at: row
            .get::<&str, _>("submitted_at")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        expires_at: row
            .get::<&str, _>("expires_at")
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        approved_at: row
            .get::<Option<&str>, _>("approved_at")
            .map(|s| s.parse::<DateTime<Utc>>().expect("valid timestamp")),
    }
}

#[async_trait]
impl PolicyRepository for SqlitePolicyRepository {
    async fn create(&self, policy: &Policy) -> AppResult<Policy> {
        let kind = serialize_enum(&policy.kind);
        sqlx::query(
            "INSERT INTO policies (id, name, kind, version, checksum, entry_count, \
             assigned_agents, created_at, updated_at, updated_by, content) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&policy.id)
        .bind(&policy.name)
        .bind(&kind)
        .bind(policy.version as i32)
        .bind(&policy.checksum)
        .bind(policy.entry_count as i64)
        .bind(policy.assigned_agents as i64)
        .bind(policy.created_at.to_rfc3339())
        .bind(policy.updated_at.to_rfc3339())
        .bind(&policy.updated_by)
        .bind(&policy.content)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.message().contains("UNIQUE") {
                    return AppError::Conflict(format!("policy {} already exists", policy.id));
                }
            }
            AppError::Database(e)
        })?;

        Ok(policy.clone())
    }

    async fn get(&self, id: &str) -> AppResult<Option<Policy>> {
        let row = sqlx::query("SELECT * FROM policies WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.as_ref().map(row_to_policy))
    }

    async fn list(&self) -> AppResult<Vec<Policy>> {
        let rows = sqlx::query("SELECT * FROM policies")
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.iter().map(row_to_policy).collect())
    }

    async fn update(&self, id: &str, policy: &Policy) -> AppResult<Policy> {
        let mut tx = self.pool.begin().await?;

        let existing = sqlx::query("SELECT version FROM policies WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("policy {id} not found")))?;

        let current_version = existing.get::<i32, _>("version") as u32;
        let new_version = current_version + 1;
        let now = Utc::now();
        let kind = serialize_enum(&policy.kind);

        sqlx::query(
            "UPDATE policies SET name = ?, kind = ?, version = ?, checksum = ?, \
             entry_count = ?, content = ?, updated_by = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&policy.name)
        .bind(&kind)
        .bind(new_version as i32)
        .bind(&policy.checksum)
        .bind(policy.entry_count as i64)
        .bind(&policy.content)
        .bind(&policy.updated_by)
        .bind(now.to_rfc3339())
        .bind(id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let mut result = policy.clone();
        result.version = new_version;
        result.updated_at = now;
        Ok(result)
    }

    async fn delete(&self, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM policies WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("policy {id} not found")));
        }
        Ok(())
    }

    async fn list_versions(&self, _id: &str) -> AppResult<Vec<Policy>> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn diff(&self, _id: &str, _v1: u32, _v2: u32) -> AppResult<String> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn rollback(&self, _id: &str, _version: u32) -> AppResult<Policy> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn submit_for_approval(&self, change: &PolicyChange) -> AppResult<PolicyChange> {
        let now = Utc::now();
        let status = serialize_enum(&ApprovalStatus::PendingApproval);

        sqlx::query(
            "INSERT INTO policy_changes (id, policy_id, drafter, approver, status, \
             previous_version, proposed_version, submitted_at, expires_at, approved_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&change.id)
        .bind(&change.policy_id)
        .bind(&change.drafter)
        .bind(&change.approver)
        .bind(&status)
        .bind(change.previous_version as i32)
        .bind(change.proposed_version as i32)
        .bind(now.to_rfc3339())
        .bind(change.expires_at.to_rfc3339())
        .bind(change.approved_at.map(|t| t.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        let mut stored = change.clone();
        stored.status = ApprovalStatus::PendingApproval;
        stored.submitted_at = now;
        Ok(stored)
    }

    async fn approve(&self, change_id: &str, approver: &str) -> AppResult<PolicyChange> {
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query("SELECT * FROM policy_changes WHERE id = ?")
            .bind(change_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("change {change_id} not found")))?;

        let change = row_to_policy_change(&row);

        if change.drafter == approver {
            return Err(AppError::Forbidden(
                "drafter cannot approve their own change (SR-018)".into(),
            ));
        }

        if change.status != ApprovalStatus::PendingApproval {
            return Err(AppError::BadRequest(format!(
                "change is in {:?} status, expected pending_approval",
                change.status
            )));
        }

        let now = Utc::now();
        let approved_status = serialize_enum(&ApprovalStatus::Approved);

        sqlx::query(
            "UPDATE policy_changes SET status = ?, approver = ?, approved_at = ? WHERE id = ?",
        )
        .bind(&approved_status)
        .bind(approver)
        .bind(now.to_rfc3339())
        .bind(change_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let mut result = change;
        result.status = ApprovalStatus::Approved;
        result.approver = Some(approver.to_string());
        result.approved_at = Some(now);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::policy::PolicyKind;
    use crate::repository::sqlite::test_db;
    use chrono::Duration;
    use std::sync::Arc;

    fn make_test_policy(id: &str, name: &str) -> Policy {
        let now = Utc::now();
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            kind: PolicyKind::Ima,
            version: 1,
            checksum: "abc123".into(),
            entry_count: 10,
            assigned_agents: 0,
            created_at: now,
            updated_at: now,
            updated_by: "admin@example.com".into(),
            content: Some("policy content".into()),
        }
    }

    fn make_test_change(id: &str, policy_id: &str, drafter: &str) -> PolicyChange {
        let now = Utc::now();
        PolicyChange {
            id: id.to_string(),
            policy_id: policy_id.to_string(),
            drafter: drafter.to_string(),
            approver: None,
            status: ApprovalStatus::Draft,
            previous_version: 1,
            proposed_version: 2,
            submitted_at: now,
            expires_at: now + Duration::days(7),
            approved_at: None,
        }
    }

    #[tokio::test]
    async fn sqlite_create_and_get_policy() {
        let db = test_db().await;
        let repo: Arc<dyn PolicyRepository> = Arc::new(db.policy_repo());
        let policy = make_test_policy("pol-1", "ima-production");

        repo.create(&policy).await.unwrap();
        let retrieved = repo.get("pol-1").await.unwrap().unwrap();

        assert_eq!(retrieved.id, "pol-1");
        assert_eq!(retrieved.name, "ima-production");
        assert_eq!(retrieved.version, 1);
    }

    #[tokio::test]
    async fn sqlite_create_duplicate_returns_conflict() {
        let db = test_db().await;
        let repo = db.policy_repo();
        let policy = make_test_policy("pol-1", "ima-production");

        repo.create(&policy).await.unwrap();
        let result = repo.create(&policy).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_list_returns_all() {
        let db = test_db().await;
        let repo = db.policy_repo();

        repo.create(&make_test_policy("pol-1", "ima-prod"))
            .await
            .unwrap();
        repo.create(&make_test_policy("pol-2", "ima-staging"))
            .await
            .unwrap();

        let all = repo.list().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn sqlite_update_bumps_version() {
        let db = test_db().await;
        let repo = db.policy_repo();
        let policy = make_test_policy("pol-1", "ima-production");
        repo.create(&policy).await.unwrap();

        let mut updated = policy.clone();
        updated.entry_count = 42;
        updated.updated_by = "operator@example.com".into();

        let result = repo.update("pol-1", &updated).await.unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.entry_count, 42);
    }

    #[tokio::test]
    async fn sqlite_delete_removes_policy() {
        let db = test_db().await;
        let repo = db.policy_repo();
        repo.create(&make_test_policy("pol-1", "doomed"))
            .await
            .unwrap();

        repo.delete("pol-1").await.unwrap();
        let result = repo.get("pol-1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn sqlite_delete_nonexistent_returns_not_found() {
        let db = test_db().await;
        let repo = db.policy_repo();
        let result = repo.delete("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_submit_and_approve_change() {
        let db = test_db().await;
        let repo = db.policy_repo();
        let change = make_test_change("chg-1", "pol-1", "alice@example.com");

        let submitted = repo.submit_for_approval(&change).await.unwrap();
        assert_eq!(submitted.status, ApprovalStatus::PendingApproval);

        let approved = repo.approve("chg-1", "bob@example.com").await.unwrap();
        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.approver.as_deref(), Some("bob@example.com"));
    }

    #[tokio::test]
    async fn sqlite_approve_rejects_self_approval() {
        let db = test_db().await;
        let repo: Arc<dyn PolicyRepository> = Arc::new(db.policy_repo());
        let change = make_test_change("chg-1", "pol-1", "alice@example.com");

        repo.submit_for_approval(&change).await.unwrap();
        let result = repo.approve("chg-1", "alice@example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_update_nonexistent_returns_not_found() {
        let db = test_db().await;
        let repo = db.policy_repo();
        let policy = make_test_policy("nonexistent", "phantom");
        let result = repo.update("nonexistent", &policy).await;
        assert!(result.is_err());
    }
}
