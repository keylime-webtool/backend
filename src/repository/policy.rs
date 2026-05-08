use std::sync::RwLock;

use async_trait::async_trait;
use chrono::Utc;

use crate::error::{AppError, AppResult};
use crate::models::policy::{ApprovalStatus, Policy, PolicyChange};

#[async_trait]
pub trait PolicyRepository: Send + Sync + 'static {
    async fn create(&self, policy: &Policy) -> AppResult<Policy>;
    async fn get(&self, id: &str) -> AppResult<Option<Policy>>;
    async fn list(&self) -> AppResult<Vec<Policy>>;
    async fn update(&self, id: &str, policy: &Policy) -> AppResult<Policy>;
    async fn delete(&self, id: &str) -> AppResult<()>;
    async fn list_versions(&self, id: &str) -> AppResult<Vec<Policy>>;
    async fn diff(&self, id: &str, v1: u32, v2: u32) -> AppResult<String>;
    async fn rollback(&self, id: &str, version: u32) -> AppResult<Policy>;
    async fn submit_for_approval(&self, change: &PolicyChange) -> AppResult<PolicyChange>;
    async fn approve(&self, change_id: &str, approver: &str) -> AppResult<PolicyChange>;
}

pub struct InMemoryPolicyRepository {
    policies: RwLock<Vec<Policy>>,
    changes: RwLock<Vec<PolicyChange>>,
}

impl InMemoryPolicyRepository {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            changes: RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryPolicyRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyRepository for InMemoryPolicyRepository {
    async fn create(&self, policy: &Policy) -> AppResult<Policy> {
        let mut policies = self.policies.write().unwrap();
        if policies.iter().any(|p| p.id == policy.id) {
            return Err(AppError::Conflict(format!(
                "policy {} already exists",
                policy.id
            )));
        }
        let stored = policy.clone();
        policies.push(stored.clone());
        Ok(stored)
    }

    async fn get(&self, id: &str) -> AppResult<Option<Policy>> {
        let policies = self.policies.read().unwrap();
        Ok(policies.iter().find(|p| p.id == id).cloned())
    }

    async fn list(&self) -> AppResult<Vec<Policy>> {
        let policies = self.policies.read().unwrap();
        Ok(policies.clone())
    }

    async fn update(&self, id: &str, policy: &Policy) -> AppResult<Policy> {
        let mut policies = self.policies.write().unwrap();
        let existing = policies
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| AppError::NotFound(format!("policy {id} not found")))?;

        existing.name = policy.name.clone();
        existing.kind = policy.kind;
        existing.checksum = policy.checksum.clone();
        existing.entry_count = policy.entry_count;
        existing.content = policy.content.clone();
        existing.updated_by = policy.updated_by.clone();
        existing.updated_at = Utc::now();
        existing.version += 1;
        Ok(existing.clone())
    }

    async fn delete(&self, id: &str) -> AppResult<()> {
        let mut policies = self.policies.write().unwrap();
        let len_before = policies.len();
        policies.retain(|p| p.id != id);
        if policies.len() == len_before {
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
        let mut stored = change.clone();
        stored.status = ApprovalStatus::PendingApproval;
        stored.submitted_at = Utc::now();
        let mut changes = self.changes.write().unwrap();
        changes.push(stored.clone());
        Ok(stored)
    }

    // SR-018: drafter != approver enforcement
    async fn approve(&self, change_id: &str, approver: &str) -> AppResult<PolicyChange> {
        let mut changes = self.changes.write().unwrap();
        let change = changes
            .iter_mut()
            .find(|c| c.id == change_id)
            .ok_or_else(|| AppError::NotFound(format!("change {change_id} not found")))?;

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

        change.status = ApprovalStatus::Approved;
        change.approver = Some(approver.to_string());
        change.approved_at = Some(Utc::now());
        Ok(change.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::policy::PolicyKind;
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
    async fn create_and_get_policy() {
        let repo: Arc<dyn PolicyRepository> = Arc::new(InMemoryPolicyRepository::new());
        let policy = make_test_policy("pol-1", "ima-production");

        repo.create(&policy).await.unwrap();
        let retrieved = repo.get("pol-1").await.unwrap().unwrap();

        assert_eq!(retrieved.id, "pol-1");
        assert_eq!(retrieved.name, "ima-production");
        assert_eq!(retrieved.version, 1);
    }

    #[tokio::test]
    async fn create_duplicate_returns_conflict() {
        let repo = InMemoryPolicyRepository::new();
        let policy = make_test_policy("pol-1", "ima-production");

        repo.create(&policy).await.unwrap();
        let result = repo.create(&policy).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_returns_all_policies() {
        let repo: Arc<dyn PolicyRepository> = Arc::new(InMemoryPolicyRepository::new());

        repo.create(&make_test_policy("pol-1", "ima-prod"))
            .await
            .unwrap();
        repo.create(&make_test_policy("pol-2", "ima-staging"))
            .await
            .unwrap();
        repo.create(&make_test_policy("pol-3", "mb-policy"))
            .await
            .unwrap();

        let all = repo.list().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn update_bumps_version() {
        let repo = InMemoryPolicyRepository::new();
        let policy = make_test_policy("pol-1", "ima-production");
        repo.create(&policy).await.unwrap();

        let mut updated = policy.clone();
        updated.entry_count = 42;
        updated.updated_by = "operator@example.com".into();

        let result = repo.update("pol-1", &updated).await.unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.entry_count, 42);
        assert_eq!(result.updated_by, "operator@example.com");
    }

    #[tokio::test]
    async fn delete_removes_policy() {
        let repo: Arc<dyn PolicyRepository> = Arc::new(InMemoryPolicyRepository::new());
        repo.create(&make_test_policy("pol-1", "doomed"))
            .await
            .unwrap();

        repo.delete("pol-1").await.unwrap();

        let result = repo.get("pol-1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let repo: Arc<dyn PolicyRepository> = Arc::new(InMemoryPolicyRepository::new());
        let result = repo.get("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_not_found() {
        let repo = InMemoryPolicyRepository::new();
        let result = repo.delete("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn submit_and_approve_change() {
        let repo = InMemoryPolicyRepository::new();
        let change = make_test_change("chg-1", "pol-1", "alice@example.com");

        let submitted = repo.submit_for_approval(&change).await.unwrap();
        assert_eq!(submitted.status, ApprovalStatus::PendingApproval);

        let approved = repo.approve("chg-1", "bob@example.com").await.unwrap();
        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.approver.as_deref(), Some("bob@example.com"));
        assert!(approved.approved_at.is_some());
    }

    #[tokio::test]
    async fn approve_rejects_when_drafter_equals_approver() {
        let repo: Arc<dyn PolicyRepository> = Arc::new(InMemoryPolicyRepository::new());
        let change = make_test_change("chg-1", "pol-1", "alice@example.com");

        repo.submit_for_approval(&change).await.unwrap();
        let result = repo.approve("chg-1", "alice@example.com").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn approve_rejects_non_pending_change() {
        let repo = InMemoryPolicyRepository::new();
        let change = make_test_change("chg-1", "pol-1", "alice@example.com");

        repo.submit_for_approval(&change).await.unwrap();
        repo.approve("chg-1", "bob@example.com").await.unwrap();

        let result = repo.approve("chg-1", "charlie@example.com").await;
        assert!(result.is_err());
    }
}
