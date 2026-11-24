use std::sync::{Arc, Mutex};

use crate::audit::logger::{AuditEntry, AuditEntryParams, AuditLogger};
use crate::error::AppResult;
use crate::repository::audit::AuditFilter;
use crate::repository::AuditRepository;

/// Records tamper-evident audit entries into an [AuditRepository] (SR-015).
///
/// Owns the [AuditLogger] chain tip so that every recorded entry is linked
/// to the previous one, and serializes entry creation so ids and hashes
/// remain contiguous under concurrent handler calls.
pub struct AuditService {
    repo: Arc<dyn AuditRepository>,
    logger: Mutex<AuditLogger>,
}

impl AuditService {
    /// Start a fresh hash chain against `repo`.
    pub fn new(repo: Arc<dyn AuditRepository>) -> Self {
        Self {
            repo,
            logger: Mutex::new(AuditLogger::new(None, 1)),
        }
    }

    /// Resume the hash chain from the repository's persisted tip (FR-061).
    ///
    /// With SQLite persistence this keeps the chain unbroken across restarts;
    /// on an empty repository it is equivalent to [AuditService::new].
    pub async fn resume(repo: Arc<dyn AuditRepository>) -> AppResult<Self> {
        let entries = repo.query(&AuditFilter::default()).await?;
        let (last_hash, next_id) = match entries.last() {
            Some(tip) => (Some(tip.entry_hash.clone()), tip.id + 1),
            None => (None, 1),
        };
        Ok(Self {
            repo,
            logger: Mutex::new(AuditLogger::new(last_hash, next_id)),
        })
    }

    /// Build the next chained entry and persist it.
    pub async fn record(&self, params: AuditEntryParams<'_>) -> AppResult<()> {
        let entry = self.next_entry(params);
        self.repo.append(entry).await
    }

    fn next_entry(&self, params: AuditEntryParams<'_>) -> AuditEntry {
        // A poisoned lock means another recording panicked mid-chain;
        // propagating the panic is safer than forking the chain.
        self.logger.lock().unwrap().create_entry(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::logger::AuditSeverity;
    use crate::repository::InMemoryAuditRepository;

    fn system_action(action: &'static str, resource: &'static str) -> AuditEntryParams<'static> {
        AuditEntryParams::system(AuditSeverity::Info, action, resource, "SUCCESS")
    }

    #[tokio::test]
    async fn record_appends_chained_entries() {
        let repo: Arc<dyn AuditRepository> = Arc::new(InMemoryAuditRepository::new());
        let service = AuditService::new(repo.clone());

        service
            .record(system_action("LOGIN", "session"))
            .await
            .unwrap();
        service
            .record(system_action("READ", "agents"))
            .await
            .unwrap();

        let entries = repo.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
        assert!(repo.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn record_assigns_sequential_ids() {
        let repo: Arc<dyn AuditRepository> = Arc::new(InMemoryAuditRepository::new());
        let service = AuditService::new(repo.clone());

        service.record(system_action("A", "r1")).await.unwrap();
        service.record(system_action("B", "r2")).await.unwrap();
        service.record(system_action("C", "r3")).await.unwrap();

        let entries = repo.query(&AuditFilter::default()).await.unwrap();
        let ids: Vec<u64> = entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn resume_continues_from_persisted_tip() {
        let repo: Arc<dyn AuditRepository> = Arc::new(InMemoryAuditRepository::new());
        let first = AuditService::new(repo.clone());
        first.record(system_action("A", "r1")).await.unwrap();
        first.record(system_action("B", "r2")).await.unwrap();
        let tip_hash = repo
            .query(&AuditFilter::default())
            .await
            .unwrap()
            .last()
            .unwrap()
            .entry_hash
            .clone();

        let resumed = AuditService::resume(repo.clone()).await.unwrap();
        resumed.record(system_action("C", "r3")).await.unwrap();

        let entries = repo.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].id, 3);
        assert_eq!(entries[2].previous_hash, tip_hash);
        assert!(repo.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn resume_on_empty_repository_starts_fresh_chain() {
        let repo: Arc<dyn AuditRepository> = Arc::new(InMemoryAuditRepository::new());

        let service = AuditService::resume(repo.clone()).await.unwrap();
        service.record(system_action("A", "r1")).await.unwrap();

        let entries = repo.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 1);
        assert!(repo.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn system_params_use_placeholder_actor() {
        let params = AuditEntryParams::system(
            AuditSeverity::Warning,
            "alert_action",
            "alert-42",
            "escalated",
        );
        let repo: Arc<dyn AuditRepository> = Arc::new(InMemoryAuditRepository::new());
        let service = AuditService::new(repo.clone());
        service.record(params).await.unwrap();

        let entries = repo.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(entries[0].actor, "system");
        assert_eq!(entries[0].action, "alert_action");
        assert_eq!(entries[0].resource, "alert-42");
        assert_eq!(entries[0].result, "escalated");
    }

    #[tokio::test]
    async fn sqlite_resume_keeps_chain_valid_across_service_restart() {
        use crate::repository::sqlite::test_db;

        let db = test_db().await;
        let repo: Arc<dyn AuditRepository> = Arc::new(db.audit_repo());

        let first = AuditService::new(repo.clone());
        first
            .record(system_action("config_change", "settings/keylime"))
            .await
            .unwrap();

        let restarted = AuditService::resume(repo.clone()).await.unwrap();
        restarted
            .record(system_action("config_change", "settings/certificates"))
            .await
            .unwrap();

        let entries = repo.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
        assert!(repo.verify_chain().await.is_ok());
    }
}
