use std::sync::RwLock;

use async_trait::async_trait;
use serde::Deserialize;

use crate::audit::logger::{AuditEntry, AuditLogger};
use crate::error::{AppError, AppResult};

#[derive(Debug, Default, Deserialize)]
pub struct AuditFilter {
    pub severity: Option<String>,
    pub action: Option<String>,
    pub actor: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
}

#[async_trait]
pub trait AuditRepository: Send + Sync + 'static {
    async fn append(&self, entry: AuditEntry) -> AppResult<()>;
    async fn query(&self, filter: &AuditFilter) -> AppResult<Vec<AuditEntry>>;
    async fn verify_chain(&self) -> AppResult<()>;
    async fn export(&self, filter: &AuditFilter) -> AppResult<Vec<AuditEntry>>;
}

pub struct InMemoryAuditRepository {
    entries: RwLock<Vec<AuditEntry>>,
}

impl InMemoryAuditRepository {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryAuditRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditRepository for InMemoryAuditRepository {
    async fn append(&self, entry: AuditEntry) -> AppResult<()> {
        let mut entries = self.entries.write().unwrap();
        entries.push(entry);
        Ok(())
    }

    async fn query(&self, _filter: &AuditFilter) -> AppResult<Vec<AuditEntry>> {
        let entries = self.entries.read().unwrap();
        Ok(entries.clone())
    }

    async fn verify_chain(&self) -> AppResult<()> {
        let entries = self.entries.read().unwrap();
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
    use std::sync::Arc;

    #[tokio::test]
    async fn append_and_query_entries() {
        let repo: Arc<dyn AuditRepository> = Arc::new(InMemoryAuditRepository::new());
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
    async fn verify_chain_passes_for_valid_entries() {
        let repo = InMemoryAuditRepository::new();
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
    async fn verify_chain_detects_broken_link() {
        let repo = InMemoryAuditRepository::new();
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

        // Create an entry with a deliberately wrong previous_hash
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
    async fn verify_chain_passes_for_empty_chain() {
        let repo: Arc<dyn AuditRepository> = Arc::new(InMemoryAuditRepository::new());
        assert!(repo.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn export_returns_same_as_query() {
        let repo = InMemoryAuditRepository::new();
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

        let filter = AuditFilter::default();
        let queried = repo.query(&filter).await.unwrap();
        let exported = repo.export(&filter).await.unwrap();

        assert_eq!(queried.len(), exported.len());
        for (q, e) in queried.iter().zip(exported.iter()) {
            assert_eq!(q.id, e.id);
            assert_eq!(q.action, e.action);
            assert_eq!(q.entry_hash, e.entry_hash);
        }
    }
}
