pub mod alert;
pub mod attestation;
pub mod audit;
pub mod cache;
pub mod policy;
pub mod sqlite;

#[cfg(test)]
mod repository_tests;

pub use alert::{AlertRepository, InMemoryAlertRepository};
pub use attestation::{AttestationRepository, FallbackAttestationRepository};
pub use audit::{AuditFilter, AuditRepository, InMemoryAuditRepository};
pub use cache::{CacheBackend, InMemoryCacheBackend, RedisCacheBackend};
pub use policy::{InMemoryPolicyRepository, PolicyRepository};
pub use sqlite::SqliteDb;

use std::sync::Arc;

pub struct Repositories {
    pub alert: Arc<dyn AlertRepository>,
    pub attestation: Arc<dyn AttestationRepository>,
    pub policy: Arc<dyn PolicyRepository>,
    pub audit: Arc<dyn AuditRepository>,
}

impl Repositories {
    pub fn in_memory() -> Self {
        Self {
            alert: Arc::new(InMemoryAlertRepository::new_with_seed_data()),
            attestation: Arc::new(FallbackAttestationRepository::new()),
            policy: Arc::new(InMemoryPolicyRepository::new()),
            audit: Arc::new(InMemoryAuditRepository::new()),
        }
    }
}
