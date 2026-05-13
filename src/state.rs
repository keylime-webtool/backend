use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::time::Instant;

use crate::config::SshConfig;
use crate::keylime::client::KeylimeClient;
use crate::repository::{
    AlertRepository, AttestationRepository, AuditRepository, CacheBackend, PolicyRepository,
};
use crate::settings_store::{self, PersistedKeylime, PersistedSettings};

const DEDUP_INTERVAL: Duration = Duration::from_secs(30);

struct AttestationSnapshot {
    success: bool,
    recorded_at: Instant,
}

#[derive(Clone)]
pub struct AppState {
    keylime_inner: Arc<RwLock<Arc<KeylimeClient>>>,
    pub alert_repo: Arc<dyn AlertRepository>,
    pub attestation_repo: Arc<dyn AttestationRepository>,
    pub policy_repo: Arc<dyn PolicyRepository>,
    pub audit_repo: Arc<dyn AuditRepository>,
    pub cache: Arc<dyn CacheBackend>,
    config_path: Option<PathBuf>,
    seed_mock_data: Arc<AtomicBool>,
    ssh_config: Arc<SshConfig>,
    attestation_tracker: Arc<RwLock<HashMap<String, AttestationSnapshot>>>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keylime: KeylimeClient,
        alert_repo: Arc<dyn AlertRepository>,
        attestation_repo: Arc<dyn AttestationRepository>,
        policy_repo: Arc<dyn PolicyRepository>,
        audit_repo: Arc<dyn AuditRepository>,
        cache: Arc<dyn CacheBackend>,
        config_path: Option<PathBuf>,
        seed_mock_data: bool,
    ) -> Self {
        Self {
            keylime_inner: Arc::new(RwLock::new(Arc::new(keylime))),
            alert_repo,
            attestation_repo,
            policy_repo,
            audit_repo,
            cache,
            config_path,
            seed_mock_data: Arc::new(AtomicBool::new(seed_mock_data)),
            ssh_config: Arc::new(SshConfig::default()),
            attestation_tracker: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_ssh_config(mut self, ssh_config: SshConfig) -> Self {
        self.ssh_config = Arc::new(ssh_config);
        self
    }

    pub fn ssh_config(&self) -> &SshConfig {
        &self.ssh_config
    }

    pub fn keylime(&self) -> Arc<KeylimeClient> {
        self.keylime_inner.read().unwrap().clone()
    }

    pub fn swap_keylime(&self, new_client: KeylimeClient) {
        *self.keylime_inner.write().unwrap() = Arc::new(new_client);
    }

    pub fn seed_mock_data(&self) -> bool {
        self.seed_mock_data.load(Ordering::Relaxed)
    }

    pub fn set_seed_mock_data(&self, val: bool) {
        self.seed_mock_data.store(val, Ordering::Relaxed);
    }

    pub fn persist_settings(&self) {
        let Some(path) = self.config_path.clone() else {
            return;
        };
        let kl = self.keylime();
        let settings = PersistedSettings {
            keylime: Some(PersistedKeylime {
                verifier_url: kl.verifier_url().to_string(),
                registrar_url: kl.registrar_url().to_string(),
            }),
            mtls: kl.mtls_config().cloned(),
            seed_mock_data: if self.seed_mock_data() {
                Some(true)
            } else {
                None
            },
        };
        tokio::spawn(settings_store::save_persisted_settings(path, settings));
    }

    pub fn should_record_attestation(&self, agent_id: &str, success: bool) -> bool {
        let tracker = self.attestation_tracker.read().unwrap();
        match tracker.get(agent_id) {
            None => true,
            Some(snapshot) => {
                if snapshot.success != success {
                    return true;
                }
                snapshot.recorded_at.elapsed() >= DEDUP_INTERVAL
            }
        }
    }

    pub fn tracked_agent_ids(&self) -> Vec<String> {
        let tracker = self.attestation_tracker.read().unwrap();
        tracker.keys().cloned().collect()
    }

    pub fn tracked_success(&self, agent_id: &str) -> Option<bool> {
        let tracker = self.attestation_tracker.read().unwrap();
        tracker.get(agent_id).map(|s| s.success)
    }

    pub fn mark_recorded(&self, agent_id: &str, success: bool) {
        let mut tracker = self.attestation_tracker.write().unwrap();
        tracker.insert(
            agent_id.to_string(),
            AttestationSnapshot {
                success,
                recorded_at: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeylimeConfig;
    use crate::keylime::client::KeylimeClient;
    use crate::repository::{InMemoryCacheBackend, Repositories};

    fn test_state() -> AppState {
        let config = KeylimeConfig {
            verifier_url: "http://localhost:3000".into(),
            registrar_url: "http://localhost:3001".into(),
            mtls: None,
            timeout_secs: 5,
            observation_interval_secs: 30,
            circuit_breaker: Default::default(),
        };
        let client = KeylimeClient::new(config).unwrap();
        let repos = Repositories::in_memory();
        AppState::new(
            client,
            repos.alert,
            repos.attestation,
            repos.policy,
            repos.audit,
            Arc::new(InMemoryCacheBackend::new()),
            None,
            false,
        )
    }

    #[test]
    fn dedup_tracker_records_new_agent() {
        let state = test_state();
        assert!(state.should_record_attestation("agent-1", true));
    }

    #[test]
    fn dedup_tracker_blocks_duplicate_within_interval() {
        let state = test_state();
        state.mark_recorded("agent-1", true);
        assert!(!state.should_record_attestation("agent-1", true));
    }

    #[test]
    fn dedup_tracker_allows_state_change() {
        let state = test_state();
        state.mark_recorded("agent-1", true);
        assert!(state.should_record_attestation("agent-1", false));
    }

    #[test]
    fn dedup_tracker_allows_after_interval() {
        let state = test_state();
        {
            let mut tracker = state.attestation_tracker.write().unwrap();
            tracker.insert(
                "agent-1".to_string(),
                AttestationSnapshot {
                    success: true,
                    recorded_at: Instant::now() - DEDUP_INTERVAL - Duration::from_secs(1),
                },
            );
        }
        assert!(state.should_record_attestation("agent-1", true));
    }
}
