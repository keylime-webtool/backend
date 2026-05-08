use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::config::SshConfig;
use crate::keylime::client::KeylimeClient;
use crate::repository::{
    AlertRepository, AttestationRepository, AuditRepository, CacheBackend, PolicyRepository,
};
use crate::settings_store::{self, PersistedKeylime, PersistedSettings};

#[derive(Clone)]
pub struct AppState {
    keylime_inner: Arc<RwLock<Arc<KeylimeClient>>>,
    pub alert_repo: Arc<dyn AlertRepository>,
    pub attestation_repo: Arc<dyn AttestationRepository>,
    pub policy_repo: Arc<dyn PolicyRepository>,
    pub audit_repo: Arc<dyn AuditRepository>,
    pub cache: Arc<dyn CacheBackend>,
    config_path: Option<PathBuf>,
    ssh_config: Arc<SshConfig>,
}

impl AppState {
    pub fn new(
        keylime: KeylimeClient,
        alert_repo: Arc<dyn AlertRepository>,
        attestation_repo: Arc<dyn AttestationRepository>,
        policy_repo: Arc<dyn PolicyRepository>,
        audit_repo: Arc<dyn AuditRepository>,
        cache: Arc<dyn CacheBackend>,
        config_path: Option<PathBuf>,
    ) -> Self {
        Self {
            keylime_inner: Arc::new(RwLock::new(Arc::new(keylime))),
            alert_repo,
            attestation_repo,
            policy_repo,
            audit_repo,
            cache,
            config_path,
            ssh_config: Arc::new(SshConfig::default()),
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
        };
        tokio::spawn(settings_store::save_persisted_settings(path, settings));
    }
}
