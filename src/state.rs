use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::config::SshConfig;
use crate::keylime::client::KeylimeClient;
use crate::models::alert_store::AlertStore;
use crate::settings_store::{self, PersistedKeylime, PersistedSettings};

/// Shared application state passed to Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    keylime_inner: Arc<RwLock<Arc<KeylimeClient>>>,
    pub alert_store: Arc<AlertStore>,
    config_path: Option<PathBuf>,
    ssh_config: Arc<SshConfig>,
}

impl AppState {
    pub fn new(
        keylime: KeylimeClient,
        alert_store: AlertStore,
        config_path: Option<PathBuf>,
    ) -> Self {
        Self {
            keylime_inner: Arc::new(RwLock::new(Arc::new(keylime))),
            alert_store: Arc::new(alert_store),
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

    /// Get a snapshot of the current KeylimeClient (cheap Arc clone).
    pub fn keylime(&self) -> Arc<KeylimeClient> {
        self.keylime_inner.read().unwrap().clone()
    }

    /// Replace the KeylimeClient with a new one (used by settings API).
    pub fn swap_keylime(&self, new_client: KeylimeClient) {
        *self.keylime_inner.write().unwrap() = Arc::new(new_client);
    }

    /// Persist the current keylime settings to the config file (if configured).
    ///
    /// This is fire-and-forget: failures are logged as warnings but never
    /// propagate to the caller.
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
