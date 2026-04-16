use std::sync::{Arc, RwLock};

use crate::keylime::client::KeylimeClient;
use crate::models::alert_store::AlertStore;

/// Shared application state passed to Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    keylime_inner: Arc<RwLock<Arc<KeylimeClient>>>,
    pub alert_store: Arc<AlertStore>,
}

impl AppState {
    pub fn new(keylime: KeylimeClient, alert_store: AlertStore) -> Self {
        Self {
            keylime_inner: Arc::new(RwLock::new(Arc::new(keylime))),
            alert_store: Arc::new(alert_store),
        }
    }

    /// Get a snapshot of the current KeylimeClient (cheap Arc clone).
    pub fn keylime(&self) -> Arc<KeylimeClient> {
        self.keylime_inner.read().unwrap().clone()
    }

    /// Replace the KeylimeClient with a new one (used by settings API).
    pub fn swap_keylime(&self, new_client: KeylimeClient) {
        *self.keylime_inner.write().unwrap() = Arc::new(new_client);
    }
}
