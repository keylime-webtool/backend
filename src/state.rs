use std::sync::Arc;

use crate::keylime::client::KeylimeClient;
use crate::models::alert_store::AlertStore;

/// Shared application state passed to Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub keylime: Arc<KeylimeClient>,
    pub alert_store: Arc<AlertStore>,
}
