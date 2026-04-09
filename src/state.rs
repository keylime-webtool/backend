use std::sync::Arc;

use crate::keylime::client::KeylimeClient;

/// Shared application state passed to Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub keylime: Arc<KeylimeClient>,
}
