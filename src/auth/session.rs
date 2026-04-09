use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Server-side session store for revocation support (SR-011).
/// Tracks active session IDs; revoking a session invalidates the JWT
/// even if the token has not yet expired.
#[derive(Debug, Clone)]
pub struct SessionStore {
    /// Set of revoked session IDs.
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            revoked: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Revoke a session, making its JWT invalid immediately.
    pub async fn revoke(&self, session_id: &str) {
        self.revoked.write().await.insert(session_id.to_string());
    }

    /// Check whether a session has been revoked.
    pub async fn is_revoked(&self, session_id: &str) -> bool {
        self.revoked.read().await.contains(session_id)
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
