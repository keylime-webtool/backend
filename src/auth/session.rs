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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_session_is_not_revoked() {
        let store = SessionStore::new();
        assert!(!store.is_revoked("sess-1").await);
    }

    #[tokio::test]
    async fn revoke_marks_session() {
        let store = SessionStore::new();
        store.revoke("sess-1").await;
        assert!(store.is_revoked("sess-1").await);
    }

    #[tokio::test]
    async fn other_sessions_unaffected() {
        let store = SessionStore::new();
        store.revoke("sess-1").await;
        assert!(!store.is_revoked("sess-2").await);
    }

    #[tokio::test]
    async fn multiple_revocations() {
        let store = SessionStore::new();
        store.revoke("a").await;
        store.revoke("b").await;
        assert!(store.is_revoked("a").await);
        assert!(store.is_revoked("b").await);
        assert!(!store.is_revoked("c").await);
    }

    #[test]
    fn default_creates_empty_store() {
        let store = SessionStore::default();
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(!rt.block_on(store.is_revoked("any")));
    }
}
