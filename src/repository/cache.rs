use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;

use crate::error::AppResult;

#[async_trait]
pub trait CacheBackend: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Option<Vec<u8>>;
    async fn set(&self, key: &str, value: &[u8], ttl: Duration);
    async fn invalidate(&self, key: &str);
    async fn invalidate_prefix(&self, prefix: &str);
}

pub struct RedisCacheBackend {
    conn: MultiplexedConnection,
}

impl RedisCacheBackend {
    pub async fn connect(redis_url: &str) -> AppResult<Self> {
        let client = redis::Client::open(redis_url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl CacheBackend for RedisCacheBackend {
    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut conn = self.conn.clone();
        conn.get::<_, Option<Vec<u8>>>(key).await.ok().flatten()
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) {
        let mut conn = self.conn.clone();
        let _: Result<(), _> = conn.set_ex::<_, _, ()>(key, value, ttl.as_secs()).await;
    }

    async fn invalidate(&self, key: &str) {
        let mut conn = self.conn.clone();
        let _: Result<(), _> = conn.del::<_, ()>(key).await;
    }

    async fn invalidate_prefix(&self, prefix: &str) {
        let mut conn = self.conn.clone();
        let keys: Vec<String> = conn.keys(format!("{prefix}*")).await.unwrap_or_default();
        for key in keys {
            let _: Result<(), _> = conn.del::<_, ()>(&key).await;
        }
    }
}

pub struct InMemoryCacheBackend {
    store: DashMap<String, (Vec<u8>, Instant)>,
}

impl InMemoryCacheBackend {
    pub fn new() -> Self {
        Self {
            store: DashMap::new(),
        }
    }
}

impl Default for InMemoryCacheBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheBackend for InMemoryCacheBackend {
    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let entry = self.store.get(key)?;
        let (value, expires_at) = entry.value();
        if Instant::now() > *expires_at {
            drop(entry);
            self.store.remove(key);
            return None;
        }
        Some(value.clone())
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) {
        let expires_at = Instant::now() + ttl;
        self.store
            .insert(key.to_string(), (value.to_vec(), expires_at));
    }

    async fn invalidate(&self, key: &str) {
        self.store.remove(key);
    }

    async fn invalidate_prefix(&self, prefix: &str) {
        let keys_to_remove: Vec<String> = self
            .store
            .iter()
            .filter(|entry| entry.key().starts_with(prefix))
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys_to_remove {
            self.store.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn in_memory_set_and_get() {
        let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
        cache.set("key1", b"value1", Duration::from_secs(60)).await;
        let val = cache.get("key1").await;
        assert_eq!(val, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn in_memory_returns_none_for_missing_key() {
        let cache = InMemoryCacheBackend::new();
        assert_eq!(cache.get("nonexistent").await, None);
    }

    #[tokio::test]
    async fn in_memory_invalidate_removes_entry() {
        let cache = InMemoryCacheBackend::new();
        cache.set("key1", b"val", Duration::from_secs(60)).await;
        cache.invalidate("key1").await;
        assert_eq!(cache.get("key1").await, None);
    }

    #[tokio::test]
    async fn in_memory_invalidate_prefix_removes_matching_keys() {
        let cache = InMemoryCacheBackend::new();
        cache
            .set("agents:list:all", b"a", Duration::from_secs(60))
            .await;
        cache
            .set("agents:detail:1", b"b", Duration::from_secs(60))
            .await;
        cache
            .set("certs:expiry", b"c", Duration::from_secs(60))
            .await;

        cache.invalidate_prefix("agents:").await;

        assert_eq!(cache.get("agents:list:all").await, None);
        assert_eq!(cache.get("agents:detail:1").await, None);
        assert_eq!(cache.get("certs:expiry").await, Some(b"c".to_vec()));
    }

    #[tokio::test]
    async fn in_memory_expired_entries_return_none() {
        let cache = InMemoryCacheBackend::new();
        let expires_at = Instant::now() - Duration::from_secs(1);
        cache
            .store
            .insert("expired".to_string(), (b"val".to_vec(), expires_at));

        assert_eq!(cache.get("expired").await, None);
        assert!(cache.store.get("expired").is_none());
    }
}
