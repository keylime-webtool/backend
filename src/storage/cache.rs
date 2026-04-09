use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use std::time::Duration;

use crate::config::CacheConfig;
use crate::error::AppResult;

/// Redis cache with tiered TTLs per NFR-019.
///
/// Cache TTLs:
///   - Agent list:   10s
///   - Agent detail:  30s
///   - Policies:      60s
///   - Certificates: 300s
#[derive(Debug, Clone)]
pub struct Cache {
    conn: MultiplexedConnection,
    ttl_agent_list: Duration,
    ttl_agent_detail: Duration,
    ttl_policies: Duration,
    ttl_certs: Duration,
}

/// Cache key namespace to prevent collisions.
#[derive(Debug, Clone, Copy)]
pub enum CacheNamespace {
    AgentList,
    AgentDetail,
    Policies,
    Certificates,
}

impl CacheNamespace {
    fn prefix(self) -> &'static str {
        match self {
            Self::AgentList => "agents:list",
            Self::AgentDetail => "agents:detail",
            Self::Policies => "policies",
            Self::Certificates => "certs",
        }
    }
}

impl Cache {
    pub async fn connect(config: &CacheConfig) -> AppResult<Self> {
        let client = redis::Client::open(config.redis_url.as_str())?;
        let conn = client.get_multiplexed_async_connection().await?;

        Ok(Self {
            conn,
            ttl_agent_list: Duration::from_secs(config.ttl_agent_list_secs),
            ttl_agent_detail: Duration::from_secs(config.ttl_agent_detail_secs),
            ttl_policies: Duration::from_secs(config.ttl_policies_secs),
            ttl_certs: Duration::from_secs(config.ttl_certs_secs),
        })
    }

    fn ttl_for(&self, ns: CacheNamespace) -> Duration {
        match ns {
            CacheNamespace::AgentList => self.ttl_agent_list,
            CacheNamespace::AgentDetail => self.ttl_agent_detail,
            CacheNamespace::Policies => self.ttl_policies,
            CacheNamespace::Certificates => self.ttl_certs,
        }
    }

    fn full_key(ns: CacheNamespace, key: &str) -> String {
        format!("{}:{}", ns.prefix(), key)
    }

    /// Get a cached value by namespace and key.
    pub async fn get(&self, ns: CacheNamespace, key: &str) -> AppResult<Option<String>> {
        let mut conn = self.conn.clone();
        let val: Option<String> = conn.get(Self::full_key(ns, key)).await?;
        Ok(val)
    }

    /// Set a cached value with the namespace's TTL.
    pub async fn set(&self, ns: CacheNamespace, key: &str, value: &str) -> AppResult<()> {
        let mut conn = self.conn.clone();
        let ttl = self.ttl_for(ns);
        conn.set_ex::<_, _, ()>(Self::full_key(ns, key), value, ttl.as_secs())
            .await?;
        Ok(())
    }

    /// Invalidate a cached entry.
    pub async fn invalidate(&self, ns: CacheNamespace, key: &str) -> AppResult<()> {
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(Self::full_key(ns, key)).await?;
        Ok(())
    }
}
