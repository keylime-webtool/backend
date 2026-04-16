use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level application configuration.
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub keylime: KeylimeConfig,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub auth: AuthConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub integrations: IntegrationsConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct KeylimeConfig {
    pub verifier_url: String,
    pub registrar_url: String,
    pub mtls: Option<MtlsConfig>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    pub cert: PathBuf,
    /// Path to private key or HSM/Vault URI (SR-005, SR-006).
    pub key: String,
    pub ca_cert: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_reset_timeout_secs")]
    pub reset_timeout_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            reset_timeout_secs: default_reset_timeout_secs(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    pub redis_url: String,
    #[serde(default = "default_ttl_agent_list")]
    pub ttl_agent_list_secs: u64,
    #[serde(default = "default_ttl_agent_detail")]
    pub ttl_agent_detail_secs: u64,
    #[serde(default = "default_ttl_policies")]
    pub ttl_policies_secs: u64,
    #[serde(default = "default_ttl_certs")]
    pub ttl_certs_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub oidc: OidcConfig,
    pub jwt_secret: String,
    #[serde(default = "default_session_timeout_secs")]
    pub session_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub mfa_required_for_admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_retention_days")]
    pub log_retention_days: u32,
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,
    pub rfc3161_timestamp_url: Option<String>,
    pub rekor_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct IntegrationsConfig {
    #[serde(default)]
    pub siem: SiemConfig,
    pub slack_webhook_url: Option<String>,
    pub email: Option<EmailConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SiemConfig {
    pub syslog_endpoint: Option<String>,
    pub splunk_hec_endpoint: Option<String>,
    pub splunk_token: Option<String>,
    #[serde(default = "default_true")]
    pub prometheus_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
}

// Defaults

fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    8080
}
fn default_timeout_secs() -> u64 {
    30
}
fn default_failure_threshold() -> u32 {
    5
}
fn default_reset_timeout_secs() -> u64 {
    60
}
fn default_pool_size() -> u32 {
    20
}
fn default_connect_timeout_secs() -> u64 {
    5
}
fn default_ttl_agent_list() -> u64 {
    10
}
fn default_ttl_agent_detail() -> u64 {
    30
}
fn default_ttl_policies() -> u64 {
    60
}
fn default_ttl_certs() -> u64 {
    300
}
fn default_session_timeout_secs() -> u64 {
    900
}
fn default_true() -> bool {
    true
}
fn default_retention_days() -> u32 {
    365
}
fn default_hash_algorithm() -> String {
    "sha256".to_string()
}
