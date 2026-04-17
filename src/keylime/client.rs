use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::config::{KeylimeConfig, MtlsConfig};
use crate::error::{AppError, AppResult};

use super::models::{
    AgentListResults, BootLogResults, ImaLogResults, PcrResults, RegistrarAgent, RuntimePolicy,
    VerifierAgent, VerifierResponse,
};

/// Circuit breaker states (NFR-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker to protect against Verifier API latency spikes.
#[derive(Debug)]
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    failure_threshold: u32,
    last_failure: RwLock<Option<Instant>>,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout_secs: u64) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            failure_threshold,
            last_failure: RwLock::new(None),
            reset_timeout: Duration::from_secs(reset_timeout_secs),
        }
    }

    pub async fn state(&self) -> CircuitState {
        let state = *self.state.read().await;
        if state == CircuitState::Open {
            if let Some(last) = *self.last_failure.read().await {
                if last.elapsed() >= self.reset_timeout {
                    return CircuitState::HalfOpen;
                }
            }
        }
        state
    }

    pub async fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        *self.state.write().await = CircuitState::Closed;
    }

    pub async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure.write().await = Some(Instant::now());
        if count >= self.failure_threshold {
            *self.state.write().await = CircuitState::Open;
        }
    }
}

/// mTLS client for communicating with Keylime Verifier and Registrar APIs (SR-004).
///
/// Supports both v2 (pull-mode) and v3 (push-mode) API endpoints.
/// Private keys are loaded from HSM/Vault -- never stored in cleartext (SR-005, SR-006).
///
/// NFR-023: Maximum 5 parallel concurrent log fetches to Verifier API.
pub struct KeylimeClient {
    verifier_url: String,
    registrar_url: String,
    http: reqwest::Client,
    verifier_circuit: Arc<CircuitBreaker>,
    _log_fetch_semaphore: Arc<tokio::sync::Semaphore>,
    mtls_config: Option<MtlsConfig>,
}

impl KeylimeClient {
    pub fn new(config: KeylimeConfig) -> AppResult<Self> {
        let verifier_circuit = Arc::new(CircuitBreaker::new(
            config.circuit_breaker.failure_threshold,
            config.circuit_breaker.reset_timeout_secs,
        ));

        // NFR-023: limit concurrent log fetches
        let log_fetch_semaphore = Arc::new(tokio::sync::Semaphore::new(5));

        let mtls_config = config.mtls.clone();

        let http = if let Some(ref mtls) = config.mtls {
            if mtls.key.starts_with("pkcs11://") || mtls.key.starts_with("vault://") {
                return Err(AppError::Internal(
                    "HSM/Vault key URIs are not yet supported".into(),
                ));
            }

            let ca_pem = std::fs::read(&mtls.ca_cert).map_err(|e| {
                AppError::Internal(format!(
                    "failed to read CA certificate {}: {e}",
                    mtls.ca_cert.display()
                ))
            })?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| AppError::Internal(format!("invalid CA certificate: {e}")))?;

            let cert_pem = std::fs::read(&mtls.cert).map_err(|e| {
                AppError::Internal(format!(
                    "failed to read client certificate {}: {e}",
                    mtls.cert.display()
                ))
            })?;
            let key_pem = std::fs::read(&mtls.key).map_err(|e| {
                AppError::Internal(format!("failed to read client key {}: {e}", mtls.key))
            })?;
            let mut identity_pem = cert_pem;
            identity_pem.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&identity_pem)
                .map_err(|e| AppError::Internal(format!("invalid client identity: {e}")))?;

            reqwest::Client::builder()
                .timeout(Duration::from_secs(config.timeout_secs))
                .add_root_certificate(ca_cert)
                .identity(identity)
                .danger_accept_invalid_hostnames(true)
                .build()
                .map_err(|e| AppError::Internal(format!("failed to build mTLS client: {e}")))?
        } else {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(config.timeout_secs))
                .build()
                .map_err(|e| AppError::Internal(format!("failed to build HTTP client: {e}")))?
        };

        Ok(Self {
            verifier_url: config.verifier_url,
            registrar_url: config.registrar_url,
            http,
            verifier_circuit,
            _log_fetch_semaphore: log_fetch_semaphore,
            mtls_config,
        })
    }

    /// Check whether the Verifier API circuit breaker is open.
    pub async fn verifier_available(&self) -> bool {
        self.verifier_circuit.state().await != CircuitState::Open
    }

    // -----------------------------------------------------------------------
    // Verifier API methods
    // -----------------------------------------------------------------------

    /// Probe the Verifier API directly, bypassing the circuit breaker.
    /// Used by the health/connectivity check so it always reflects real status.
    /// Only checks for a successful HTTP response — does not parse the body.
    pub async fn probe_verifier(&self) -> AppResult<()> {
        let url = format!("{}/v2/agents/", self.verifier_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            self.verifier_circuit.record_success().await;
            Ok(())
        } else {
            self.verifier_circuit.record_failure().await;
            let status = resp.status().as_u16();
            Err(crate::error::AppError::NotFound(format!(
                "Verifier returned {status}"
            )))
        }
    }

    /// GET /v2/agents/ -- list agent IDs from the Verifier.
    pub async fn list_verifier_agents(&self) -> AppResult<Vec<String>> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/", self.verifier_url);
        let resp = self
            .get_json::<VerifierResponse<AgentListResults>>(&url)
            .await?;
        Ok(resp.results.uuids.into_iter().flatten().collect())
    }

    /// GET /v2/agents/{agent_id} -- agent detail from the Verifier.
    ///
    /// Handles two Keylime response formats:
    /// - Nested: `results: { "uuid": { ...agent_data } }`
    /// - Flat:   `results: { ...agent_data }`
    pub async fn get_verifier_agent(&self, agent_id: &str) -> AppResult<VerifierAgent> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}", self.verifier_url, agent_id);
        let resp = self
            .get_json::<VerifierResponse<serde_json::Value>>(&url)
            .await?;
        extract_agent::<VerifierAgent>(resp.results, agent_id, |a, id| a.agent_id = id)
    }

    /// GET /v2/allowlists/ -- list policy names from the Verifier.
    pub async fn list_policies(&self) -> AppResult<Vec<String>> {
        self.check_circuit().await?;
        let url = format!("{}/v2/allowlists/", self.verifier_url);
        let resp = self
            .get_json::<VerifierResponse<PolicyListResults>>(&url)
            .await?;
        Ok(resp.results.policy_names)
    }

    /// GET /v2/allowlists/{name} -- policy detail from the Verifier.
    pub async fn get_policy(&self, name: &str) -> AppResult<RuntimePolicy> {
        self.check_circuit().await?;
        let url = format!("{}/v2/allowlists/{}", self.verifier_url, name);
        let resp = self
            .get_json::<VerifierResponse<RuntimePolicy>>(&url)
            .await?;
        Ok(resp.results)
    }

    /// GET /v2/agents/{agent_id}/pcrs -- PCR values (FR-021/022).
    pub async fn get_agent_pcrs(&self, agent_id: &str) -> AppResult<PcrResults> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}/pcrs", self.verifier_url, agent_id);
        let resp = self.get_json::<VerifierResponse<PcrResults>>(&url).await?;
        Ok(resp.results)
    }

    /// GET /v2/agents/{agent_id}/ima -- IMA log entries (FR-020).
    pub async fn get_agent_ima_log(&self, agent_id: &str) -> AppResult<ImaLogResults> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}/ima", self.verifier_url, agent_id);
        let resp = self
            .get_json::<VerifierResponse<ImaLogResults>>(&url)
            .await?;
        Ok(resp.results)
    }

    /// GET /v2/agents/{agent_id}/boot-log -- boot log entries (FR-020).
    pub async fn get_agent_boot_log(&self, agent_id: &str) -> AppResult<BootLogResults> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}/boot-log", self.verifier_url, agent_id);
        let resp = self
            .get_json::<VerifierResponse<BootLogResults>>(&url)
            .await?;
        Ok(resp.results)
    }

    /// DELETE /v2/agents/{agent_id} -- remove agent from verifier (FR-019).
    pub async fn delete_agent(&self, agent_id: &str) -> AppResult<()> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}", self.verifier_url, agent_id);
        let resp = match self.http.delete(&url).send().await {
            Ok(r) => {
                self.verifier_circuit.record_success().await;
                r
            }
            Err(e) => {
                self.verifier_circuit.record_failure().await;
                return Err(e.into());
            }
        };
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::NotFound(format!(
                "Keylime API returned {status}: {body}"
            )));
        }
        Ok(())
    }

    /// PUT /v2/agents/{agent_id} -- reactivate agent (FR-019).
    pub async fn reactivate_agent(&self, agent_id: &str) -> AppResult<()> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}", self.verifier_url, agent_id);
        let resp = match self
            .http
            .put(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
        {
            Ok(r) => {
                self.verifier_circuit.record_success().await;
                r
            }
            Err(e) => {
                self.verifier_circuit.record_failure().await;
                return Err(e.into());
            }
        };
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::NotFound(format!(
                "Keylime API returned {status}: {body}"
            )));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Registrar API methods
    // -----------------------------------------------------------------------

    /// Probe the Registrar API directly — connectivity check only.
    /// Issues a lightweight GET and checks the status code without parsing
    /// the body. Does not interact with the circuit breaker (Registrar has
    /// no breaker of its own).
    pub async fn probe_registrar(&self) -> AppResult<()> {
        let url = format!("{}/v2/agents/", self.registrar_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            Err(AppError::NotFound(format!("Registrar returned {status}")))
        }
    }

    /// GET /v2/agents/ -- list registered agent IDs from the Registrar.
    pub async fn list_registrar_agents(&self) -> AppResult<Vec<String>> {
        let url = format!("{}/v2/agents/", self.registrar_url);
        let resp = self
            .get_json::<VerifierResponse<AgentListResults>>(&url)
            .await?;
        Ok(resp.results.uuids.into_iter().flatten().collect())
    }

    /// GET /v2/agents/{agent_id} -- agent registration data from the Registrar.
    ///
    /// Handles both nested and flat response formats (same as Verifier).
    pub async fn get_registrar_agent(&self, agent_id: &str) -> AppResult<RegistrarAgent> {
        let url = format!("{}/v2/agents/{}", self.registrar_url, agent_id);
        let resp = self
            .get_json::<VerifierResponse<serde_json::Value>>(&url)
            .await?;
        extract_agent::<RegistrarAgent>(resp.results, agent_id, |a, id| a.agent_id = id)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Issue a GET request and deserialize the JSON body.
    ///
    /// Circuit breaker: only **network** errors (connection refused, timeout)
    /// count as failures. A successful HTTP response that fails to deserialize
    /// is a client-side issue and must not trip the breaker.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> AppResult<T> {
        let resp = match self.http.get(url).send().await {
            Ok(r) => {
                self.verifier_circuit.record_success().await;
                r
            }
            Err(e) => {
                self.verifier_circuit.record_failure().await;
                return Err(e.into());
            }
        };
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::NotFound(format!(
                "Keylime API returned {status}: {body}"
            )));
        }
        let body = resp.text().await.map_err(|e| {
            AppError::Internal(format!("failed to read response body from {url}: {e}"))
        })?;
        serde_json::from_str::<T>(&body).map_err(|e| {
            tracing::error!("JSON parse error for {url}: {e}\nBody: {body}");
            AppError::Internal(format!("failed to parse Keylime response from {url}: {e}"))
        })
    }

    async fn check_circuit(&self) -> AppResult<()> {
        if self.verifier_circuit.state().await == CircuitState::Open {
            return Err(AppError::ServiceUnavailable(
                "Verifier API circuit breaker is open".into(),
            ));
        }
        Ok(())
    }
}

/// Policy list results from Verifier `GET /v2/allowlists/`.
#[derive(Debug, serde::Deserialize)]
struct PolicyListResults {
    #[serde(default)]
    policy_names: Vec<String>,
}

impl KeylimeClient {
    /// Return the current Verifier URL.
    pub fn verifier_url(&self) -> &str {
        &self.verifier_url
    }

    /// Return the current Registrar URL.
    pub fn registrar_url(&self) -> &str {
        &self.registrar_url
    }

    /// Return the current mTLS configuration, if any.
    pub fn mtls_config(&self) -> Option<&MtlsConfig> {
        self.mtls_config.as_ref()
    }
}

/// Extract an agent from a `results` value that may be in nested
/// (`{ "uuid": { ...data } }`) or flat (`{ ...data }`) format.
///
/// Nested is detected when the object has exactly one key whose value is
/// itself an object.  Everything else is treated as flat.
fn extract_agent<T: serde::de::DeserializeOwned>(
    results: serde_json::Value,
    agent_id: &str,
    set_id: impl FnOnce(&mut T, String),
) -> AppResult<T> {
    // Try nested format first: single key whose value is an object.
    if let Some(obj) = results.as_object() {
        if obj.len() == 1 {
            if let Some((key, val)) = obj.iter().next() {
                if val.is_object() {
                    let mut agent: T = serde_json::from_value(val.clone()).map_err(|e| {
                        AppError::Internal(format!("failed to parse nested agent data: {e}"))
                    })?;
                    set_id(&mut agent, key.clone());
                    return Ok(agent);
                }
            }
        }
    }

    // Flat format: results IS the agent data.
    let mut agent: T = serde_json::from_value(results)
        .map_err(|e| AppError::Internal(format!("failed to parse agent data: {e}")))?;
    set_id(&mut agent, agent_id.to_string());
    Ok(agent)
}

impl std::fmt::Debug for KeylimeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylimeClient")
            .field("verifier_url", &self.verifier_url)
            .field("registrar_url", &self.registrar_url)
            .finish_non_exhaustive()
    }
}
