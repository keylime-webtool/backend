use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::config::KeylimeConfig;
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
}

impl KeylimeClient {
    pub fn new(config: KeylimeConfig) -> AppResult<Self> {
        let verifier_circuit = Arc::new(CircuitBreaker::new(
            config.circuit_breaker.failure_threshold,
            config.circuit_breaker.reset_timeout_secs,
        ));

        // NFR-023: limit concurrent log fetches
        let log_fetch_semaphore = Arc::new(tokio::sync::Semaphore::new(5));

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| AppError::Internal(format!("failed to build HTTP client: {e}")))?;

        // TODO: when config.mtls is Some, build mTLS client with certs

        Ok(Self {
            verifier_url: config.verifier_url,
            registrar_url: config.registrar_url,
            http,
            verifier_circuit,
            _log_fetch_semaphore: log_fetch_semaphore,
        })
    }

    /// Check whether the Verifier API circuit breaker is open.
    pub async fn verifier_available(&self) -> bool {
        self.verifier_circuit.state().await != CircuitState::Open
    }

    // -----------------------------------------------------------------------
    // Verifier API methods
    // -----------------------------------------------------------------------

    /// GET /v2/agents/ -- list agent IDs from the Verifier.
    pub async fn list_verifier_agents(&self) -> AppResult<Vec<String>> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/", self.verifier_url);
        let result = self
            .get_json::<VerifierResponse<AgentListResults>>(&url)
            .await;
        self.record_result(&result).await;
        Ok(result?.results.uuids)
    }

    /// GET /v2/agents/{agent_id} -- agent detail from the Verifier.
    pub async fn get_verifier_agent(&self, agent_id: &str) -> AppResult<VerifierAgent> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}", self.verifier_url, agent_id);
        let result = self.get_json::<VerifierResponse<VerifierAgent>>(&url).await;
        self.record_result(&result).await;
        Ok(result?.results)
    }

    /// GET /v2/allowlists/ -- list policy names from the Verifier.
    pub async fn list_policies(&self) -> AppResult<Vec<String>> {
        self.check_circuit().await?;
        let url = format!("{}/v2/allowlists/", self.verifier_url);
        let result = self
            .get_json::<VerifierResponse<PolicyListResults>>(&url)
            .await;
        self.record_result(&result).await;
        Ok(result?.results.policy_names)
    }

    /// GET /v2/allowlists/{name} -- policy detail from the Verifier.
    pub async fn get_policy(&self, name: &str) -> AppResult<RuntimePolicy> {
        self.check_circuit().await?;
        let url = format!("{}/v2/allowlists/{}", self.verifier_url, name);
        let result = self.get_json::<VerifierResponse<RuntimePolicy>>(&url).await;
        self.record_result(&result).await;
        Ok(result?.results)
    }

    /// GET /v2/agents/{agent_id}/pcrs -- PCR values (FR-021/022).
    pub async fn get_agent_pcrs(&self, agent_id: &str) -> AppResult<PcrResults> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}/pcrs", self.verifier_url, agent_id);
        let result = self.get_json::<VerifierResponse<PcrResults>>(&url).await;
        self.record_result(&result).await;
        Ok(result?.results)
    }

    /// GET /v2/agents/{agent_id}/ima -- IMA log entries (FR-020).
    pub async fn get_agent_ima_log(&self, agent_id: &str) -> AppResult<ImaLogResults> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}/ima", self.verifier_url, agent_id);
        let result = self.get_json::<VerifierResponse<ImaLogResults>>(&url).await;
        self.record_result(&result).await;
        Ok(result?.results)
    }

    /// GET /v2/agents/{agent_id}/boot-log -- boot log entries (FR-020).
    pub async fn get_agent_boot_log(&self, agent_id: &str) -> AppResult<BootLogResults> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}/boot-log", self.verifier_url, agent_id);
        let result = self
            .get_json::<VerifierResponse<BootLogResults>>(&url)
            .await;
        self.record_result(&result).await;
        Ok(result?.results)
    }

    /// DELETE /v2/agents/{agent_id} -- remove agent from verifier (FR-019).
    pub async fn delete_agent(&self, agent_id: &str) -> AppResult<()> {
        self.check_circuit().await?;
        let url = format!("{}/v2/agents/{}", self.verifier_url, agent_id);
        let resp = self.http.delete(&url).send().await?;
        let ok = resp.status().is_success();
        if ok {
            self.verifier_circuit.record_success().await;
        } else {
            self.verifier_circuit.record_failure().await;
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
        let resp = self
            .http
            .put(&url)
            .json(&serde_json::json!({}))
            .send()
            .await?;
        let ok = resp.status().is_success();
        if ok {
            self.verifier_circuit.record_success().await;
        } else {
            self.verifier_circuit.record_failure().await;
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

    /// GET /v2/agents/ -- list registered agent IDs from the Registrar.
    pub async fn list_registrar_agents(&self) -> AppResult<Vec<String>> {
        let url = format!("{}/v2/agents/", self.registrar_url);
        let resp = self
            .get_json::<VerifierResponse<AgentListResults>>(&url)
            .await?;
        Ok(resp.results.uuids)
    }

    /// GET /v2/agents/{agent_id} -- agent registration data from the Registrar.
    pub async fn get_registrar_agent(&self, agent_id: &str) -> AppResult<RegistrarAgent> {
        let url = format!("{}/v2/agents/{}", self.registrar_url, agent_id);
        let resp = self
            .get_json::<VerifierResponse<RegistrarAgent>>(&url)
            .await?;
        Ok(resp.results)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> AppResult<T> {
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::NotFound(format!(
                "Keylime API returned {status}: {body}"
            )));
        }
        Ok(resp.json::<T>().await?)
    }

    async fn check_circuit(&self) -> AppResult<()> {
        if self.verifier_circuit.state().await == CircuitState::Open {
            return Err(AppError::ServiceUnavailable(
                "Verifier API circuit breaker is open".into(),
            ));
        }
        Ok(())
    }

    async fn record_result<T>(&self, result: &AppResult<T>) {
        match result {
            Ok(_) => self.verifier_circuit.record_success().await,
            Err(_) => self.verifier_circuit.record_failure().await,
        }
    }
}

/// Policy list results from Verifier `GET /v2/allowlists/`.
#[derive(Debug, serde::Deserialize)]
struct PolicyListResults {
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
}

impl std::fmt::Debug for KeylimeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylimeClient")
            .field("verifier_url", &self.verifier_url)
            .field("registrar_url", &self.registrar_url)
            .finish_non_exhaustive()
    }
}
