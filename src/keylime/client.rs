use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::config::KeylimeConfig;
use crate::error::AppResult;

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
    _config: KeylimeConfig,
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

        Ok(Self {
            _config: config,
            verifier_circuit,
            _log_fetch_semaphore: log_fetch_semaphore,
        })
    }

    /// Check whether the Verifier API circuit breaker is open.
    pub async fn verifier_available(&self) -> bool {
        self.verifier_circuit.state().await != CircuitState::Open
    }

    // TODO: Implement mTLS HTTP client setup via rustls
    // TODO: GET /v2/agents/ -- list agents (pull mode)
    // TODO: GET /v2/agents/{agent_id} -- agent detail
    // TODO: GET /v3/agents/ -- list agents (push mode)
    // TODO: GET /v2/allowlists/ -- list IMA policies
    // TODO: POST /v2/allowlists/ -- create IMA policy
    // TODO: Registrar API: GET /v2/agents/ -- registration data
}

impl std::fmt::Debug for KeylimeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylimeClient").finish_non_exhaustive()
    }
}
