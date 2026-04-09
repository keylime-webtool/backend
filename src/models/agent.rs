use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Pull-mode (v2 API) agent states.
/// See FR-069 for state machine visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentState {
    Registered = 0,
    Start = 1,
    Saved = 2,
    GetQuote = 3,
    Retry = 4,
    ProvideV = 5,
    Failed = 7,
    Terminated = 8,
    InvalidQuote = 9,
    TenantFailed = 10,
}

impl AgentState {
    pub fn is_failed(self) -> bool {
        matches!(
            self,
            AgentState::Failed | AgentState::InvalidQuote | AgentState::TenantFailed
        )
    }
}

/// Attestation mode the agent operates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMode {
    Pull,
    Push,
}

/// Core agent representation aggregated from Verifier + Registrar data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: Uuid,
    pub ip: String,
    pub hostname: Option<String>,
    pub state: AgentState,
    pub attestation_mode: AttestationMode,
    pub verifier_id: String,
    pub registration_date: DateTime<Utc>,
    pub last_attestation: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
    pub total_attestations: u64,
    pub boot_time: Option<DateTime<Utc>>,
    pub hash_algorithm: String,
    pub encryption_algorithm: String,
    pub signing_algorithm: String,
    pub ima_pcrs: Vec<u8>,
    pub ima_policy_id: Option<String>,
    pub mb_policy_id: Option<String>,
    pub tpm_policy: Option<String>,
    pub regcount: u32,
}

/// Agent summary for list views (FR-012).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub id: Uuid,
    pub ip: String,
    pub state: AgentState,
    pub attestation_mode: AttestationMode,
    pub last_attestation: Option<DateTime<Utc>>,
    pub assigned_policy: Option<String>,
    pub failure_count: u32,
}
