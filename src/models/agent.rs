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

impl TryFrom<i32> for AgentState {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AgentState::Registered),
            1 => Ok(AgentState::Start),
            2 => Ok(AgentState::Saved),
            3 => Ok(AgentState::GetQuote),
            4 => Ok(AgentState::Retry),
            5 => Ok(AgentState::ProvideV),
            7 => Ok(AgentState::Failed),
            8 => Ok(AgentState::Terminated),
            9 => Ok(AgentState::InvalidQuote),
            10 => Ok(AgentState::TenantFailed),
            _ => Err(format!("unknown operational_state: {value}")),
        }
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

impl AgentState {
    /// Returns all valid agent states.
    pub fn all() -> &'static [AgentState] {
        &[
            AgentState::Registered,
            AgentState::Start,
            AgentState::Saved,
            AgentState::GetQuote,
            AgentState::Retry,
            AgentState::ProvideV,
            AgentState::Failed,
            AgentState::Terminated,
            AgentState::InvalidQuote,
            AgentState::TenantFailed,
        ]
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_states_are_detected() {
        assert!(AgentState::Failed.is_failed());
        assert!(AgentState::InvalidQuote.is_failed());
        assert!(AgentState::TenantFailed.is_failed());
    }

    #[test]
    fn non_failed_states_are_not_failed() {
        let non_failed = [
            AgentState::Registered,
            AgentState::Start,
            AgentState::Saved,
            AgentState::GetQuote,
            AgentState::Retry,
            AgentState::ProvideV,
            AgentState::Terminated,
        ];
        for state in non_failed {
            assert!(!state.is_failed(), "{state:?} should not be failed");
        }
    }

    #[test]
    fn all_states_returns_all_variants() {
        assert_eq!(AgentState::all().len(), 10);
    }

    #[test]
    fn agent_state_serde_roundtrip() {
        let state = AgentState::GetQuote;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"GET_QUOTE\"");
        let deserialized: AgentState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }

    #[test]
    fn attestation_mode_serde_roundtrip() {
        let mode = AttestationMode::Push;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"push\"");
        let deserialized: AttestationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, mode);
    }
}
