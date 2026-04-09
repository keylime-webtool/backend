use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Attestation failure severity levels (FR-025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Attestation failure types (FR-025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureType {
    QuoteInvalid,
    PolicyViolation,
    EvidenceChainBroken,
    BootViolation,
    Timeout,
    PcrMismatch,
    ClockSkew,
    Unknown,
}

impl FailureType {
    pub fn default_severity(self) -> FailureSeverity {
        match self {
            Self::QuoteInvalid | Self::PolicyViolation | Self::EvidenceChainBroken => {
                FailureSeverity::Critical
            }
            Self::BootViolation | Self::Unknown => FailureSeverity::High,
            Self::Timeout | Self::PcrMismatch => FailureSeverity::Medium,
            Self::ClockSkew => FailureSeverity::Low,
        }
    }
}

/// A single attestation result record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub failure_type: Option<FailureType>,
    pub failure_reason: Option<String>,
    pub latency_ms: u64,
    pub verifier_id: String,
}

/// Verification pipeline stage (FR-030).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    ReceiveQuote,
    ValidateTpmQuote,
    CheckPcrValues,
    VerifyImaLog,
    VerifyMeasuredBoot,
}

/// Status of a single pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Pass,
    Fail,
    NotReached,
}

/// A verification pipeline result for one attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    pub stage: PipelineStage,
    pub status: StageStatus,
    pub duration_ms: Option<u64>,
}

/// Correlated incident grouping multiple failures (FR-026).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedIncident {
    pub id: Uuid,
    pub failure_ids: Vec<Uuid>,
    pub correlation_type: CorrelationType,
    pub suggested_root_cause: Option<String>,
    pub recommended_action: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    Temporal,
    Causal,
    Topological,
    PolicyLinked,
}
