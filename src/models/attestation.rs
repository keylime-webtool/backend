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

/// A single hourly bucket in the attestation timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineBucket {
    pub hour: DateTime<Utc>,
    pub successful: u64,
    pub failed: u64,
    pub timed_out: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_failure_types_map_to_critical_severity() {
        assert_eq!(
            FailureType::QuoteInvalid.default_severity(),
            FailureSeverity::Critical
        );
        assert_eq!(
            FailureType::PolicyViolation.default_severity(),
            FailureSeverity::Critical
        );
        assert_eq!(
            FailureType::EvidenceChainBroken.default_severity(),
            FailureSeverity::Critical
        );
    }

    #[test]
    fn high_severity_failure_types() {
        assert_eq!(
            FailureType::BootViolation.default_severity(),
            FailureSeverity::High
        );
        assert_eq!(
            FailureType::Unknown.default_severity(),
            FailureSeverity::High
        );
    }

    #[test]
    fn medium_severity_failure_types() {
        assert_eq!(
            FailureType::Timeout.default_severity(),
            FailureSeverity::Medium
        );
        assert_eq!(
            FailureType::PcrMismatch.default_severity(),
            FailureSeverity::Medium
        );
    }

    #[test]
    fn low_severity_failure_types() {
        assert_eq!(
            FailureType::ClockSkew.default_severity(),
            FailureSeverity::Low
        );
    }

    #[test]
    fn failure_type_serde_roundtrip() {
        let ft = FailureType::EvidenceChainBroken;
        let json = serde_json::to_string(&ft).unwrap();
        assert_eq!(json, "\"EVIDENCE_CHAIN_BROKEN\"");
        let deserialized: FailureType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ft);
    }

    #[test]
    fn pipeline_stage_serde_roundtrip() {
        let stage = PipelineStage::ValidateTpmQuote;
        let json = serde_json::to_string(&stage).unwrap();
        assert_eq!(json, "\"validate_tpm_quote\"");
        let deserialized: PipelineStage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, stage);
    }

    #[test]
    fn correlation_type_serde_roundtrip() {
        let ct = CorrelationType::Topological;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"topological\"");
        let deserialized: CorrelationType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ct);
    }
}
