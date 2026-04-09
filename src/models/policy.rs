use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Policy type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    Ima,
    MeasuredBoot,
}

/// An IMA or measured boot policy (FR-033, FR-036).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub kind: PolicyKind,
    pub version: u32,
    pub checksum: String,
    pub entry_count: u64,
    pub assigned_agents: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub content: Option<String>,
}

/// Policy change approval status (FR-039, two-person rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Draft,
    PendingApproval,
    Approved,
    Rejected,
    Expired,
}

/// A pending policy change awaiting approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChange {
    pub id: String,
    pub policy_id: String,
    pub drafter: String,
    pub approver: Option<String>,
    pub status: ApprovalStatus,
    pub previous_version: u32,
    pub proposed_version: u32,
    pub submitted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
}

/// Impact analysis result (FR-038).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    pub policy_id: String,
    pub unaffected_agents: u64,
    pub affected_agents: u64,
    pub will_fail_agents: u64,
    pub hashes_added: u64,
    pub hashes_removed: u64,
    pub hashes_modified: u64,
    pub recommendation: String,
}
