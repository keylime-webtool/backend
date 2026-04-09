use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Certificate types in the Keylime ecosystem (FR-050).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateType {
    Ek,
    Ak,
    Iak,
    IDevId,
    MTls,
    Server,
}

/// Certificate validity status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Valid,
    ExpiringSoon,
    Critical,
    Expired,
}

/// A certificate record (FR-050, FR-051, FR-052).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    pub cert_type: CertificateType,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub public_key_algorithm: String,
    pub public_key_size: u32,
    pub signature_algorithm: String,
    pub sans: Vec<String>,
    pub key_usage: Vec<String>,
    pub status: CertificateStatus,
    pub associated_entity: String,
    pub chain_valid: Option<bool>,
}

/// Certificate expiry summary (FR-051).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateExpirySummary {
    pub expired: u64,
    pub expiring_30d: u64,
    pub valid: u64,
    pub total: u64,
}
