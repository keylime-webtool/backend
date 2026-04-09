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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_type_serde_roundtrip() {
        for (ct, expected) in [
            (CertificateType::Ek, "\"EK\""),
            (CertificateType::Ak, "\"AK\""),
            (CertificateType::Iak, "\"IAK\""),
            (CertificateType::IDevId, "\"I_DEV_ID\""),
            (CertificateType::MTls, "\"M_TLS\""),
            (CertificateType::Server, "\"SERVER\""),
        ] {
            let json = serde_json::to_string(&ct).unwrap();
            assert_eq!(json, expected, "serialization mismatch for {ct:?}");
            let deserialized: CertificateType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, ct);
        }
    }

    #[test]
    fn certificate_status_serde_roundtrip() {
        for (status, expected) in [
            (CertificateStatus::Valid, "\"valid\""),
            (CertificateStatus::ExpiringSoon, "\"expiring_soon\""),
            (CertificateStatus::Critical, "\"critical\""),
            (CertificateStatus::Expired, "\"expired\""),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
            let deserialized: CertificateStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn expiry_summary_serializes() {
        let summary = CertificateExpirySummary {
            expired: 2,
            expiring_30d: 5,
            valid: 100,
            total: 107,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["expired"], 2);
        assert_eq!(json["expiring_30d"], 5);
        assert_eq!(json["valid"], 100);
        assert_eq!(json["total"], 107);
    }
}
