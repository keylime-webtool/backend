use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Certificate types exposed by Keylime APIs (FR-050).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateType {
    Ek,
    Ak,
    #[serde(rename = "mtls")]
    MTls,
}

impl CertificateType {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ek" => Some(Self::Ek),
            "ak" => Some(Self::Ak),
            "mtls" | "m_tls" => Some(Self::MTls),
            _ => None,
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::Ek => "ek",
            Self::Ak => "ak",
            Self::MTls => "mtls",
        }
    }
}

/// Certificate validity status (SDD 3.3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Valid,
    ExpiringSoon,
    Critical,
    Expired,
}

/// Six-tier expiry category matching the frontend contract (FR-051).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryCategory {
    Valid,
    #[serde(rename = "warning_90d")]
    Warning90d,
    #[serde(rename = "warning_30d")]
    Warning30d,
    #[serde(rename = "critical_7d")]
    Critical7d,
    #[serde(rename = "critical_1d")]
    Critical1d,
    Expired,
}

/// Chain validation status string for the frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationStatus {
    Valid,
    Invalid,
    Unknown,
}

impl ValidationStatus {
    pub fn from_chain_valid(chain_valid: Option<bool>) -> Self {
        match chain_valid {
            Some(true) => Self::Valid,
            Some(false) => Self::Invalid,
            None => Self::Unknown,
        }
    }
}

/// A certificate record (FR-050, FR-051, FR-052).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    #[serde(skip_serializing)]
    pub agent_id: Uuid,
    #[serde(rename = "type")]
    pub cert_type: CertificateType,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub public_key_algorithm: String,
    pub public_key_size: u32,
    pub signature_algorithm: String,
    #[serde(rename = "san")]
    pub sans: Vec<String>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub status: CertificateStatus,
    pub expiry_category: ExpiryCategory,
    pub associated_entity: String,
    pub validation_status: ValidationStatus,
    pub chain_valid: Option<bool>,
    pub chain: Vec<Certificate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_pem: Option<String>,
    #[serde(skip)]
    pub raw_der: Option<Vec<u8>>,
}

/// One week in the 90-day expiry timeline (FR-051).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryTimelineEntry {
    pub week_start: DateTime<Utc>,
    pub week_end: DateTime<Utc>,
    pub count: u64,
}

/// Certificate expiry summary (FR-051).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateExpirySummary {
    pub expired: u64,
    pub expiring_30d: u64,
    pub expiring_90d: u64,
    pub valid: u64,
    pub total: u64,
    pub timeline_90d: Vec<ExpiryTimelineEntry>,
}

/// Per-agent certificate summary for embedding in agent detail (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCertSummary {
    #[serde(rename = "type")]
    pub cert_type: CertificateType,
    pub status: CertificateStatus,
    pub expiry_category: ExpiryCategory,
    pub not_after: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub chain_valid: Option<bool>,
    pub validation_status: ValidationStatus,
}

/// Timeline entry for the /certificates/timeline endpoint (FR-051).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateTimelineEntry {
    pub date: String,
    pub count: u64,
    pub expiry_category: ExpiryCategory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_type_serde_roundtrip() {
        for (ct, expected) in [
            (CertificateType::Ek, "\"ek\""),
            (CertificateType::Ak, "\"ak\""),
            (CertificateType::MTls, "\"mtls\""),
        ] {
            let json = serde_json::to_string(&ct).unwrap();
            assert_eq!(json, expected, "serialization mismatch for {ct:?}");
            let deserialized: CertificateType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, ct);
        }
    }

    #[test]
    fn certificate_type_from_str_loose() {
        assert_eq!(
            CertificateType::from_str_loose("ek"),
            Some(CertificateType::Ek)
        );
        assert_eq!(
            CertificateType::from_str_loose("EK"),
            Some(CertificateType::Ek)
        );
        assert_eq!(
            CertificateType::from_str_loose("ak"),
            Some(CertificateType::Ak)
        );
        assert_eq!(
            CertificateType::from_str_loose("mtls"),
            Some(CertificateType::MTls)
        );
        assert_eq!(
            CertificateType::from_str_loose("m_tls"),
            Some(CertificateType::MTls)
        );
        assert_eq!(CertificateType::from_str_loose("iak"), None);
        assert_eq!(CertificateType::from_str_loose("server"), None);
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
    fn expiry_category_serde_roundtrip() {
        for (cat, expected) in [
            (ExpiryCategory::Valid, "\"valid\""),
            (ExpiryCategory::Warning90d, "\"warning_90d\""),
            (ExpiryCategory::Warning30d, "\"warning_30d\""),
            (ExpiryCategory::Critical7d, "\"critical_7d\""),
            (ExpiryCategory::Critical1d, "\"critical_1d\""),
            (ExpiryCategory::Expired, "\"expired\""),
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            assert_eq!(json, expected);
            let deserialized: ExpiryCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, cat);
        }
    }

    #[test]
    fn validation_status_from_chain_valid() {
        assert_eq!(
            ValidationStatus::from_chain_valid(Some(true)),
            ValidationStatus::Valid
        );
        assert_eq!(
            ValidationStatus::from_chain_valid(Some(false)),
            ValidationStatus::Invalid
        );
        assert_eq!(
            ValidationStatus::from_chain_valid(None),
            ValidationStatus::Unknown
        );
    }

    #[test]
    fn expiry_summary_serializes() {
        let summary = CertificateExpirySummary {
            expired: 2,
            expiring_30d: 5,
            expiring_90d: 8,
            valid: 100,
            total: 110,
            timeline_90d: vec![],
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["expired"], 2);
        assert_eq!(json["expiring_30d"], 5);
        assert_eq!(json["expiring_90d"], 8);
        assert_eq!(json["valid"], 100);
        assert_eq!(json["total"], 110);
    }

    #[test]
    fn agent_cert_summary_serializes() {
        let summary = AgentCertSummary {
            cert_type: CertificateType::Ek,
            status: CertificateStatus::Valid,
            expiry_category: ExpiryCategory::Valid,
            not_after: Utc::now(),
            days_until_expiry: 365,
            chain_valid: Some(true),
            validation_status: ValidationStatus::Valid,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["type"], "ek");
        assert_eq!(json["status"], "valid");
        assert_eq!(json["expiry_category"], "valid");
        assert_eq!(json["days_until_expiry"], 365);
        assert_eq!(json["chain_valid"], true);
        assert_eq!(json["validation_status"], "valid");
    }

    #[test]
    fn raw_pem_skipped_when_none() {
        let cert = Certificate {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            cert_type: CertificateType::Ek,
            subject_dn: "CN=test".into(),
            issuer_dn: "CN=ca".into(),
            serial_number: "1".into(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            public_key_algorithm: "RSA".into(),
            public_key_size: 2048,
            signature_algorithm: "SHA256withRSA".into(),
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            status: CertificateStatus::Valid,
            expiry_category: ExpiryCategory::Valid,
            associated_entity: "agent-1".into(),
            validation_status: ValidationStatus::Unknown,
            chain_valid: None,
            chain: vec![],
            raw_pem: None,
            raw_der: None,
        };
        let json = serde_json::to_value(&cert).unwrap();
        assert!(!json.as_object().unwrap().contains_key("raw_pem"));
        assert_eq!(json["type"], "ek");
        assert!(json["san"].is_array());
        assert!(json["chain"].is_array());
        assert_eq!(json["validation_status"], "unknown");
        assert!(!json.as_object().unwrap().contains_key("agent_id"));
    }

    #[test]
    fn certificate_type_serializes_as_type_field() {
        let cert = Certificate {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            cert_type: CertificateType::MTls,
            subject_dn: "CN=test".into(),
            issuer_dn: "CN=ca".into(),
            serial_number: "1".into(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            public_key_algorithm: "RSA".into(),
            public_key_size: 2048,
            signature_algorithm: "SHA256withRSA".into(),
            sans: vec!["example.com".into()],
            key_usage: vec![],
            extended_key_usage: vec![],
            status: CertificateStatus::Valid,
            expiry_category: ExpiryCategory::Warning30d,
            associated_entity: "agent-1".into(),
            validation_status: ValidationStatus::Unknown,
            chain_valid: None,
            chain: vec![],
            raw_pem: None,
            raw_der: None,
        };
        let json = serde_json::to_value(&cert).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("type"), "should have 'type' key");
        assert!(
            !obj.contains_key("cert_type"),
            "should NOT have 'cert_type' key"
        );
        assert_eq!(json["type"], "mtls");
        assert!(obj.contains_key("san"), "should have 'san' key");
        assert!(!obj.contains_key("sans"), "should NOT have 'sans' key");
        assert_eq!(json["san"][0], "example.com");
        assert_eq!(json["expiry_category"], "warning_30d");
    }
}
