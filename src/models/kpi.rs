use serde::{Deserialize, Serialize};

/// Fleet overview KPIs (FR-001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetKpis {
    pub total_active_agents: u64,
    pub failed_agents: u64,
    pub attestation_success_rate: f64,
    pub average_attestation_latency_ms: f64,
    pub certificate_expiry_warnings: u64,
    pub active_ima_policies: u64,
    pub revocation_events_24h: u64,
    pub registration_count: u64,
}

/// Attestation analytics summary (FR-024).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSummary {
    pub total_successful: u64,
    pub total_failed: u64,
    pub average_latency_ms: f64,
    pub success_rate: f64,
}

/// Backend service health status (FR-057).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub name: String,
    pub endpoint: String,
    pub status: ServiceStatus,
    pub uptime_seconds: Option<u64>,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceStatus {
    Up,
    Down,
    HighLoad,
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_kpis_serializes() {
        let kpis = FleetKpis {
            total_active_agents: 500,
            failed_agents: 3,
            attestation_success_rate: 99.4,
            average_attestation_latency_ms: 45.2,
            certificate_expiry_warnings: 2,
            active_ima_policies: 5,
            revocation_events_24h: 0,
            registration_count: 512,
        };
        let json = serde_json::to_value(&kpis).unwrap();
        assert_eq!(json["total_active_agents"], 500);
        assert_eq!(json["failed_agents"], 3);
        assert_eq!(json["attestation_success_rate"], 99.4);
        assert_eq!(json["revocation_events_24h"], 0);
    }

    #[test]
    fn attestation_summary_serializes() {
        let summary = AttestationSummary {
            total_successful: 1000,
            total_failed: 5,
            average_latency_ms: 42.0,
            success_rate: 99.5,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["total_successful"], 1000);
        assert_eq!(json["total_failed"], 5);
        assert_eq!(json["success_rate"], 99.5);
    }

    #[test]
    fn service_status_serde_roundtrip() {
        for (status, expected) in [
            (ServiceStatus::Up, "\"UP\""),
            (ServiceStatus::Down, "\"DOWN\""),
            (ServiceStatus::HighLoad, "\"HIGH_LOAD\""),
            (ServiceStatus::Timeout, "\"TIMEOUT\""),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
            let deserialized: ServiceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn service_health_serializes() {
        let health = ServiceHealth {
            name: "verifier".into(),
            endpoint: "https://verifier:8881".into(),
            status: ServiceStatus::Up,
            uptime_seconds: Some(86400),
            latency_ms: Some(12),
        };
        let json = serde_json::to_value(&health).unwrap();
        assert_eq!(json["name"], "verifier");
        assert_eq!(json["status"], "UP");
        assert_eq!(json["uptime_seconds"], 86400);
    }
}
