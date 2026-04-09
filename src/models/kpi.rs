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
