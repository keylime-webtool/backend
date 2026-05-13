use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Alert severity levels (FR-025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

/// Alert lifecycle states (FR-047).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    New,
    Acknowledged,
    UnderInvestigation,
    Resolved,
    Dismissed,
}

/// Alert type categories matching frontend expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    AttestationFailure,
    CertExpiry,
    PolicyViolation,
    PcrChange,
    ServiceDown,
    RateLimit,
    ClockSkew,
}

/// An alert in the system — fields match the frontend `Alert` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub description: String,
    pub affected_agents: Vec<String>,
    pub state: AlertState,
    pub created_timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_timestamp: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub investigation_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    pub auto_resolved: bool,
    pub escalation_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_window: Option<String>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ticket_id: Option<String>,
    #[serde(skip)]
    pub mock: bool,
}

/// Summary statistics for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub critical: u64,
    pub warnings: u64,
    pub info: u64,
    pub active_alerts: u64,
    pub active_critical: u64,
    pub active_warnings: u64,
}

pub fn seed_alerts() -> Vec<Alert> {
    let now = Utc::now();

    vec![
        Alert {
            id: Uuid::parse_str("a0000001-0000-4000-8000-000000000001").unwrap(),
            alert_type: AlertType::AttestationFailure,
            severity: AlertSeverity::Critical,
            description: "Agent attestation failed: quote verification returned INVALID — \
                          PCR values do not match expected policy"
                .into(),
            affected_agents: vec!["a1b2c3d4-0000-1111-2222-333344445555".into()],
            state: AlertState::New,
            created_timestamp: now - Duration::minutes(45),
            acknowledged_timestamp: None,
            assigned_to: None,
            investigation_notes: None,
            root_cause: None,
            resolution: None,
            auto_resolved: false,
            escalation_count: 0,
            sla_window: Some("15m".into()),
            source: "verifier".into(),
            external_ticket_id: None,
            mock: true,
        },
        Alert {
            id: Uuid::parse_str("a0000001-0000-4000-8000-000000000002").unwrap(),
            alert_type: AlertType::AttestationFailure,
            severity: AlertSeverity::Warning,
            description: "Push-mode agent has 3 consecutive attestation failures — \
                          evidence submission timeout"
                .into(),
            affected_agents: vec!["b2c3d4e5-a1b0-8765-4321-fedcba987654".into()],
            state: AlertState::Acknowledged,
            created_timestamp: now - Duration::hours(2),
            acknowledged_timestamp: Some(now - Duration::hours(1)),
            assigned_to: Some("operator@example.com".into()),
            investigation_notes: None,
            root_cause: None,
            resolution: None,
            auto_resolved: false,
            escalation_count: 0,
            sla_window: Some("30m".into()),
            source: "verifier".into(),
            external_ticket_id: None,
            mock: true,
        },
        Alert {
            id: Uuid::parse_str("a0000001-0000-4000-8000-000000000003").unwrap(),
            alert_type: AlertType::CertExpiry,
            severity: AlertSeverity::Warning,
            description: "EK certificate expires in 28 days — renewal recommended".into(),
            affected_agents: vec!["d432fbb3-d2f1-4a97-9ef7-75bd81c00000".into()],
            state: AlertState::New,
            created_timestamp: now - Duration::hours(6),
            acknowledged_timestamp: None,
            assigned_to: None,
            investigation_notes: None,
            root_cause: None,
            resolution: None,
            auto_resolved: false,
            escalation_count: 0,
            sla_window: None,
            source: "certificate-monitor".into(),
            external_ticket_id: None,
            mock: true,
        },
        Alert {
            id: Uuid::parse_str("a0000001-0000-4000-8000-000000000004").unwrap(),
            alert_type: AlertType::PcrChange,
            severity: AlertSeverity::Info,
            description: "PCR-14 value changed after kernel update — \
                          verified as legitimate change"
                .into(),
            affected_agents: vec!["f7e6d5c4-b3a2-9180-7654-321098765432".into()],
            state: AlertState::Resolved,
            created_timestamp: now - Duration::hours(26),
            acknowledged_timestamp: Some(now - Duration::hours(25)),
            assigned_to: Some("admin@example.com".into()),
            investigation_notes: Some(
                "Kernel updated from 6.1.0 to 6.1.5 — PCR change expected".into(),
            ),
            root_cause: Some("Planned kernel update".into()),
            resolution: Some("Policy updated to reflect new kernel measurements".into()),
            auto_resolved: false,
            escalation_count: 0,
            sla_window: None,
            source: "verifier".into(),
            external_ticket_id: None,
            mock: true,
        },
        Alert {
            id: Uuid::parse_str("a0000001-0000-4000-8000-000000000005").unwrap(),
            alert_type: AlertType::PolicyViolation,
            severity: AlertSeverity::Critical,
            description: "IMA policy violation: unauthorized binary /usr/local/bin/suspect \
                          executed on agent"
                .into(),
            affected_agents: vec!["a1b2c3d4-0000-1111-2222-333344445555".into()],
            state: AlertState::UnderInvestigation,
            created_timestamp: now - Duration::hours(1),
            acknowledged_timestamp: Some(now - Duration::minutes(50)),
            assigned_to: Some("security-team@example.com".into()),
            investigation_notes: Some(
                "Binary hash does not match any known package. Escalated to security team.".into(),
            ),
            root_cause: None,
            resolution: None,
            auto_resolved: false,
            escalation_count: 1,
            sla_window: Some("15m".into()),
            source: "verifier".into(),
            external_ticket_id: Some("SEC-2024-0042".into()),
            mock: true,
        },
        Alert {
            id: Uuid::parse_str("a0000001-0000-4000-8000-000000000006").unwrap(),
            alert_type: AlertType::ClockSkew,
            severity: AlertSeverity::Info,
            description: "Clock skew of 2.3s detected between agent and verifier".into(),
            affected_agents: vec!["c5d6e7f8-a9b0-4321-8765-abcdef012345".into()],
            state: AlertState::Dismissed,
            created_timestamp: now - Duration::hours(48),
            acknowledged_timestamp: Some(now - Duration::hours(47)),
            assigned_to: None,
            investigation_notes: None,
            root_cause: None,
            resolution: Some("NTP sync corrected the drift — false positive".into()),
            auto_resolved: false,
            escalation_count: 0,
            sla_window: None,
            source: "verifier".into(),
            external_ticket_id: None,
            mock: true,
        },
    ]
}

/// Notification for external channels (FR-010).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: Uuid,
    pub alert_id: Uuid,
    pub channel: NotificationChannel,
    pub status: DeliveryStatus,
    pub retry_count: u32,
    pub sent_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Slack,
    Webhook,
    ZeroMq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Sent,
    Failed,
    Retrying,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_severity_serde_roundtrip() {
        let severity = AlertSeverity::Critical;
        let json = serde_json::to_string(&severity).unwrap();
        assert_eq!(json, "\"critical\"");
        let deserialized: AlertSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, severity);
    }

    #[test]
    fn alert_state_serde_roundtrip() {
        let state = AlertState::UnderInvestigation;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"under_investigation\"");
        let deserialized: AlertState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }

    #[test]
    fn alert_type_serde_roundtrip() {
        let alert_type = AlertType::AttestationFailure;
        let json = serde_json::to_string(&alert_type).unwrap();
        assert_eq!(json, "\"attestation_failure\"");
        let deserialized: AlertType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, alert_type);
    }

    #[test]
    fn alert_type_field_renames_to_type_in_json() {
        let alert = Alert {
            id: Uuid::nil(),
            alert_type: AlertType::CertExpiry,
            severity: AlertSeverity::Warning,
            description: "test".into(),
            affected_agents: vec![],
            state: AlertState::New,
            created_timestamp: Utc::now(),
            acknowledged_timestamp: None,
            assigned_to: None,
            investigation_notes: None,
            root_cause: None,
            resolution: None,
            auto_resolved: false,
            escalation_count: 0,
            sla_window: None,
            source: "test".into(),
            external_ticket_id: None,
            mock: false,
        };
        let json = serde_json::to_value(&alert).unwrap();
        assert!(json.get("type").is_some());
        assert!(json.get("alert_type").is_none());
        assert!(json.get("mock").is_none());
        assert_eq!(json["type"], "cert_expiry");
    }

    #[test]
    fn notification_channel_serde_roundtrip() {
        let channel = NotificationChannel::ZeroMq;
        let json = serde_json::to_string(&channel).unwrap();
        assert_eq!(json, "\"zero_mq\"");
        let deserialized: NotificationChannel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, channel);
    }

    #[test]
    fn delivery_status_serde_roundtrip() {
        for (status, expected) in [
            (DeliveryStatus::Pending, "\"pending\""),
            (DeliveryStatus::Sent, "\"sent\""),
            (DeliveryStatus::Failed, "\"failed\""),
            (DeliveryStatus::Retrying, "\"retrying\""),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
            let deserialized: DeliveryStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }
}
