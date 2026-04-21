use chrono::{DateTime, Utc};
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
}

/// Summary statistics for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub critical: u64,
    pub warnings: u64,
    pub info: u64,
    pub active_alerts: u64,
    pub active_critical: u64,
    pub resolved_24h: u64,
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
        };
        let json = serde_json::to_value(&alert).unwrap();
        assert!(json.get("type").is_some());
        assert!(json.get("alert_type").is_none());
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
