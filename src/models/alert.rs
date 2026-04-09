use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

/// Alert lifecycle states (FR-047).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    New,
    Acknowledged,
    UnderInvestigation,
    Resolved,
    Dismissed,
}

/// An alert in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub title: String,
    pub description: String,
    pub agent_id: Option<Uuid>,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_reason: Option<String>,
    pub assigned_to: Option<String>,
    pub escalation_level: u8,
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
        assert_eq!(json, "\"CRITICAL\"");
        let deserialized: AlertSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, severity);
    }

    #[test]
    fn alert_status_serde_roundtrip() {
        let status = AlertStatus::UnderInvestigation;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"under_investigation\"");
        let deserialized: AlertStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, status);
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
