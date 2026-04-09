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
