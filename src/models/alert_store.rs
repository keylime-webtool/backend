use std::sync::RwLock;

use chrono::{Duration, Utc};
use uuid::Uuid;

use super::alert::{Alert, AlertSeverity, AlertState, AlertSummary, AlertType};

/// In-memory alert store for development (pre-database).
///
/// Seeded with realistic alerts derived from known mock agents.
pub struct AlertStore {
    alerts: RwLock<Vec<Alert>>,
}

impl AlertStore {
    /// Create a new store seeded with sample alerts based on mock agent states.
    pub fn new_with_seed_data() -> Self {
        let now = Utc::now();

        let alerts = vec![
            // CRITICAL: failed pull-mode agent attestation failure (New)
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
            },
            // WARNING: failed push-mode agent consecutive failures (Acknowledged)
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
            },
            // WARNING: certificate approaching expiry (New)
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
            },
            // INFO: PCR change detected on healthy push agent (Resolved)
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
            },
            // CRITICAL: policy violation on failed pull agent (Under Investigation)
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
                    "Binary hash does not match any known package. Escalated to security team."
                        .into(),
                ),
                root_cause: None,
                resolution: None,
                auto_resolved: false,
                escalation_count: 1,
                sla_window: Some("15m".into()),
                source: "verifier".into(),
                external_ticket_id: Some("SEC-2024-0042".into()),
            },
            // INFO: clock skew detected (Dismissed)
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
            },
        ];

        Self {
            alerts: RwLock::new(alerts),
        }
    }

    /// List all alerts, optionally filtered by severity and/or state.
    pub fn list(&self, severity: Option<&str>, state: Option<&str>) -> Vec<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts
            .iter()
            .filter(|a| {
                if let Some(sev) = severity {
                    let a_sev = serde_json::to_string(&a.severity).unwrap_or_default();
                    let a_sev = a_sev.trim_matches('"');
                    if a_sev != sev {
                        return false;
                    }
                }
                if let Some(st) = state {
                    let a_st = serde_json::to_string(&a.state).unwrap_or_default();
                    let a_st = a_st.trim_matches('"');
                    if a_st != st {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Get a single alert by ID.
    pub fn get(&self, id: Uuid) -> Option<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts.iter().find(|a| a.id == id).cloned()
    }

    /// Compute summary statistics.
    pub fn summary(&self) -> AlertSummary {
        let alerts = self.alerts.read().unwrap();
        let now = Utc::now();
        let day_ago = now - Duration::hours(24);

        let critical = alerts
            .iter()
            .filter(|a| {
                a.severity == AlertSeverity::Critical
                    && !matches!(a.state, AlertState::Resolved | AlertState::Dismissed)
            })
            .count() as u64;

        let warnings = alerts
            .iter()
            .filter(|a| {
                a.severity == AlertSeverity::Warning
                    && !matches!(a.state, AlertState::Resolved | AlertState::Dismissed)
            })
            .count() as u64;

        let resolved_24h = alerts
            .iter()
            .filter(|a| a.state == AlertState::Resolved && a.created_timestamp >= day_ago)
            .count() as u64;

        AlertSummary {
            critical,
            warnings,
            resolved_24h,
        }
    }

    /// Transition an alert to Acknowledged state.
    pub fn acknowledge(&self, id: Uuid) -> Result<(), String> {
        let mut alerts = self.alerts.write().unwrap();
        let alert = alerts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("alert {id} not found"))?;

        if alert.state != AlertState::New {
            return Err(format!(
                "cannot acknowledge alert in {:?} state — must be New",
                alert.state
            ));
        }

        alert.state = AlertState::Acknowledged;
        alert.acknowledged_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Transition an alert to UnderInvestigation state.
    pub fn investigate(&self, id: Uuid, assigned_to: Option<String>) -> Result<(), String> {
        let mut alerts = self.alerts.write().unwrap();
        let alert = alerts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("alert {id} not found"))?;

        if !matches!(alert.state, AlertState::New | AlertState::Acknowledged) {
            return Err(format!(
                "cannot investigate alert in {:?} state — must be New or Acknowledged",
                alert.state
            ));
        }

        alert.state = AlertState::UnderInvestigation;
        if alert.acknowledged_timestamp.is_none() {
            alert.acknowledged_timestamp = Some(Utc::now());
        }
        if let Some(assignee) = assigned_to {
            alert.assigned_to = Some(assignee);
        }
        Ok(())
    }

    /// Transition an alert to Resolved state.
    pub fn resolve(&self, id: Uuid, resolution: Option<String>) -> Result<(), String> {
        let mut alerts = self.alerts.write().unwrap();
        let alert = alerts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("alert {id} not found"))?;

        if matches!(alert.state, AlertState::Resolved | AlertState::Dismissed) {
            return Err(format!("alert already in terminal state {:?}", alert.state));
        }

        alert.state = AlertState::Resolved;
        if let Some(reason) = resolution {
            alert.resolution = Some(reason);
        }
        Ok(())
    }

    /// Transition an alert to Dismissed state.
    pub fn dismiss(&self, id: Uuid) -> Result<(), String> {
        let mut alerts = self.alerts.write().unwrap();
        let alert = alerts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("alert {id} not found"))?;

        if matches!(alert.state, AlertState::Resolved | AlertState::Dismissed) {
            return Err(format!("alert already in terminal state {:?}", alert.state));
        }

        alert.state = AlertState::Dismissed;
        Ok(())
    }

    /// Escalate an alert — increments escalation count.
    pub fn escalate(&self, id: Uuid) -> Result<(), String> {
        let mut alerts = self.alerts.write().unwrap();
        let alert = alerts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("alert {id} not found"))?;

        if matches!(alert.state, AlertState::Resolved | AlertState::Dismissed) {
            return Err(format!(
                "cannot escalate alert in terminal state {:?}",
                alert.state
            ));
        }

        alert.escalation_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_data_has_expected_alerts() {
        let store = AlertStore::new_with_seed_data();
        let all = store.list(None, None);
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn filter_by_severity() {
        let store = AlertStore::new_with_seed_data();
        let critical = store.list(Some("critical"), None);
        assert_eq!(critical.len(), 2);
        let info = store.list(Some("info"), None);
        assert_eq!(info.len(), 2);
    }

    #[test]
    fn filter_by_state() {
        let store = AlertStore::new_with_seed_data();
        let new_alerts = store.list(None, Some("new"));
        assert_eq!(new_alerts.len(), 2);
    }

    #[test]
    fn acknowledge_transitions_new_to_acknowledged() {
        let store = AlertStore::new_with_seed_data();
        let new_alerts = store.list(None, Some("new"));
        let id = new_alerts[0].id;

        store.acknowledge(id).unwrap();

        let alert = store.get(id).unwrap();
        assert_eq!(alert.state, AlertState::Acknowledged);
        assert!(alert.acknowledged_timestamp.is_some());
    }

    #[test]
    fn acknowledge_rejects_non_new_state() {
        let store = AlertStore::new_with_seed_data();
        // The acknowledged alert
        let acked = store.list(None, Some("acknowledged"));
        let id = acked[0].id;

        let result = store.acknowledge(id);
        assert!(result.is_err());
    }

    #[test]
    fn investigate_sets_assignee() {
        let store = AlertStore::new_with_seed_data();
        let new_alerts = store.list(None, Some("new"));
        let id = new_alerts[0].id;

        store
            .investigate(id, Some("analyst@example.com".into()))
            .unwrap();

        let alert = store.get(id).unwrap();
        assert_eq!(alert.state, AlertState::UnderInvestigation);
        assert_eq!(alert.assigned_to.as_deref(), Some("analyst@example.com"));
    }

    #[test]
    fn resolve_sets_resolution_reason() {
        let store = AlertStore::new_with_seed_data();
        let new_alerts = store.list(None, Some("new"));
        let id = new_alerts[0].id;

        store.resolve(id, Some("fixed the issue".into())).unwrap();

        let alert = store.get(id).unwrap();
        assert_eq!(alert.state, AlertState::Resolved);
        assert_eq!(alert.resolution.as_deref(), Some("fixed the issue"));
    }

    #[test]
    fn dismiss_transitions_to_dismissed() {
        let store = AlertStore::new_with_seed_data();
        let new_alerts = store.list(None, Some("new"));
        let id = new_alerts[0].id;

        store.dismiss(id).unwrap();

        let alert = store.get(id).unwrap();
        assert_eq!(alert.state, AlertState::Dismissed);
    }

    #[test]
    fn escalate_increments_count() {
        let store = AlertStore::new_with_seed_data();
        let new_alerts = store.list(None, Some("new"));
        let id = new_alerts[0].id;
        let before = store.get(id).unwrap().escalation_count;

        store.escalate(id).unwrap();

        let alert = store.get(id).unwrap();
        assert_eq!(alert.escalation_count, before + 1);
    }

    #[test]
    fn cannot_resolve_already_resolved() {
        let store = AlertStore::new_with_seed_data();
        let resolved = store.list(None, Some("resolved"));
        let id = resolved[0].id;

        let result = store.resolve(id, None);
        assert!(result.is_err());
    }

    #[test]
    fn summary_counts_active_alerts() {
        let store = AlertStore::new_with_seed_data();
        let summary = store.summary();
        // 2 critical total, but 1 is under_investigation (active), 1 is new (active)
        assert_eq!(summary.critical, 2);
        // 2 warnings total, but 1 is acknowledged (active), 1 is new (active)
        assert_eq!(summary.warnings, 2);
    }
}
