use std::sync::RwLock;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::models::alert::{Alert, AlertSeverity, AlertState, AlertSummary, AlertType};

#[async_trait]
pub trait AlertRepository: Send + Sync + 'static {
    async fn list(&self, severity: Option<&str>, state: Option<&str>) -> Vec<Alert>;
    async fn get(&self, id: Uuid) -> Option<Alert>;
    async fn summary(&self) -> AlertSummary;
    async fn acknowledge(&self, id: Uuid) -> Result<(), String>;
    async fn investigate(&self, id: Uuid, assigned_to: Option<String>) -> Result<(), String>;
    async fn resolve(&self, id: Uuid, resolution: Option<String>) -> Result<(), String>;
    async fn dismiss(&self, id: Uuid) -> Result<(), String>;
    async fn escalate(&self, id: Uuid) -> Result<(), String>;
}

pub struct InMemoryAlertRepository {
    alerts: RwLock<Vec<Alert>>,
}

impl InMemoryAlertRepository {
    pub fn new_with_seed_data() -> Self {
        let now = Utc::now();

        let alerts = vec![
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
}

#[async_trait]
impl AlertRepository for InMemoryAlertRepository {
    async fn list(&self, severity: Option<&str>, state: Option<&str>) -> Vec<Alert> {
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

    async fn get(&self, id: Uuid) -> Option<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts.iter().find(|a| a.id == id).cloned()
    }

    async fn summary(&self) -> AlertSummary {
        let alerts = self.alerts.read().unwrap();

        let critical = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count() as u64;

        let warnings = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Warning)
            .count() as u64;

        let info = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Info)
            .count() as u64;

        let is_active =
            |a: &&Alert| !matches!(a.state, AlertState::Resolved | AlertState::Dismissed);

        let active_critical = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical && is_active(a))
            .count() as u64;

        let active_warnings = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Warning && is_active(a))
            .count() as u64;

        let active_alerts = active_critical + active_warnings;

        AlertSummary {
            critical,
            warnings,
            info,
            active_alerts,
            active_critical,
            active_warnings,
        }
    }

    async fn acknowledge(&self, id: Uuid) -> Result<(), String> {
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

    async fn investigate(&self, id: Uuid, assigned_to: Option<String>) -> Result<(), String> {
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

    async fn resolve(&self, id: Uuid, resolution: Option<String>) -> Result<(), String> {
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

    async fn dismiss(&self, id: Uuid) -> Result<(), String> {
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

    async fn escalate(&self, id: Uuid) -> Result<(), String> {
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
    use std::sync::Arc;

    fn make_repo() -> Arc<dyn AlertRepository> {
        Arc::new(InMemoryAlertRepository::new_with_seed_data())
    }

    #[tokio::test]
    async fn seed_data_has_expected_alerts() {
        let repo = make_repo();
        let all = repo.list(None, None).await;
        assert_eq!(all.len(), 6);
    }

    #[tokio::test]
    async fn filter_by_severity() {
        let repo = make_repo();
        let critical = repo.list(Some("critical"), None).await;
        assert_eq!(critical.len(), 2);
        let info = repo.list(Some("info"), None).await;
        assert_eq!(info.len(), 2);
    }

    #[tokio::test]
    async fn filter_by_state() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        assert_eq!(new_alerts.len(), 2);
    }

    #[tokio::test]
    async fn acknowledge_transitions_new_to_acknowledged() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        let id = new_alerts[0].id;

        repo.acknowledge(id).await.unwrap();

        let alert = repo.get(id).await.unwrap();
        assert_eq!(alert.state, AlertState::Acknowledged);
        assert!(alert.acknowledged_timestamp.is_some());
    }

    #[tokio::test]
    async fn acknowledge_rejects_non_new_state() {
        let repo = make_repo();
        let acked = repo.list(None, Some("acknowledged")).await;
        let id = acked[0].id;

        let result = repo.acknowledge(id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn investigate_sets_assignee() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        let id = new_alerts[0].id;

        repo.investigate(id, Some("analyst@example.com".into()))
            .await
            .unwrap();

        let alert = repo.get(id).await.unwrap();
        assert_eq!(alert.state, AlertState::UnderInvestigation);
        assert_eq!(alert.assigned_to.as_deref(), Some("analyst@example.com"));
    }

    #[tokio::test]
    async fn resolve_sets_resolution_reason() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        let id = new_alerts[0].id;

        repo.resolve(id, Some("fixed the issue".into()))
            .await
            .unwrap();

        let alert = repo.get(id).await.unwrap();
        assert_eq!(alert.state, AlertState::Resolved);
        assert_eq!(alert.resolution.as_deref(), Some("fixed the issue"));
    }

    #[tokio::test]
    async fn dismiss_transitions_to_dismissed() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        let id = new_alerts[0].id;

        repo.dismiss(id).await.unwrap();

        let alert = repo.get(id).await.unwrap();
        assert_eq!(alert.state, AlertState::Dismissed);
    }

    #[tokio::test]
    async fn escalate_increments_count() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        let id = new_alerts[0].id;
        let before = repo.get(id).await.unwrap().escalation_count;

        repo.escalate(id).await.unwrap();

        let alert = repo.get(id).await.unwrap();
        assert_eq!(alert.escalation_count, before + 1);
    }

    #[tokio::test]
    async fn cannot_resolve_already_resolved() {
        let repo = make_repo();
        let resolved = repo.list(None, Some("resolved")).await;
        let id = resolved[0].id;

        let result = repo.resolve(id, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn summary_counts_active_alerts() {
        let repo = make_repo();
        let summary = repo.summary().await;
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.warnings, 2);
        assert_eq!(summary.info, 2);
        assert_eq!(summary.active_alerts, 4);
        assert_eq!(summary.active_critical, 2);
        assert_eq!(summary.active_warnings, 2);
    }

    #[tokio::test]
    async fn concurrent_escalations_are_serialized() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        let id = new_alerts[0].id;
        let before = repo.get(id).await.unwrap().escalation_count;

        let n = 50u32;
        let mut handles = Vec::new();
        for _ in 0..n {
            let repo = repo.clone();
            handles.push(tokio::spawn(async move {
                repo.escalate(id).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let alert = repo.get(id).await.unwrap();
        assert_eq!(alert.escalation_count, before + n);
    }

    #[tokio::test]
    async fn concurrent_reads_during_writes() {
        let repo = make_repo();
        let new_alerts = repo.list(None, Some("new")).await;
        let id = new_alerts[0].id;

        let mut handles = Vec::new();

        // Spawn readers
        for _ in 0..20 {
            let repo = repo.clone();
            handles.push(tokio::spawn(async move {
                let _ = repo.list(None, None).await;
                let _ = repo.get(id).await;
                let _ = repo.summary().await;
            }));
        }

        // Spawn writers interleaved
        for _ in 0..10 {
            let repo = repo.clone();
            handles.push(tokio::spawn(async move {
                let _ = repo.escalate(id).await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let alert = repo.get(id).await.unwrap();
        assert!(alert.escalation_count >= 10);
    }
}
