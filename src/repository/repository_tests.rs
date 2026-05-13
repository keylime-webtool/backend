#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use crate::audit::logger::{AuditEntryParams, AuditLogger, AuditSeverity};
    use crate::models::alert::{Alert, AlertSeverity, AlertState, AlertType};
    use crate::models::attestation::{AttestationResult, FailureType};
    use crate::models::policy::{ApprovalStatus, Policy, PolicyChange, PolicyKind};
    use crate::repository::sqlite::{insert_alert, test_db};
    use crate::repository::{
        AlertRepository, AttestationRepository, AuditRepository, Repositories,
    };

    fn make_test_policy(id: &str, name: &str) -> Policy {
        let now = Utc::now();
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            kind: PolicyKind::Ima,
            version: 1,
            checksum: "abc123".into(),
            entry_count: 10,
            assigned_agents: 0,
            created_at: now,
            updated_at: now,
            updated_by: "admin@example.com".into(),
            content: Some("policy content".into()),
        }
    }

    fn make_test_change(id: &str, policy_id: &str, drafter: &str) -> PolicyChange {
        let now = Utc::now();
        PolicyChange {
            id: id.to_string(),
            policy_id: policy_id.to_string(),
            drafter: drafter.to_string(),
            approver: None,
            status: ApprovalStatus::Draft,
            previous_version: 1,
            proposed_version: 2,
            submitted_at: now,
            expires_at: now + Duration::days(7),
            approved_at: None,
        }
    }

    // ──────────────────────────────────────────────
    // 1. Factory wiring tests
    // ──────────────────────────────────────────────

    #[tokio::test]
    async fn in_memory_factory_creates_working_repos() {
        let repos = Repositories::in_memory();

        let alerts = repos.alert.list(None, None, true).await;
        assert!(
            !alerts.is_empty(),
            "in-memory alert repo should have seed data"
        );

        let summary = repos.alert.summary(true).await;
        assert!(summary.critical > 0);

        let policies = repos.policy.list().await.unwrap();
        assert!(policies.is_empty(), "in-memory policy repo starts empty");

        let audit_entries = repos
            .audit
            .query(&crate::repository::AuditFilter::default())
            .await
            .unwrap();
        assert!(
            audit_entries.is_empty(),
            "in-memory audit repo starts empty"
        );

        assert!(repos.audit.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn sqlite_factory_creates_working_repos() {
        let db = test_db().await;
        let repos = db.repositories();

        let alerts = repos.alert.list(None, None, true).await;
        assert!(alerts.is_empty(), "sqlite alert repo starts empty");

        let summary = repos.alert.summary(true).await;
        assert_eq!(summary.critical, 0);
        assert_eq!(summary.active_alerts, 0);

        let policies = repos.policy.list().await.unwrap();
        assert!(policies.is_empty());

        let audit_entries = repos
            .audit
            .query(&crate::repository::AuditFilter::default())
            .await
            .unwrap();
        assert!(audit_entries.is_empty());

        assert!(repos.audit.verify_chain().await.is_ok());
    }

    // ──────────────────────────────────────────────
    // 2. Schema idempotency
    // ──────────────────────────────────────────────

    #[tokio::test]
    async fn schema_init_is_idempotent() {
        let db = test_db().await;

        let policy = make_test_policy("pol-1", "ima-prod");
        let repos = db.repositories();
        repos.policy.create(&policy).await.unwrap();

        db.init_schema().await.unwrap();

        let retrieved = repos.policy.get("pol-1").await.unwrap();
        assert!(
            retrieved.is_some(),
            "data should survive a second init_schema()"
        );
        assert_eq!(retrieved.unwrap().name, "ima-prod");
    }

    // ──────────────────────────────────────────────
    // 3. Behavioral equivalence: policy CRUD
    // ──────────────────────────────────────────────

    async fn assert_policy_crud_contract(repos: &Repositories, label: &str) {
        let empty = repos.policy.list().await.unwrap();
        assert!(empty.is_empty(), "[{label}] should start with no policies");

        let policy = make_test_policy("equiv-1", "equivalence-test");
        repos.policy.create(&policy).await.unwrap();

        let retrieved = repos.policy.get("equiv-1").await.unwrap();
        assert!(
            retrieved.is_some(),
            "[{label}] get after create should return policy"
        );
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, "equiv-1");
        assert_eq!(retrieved.name, "equivalence-test");
        assert_eq!(retrieved.version, 1);

        repos
            .policy
            .create(&make_test_policy("equiv-2", "second"))
            .await
            .unwrap();
        let all = repos.policy.list().await.unwrap();
        assert_eq!(all.len(), 2, "[{label}] list should return both policies");

        let dup_result = repos.policy.create(&policy).await;
        assert!(
            dup_result.is_err(),
            "[{label}] duplicate create should fail"
        );

        let mut modified = policy.clone();
        modified.entry_count = 99;
        modified.updated_by = "operator@example.com".into();
        let updated = repos.policy.update("equiv-1", &modified).await.unwrap();
        assert_eq!(updated.version, 2, "[{label}] update should bump version");
        assert_eq!(updated.entry_count, 99);

        repos.policy.delete("equiv-1").await.unwrap();
        let gone = repos.policy.get("equiv-1").await.unwrap();
        assert!(
            gone.is_none(),
            "[{label}] get after delete should return None"
        );

        let delete_again = repos.policy.delete("equiv-1").await;
        assert!(
            delete_again.is_err(),
            "[{label}] deleting nonexistent should fail"
        );

        let get_missing = repos.policy.get("nonexistent").await.unwrap();
        assert!(
            get_missing.is_none(),
            "[{label}] get nonexistent should return None"
        );
    }

    #[tokio::test]
    async fn policy_crud_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        assert_policy_crud_contract(&repos, "in-memory").await;
    }

    #[tokio::test]
    async fn policy_crud_equivalence_sqlite() {
        let db = test_db().await;
        let repos = db.repositories();
        assert_policy_crud_contract(&repos, "sqlite").await;
    }

    // ──────────────────────────────────────────────
    // 4. Behavioral equivalence: SR-018 two-person approval
    // ──────────────────────────────────────────────

    async fn assert_approval_contract(repos: &Repositories, label: &str) {
        let change = make_test_change("chg-eq-1", "pol-1", "alice@example.com");

        let submitted = repos.policy.submit_for_approval(&change).await.unwrap();
        assert_eq!(
            submitted.status,
            ApprovalStatus::PendingApproval,
            "[{label}] submit should set status to PendingApproval"
        );

        let self_approve = repos.policy.approve("chg-eq-1", "alice@example.com").await;
        assert!(
            self_approve.is_err(),
            "[{label}] SR-018: drafter must not approve their own change"
        );

        let approved = repos
            .policy
            .approve("chg-eq-1", "bob@example.com")
            .await
            .unwrap();
        assert_eq!(approved.status, ApprovalStatus::Approved, "[{label}]");
        assert_eq!(approved.approver.as_deref(), Some("bob@example.com"));
        assert!(approved.approved_at.is_some());

        let double_approve = repos
            .policy
            .approve("chg-eq-1", "charlie@example.com")
            .await;
        assert!(
            double_approve.is_err(),
            "[{label}] approving an already-approved change should fail"
        );
    }

    #[tokio::test]
    async fn approval_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        assert_approval_contract(&repos, "in-memory").await;
    }

    #[tokio::test]
    async fn approval_equivalence_sqlite() {
        let db = test_db().await;
        let repos = db.repositories();
        assert_approval_contract(&repos, "sqlite").await;
    }

    // ──────────────────────────────────────────────
    // 5. Behavioral equivalence: audit hash chain
    // ──────────────────────────────────────────────

    async fn assert_audit_chain_contract(audit: &Arc<dyn AuditRepository>, label: &str) {
        assert!(
            audit.verify_chain().await.is_ok(),
            "[{label}] empty chain should verify"
        );

        let mut logger = AuditLogger::new(None, 1);

        let entry1 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin@example.com",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });
        audit.append(entry1).await.unwrap();

        let entry2 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Warning,
            actor: "admin@example.com",
            action: "UPDATE_POLICY",
            resource: "policy-1",
            source_ip: "10.0.0.1",
            user_agent: Some("curl/8.0"),
            result: "SUCCESS",
        });
        audit.append(entry2).await.unwrap();

        assert!(
            audit.verify_chain().await.is_ok(),
            "[{label}] valid 2-entry chain should verify"
        );

        let results = audit
            .query(&crate::repository::AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 2, "[{label}] should have 2 entries");
        assert_eq!(results[0].action, "LOGIN");
        assert_eq!(results[1].action, "UPDATE_POLICY");
        assert_eq!(
            results[1].user_agent.as_deref(),
            Some("curl/8.0"),
            "[{label}] user_agent should round-trip"
        );

        let mut rogue_logger = AuditLogger::new(Some("tampered_hash".into()), 3);
        let rogue = rogue_logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Critical,
            actor: "attacker",
            action: "DELETE",
            resource: "evidence",
            source_ip: "10.0.0.99",
            user_agent: None,
            result: "SUCCESS",
        });
        audit.append(rogue).await.unwrap();

        assert!(
            audit.verify_chain().await.is_err(),
            "[{label}] broken chain should fail verification"
        );
    }

    #[tokio::test]
    async fn audit_chain_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        assert_audit_chain_contract(&repos.audit, "in-memory").await;
    }

    #[tokio::test]
    async fn audit_chain_equivalence_sqlite() {
        let db = test_db().await;
        let repos = db.repositories();
        assert_audit_chain_contract(&repos.audit, "sqlite").await;
    }

    // ──────────────────────────────────────────────
    // 6. Behavioral equivalence: attestation timeline
    // ──────────────────────────────────────────────

    async fn assert_timeline_contract(attestation: &Arc<dyn AttestationRepository>, label: &str) {
        let end = Utc::now();
        let start = end - Duration::hours(24);

        let buckets = attestation
            .query_timeline(start, end, 100, 10, 4)
            .await
            .unwrap();

        assert_eq!(buckets.len(), 24, "[{label}] should have 24 hourly buckets");

        let total_success: u64 = buckets.iter().map(|b| b.successful).sum();
        let total_failed: u64 = buckets.iter().map(|b| b.failed).sum();
        let total_timed_out: u64 = buckets.iter().map(|b| b.timed_out).sum();
        assert_eq!(
            total_success, 100,
            "[{label}] successful count must sum to requested total"
        );
        assert_eq!(
            total_failed, 10,
            "[{label}] failed count must sum to requested total"
        );
        assert_eq!(
            total_timed_out, 4,
            "[{label}] timed_out count must sum to requested total"
        );
    }

    #[tokio::test]
    async fn timeline_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        assert_timeline_contract(&repos.attestation, "in-memory").await;
    }

    #[tokio::test]
    async fn timeline_equivalence_sqlite() {
        let db = test_db().await;
        let repos = db.repositories();
        assert_timeline_contract(&repos.attestation, "sqlite").await;
    }

    // ──────────────────────────────────────────────
    // 7. Behavioral equivalence: alert queries
    // ──────────────────────────────────────────────

    fn make_test_alert(id: &str, severity: AlertSeverity, state: AlertState) -> Alert {
        Alert {
            id: Uuid::parse_str(id).unwrap(),
            alert_type: AlertType::AttestationFailure,
            severity,
            description: "test alert".into(),
            affected_agents: vec!["agent-1".into()],
            state,
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
        }
    }

    const SEED_IDS: [&str; 6] = [
        "a0000001-0000-4000-8000-000000000001",
        "a0000001-0000-4000-8000-000000000002",
        "a0000001-0000-4000-8000-000000000003",
        "a0000001-0000-4000-8000-000000000004",
        "a0000001-0000-4000-8000-000000000005",
        "a0000001-0000-4000-8000-000000000006",
    ];

    async fn assert_alert_query_contract(
        alert: &Arc<dyn AlertRepository>,
        expected_total: usize,
        expected_critical: usize,
        expected_new: usize,
        label: &str,
    ) {
        let all = alert.list(None, None, true).await;
        assert_eq!(all.len(), expected_total, "[{label}] total alert count");

        let critical = alert.list(Some("critical"), None, true).await;
        assert_eq!(
            critical.len(),
            expected_critical,
            "[{label}] critical count"
        );

        let new = alert.list(None, Some("new"), true).await;
        assert_eq!(new.len(), expected_new, "[{label}] new count");

        let known_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let found = alert.get(known_id).await;
        assert!(found.is_some(), "[{label}] get known ID should return Some");

        let missing = alert.get(Uuid::nil()).await;
        assert!(
            missing.is_none(),
            "[{label}] get Uuid::nil should return None"
        );

        let summary = alert.summary(true).await;
        assert!(
            summary.critical > 0 || expected_critical == 0,
            "[{label}] summary critical count"
        );
    }

    #[tokio::test]
    async fn alert_query_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        assert_alert_query_contract(&repos.alert, 6, 2, 2, "in-memory").await;
    }

    #[tokio::test]
    async fn alert_query_equivalence_sqlite() {
        let db = test_db().await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[0], AlertSeverity::Critical, AlertState::New),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(
                SEED_IDS[1],
                AlertSeverity::Warning,
                AlertState::Acknowledged,
            ),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[2], AlertSeverity::Warning, AlertState::New),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[3], AlertSeverity::Info, AlertState::Resolved),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(
                SEED_IDS[4],
                AlertSeverity::Critical,
                AlertState::UnderInvestigation,
            ),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[5], AlertSeverity::Info, AlertState::Dismissed),
        )
        .await;
        let repos = db.repositories();
        assert_alert_query_contract(&repos.alert, 6, 2, 2, "sqlite").await;
    }

    // ──────────────────────────────────────────────
    // 8. Behavioral equivalence: alert state transitions
    // ──────────────────────────────────────────────

    async fn assert_acknowledge_contract(
        alert: &Arc<dyn AlertRepository>,
        new_id: Uuid,
        non_new_id: Uuid,
        label: &str,
    ) {
        alert.acknowledge(new_id).await.unwrap();
        let acked = alert.get(new_id).await.unwrap();
        assert_eq!(
            acked.state,
            AlertState::Acknowledged,
            "[{label}] acknowledge should set Acknowledged"
        );
        assert!(
            acked.acknowledged_timestamp.is_some(),
            "[{label}] acknowledge should set timestamp"
        );

        let reject = alert.acknowledge(non_new_id).await;
        assert!(reject.is_err(), "[{label}] acknowledge non-New should fail");
    }

    #[tokio::test]
    async fn acknowledge_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let acked_id = Uuid::parse_str(SEED_IDS[1]).unwrap();
        assert_acknowledge_contract(&repos.alert, new_id, acked_id, "in-memory").await;
    }

    #[tokio::test]
    async fn acknowledge_equivalence_sqlite() {
        let db = test_db().await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[0], AlertSeverity::Critical, AlertState::New),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(
                SEED_IDS[1],
                AlertSeverity::Warning,
                AlertState::Acknowledged,
            ),
        )
        .await;
        let repos = db.repositories();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let acked_id = Uuid::parse_str(SEED_IDS[1]).unwrap();
        assert_acknowledge_contract(&repos.alert, new_id, acked_id, "sqlite").await;
    }

    async fn assert_investigate_contract(
        alert: &Arc<dyn AlertRepository>,
        new_id: Uuid,
        resolved_id: Uuid,
        label: &str,
    ) {
        alert
            .investigate(new_id, Some("analyst@example.com".into()))
            .await
            .unwrap();
        let investigated = alert.get(new_id).await.unwrap();
        assert_eq!(
            investigated.state,
            AlertState::UnderInvestigation,
            "[{label}] investigate should set UnderInvestigation"
        );
        assert_eq!(
            investigated.assigned_to.as_deref(),
            Some("analyst@example.com"),
            "[{label}] investigate should set assignee"
        );

        let reject = alert.investigate(resolved_id, None).await;
        assert!(
            reject.is_err(),
            "[{label}] investigate Resolved should fail"
        );
    }

    #[tokio::test]
    async fn investigate_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let resolved_id = Uuid::parse_str(SEED_IDS[3]).unwrap();
        assert_investigate_contract(&repos.alert, new_id, resolved_id, "in-memory").await;
    }

    #[tokio::test]
    async fn investigate_equivalence_sqlite() {
        let db = test_db().await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[0], AlertSeverity::Critical, AlertState::New),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[3], AlertSeverity::Info, AlertState::Resolved),
        )
        .await;
        let repos = db.repositories();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let resolved_id = Uuid::parse_str(SEED_IDS[3]).unwrap();
        assert_investigate_contract(&repos.alert, new_id, resolved_id, "sqlite").await;
    }

    async fn assert_resolve_contract(
        alert: &Arc<dyn AlertRepository>,
        new_id: Uuid,
        terminal_id: Uuid,
        label: &str,
    ) {
        alert
            .resolve(new_id, Some("root cause fixed".into()))
            .await
            .unwrap();
        let resolved = alert.get(new_id).await.unwrap();
        assert_eq!(
            resolved.state,
            AlertState::Resolved,
            "[{label}] resolve should set Resolved"
        );
        assert_eq!(
            resolved.resolution.as_deref(),
            Some("root cause fixed"),
            "[{label}] resolve should set resolution text"
        );

        let reject = alert.resolve(terminal_id, None).await;
        assert!(reject.is_err(), "[{label}] resolve terminal should fail");
    }

    #[tokio::test]
    async fn resolve_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        let new_id = Uuid::parse_str(SEED_IDS[2]).unwrap();
        let resolved_id = Uuid::parse_str(SEED_IDS[3]).unwrap();
        assert_resolve_contract(&repos.alert, new_id, resolved_id, "in-memory").await;
    }

    #[tokio::test]
    async fn resolve_equivalence_sqlite() {
        let db = test_db().await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[2], AlertSeverity::Warning, AlertState::New),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[3], AlertSeverity::Info, AlertState::Resolved),
        )
        .await;
        let repos = db.repositories();
        let new_id = Uuid::parse_str(SEED_IDS[2]).unwrap();
        let resolved_id = Uuid::parse_str(SEED_IDS[3]).unwrap();
        assert_resolve_contract(&repos.alert, new_id, resolved_id, "sqlite").await;
    }

    async fn assert_dismiss_contract(
        alert: &Arc<dyn AlertRepository>,
        new_id: Uuid,
        terminal_id: Uuid,
        label: &str,
    ) {
        alert.dismiss(new_id).await.unwrap();
        let dismissed = alert.get(new_id).await.unwrap();
        assert_eq!(
            dismissed.state,
            AlertState::Dismissed,
            "[{label}] dismiss should set Dismissed"
        );

        let reject = alert.dismiss(terminal_id).await;
        assert!(reject.is_err(), "[{label}] dismiss terminal should fail");
    }

    #[tokio::test]
    async fn dismiss_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let dismissed_id = Uuid::parse_str(SEED_IDS[5]).unwrap();
        assert_dismiss_contract(&repos.alert, new_id, dismissed_id, "in-memory").await;
    }

    #[tokio::test]
    async fn dismiss_equivalence_sqlite() {
        let db = test_db().await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[0], AlertSeverity::Critical, AlertState::New),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[5], AlertSeverity::Info, AlertState::Dismissed),
        )
        .await;
        let repos = db.repositories();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let dismissed_id = Uuid::parse_str(SEED_IDS[5]).unwrap();
        assert_dismiss_contract(&repos.alert, new_id, dismissed_id, "sqlite").await;
    }

    async fn assert_escalate_contract(
        alert: &Arc<dyn AlertRepository>,
        new_id: Uuid,
        terminal_id: Uuid,
        label: &str,
    ) {
        let before = alert.get(new_id).await.unwrap().escalation_count;
        alert.escalate(new_id).await.unwrap();
        let after = alert.get(new_id).await.unwrap();
        assert_eq!(
            after.escalation_count,
            before + 1,
            "[{label}] escalate should increment count"
        );

        let reject = alert.escalate(terminal_id).await;
        assert!(reject.is_err(), "[{label}] escalate terminal should fail");
    }

    #[tokio::test]
    async fn escalate_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let resolved_id = Uuid::parse_str(SEED_IDS[3]).unwrap();
        assert_escalate_contract(&repos.alert, new_id, resolved_id, "in-memory").await;
    }

    #[tokio::test]
    async fn escalate_equivalence_sqlite() {
        let db = test_db().await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[0], AlertSeverity::Critical, AlertState::New),
        )
        .await;
        insert_alert(
            &db.pool,
            &make_test_alert(SEED_IDS[3], AlertSeverity::Info, AlertState::Resolved),
        )
        .await;
        let repos = db.repositories();
        let new_id = Uuid::parse_str(SEED_IDS[0]).unwrap();
        let resolved_id = Uuid::parse_str(SEED_IDS[3]).unwrap();
        assert_escalate_contract(&repos.alert, new_id, resolved_id, "sqlite").await;
    }

    // ──────────────────────────────────────────────
    // 9. Behavioral equivalence: attestation query_counts
    // ──────────────────────────────────────────────

    fn make_attestation_result(success: bool) -> AttestationResult {
        AttestationResult {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            success,
            failure_type: if success {
                None
            } else {
                Some(FailureType::QuoteInvalid)
            },
            failure_reason: if success {
                None
            } else {
                Some("test failure".into())
            },
            latency_ms: 42,
            verifier_id: "verifier-1".into(),
        }
    }

    async fn assert_query_counts_contract(
        attestation: &Arc<dyn AttestationRepository>,
        label: &str,
    ) {
        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);

        let (s, f, t) = attestation.query_counts(start, end).await.unwrap();
        assert_eq!(s, 0, "[{label}] empty repo should have 0 successful");
        assert_eq!(f, 0, "[{label}] empty repo should have 0 failed");
        assert_eq!(t, 0, "[{label}] empty repo should have 0 timed_out");

        for _ in 0..5 {
            attestation
                .store_result(&make_attestation_result(true))
                .await
                .unwrap();
        }
        for _ in 0..3 {
            attestation
                .store_result(&make_attestation_result(false))
                .await
                .unwrap();
        }

        let (s, f, t) = attestation.query_counts(start, end).await.unwrap();
        assert_eq!(s, 5, "[{label}] should count 5 successful");
        assert_eq!(f, 3, "[{label}] should count 3 failed");
        assert_eq!(t, 0, "[{label}] should count 0 timed_out");

        let future_start = Utc::now() + Duration::hours(10);
        let future_end = Utc::now() + Duration::hours(11);
        let (s, f, t) = attestation
            .query_counts(future_start, future_end)
            .await
            .unwrap();
        assert_eq!(s, 0, "[{label}] out-of-range should return 0 successful");
        assert_eq!(f, 0, "[{label}] out-of-range should return 0 failed");
        assert_eq!(t, 0, "[{label}] out-of-range should return 0 timed_out");
    }

    #[tokio::test]
    async fn query_counts_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        assert_query_counts_contract(&repos.attestation, "in-memory").await;
    }

    #[tokio::test]
    async fn query_counts_equivalence_sqlite() {
        let db = test_db().await;
        let repos = db.repositories();
        assert_query_counts_contract(&repos.attestation, "sqlite").await;
    }

    // ──────────────────────────────────────────────
    // 10. Behavioral equivalence: count_agent_failures
    // ──────────────────────────────────────────────

    async fn assert_count_agent_failures_contract(
        attestation: &Arc<dyn AttestationRepository>,
        label: &str,
    ) {
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();
        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);

        let c = attestation
            .count_agent_failures(agent_a, start, end)
            .await
            .unwrap();
        assert_eq!(c, 0, "[{label}] empty repo should return 0");

        for _ in 0..3 {
            let mut r = make_attestation_result(false);
            r.agent_id = agent_a;
            attestation.store_result(&r).await.unwrap();
        }
        for _ in 0..2 {
            let mut r = make_attestation_result(false);
            r.agent_id = agent_b;
            attestation.store_result(&r).await.unwrap();
        }
        let mut r = make_attestation_result(true);
        r.agent_id = agent_a;
        attestation.store_result(&r).await.unwrap();

        let c = attestation
            .count_agent_failures(agent_a, start, end)
            .await
            .unwrap();
        assert_eq!(c, 3, "[{label}] agent_a should have 3 failures");

        let c = attestation
            .count_agent_failures(agent_b, start, end)
            .await
            .unwrap();
        assert_eq!(c, 2, "[{label}] agent_b should have 2 failures");

        let c = attestation
            .count_agent_failures(Uuid::new_v4(), start, end)
            .await
            .unwrap();
        assert_eq!(c, 0, "[{label}] unknown agent should return 0");
    }

    #[tokio::test]
    async fn count_agent_failures_equivalence_in_memory() {
        let repos = Repositories::in_memory();
        assert_count_agent_failures_contract(&repos.attestation, "in-memory").await;
    }

    #[tokio::test]
    async fn count_agent_failures_equivalence_sqlite() {
        let db = test_db().await;
        let repos = db.repositories();
        assert_count_agent_failures_contract(&repos.attestation, "sqlite").await;
    }
}
