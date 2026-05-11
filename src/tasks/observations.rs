use std::collections::HashSet;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::interval;
use tracing::{info, warn};

use crate::api::handlers::attestations::record_agent_observations;
use crate::models::agent::AgentState;
use crate::state::AppState;

const RECONCILIATION_EVERY_N_TICKS: u64 = 10;

pub async fn background_observation_loop(
    state: AppState,
    interval_secs: u64,
    mut shutdown_rx: watch::Receiver<()>,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs));
    let mut tick_count: u64 = 0;
    let mut total_observations: u64 = 0;

    info!(
        interval_secs,
        "background observation task started (FR-087)"
    );

    loop {
        tokio::select! {
            _ = ticker.tick() => {},
            _ = shutdown_rx.changed() => {
                info!(total_observations, "background observation task shutting down");
                return;
            }
        }

        tick_count += 1;
        record_agent_observations(&state).await;
        total_observations += 1;

        if tick_count % RECONCILIATION_EVERY_N_TICKS == 0 {
            reconcile_fleet(&state).await;
        }
    }
}

async fn reconcile_fleet(state: &AppState) {
    let verifier_ids = match state.keylime().list_verifier_agents().await {
        Ok(ids) => ids,
        Err(e) => {
            warn!("reconciliation: failed to list agents: {e}");
            return;
        }
    };

    let tracked_ids: HashSet<String> = state.tracked_agent_ids().into_iter().collect();
    let verifier_set: HashSet<&String> = verifier_ids.iter().collect();

    let new_agents: Vec<_> = verifier_ids
        .iter()
        .filter(|id| !tracked_ids.contains(*id))
        .collect();
    if !new_agents.is_empty() {
        info!(
            count = new_agents.len(),
            "reconciliation: discovered untracked agents"
        );
    }

    let removed_agents: Vec<_> = tracked_ids
        .iter()
        .filter(|id| !verifier_set.contains(id))
        .collect();
    if !removed_agents.is_empty() {
        info!(
            count = removed_agents.len(),
            "reconciliation: agents no longer in verifier"
        );
    }

    let mut corrections = 0u64;
    for id_str in &verifier_ids {
        let tracked = state.tracked_success(id_str);
        let Some(tracked_success) = tracked else {
            continue;
        };

        let agent = match state.keylime().get_verifier_agent(id_str).await {
            Ok(a) => a,
            Err(_) => continue,
        };

        let agent_state = if agent.is_push_mode() {
            AgentState::from_push_agent(&agent)
        } else {
            AgentState::from_operational_state(&agent.operational_state)
                .unwrap_or(AgentState::Failed)
        };

        let actual_success = !agent_state.is_failed();
        if actual_success != tracked_success {
            corrections += 1;
            info!(
                agent_id = id_str,
                tracked = tracked_success,
                actual = actual_success,
                "reconciliation: corrected stale tracker entry"
            );
            state.mark_recorded(id_str, actual_success);
        }
    }

    info!(
        corrections,
        verifier_count = verifier_ids.len(),
        tracked_count = tracked_ids.len(),
        "reconciliation sweep complete"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::config::KeylimeConfig;
    use crate::keylime::client::KeylimeClient;
    use crate::repository::{InMemoryCacheBackend, Repositories};

    fn test_state() -> AppState {
        let config = KeylimeConfig {
            verifier_url: "http://localhost:3000".into(),
            registrar_url: "http://localhost:3001".into(),
            mtls: None,
            timeout_secs: 5,
            observation_interval_secs: 1,
            circuit_breaker: Default::default(),
        };
        let client = KeylimeClient::new(config).unwrap();
        let repos = Repositories::in_memory();
        AppState::new(
            client,
            repos.alert,
            repos.attestation,
            repos.policy,
            repos.audit,
            Arc::new(InMemoryCacheBackend::new()),
            None,
        )
    }

    #[tokio::test]
    async fn shutdown_signal_stops_loop() {
        let state = test_state();
        let (tx, rx) = watch::channel(());

        let handle = tokio::spawn(background_observation_loop(state, 3600, rx));

        tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "loop should exit promptly on shutdown signal"
        );
    }

    #[tokio::test]
    async fn api_error_does_not_crash_loop() {
        let state = test_state();
        let (tx, rx) = watch::channel(());

        let handle = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(50));
            let mut shutdown = rx;
            for _ in 0..3 {
                tokio::select! {
                    _ = ticker.tick() => {},
                    _ = shutdown.changed() => return,
                }
                record_agent_observations(&state).await;
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "loop should survive API errors");

        drop(tx);
    }

    #[test]
    fn reconciliation_tick_cadence() {
        for tick in 1..=30 {
            let should_reconcile = tick % RECONCILIATION_EVERY_N_TICKS == 0;
            match tick {
                10 | 20 | 30 => assert!(should_reconcile, "tick {tick} should reconcile"),
                _ => assert!(!should_reconcile, "tick {tick} should not reconcile"),
            }
        }
    }

    #[test]
    fn dedup_tracker_suppresses_duplicate() {
        let state = test_state();
        state.mark_recorded("agent-1", true);
        assert!(
            !state.should_record_attestation("agent-1", true),
            "duplicate within interval should be suppressed"
        );
    }

    #[test]
    fn state_change_bypasses_dedup() {
        let state = test_state();
        state.mark_recorded("agent-1", true);
        assert!(
            state.should_record_attestation("agent-1", false),
            "pass -> fail should record immediately"
        );
    }
}
