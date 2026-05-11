use axum::extract::State;
use axum::Json;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::agent::AgentState;
use crate::models::kpi::FleetKpis;
use crate::state::AppState;

/// GET /api/kpis -- Fleet overview KPIs (FR-001).
pub async fn get_kpis(State(state): State<AppState>) -> AppResult<Json<ApiResponse<FleetKpis>>> {
    // Fetch all agent IDs from Verifier
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let total = agent_ids.len() as u64;

    let mut failed: u64 = 0;
    let mut active: u64 = 0;
    let mut policy_count: u64 = 0;

    // Fetch each agent's state to compute KPIs
    for id_str in &agent_ids {
        match state.keylime().get_verifier_agent(id_str).await {
            Ok(agent) => {
                let agent_state = if agent.is_push_mode() {
                    AgentState::from_push_agent(&agent)
                } else {
                    AgentState::from_operational_state(&agent.operational_state)
                        .map_err(AppError::Internal)?
                };
                if agent_state.is_failed() {
                    failed += 1;
                } else {
                    active += 1;
                }
                if agent.effective_ima_policy().is_some() {
                    policy_count += 1;
                }
            }
            Err(_) => {
                failed += 1;
            }
        }
    }

    let kpis = compute_fleet_kpis(active, failed, policy_count, total);

    Ok(Json(ApiResponse::ok(kpis)))
}

pub(crate) fn compute_fleet_kpis(
    active: u64,
    failed: u64,
    policy_count: u64,
    total: u64,
) -> FleetKpis {
    let success_rate = if total > 0 {
        ((total - failed) as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    FleetKpis {
        total_active_agents: active,
        failed_agents: failed,
        attestation_success_rate: success_rate,
        average_attestation_latency_ms: 0.0,
        certificate_expiry_warnings: 0,
        active_ima_policies: policy_count,
        revocation_events_24h: 0,
        registration_count: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_fleet() {
        let kpis = compute_fleet_kpis(0, 0, 0, 0);
        assert_eq!(kpis.attestation_success_rate, 100.0);
        assert_eq!(kpis.total_active_agents, 0);
        assert_eq!(kpis.failed_agents, 0);
        assert_eq!(kpis.registration_count, 0);
    }

    #[test]
    fn all_active() {
        let kpis = compute_fleet_kpis(10, 0, 3, 10);
        assert_eq!(kpis.attestation_success_rate, 100.0);
        assert_eq!(kpis.total_active_agents, 10);
        assert_eq!(kpis.active_ima_policies, 3);
    }

    #[test]
    fn all_failed() {
        let kpis = compute_fleet_kpis(0, 5, 0, 5);
        assert_eq!(kpis.attestation_success_rate, 0.0);
        assert_eq!(kpis.failed_agents, 5);
    }

    #[test]
    fn mixed_fleet() {
        let kpis = compute_fleet_kpis(7, 3, 2, 10);
        assert!((kpis.attestation_success_rate - 70.0).abs() < 0.01);
        assert_eq!(kpis.total_active_agents, 7);
        assert_eq!(kpis.failed_agents, 3);
    }
}
