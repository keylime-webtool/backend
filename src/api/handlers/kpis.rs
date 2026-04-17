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
                if agent.ima_policy.is_some() {
                    policy_count += 1;
                }
            }
            Err(_) => {
                failed += 1;
            }
        }
    }

    let success_rate = if total > 0 {
        ((total - failed) as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    let kpis = FleetKpis {
        total_active_agents: active,
        failed_agents: failed,
        attestation_success_rate: success_rate,
        average_attestation_latency_ms: 0.0, // requires TimescaleDB
        certificate_expiry_warnings: 0,      // requires cert tracking
        active_ima_policies: policy_count,
        revocation_events_24h: 0, // requires event store
        registration_count: total,
    };

    Ok(Json(ApiResponse::ok(kpis)))
}
