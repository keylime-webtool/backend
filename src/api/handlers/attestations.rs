use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::agent::AgentState;
use crate::models::attestation::{AttestationResult, CorrelatedIncident, PipelineResult};
use crate::models::kpi::AttestationSummary;
use crate::state::AppState;

/// Query parameters for attestation analytics time range (FR-005).
#[derive(Debug, Deserialize)]
pub struct TimeRangeParams {
    pub range: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
}

/// GET /api/attestations/summary -- Analytics overview KPIs (FR-024).
pub async fn get_summary(
    Query(_params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<AttestationSummary>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations -- Attestation history (FR-024).
pub async fn list_attestations(
    Query(_params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<Vec<AttestationResult>>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations/failures -- Failure categorization (FR-025).
pub async fn get_failures(
    Query(_params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations/incidents -- Correlated incidents (FR-026, FR-027).
pub async fn list_incidents() -> AppResult<Json<ApiResponse<Vec<CorrelatedIncident>>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations/incidents/:id -- Incident detail with root cause (FR-027).
pub async fn get_incident(
    Path(_id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<CorrelatedIncident>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/attestations/incidents/:id/rollback -- One-click policy rollback (FR-028).
pub async fn rollback_from_incident(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations/pipeline/:agent_id -- Verification pipeline (FR-030).
pub async fn get_pipeline(
    Path(_agent_id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<Vec<PipelineResult>>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations/push-mode -- Push mode analytics (FR-029).
pub async fn get_push_mode_analytics() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations/pull-mode -- Pull mode monitoring (FR-054).
pub async fn get_pull_mode_monitoring() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/attestations/state-machine -- Agent state distribution (FR-069).
pub async fn get_state_machine(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<HashMap<String, u64>>>> {
    let agent_ids = state.keylime.list_verifier_agents().await?;

    let mut distribution: HashMap<String, u64> = HashMap::new();
    // Initialize all known states to 0
    for s in AgentState::all() {
        let name = serde_json::to_string(s)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        distribution.insert(name, 0);
    }

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime.get_verifier_agent(id_str).await {
            if let Ok(agent_state) = AgentState::try_from(agent.operational_state) {
                let name = serde_json::to_string(&agent_state)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string();
                *distribution.entry(name).or_insert(0) += 1;
            }
        }
    }

    Ok(Json(ApiResponse::ok(distribution)))
}
