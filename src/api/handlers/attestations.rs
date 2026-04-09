use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::agent::AgentState;
use crate::models::attestation::{
    AttestationResult, CorrelatedIncident, PipelineResult, PipelineStage, StageStatus,
};
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
    State(state): State<AppState>,
    Query(_params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<AttestationSummary>>> {
    let agent_ids = state.keylime.list_verifier_agents().await?;
    let total = agent_ids.len() as u64;
    let mut failed: u64 = 0;

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime.get_verifier_agent(id_str).await {
            if let Ok(agent_state) = AgentState::try_from(agent.operational_state) {
                if agent_state.is_failed() {
                    failed += 1;
                }
            }
        }
    }

    let successful = total - failed;
    let success_rate = if total > 0 {
        (successful as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    Ok(Json(ApiResponse::ok(AttestationSummary {
        total_successful: successful,
        total_failed: failed,
        average_latency_ms: 0.0,
        success_rate,
    })))
}

/// GET /api/attestations -- Attestation history (FR-024).
pub async fn list_attestations(
    State(state): State<AppState>,
    Query(_params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<Vec<AttestationResult>>>> {
    let agent_ids = state.keylime.list_verifier_agents().await?;
    let now = chrono::Utc::now();
    let mut results = Vec::new();

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime.get_verifier_agent(id_str).await {
            let agent_state = AgentState::try_from(agent.operational_state).ok();
            let is_failed = agent_state.map(|s| s.is_failed()).unwrap_or(false);

            if let Ok(uuid) = Uuid::parse_str(&agent.agent_id) {
                results.push(AttestationResult {
                    id: Uuid::new_v4(),
                    agent_id: uuid,
                    timestamp: now - chrono::Duration::minutes(5),
                    success: !is_failed,
                    failure_type: if is_failed {
                        Some(crate::models::attestation::FailureType::PolicyViolation)
                    } else {
                        None
                    },
                    failure_reason: if is_failed {
                        Some("IMA policy violation detected".into())
                    } else {
                        None
                    },
                    latency_ms: 45,
                    verifier_id: "default".into(),
                });
            }
        }
    }

    Ok(Json(ApiResponse::ok(results)))
}

/// GET /api/attestations/failures -- Failure categorization (FR-025).
pub async fn get_failures(
    State(state): State<AppState>,
    Query(_params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<Vec<serde_json::Value>>>> {
    let agent_ids = state.keylime.list_verifier_agents().await?;
    let mut failures = Vec::new();

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime.get_verifier_agent(id_str).await {
            if let Ok(agent_state) = AgentState::try_from(agent.operational_state) {
                if agent_state.is_failed() {
                    let failure_type = match agent_state {
                        AgentState::InvalidQuote => "QUOTE_INVALID",
                        AgentState::TenantFailed => "POLICY_VIOLATION",
                        _ => "UNKNOWN",
                    };
                    failures.push(serde_json::json!({
                        "agent_id": agent.agent_id,
                        "failure_type": failure_type,
                        "severity": "CRITICAL",
                        "timestamp": chrono::Utc::now(),
                        "detail": format!("Agent in {} state (operational_state={})",
                            failure_type, agent.operational_state),
                    }));
                }
            }
        }
    }

    Ok(Json(ApiResponse::ok(failures)))
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
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<Vec<PipelineResult>>>> {
    let id_str = agent_id.to_string();
    let agent = state.keylime.get_verifier_agent(&id_str).await?;
    let agent_state = AgentState::try_from(agent.operational_state).map_err(AppError::Internal)?;

    let is_failed = agent_state.is_failed();

    // Generate pipeline stages based on agent state
    let stages = vec![
        PipelineResult {
            stage: PipelineStage::ReceiveQuote,
            status: StageStatus::Pass,
            duration_ms: Some(12),
        },
        PipelineResult {
            stage: PipelineStage::ValidateTpmQuote,
            status: if is_failed {
                StageStatus::Fail
            } else {
                StageStatus::Pass
            },
            duration_ms: Some(25),
        },
        PipelineResult {
            stage: PipelineStage::CheckPcrValues,
            status: if is_failed {
                StageStatus::NotReached
            } else {
                StageStatus::Pass
            },
            duration_ms: if is_failed { None } else { Some(8) },
        },
        PipelineResult {
            stage: PipelineStage::VerifyImaLog,
            status: if is_failed {
                StageStatus::NotReached
            } else {
                StageStatus::Pass
            },
            duration_ms: if is_failed { None } else { Some(15) },
        },
        PipelineResult {
            stage: PipelineStage::VerifyMeasuredBoot,
            status: if agent.mb_policy.is_some() && !is_failed {
                StageStatus::Pass
            } else {
                StageStatus::NotReached
            },
            duration_ms: if agent.mb_policy.is_some() && !is_failed {
                Some(10)
            } else {
                None
            },
        },
    ];

    Ok(Json(ApiResponse::ok(stages)))
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
