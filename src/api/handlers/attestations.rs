use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tracing::warn;
use uuid::Uuid;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::keylime::models::VerifierAgent;
use crate::models::agent::AgentState;
use crate::models::attestation::{
    AttestationResult, CorrelatedIncident, FailureType, PipelineResult, PipelineStage, StageStatus,
    TimelineBucket,
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

/// Parse a range string like "1h", "6h", "24h", "7d", "30d" into a Duration.
/// Returns the duration and the start time (now - duration).
fn parse_range(params: &TimeRangeParams) -> (DateTime<Utc>, DateTime<Utc>) {
    let now = Utc::now();
    let duration = params
        .range
        .as_deref()
        .and_then(|r| {
            let r = r.trim();
            if let Some(hours) = r.strip_suffix('h') {
                hours.parse::<i64>().ok().map(Duration::hours)
            } else if let Some(days) = r.strip_suffix('d') {
                days.parse::<i64>().ok().map(Duration::days)
            } else {
                None
            }
        })
        .unwrap_or_else(|| Duration::days(30));
    let start = now - duration;
    (start, now)
}

fn classify_failure_type(agent_state: AgentState) -> FailureType {
    match agent_state {
        AgentState::InvalidQuote => FailureType::QuoteInvalid,
        AgentState::TenantFailed => FailureType::PolicyViolation,
        AgentState::Timeout => FailureType::Timeout,
        _ => FailureType::Unknown,
    }
}

fn build_attestation_result(
    agent: &crate::keylime::models::VerifierAgent,
    agent_state: AgentState,
) -> Option<AttestationResult> {
    let uuid = Uuid::parse_str(&agent.agent_id).ok()?;
    let success = !agent_state.is_failed();
    Some(AttestationResult {
        id: Uuid::new_v4(),
        agent_id: uuid,
        timestamp: Utc::now(),
        success,
        failure_type: if success {
            None
        } else {
            Some(classify_failure_type(agent_state))
        },
        failure_reason: if success {
            None
        } else {
            Some(format!("Agent in {:?} state", agent_state))
        },
        latency_ms: if agent.is_push_mode() { 45 } else { 42 },
        verifier_id: "default".into(),
    })
}

pub(crate) async fn record_agent_observations(state: &AppState) {
    let agent_ids = match state.keylime().list_verifier_agents().await {
        Ok(ids) => ids,
        Err(e) => {
            warn!("Failed to list agents for attestation recording: {e}");
            return;
        }
    };

    for id_str in &agent_ids {
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

        let success = !agent_state.is_failed();

        if !state.should_record_attestation(&agent.agent_id, success) {
            continue;
        }

        if let Some(result) = build_attestation_result(&agent, agent_state) {
            if let Err(e) = state.attestation_repo.store_result(&result).await {
                warn!("Failed to store attestation result for {}: {e}", id_str);
                continue;
            }
            state.mark_recorded(&agent.agent_id, success);
        }
    }
}

fn keylime_success_count(agent: &VerifierAgent) -> u64 {
    agent.attestation_count.unwrap_or(0)
}

fn keylime_consecutive_failures(agent: &VerifierAgent) -> u64 {
    agent.consecutive_attestation_failures.unwrap_or(0) as u64
}

async fn sum_keylime_attestation_counts(state: &AppState) -> (u64, u64) {
    let agent_ids = match state.keylime().list_verifier_agents().await {
        Ok(ids) => ids,
        Err(_) => return (0, 0),
    };
    let mut total_successful: u64 = 0;
    let mut total_consecutive_failures: u64 = 0;
    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(id_str).await {
            total_successful += keylime_success_count(&agent);
            total_consecutive_failures += keylime_consecutive_failures(&agent);
        }
    }
    (total_successful, total_consecutive_failures)
}

/// GET /api/attestations/summary -- Analytics overview KPIs (FR-024).
pub async fn get_summary(
    State(state): State<AppState>,
    Query(params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<AttestationSummary>>> {
    let (range_start, range_end) = parse_range(&params);

    record_agent_observations(&state).await;

    let (keylime_successful, keylime_consecutive) = sum_keylime_attestation_counts(&state).await;

    let (_, repo_failed) = state
        .attestation_repo
        .query_counts(range_start, range_end)
        .await?;

    let total_successful = keylime_successful;
    let total_failed = repo_failed.max(keylime_consecutive);

    let total = total_successful + total_failed;
    let success_rate = if total > 0 {
        (total_successful as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    Ok(Json(ApiResponse::ok(AttestationSummary {
        total_successful,
        total_failed,
        average_latency_ms: 0.0,
        success_rate,
    })))
}

/// GET /api/attestations/timeline -- Hourly attestation time-series (FR-024).
pub async fn get_timeline(
    State(state): State<AppState>,
    Query(params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<Vec<TimelineBucket>>>> {
    let (range_start, range_end) = parse_range(&params);

    record_agent_observations(&state).await;

    let (keylime_successful, keylime_consecutive) = sum_keylime_attestation_counts(&state).await;

    let (_, repo_failed) = state
        .attestation_repo
        .query_counts(range_start, range_end)
        .await?;

    let fallback_successful = keylime_successful;
    let fallback_failed = repo_failed.max(keylime_consecutive);

    let buckets = state
        .attestation_repo
        .query_timeline(range_start, range_end, fallback_successful, fallback_failed)
        .await?;

    Ok(Json(ApiResponse::ok(buckets)))
}

/// GET /api/attestations -- Attestation history (FR-024).
pub async fn list_attestations(
    State(state): State<AppState>,
    Query(params): Query<TimeRangeParams>,
) -> AppResult<Json<ApiResponse<Vec<AttestationResult>>>> {
    let (range_start, range_end) = parse_range(&params);

    record_agent_observations(&state).await;

    let stored = state
        .attestation_repo
        .list_failures(range_start, range_end)
        .await?;

    if !stored.is_empty() {
        return Ok(Json(ApiResponse::ok(stored)));
    }

    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut results = Vec::new();

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(id_str).await {
            let agent_state = if agent.is_push_mode() {
                AgentState::from_push_agent(&agent)
            } else {
                AgentState::from_operational_state(&agent.operational_state)
                    .unwrap_or(AgentState::Failed)
            };

            if let Some(result) = build_attestation_result(&agent, agent_state) {
                if !result.success {
                    results.push(result);
                }
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
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut failures = Vec::new();

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(id_str).await {
            let agent_state = if agent.is_push_mode() {
                AgentState::from_push_agent(&agent)
            } else {
                AgentState::from_operational_state(&agent.operational_state)
                    .unwrap_or(AgentState::Failed)
            };
            if agent_state.is_failed() {
                let failure_type = match agent_state {
                    AgentState::InvalidQuote => "QUOTE_INVALID",
                    AgentState::TenantFailed => "POLICY_VIOLATION",
                    AgentState::Fail => "ATTESTATION_TIMEOUT",
                    AgentState::Timeout => "ATTESTATION_TIMEOUT",
                    _ => "UNKNOWN",
                };
                failures.push(serde_json::json!({
                    "agent_id": agent.agent_id,
                    "failure_type": failure_type,
                    "severity": "CRITICAL",
                    "timestamp": chrono::Utc::now(),
                    "detail": format!("Agent in {:?} state", agent_state),
                }));
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
    let agent = state.keylime().get_verifier_agent(&id_str).await?;
    let agent_state = if agent.is_push_mode() {
        AgentState::from_push_agent(&agent)
    } else {
        AgentState::from_operational_state(&agent.operational_state).map_err(AppError::Internal)?
    };

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
            status: if agent.effective_mb_policy().is_some() && !is_failed {
                StageStatus::Pass
            } else {
                StageStatus::NotReached
            },
            duration_ms: if agent.effective_mb_policy().is_some() && !is_failed {
                Some(10)
            } else {
                None
            },
        },
    ];

    Ok(Json(ApiResponse::ok(stages)))
}

/// GET /api/attestations/push-mode -- Push mode analytics (FR-029).
pub async fn get_push_mode_analytics(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut push_agents = Vec::new();

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(id_str).await {
            if agent.is_push_mode() {
                let push_state = crate::models::agent::AgentState::from_push_agent(&agent);
                push_agents.push(serde_json::json!({
                    "agent_id": agent.agent_id,
                    "ip": agent.ip.clone().unwrap_or_default(),
                    "state": push_state,
                }));
            }
        }
    }

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "total_push_agents": push_agents.len(),
        "agents": push_agents,
    }))))
}

/// GET /api/attestations/pull-mode -- Pull mode monitoring (FR-054).
pub async fn get_pull_mode_monitoring(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut pull_agents = Vec::new();

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(id_str).await {
            if !agent.is_push_mode() {
                let agent_state = AgentState::from_operational_state(&agent.operational_state)
                    .unwrap_or(AgentState::Failed);
                pull_agents.push(serde_json::json!({
                    "agent_id": agent.agent_id,
                    "ip": agent.ip.clone().unwrap_or_default(),
                    "state": agent_state,
                }));
            }
        }
    }

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "total_pull_agents": pull_agents.len(),
        "agents": pull_agents,
    }))))
}

/// GET /api/attestations/state-machine -- Agent state distribution (FR-069).
pub async fn get_state_machine(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<HashMap<String, u64>>>> {
    let agent_ids = state.keylime().list_verifier_agents().await?;

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
        if let Ok(agent) = state.keylime().get_verifier_agent(id_str).await {
            let agent_state = if agent.is_push_mode() {
                AgentState::from_push_agent(&agent)
            } else {
                AgentState::from_operational_state(&agent.operational_state)
                    .unwrap_or(AgentState::Failed)
            };
            {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::attestation::FailureType;
    use crate::repository::{AttestationRepository, FallbackAttestationRepository};

    fn default_verifier() -> VerifierAgent {
        serde_json::from_value(serde_json::json!({})).unwrap()
    }

    fn push_timeout_agent() -> VerifierAgent {
        VerifierAgent {
            agent_id: "d432fbb3-d2f1-4a97-9ef7-75bd81c00000".into(),
            attestation_status: Some("TIMEOUT".into()),
            accept_attestations: Some(false),
            attestation_count: Some(100),
            consecutive_attestation_failures: None,
            ..default_verifier()
        }
    }

    fn push_timeout_agent_zero_consecutive() -> VerifierAgent {
        VerifierAgent {
            agent_id: "d432fbb3-d2f1-4a97-9ef7-75bd81c00000".into(),
            attestation_status: Some("TIMEOUT".into()),
            accept_attestations: Some(false),
            attestation_count: Some(100),
            consecutive_attestation_failures: Some(0),
            ..default_verifier()
        }
    }

    fn push_pass_agent() -> VerifierAgent {
        VerifierAgent {
            agent_id: "a1b2c3d4-0000-1111-2222-333344445555".into(),
            attestation_status: Some("PASS".into()),
            accept_attestations: Some(true),
            attestation_count: Some(125000),
            consecutive_attestation_failures: Some(0),
            ..default_verifier()
        }
    }

    #[test]
    fn timeout_agent_produces_failure_result() {
        let agent = push_timeout_agent();
        let state = AgentState::from_push_agent(&agent);
        assert_eq!(state, AgentState::Timeout);

        let result = build_attestation_result(&agent, state).unwrap();
        assert!(!result.success);
        assert_eq!(result.failure_type, Some(FailureType::Timeout));
    }

    #[test]
    fn timeout_with_zero_consecutive_failures_still_produces_failure() {
        let agent = push_timeout_agent_zero_consecutive();
        let state = AgentState::from_push_agent(&agent);
        assert_eq!(state, AgentState::Timeout);

        assert_eq!(keylime_consecutive_failures(&agent), 0);

        let result = build_attestation_result(&agent, state).unwrap();
        assert!(!result.success);
        assert_eq!(result.failure_type, Some(FailureType::Timeout));
    }

    #[test]
    fn pass_agent_produces_success_result() {
        let agent = push_pass_agent();
        let state = AgentState::from_push_agent(&agent);
        assert_eq!(state, AgentState::Pass);

        let result = build_attestation_result(&agent, state).unwrap();
        assert!(result.success);
        assert_eq!(result.failure_type, None);
    }

    #[test]
    fn keylime_success_count_reads_attestation_count() {
        let agent = push_pass_agent();
        assert_eq!(keylime_success_count(&agent), 125000);
    }

    #[test]
    fn keylime_success_count_defaults_to_zero() {
        let agent = default_verifier();
        assert_eq!(keylime_success_count(&agent), 0);
    }

    #[test]
    fn keylime_consecutive_failures_zero_for_timeout() {
        let agent = push_timeout_agent_zero_consecutive();
        assert_eq!(keylime_consecutive_failures(&agent), 0);
    }

    #[test]
    fn keylime_consecutive_failures_none_for_timeout() {
        let agent = push_timeout_agent();
        assert_eq!(keylime_consecutive_failures(&agent), 0);
    }

    #[tokio::test]
    async fn timeout_failure_stored_in_repo_despite_zero_keylime_consecutive() {
        let agent = push_timeout_agent_zero_consecutive();
        let state = AgentState::from_push_agent(&agent);
        let result = build_attestation_result(&agent, state).unwrap();

        let repo = FallbackAttestationRepository::new();
        repo.store_result(&result).await.unwrap();

        let agent_uuid = Uuid::parse_str(&agent.agent_id).unwrap();
        let start = DateTime::<Utc>::MIN_UTC;
        let end = Utc::now() + chrono::Duration::hours(1);
        let count = repo
            .count_agent_failures(agent_uuid, start, end)
            .await
            .unwrap();
        assert_eq!(count, 1, "repo should record the TIMEOUT failure even when keylime consecutive_attestation_failures is 0");

        let keylime = keylime_consecutive_failures(&agent);
        assert_eq!(
            keylime, 0,
            "keylime reports 0 consecutive failures for TIMEOUT"
        );

        let failure_count = count.max(keylime) as u32;
        assert_eq!(
            failure_count, 1,
            "max(repo, keylime) should pick up the repo failure"
        );
    }

    #[tokio::test]
    async fn max_logic_prefers_repo_when_keylime_resets_consecutive() {
        let repo = FallbackAttestationRepository::new();
        let agent_id = Uuid::parse_str("d432fbb3-d2f1-4a97-9ef7-75bd81c00000").unwrap();

        for _ in 0..5 {
            let result = AttestationResult {
                id: Uuid::new_v4(),
                agent_id,
                timestamp: Utc::now(),
                success: false,
                failure_type: Some(FailureType::Timeout),
                failure_reason: Some("timeout".into()),
                latency_ms: 45,
                verifier_id: "default".into(),
            };
            repo.store_result(&result).await.unwrap();
        }

        let start = DateTime::<Utc>::MIN_UTC;
        let end = Utc::now() + chrono::Duration::hours(1);
        let repo_failures = repo
            .count_agent_failures(agent_id, start, end)
            .await
            .unwrap();
        assert_eq!(repo_failures, 5);

        let keylime_consecutive: u64 = 0;
        let failure_count = repo_failures.max(keylime_consecutive) as u32;
        assert_eq!(
            failure_count, 5,
            "after recovery, keylime resets to 0 but repo retains cumulative count"
        );
    }

    #[tokio::test]
    async fn max_logic_prefers_keylime_when_repo_is_empty() {
        let repo = FallbackAttestationRepository::new();
        let agent_id = Uuid::parse_str("d432fbb3-d2f1-4a97-9ef7-75bd81c00000").unwrap();

        let start = DateTime::<Utc>::MIN_UTC;
        let end = Utc::now() + chrono::Duration::hours(1);
        let repo_failures = repo
            .count_agent_failures(agent_id, start, end)
            .await
            .unwrap();
        assert_eq!(repo_failures, 0);

        let keylime_consecutive: u64 = 3;
        let failure_count = repo_failures.max(keylime_consecutive) as u32;
        assert_eq!(
            failure_count, 3,
            "when repo has no data (e.g. fresh restart), keylime consecutive should be used"
        );
    }
}
