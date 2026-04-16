use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::policy::{ImpactAnalysis, Policy, PolicyChange, PolicyKind};
use crate::state::AppState;

/// GET /api/policies -- List all policies (FR-033).
pub async fn list_policies(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<Vec<Policy>>>> {
    let policy_names = state.keylime().list_policies().await?;

    let mut policies = Vec::new();
    for name in &policy_names {
        let runtime = state.keylime().get_policy(name).await?;

        // Count how many agents use this policy
        let agent_ids = state.keylime().list_verifier_agents().await?;
        let mut assigned: u64 = 0;
        for id in &agent_ids {
            if let Ok(agent) = state.keylime().get_verifier_agent(id).await {
                if agent.ima_policy.as_deref() == Some(name)
                    || agent.mb_policy.as_deref() == Some(name)
                {
                    assigned += 1;
                }
            }
        }

        let kind = if name.contains("boot") {
            PolicyKind::MeasuredBoot
        } else {
            PolicyKind::Ima
        };

        let entry_count = runtime
            .runtime_policy
            .as_ref()
            .and_then(|v| v.get("digests"))
            .and_then(|v| v.as_object())
            .map(|o| o.len() as u64)
            .unwrap_or(0);

        policies.push(Policy {
            id: name.clone(),
            name: name.clone(),
            kind,
            version: 1,
            checksum: String::new(),
            entry_count,
            assigned_agents: assigned,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            updated_by: "system".into(),
            content: runtime.runtime_policy.map(|v| v.to_string()),
        });
    }

    Ok(Json(ApiResponse::ok(policies)))
}

/// GET /api/policies/:id -- Policy detail.
pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<ApiResponse<Policy>>> {
    let runtime = state.keylime().get_policy(&id).await?;

    let kind = if id.contains("boot") {
        PolicyKind::MeasuredBoot
    } else {
        PolicyKind::Ima
    };

    let entry_count = runtime
        .runtime_policy
        .as_ref()
        .and_then(|v| v.get("digests"))
        .and_then(|v| v.as_object())
        .map(|o| o.len() as u64)
        .unwrap_or(0);

    let policy = Policy {
        id: runtime.name.clone(),
        name: runtime.name,
        kind,
        version: 1,
        checksum: String::new(),
        entry_count,
        assigned_agents: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        updated_by: "system".into(),
        content: runtime.runtime_policy.map(|v| v.to_string()),
    };

    Ok(Json(ApiResponse::ok(policy)))
}

/// POST /api/policies -- Create a new policy (FR-034).
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub kind: String,
    pub content: String,
}

pub async fn create_policy(
    Json(_body): Json<CreatePolicyRequest>,
) -> AppResult<Json<ApiResponse<Policy>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// PUT /api/policies/:id -- Update a policy (FR-034, triggers two-person rule FR-039).
#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub content: String,
}

pub async fn update_policy(
    Path(_id): Path<String>,
    Json(_body): Json<UpdatePolicyRequest>,
) -> AppResult<Json<ApiResponse<PolicyChange>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// DELETE /api/policies/:id -- Delete a policy (Admin only).
pub async fn delete_policy(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/policies/:id/versions -- Version history (FR-035).
pub async fn list_versions(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/policies/:id/diff?v1=X&v2=Y -- Side-by-side version diff (FR-035).
pub async fn diff_versions(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/policies/:id/rollback/:version -- Rollback to previous version (FR-035).
pub async fn rollback_policy(
    Path((_id, _version)): Path<(String, u32)>,
) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/policies/:id/impact -- Pre-update impact analysis (FR-038).
pub async fn impact_analysis(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<ApiResponse<ImpactAnalysis>>> {
    // Count agents using this policy
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut affected: u64 = 0;
    let mut unaffected: u64 = 0;

    for aid in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(aid).await {
            if agent.ima_policy.as_deref() == Some(&id) || agent.mb_policy.as_deref() == Some(&id) {
                affected += 1;
            } else {
                unaffected += 1;
            }
        }
    }

    let recommendation = if affected == 0 {
        "No agents use this policy — safe to update.".into()
    } else {
        format!("{affected} agent(s) will be re-evaluated after update. Review changes carefully.")
    };

    Ok(Json(ApiResponse::ok(ImpactAnalysis {
        policy_id: id,
        unaffected_agents: unaffected,
        affected_agents: affected,
        will_fail_agents: 0,
        hashes_added: 0,
        hashes_removed: 0,
        hashes_modified: 0,
        recommendation,
    })))
}

/// POST /api/policies/changes/:id/approve -- Two-person approval (FR-039).
pub async fn approve_change(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/policies/assignment-matrix -- Policy assignment matrix (FR-037).
pub async fn assignment_matrix(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<Vec<serde_json::Value>>>> {
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut matrix = Vec::new();

    for aid in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(aid).await {
            matrix.push(serde_json::json!({
                "agent_id": agent.agent_id,
                "ip": agent.ip,
                "ima_policy": agent.ima_policy,
                "mb_policy": agent.mb_policy,
            }));
        }
    }

    Ok(Json(ApiResponse::ok(matrix)))
}
