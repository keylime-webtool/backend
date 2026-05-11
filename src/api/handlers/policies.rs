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
    let ima_names = state.keylime().list_policies().await?;
    let mb_names = state.keylime().list_mb_policies().await.unwrap_or_default();

    // Fetch all agents once — avoids O(policies × agents) API calls.
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut agents = Vec::new();
    for id in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(id).await {
            agents.push(agent);
        }
    }

    let mut policies = Vec::new();

    // IMA policies from GET /v2/allowlists/
    for name in &ima_names {
        let runtime = state.keylime().get_policy(name).await?;
        let assigned = count_assigned(&agents, name, PolicyKind::Ima);
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
            kind: PolicyKind::Ima,
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

    // MB policies from GET /v2/mbpolicies/
    for name in &mb_names {
        let assigned = count_assigned(&agents, name, PolicyKind::MeasuredBoot);
        policies.push(Policy {
            id: name.clone(),
            name: name.clone(),
            kind: PolicyKind::MeasuredBoot,
            version: 1,
            checksum: String::new(),
            entry_count: 0,
            assigned_agents: assigned,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            updated_by: "system".into(),
            content: None,
        });
    }

    Ok(Json(ApiResponse::ok(policies)))
}

pub(crate) fn count_assigned(
    agents: &[crate::keylime::models::VerifierAgent],
    name: &str,
    kind: PolicyKind,
) -> u64 {
    agents
        .iter()
        .filter(|agent| match kind {
            PolicyKind::Ima => agent
                .effective_ima_policy()
                .map(|p| p == name)
                .unwrap_or_else(|| agent.has_runtime_policy == Some(1)),
            PolicyKind::MeasuredBoot => agent
                .effective_mb_policy()
                .map(|p| p == name)
                .unwrap_or_else(|| agent.has_mb_refstate == Some(1)),
        })
        .count() as u64
}

/// GET /api/policies/:id -- Policy detail.
pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<ApiResponse<Policy>>> {
    let runtime = state.keylime().get_policy(&id).await?;

    let mb_names = state.keylime().list_mb_policies().await.unwrap_or_default();
    let kind = if mb_names.contains(&id) {
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
    let mb_names = state.keylime().list_mb_policies().await.unwrap_or_default();
    let kind = if mb_names.contains(&id) {
        PolicyKind::MeasuredBoot
    } else {
        PolicyKind::Ima
    };

    let agent_ids = state.keylime().list_verifier_agents().await?;
    let mut affected: u64 = 0;
    let mut unaffected: u64 = 0;

    for aid in &agent_ids {
        if let Ok(agent) = state.keylime().get_verifier_agent(aid).await {
            // Check exact policy name first (mock data), fall back to
            // type-level flag (real Keylime v2 — approximate).
            let matches = match kind {
                PolicyKind::Ima => agent
                    .effective_ima_policy()
                    .map(|p| p == id.as_str())
                    .unwrap_or_else(|| agent.has_runtime_policy == Some(1)),
                PolicyKind::MeasuredBoot => agent
                    .effective_mb_policy()
                    .map(|p| p == id.as_str())
                    .unwrap_or_else(|| agent.has_mb_refstate == Some(1)),
            };
            if matches {
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
                "ip": agent.ip.clone().unwrap_or_default(),
                "ima_policy": agent.effective_ima_policy(),
                "mb_policy": agent.effective_mb_policy(),
                "has_runtime_policy": agent.has_runtime_policy,
                "has_mb_refstate": agent.has_mb_refstate,
            }));
        }
    }

    Ok(Json(ApiResponse::ok(matrix)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylime::models::VerifierAgent;

    fn make_agent(ima: Option<&str>, mb: Option<&str>) -> VerifierAgent {
        let mut agent: VerifierAgent = serde_json::from_value(serde_json::json!({})).unwrap();
        if let Some(p) = ima {
            agent.ima_policy = Some(p.to_string());
        }
        if let Some(p) = mb {
            agent.mb_policy = Some(p.to_string());
        }
        agent
    }

    #[test]
    fn count_assigned_empty_agents() {
        let agents: Vec<VerifierAgent> = vec![];
        assert_eq!(count_assigned(&agents, "test", PolicyKind::Ima), 0);
    }

    #[test]
    fn count_assigned_ima_match() {
        let agents = vec![
            make_agent(Some("prod-v1"), None),
            make_agent(Some("staging"), None),
            make_agent(Some("prod-v1"), None),
        ];
        assert_eq!(count_assigned(&agents, "prod-v1", PolicyKind::Ima), 2);
    }

    #[test]
    fn count_assigned_mb_match() {
        let agents = vec![
            make_agent(None, Some("boot-v1")),
            make_agent(None, Some("boot-v2")),
        ];
        assert_eq!(
            count_assigned(&agents, "boot-v1", PolicyKind::MeasuredBoot),
            1
        );
    }

    #[test]
    fn count_assigned_fallback_flag() {
        let mut agent: VerifierAgent = serde_json::from_value(serde_json::json!({})).unwrap();
        agent.has_runtime_policy = Some(1);
        let agents = vec![agent];
        assert_eq!(count_assigned(&agents, "any-name", PolicyKind::Ima), 1);
    }

    #[test]
    fn count_assigned_no_match() {
        let agents = vec![make_agent(Some("other"), None)];
        assert_eq!(count_assigned(&agents, "prod-v1", PolicyKind::Ima), 0);
    }
}
