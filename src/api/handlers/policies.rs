use axum::extract::Path;
use axum::Json;
use serde::Deserialize;

use crate::api::response::ApiResponse;
use crate::error::AppResult;
use crate::models::policy::{ImpactAnalysis, Policy, PolicyChange};

/// GET /api/policies -- List all policies (FR-033).
pub async fn list_policies() -> AppResult<Json<ApiResponse<Vec<Policy>>>> {
    todo!()
}

/// GET /api/policies/:id -- Policy detail.
pub async fn get_policy(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<Policy>>> {
    todo!()
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
    todo!()
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
    // TODO: create draft, run impact analysis, submit for approval
    todo!()
}

/// DELETE /api/policies/:id -- Delete a policy (Admin only).
pub async fn delete_policy(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// GET /api/policies/:id/versions -- Version history (FR-035).
pub async fn list_versions(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// GET /api/policies/:id/diff?v1=X&v2=Y -- Side-by-side version diff (FR-035).
pub async fn diff_versions(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// POST /api/policies/:id/rollback/:version -- Rollback to previous version (FR-035).
pub async fn rollback_policy(
    Path((_id, _version)): Path<(String, u32)>,
) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// POST /api/policies/:id/impact -- Pre-update impact analysis (FR-038).
pub async fn impact_analysis(
    Path(_id): Path<String>,
) -> AppResult<Json<ApiResponse<ImpactAnalysis>>> {
    todo!()
}

/// POST /api/policies/changes/:id/approve -- Two-person approval (FR-039).
pub async fn approve_change(Path(_id): Path<String>) -> AppResult<Json<ApiResponse<()>>> {
    // TODO: ensure approver != drafter (SR-018)
    todo!()
}

/// GET /api/policies/assignment-matrix -- Policy assignment matrix (FR-037).
pub async fn assignment_matrix() -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}
