use axum::extract::{Path, Query};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::response::{ApiResponse, PaginatedResponse};
use crate::error::AppResult;
use crate::models::agent::{Agent, AgentSummary};

/// Query parameters for agent list filtering (FR-014).
#[derive(Debug, Deserialize)]
pub struct AgentListParams {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub state: Option<String>,
    pub ip: Option<String>,
    pub uuid: Option<String>,
    pub policy: Option<String>,
    pub min_failures: Option<u32>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

/// GET /api/agents -- Paginated, filterable agent list (FR-012, FR-013, FR-014).
pub async fn list_agents(
    Query(_params): Query<AgentListParams>,
) -> AppResult<Json<ApiResponse<PaginatedResponse<AgentSummary>>>> {
    // TODO: query Verifier API + cache, apply filters, paginate
    todo!()
}

/// GET /api/agents/:id -- Agent detail view (FR-018).
pub async fn get_agent(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<Agent>>> {
    // TODO: fetch agent detail from Verifier + Registrar
    todo!()
}

/// Global agent search by UUID, IP, or hostname (FR-004).
#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: String,
}

/// GET /api/agents/search -- Global search (FR-004, FR-015 CIDR support).
pub async fn search_agents(
    Query(_params): Query<SearchParams>,
) -> AppResult<Json<ApiResponse<Vec<AgentSummary>>>> {
    // TODO: search by UUID prefix, IP, CIDR range, hostname
    todo!()
}

/// POST /api/agents/:id/actions/:action -- Agent actions (FR-019).
pub async fn agent_action(
    Path((_id, _action)): Path<(Uuid, String)>,
) -> AppResult<Json<ApiResponse<()>>> {
    // TODO: reactivate, stop, delete, force_attest
    todo!()
}

/// POST /api/agents/bulk -- Bulk operations on selected agents (FR-016).
#[derive(Debug, Deserialize)]
pub struct BulkActionRequest {
    pub agent_ids: Vec<Uuid>,
    pub action: String,
}

pub async fn bulk_action(Json(_body): Json<BulkActionRequest>) -> AppResult<Json<ApiResponse<()>>> {
    // TODO: execute bulk operations, return partial success/failure summary
    todo!()
}

/// GET /api/agents/:id/timeline -- Attestation timeline (FR-020).
pub async fn get_timeline(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// GET /api/agents/:id/pcr -- PCR values (FR-021, FR-022).
pub async fn get_pcr_values(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// GET /api/agents/:id/ima-log -- IMA log entries (FR-020).
pub async fn get_ima_log(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// GET /api/agents/:id/boot-log -- Boot log entries (FR-020).
pub async fn get_boot_log(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// GET /api/agents/:id/certificates -- Agent certificates (FR-020).
pub async fn get_agent_certs(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// GET /api/agents/:id/raw -- Raw JSON agent record (FR-020).
pub async fn get_raw_data(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}
