use axum::Json;

use crate::api::response::ApiResponse;
use crate::error::AppResult;
use crate::models::kpi::FleetKpis;

/// GET /api/kpis -- Fleet overview KPIs (FR-001).
pub async fn get_kpis() -> AppResult<Json<ApiResponse<FleetKpis>>> {
    // TODO: compute KPIs from Verifier/Registrar data + cache
    todo!()
}
