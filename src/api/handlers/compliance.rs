use axum::extract::Query;
use axum::Json;
use serde::Deserialize;

use crate::api::response::ApiResponse;
use crate::error::AppResult;

/// GET /api/compliance/frameworks -- List supported frameworks (FR-059).
pub async fn list_frameworks() -> AppResult<Json<ApiResponse<()>>> {
    // NIST SP 800-155, NIST SP 800-193, PCI DSS 4.0,
    // SOC 2 Type II, FedRAMP, CIS Controls v8
    todo!()
}

/// GET /api/compliance/reports/:framework -- Framework mapping report (FR-059).
pub async fn get_report(
    axum::extract::Path(_framework): axum::extract::Path<String>,
) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}

/// Export parameters for compliance reports (FR-060).
#[derive(Debug, Deserialize)]
pub struct ExportParams {
    pub format: String,
    pub start: Option<String>,
    pub end: Option<String>,
}

/// POST /api/compliance/reports/:framework/export -- One-click export (FR-060).
pub async fn export_report(
    axum::extract::Path(_framework): axum::extract::Path<String>,
    Query(_params): Query<ExportParams>,
) -> AppResult<Json<ApiResponse<()>>> {
    // TODO: generate PDF or CSV
    todo!()
}
