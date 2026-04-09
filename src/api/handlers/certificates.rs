use axum::extract::Path;
use axum::Json;
use uuid::Uuid;

use crate::api::response::ApiResponse;
use crate::error::AppResult;
use crate::models::certificate::{Certificate, CertificateExpirySummary};

/// GET /api/certificates -- Unified certificate view (FR-050).
pub async fn list_certificates() -> AppResult<Json<ApiResponse<Vec<Certificate>>>> {
    todo!()
}

/// GET /api/certificates/expiry -- Certificate expiry dashboard (FR-051).
pub async fn expiry_summary() -> AppResult<Json<ApiResponse<CertificateExpirySummary>>> {
    todo!()
}

/// GET /api/certificates/:id -- Certificate detail inspection (FR-052).
pub async fn get_certificate(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<Certificate>>> {
    todo!()
}

/// POST /api/certificates/:id/renew -- Trigger certificate renewal (FR-053).
pub async fn renew_certificate(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    todo!()
}
