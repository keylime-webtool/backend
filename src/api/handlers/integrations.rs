use axum::Json;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::kpi::ServiceHealth;

/// GET /api/integrations/status -- Backend connectivity status (FR-057).
pub async fn connectivity_status() -> AppResult<Json<ApiResponse<Vec<ServiceHealth>>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/integrations/durable -- Durable attestation backend status (FR-058).
pub async fn durable_backends() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/integrations/revocation-channels -- Revocation channel monitoring (FR-046).
pub async fn revocation_channels() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/integrations/siem -- SIEM integration status (FR-063).
pub async fn siem_status() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}
