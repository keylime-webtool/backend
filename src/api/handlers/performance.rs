use axum::Json;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};

/// GET /api/performance/verifiers -- Verifier cluster metrics (FR-064).
pub async fn verifier_metrics() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/performance/database -- Database connection pool monitoring (FR-065).
pub async fn database_metrics() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/performance/api-response-times -- API response time tracking (FR-066).
pub async fn api_response_times() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/performance/config -- Live configuration with drift detection (FR-067).
pub async fn config_drift() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/performance/capacity -- Capacity planning projections (FR-068).
pub async fn capacity_planning() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}
