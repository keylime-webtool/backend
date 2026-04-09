use axum::extract::Path;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::alert::Alert;

/// GET /api/alerts -- Alert management dashboard (FR-047).
pub async fn list_alerts() -> AppResult<Json<ApiResponse<Vec<Alert>>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/alerts/:id/acknowledge -- Acknowledge an alert (FR-047).
pub async fn acknowledge_alert(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/alerts/:id/investigate -- Move to investigation (FR-047).
pub async fn investigate_alert(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/alerts/:id/resolve -- Resolve an alert (FR-047).
#[derive(Debug, Deserialize)]
pub struct ResolveRequest {
    pub reason: String,
}

pub async fn resolve_alert(
    Path(_id): Path<Uuid>,
    Json(_body): Json<ResolveRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/alerts/:id/dismiss -- Dismiss an alert (FR-047).
pub async fn dismiss_alert(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// GET /api/notifications -- In-app notifications with badge count (FR-009).
pub async fn list_notifications() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// PUT /api/alerts/thresholds -- Configure alert thresholds (FR-011, Admin only).
#[derive(Debug, Deserialize)]
pub struct ThresholdsConfig {
    pub attestation_success_rate: Option<f64>,
    pub latency_ceiling_factor: Option<f64>,
    pub cert_expiry_days: Option<u32>,
    pub consecutive_failures: Option<u32>,
}

pub async fn update_thresholds(
    Json(_body): Json<ThresholdsConfig>,
) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}
