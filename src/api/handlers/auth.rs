use axum::Json;
use serde::Deserialize;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};

/// POST /api/auth/login -- Initiate OIDC login flow (SR-001).
#[cfg(not(tarpaulin_include))]
pub async fn login() -> AppResult<Json<ApiResponse<LoginResponse>>> {
    Err(AppError::Internal("not implemented".into()))
}

#[derive(Debug, serde::Serialize)]
pub struct LoginResponse {
    pub redirect_url: String,
}

/// GET /api/auth/callback -- OIDC callback handler.
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

/// POST /api/auth/callback -- Exchange auth code for JWT (SR-001, SR-010).
#[cfg(not(tarpaulin_include))]
pub async fn callback(
    Json(_params): Json<CallbackParams>,
) -> AppResult<Json<ApiResponse<TokenResponse>>> {
    Err(AppError::Internal("not implemented".into()))
}

#[derive(Debug, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
}

/// POST /api/auth/refresh -- Refresh JWT (SR-010).
#[cfg(not(tarpaulin_include))]
pub async fn refresh_token() -> AppResult<Json<ApiResponse<TokenResponse>>> {
    Err(AppError::Internal("not implemented".into()))
}

/// POST /api/auth/logout -- Revoke session (SR-011).
#[cfg(not(tarpaulin_include))]
pub async fn logout() -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}
