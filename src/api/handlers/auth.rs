use axum::Json;
use serde::Deserialize;

use crate::api::response::ApiResponse;
use crate::error::AppResult;

/// POST /api/auth/login -- Initiate OIDC login flow (SR-001).
pub async fn login() -> AppResult<Json<ApiResponse<LoginResponse>>> {
    // TODO: return OIDC authorization URL for redirect
    todo!()
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
pub async fn callback(
    Json(_params): Json<CallbackParams>,
) -> AppResult<Json<ApiResponse<TokenResponse>>> {
    // TODO: exchange code, create JWT, return token
    todo!()
}

#[derive(Debug, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
}

/// POST /api/auth/refresh -- Refresh JWT (SR-010).
pub async fn refresh_token() -> AppResult<Json<ApiResponse<TokenResponse>>> {
    todo!()
}

/// POST /api/auth/logout -- Revoke session (SR-011).
pub async fn logout() -> AppResult<Json<ApiResponse<()>>> {
    // TODO: revoke session in SessionStore
    todo!()
}
