use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::response::ApiResponse;
use crate::config::KeylimeConfig;
use crate::error::{AppError, AppResult};
use crate::keylime::client::KeylimeClient;
use crate::state::AppState;

/// Response/request body for Keylime connection settings.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeylimeSettings {
    pub verifier_url: String,
    pub registrar_url: String,
}

/// GET /api/settings/keylime -- return current Registrar/Verifier URLs.
pub async fn get_keylime(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<KeylimeSettings>>> {
    let kl = state.keylime();
    let settings = KeylimeSettings {
        verifier_url: kl.verifier_url().to_string(),
        registrar_url: kl.registrar_url().to_string(),
    };
    Ok(Json(ApiResponse::ok(settings)))
}

/// PUT /api/settings/keylime -- update Registrar/Verifier URLs.
///
/// Builds a new KeylimeClient with the provided URLs and swaps it in.
pub async fn update_keylime(
    State(state): State<AppState>,
    Json(body): Json<KeylimeSettings>,
) -> AppResult<Json<ApiResponse<KeylimeSettings>>> {
    // Basic URL validation
    if body.verifier_url.is_empty() || body.registrar_url.is_empty() {
        return Err(AppError::BadRequest(
            "verifier_url and registrar_url must not be empty".into(),
        ));
    }

    let config = KeylimeConfig {
        verifier_url: body.verifier_url.clone(),
        registrar_url: body.registrar_url.clone(),
        mtls: None,
        timeout_secs: 30,
        circuit_breaker: Default::default(),
    };

    let new_client = KeylimeClient::new(config)?;
    state.swap_keylime(new_client);

    let settings = KeylimeSettings {
        verifier_url: body.verifier_url,
        registrar_url: body.registrar_url,
    };
    Ok(Json(ApiResponse::ok(settings)))
}
