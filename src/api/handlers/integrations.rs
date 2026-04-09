use std::time::Instant;

use axum::extract::State;
use axum::Json;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::kpi::{ServiceHealth, ServiceStatus};
use crate::state::AppState;

/// GET /api/integrations/status -- Backend connectivity status (FR-057).
pub async fn connectivity_status(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<Vec<ServiceHealth>>>> {
    let mut services = Vec::new();

    // Check Verifier connectivity
    let verifier_start = Instant::now();
    let verifier_status = match state.keylime.list_verifier_agents().await {
        Ok(_) => ServiceStatus::Up,
        Err(_) => {
            if state.keylime.verifier_available().await {
                ServiceStatus::Down
            } else {
                ServiceStatus::Timeout
            }
        }
    };
    let verifier_latency = verifier_start.elapsed().as_millis() as u64;

    services.push(ServiceHealth {
        name: "keylime-verifier".into(),
        endpoint: "configured".into(),
        status: verifier_status,
        uptime_seconds: None,
        latency_ms: Some(verifier_latency),
    });

    // Check Registrar connectivity
    let registrar_start = Instant::now();
    let registrar_status = match state.keylime.list_registrar_agents().await {
        Ok(_) => ServiceStatus::Up,
        Err(_) => ServiceStatus::Down,
    };
    let registrar_latency = registrar_start.elapsed().as_millis() as u64;

    services.push(ServiceHealth {
        name: "keylime-registrar".into(),
        endpoint: "configured".into(),
        status: registrar_status,
        uptime_seconds: None,
        latency_ms: Some(registrar_latency),
    });

    Ok(Json(ApiResponse::ok(services)))
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
