use std::time::Instant;

use axum::extract::State;
use axum::Json;

use crate::api::response::ApiResponse;
use crate::error::AppResult;
use crate::models::kpi::{ServiceHealth, ServiceStatus};
use crate::state::AppState;

/// GET /api/integrations/status -- Backend connectivity status (FR-057).
pub async fn connectivity_status(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<Vec<ServiceHealth>>>> {
    let mut services = Vec::new();

    // Check Verifier connectivity (bypasses circuit breaker so health check is always live)
    let verifier_start = Instant::now();
    let verifier_status = match state.keylime().probe_verifier().await {
        Ok(_) => ServiceStatus::Up,
        Err(_) => ServiceStatus::Down,
    };
    let verifier_latency = verifier_start.elapsed().as_millis() as u64;
    let keylime = state.keylime();

    services.push(ServiceHealth {
        name: "keylime-verifier".into(),
        endpoint: keylime.verifier_url().to_string(),
        status: verifier_status,
        uptime_seconds: None,
        latency_ms: Some(verifier_latency),
    });

    // Check Registrar connectivity
    let registrar_start = Instant::now();
    let registrar_status = match state.keylime().list_registrar_agents().await {
        Ok(_) => ServiceStatus::Up,
        Err(_) => ServiceStatus::Down,
    };
    let registrar_latency = registrar_start.elapsed().as_millis() as u64;

    services.push(ServiceHealth {
        name: "keylime-registrar".into(),
        endpoint: keylime.registrar_url().to_string(),
        status: registrar_status,
        uptime_seconds: None,
        latency_ms: Some(registrar_latency),
    });

    Ok(Json(ApiResponse::ok(services)))
}

/// GET /api/integrations/durable -- Durable attestation backend status (FR-058).
pub async fn durable_backends() -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "timescaledb": {
            "status": "not_configured",
            "note": "TimescaleDB integration pending",
        },
        "redis": {
            "status": "not_configured",
            "note": "Redis cache integration pending",
        },
    }))))
}

/// GET /api/integrations/revocation-channels -- Revocation channel monitoring (FR-046).
pub async fn revocation_channels() -> AppResult<Json<ApiResponse<Vec<serde_json::Value>>>> {
    // Return configured revocation channels (none yet)
    Ok(Json(ApiResponse::ok(vec![
        serde_json::json!({
            "name": "zeromq",
            "status": "not_configured",
            "protocol": "ZeroMQ PUB/SUB",
        }),
        serde_json::json!({
            "name": "webhook",
            "status": "not_configured",
            "protocol": "HTTPS POST",
        }),
    ])))
}

/// GET /api/integrations/siem -- SIEM integration status (FR-063).
pub async fn siem_status() -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "syslog_cef": { "status": "not_configured", "format": "CEF/LEEF" },
        "splunk_hec": { "status": "not_configured", "format": "Splunk HEC JSON" },
        "elastic": { "status": "not_configured", "format": "Elastic Common Schema" },
    }))))
}
