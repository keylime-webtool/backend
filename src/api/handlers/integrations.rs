use axum::Json;

use crate::api::response::ApiResponse;
use crate::error::AppResult;
use crate::models::kpi::ServiceHealth;

/// GET /api/integrations/status -- Backend connectivity status (FR-057).
pub async fn connectivity_status() -> AppResult<Json<ApiResponse<Vec<ServiceHealth>>>> {
    // TODO: poll Verifier, Registrar, TimescaleDB, Redis, Rekor, RFC 3161 TSA
    todo!()
}

/// GET /api/integrations/durable -- Durable attestation backend status (FR-058).
pub async fn durable_backends() -> AppResult<Json<ApiResponse<()>>> {
    // TODO: Rekor, Redis time-series, SQL DB, file audit, RFC 3161 TSA
    todo!()
}

/// GET /api/integrations/revocation-channels -- Revocation channel monitoring (FR-046).
pub async fn revocation_channels() -> AppResult<Json<ApiResponse<()>>> {
    // TODO: Agent REST, ZeroMQ, Webhook statuses
    todo!()
}

/// GET /api/integrations/siem -- SIEM integration status (FR-063).
pub async fn siem_status() -> AppResult<Json<ApiResponse<()>>> {
    // TODO: Syslog, Splunk HEC, ECS, Prometheus, OpenTelemetry
    todo!()
}
