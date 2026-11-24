use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::response::{ApiResponse, PaginatedResponse};
use crate::audit::logger::{AuditEntryParams, AuditSeverity};
use crate::error::{AppError, AppResult};
use crate::models::alert::{Alert, AlertSummary};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AlertListParams {
    pub severity: Option<String>,
    pub state: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

/// Append an `alert_action` audit entry for a successful lifecycle change.
///
/// Audit failures are logged but never fail the user-facing operation.
async fn record_alert_action(state: &AppState, alert_id: Uuid, result: &str) {
    let resource = alert_id.to_string();
    let params = AuditEntryParams::system(AuditSeverity::Info, "alert_action", &resource, result);
    if let Err(e) = state.audit.record(params).await {
        tracing::warn!("failed to record audit entry for alert {alert_id}: {e}");
    }
}

/// GET /api/alerts -- Alert management dashboard (FR-047).
pub async fn list_alerts(
    State(state): State<AppState>,
    Query(params): Query<AlertListParams>,
) -> AppResult<Json<ApiResponse<PaginatedResponse<Alert>>>> {
    let alerts = state
        .alert_repo
        .list(
            params.severity.as_deref(),
            params.state.as_deref(),
            state.seed_mock_data(),
        )
        .await;

    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(25).min(100);
    let total_items = alerts.len() as u64;
    let total_pages = (total_items + per_page - 1) / per_page.max(1);
    let start = ((page - 1) * per_page) as usize;
    let items: Vec<Alert> = alerts
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .collect();

    Ok(Json(ApiResponse::ok(PaginatedResponse {
        items,
        page,
        page_size: per_page,
        total_items,
        total_pages,
    })))
}

/// GET /api/alerts/summary -- Alert summary KPIs for dashboard.
pub async fn get_summary(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<AlertSummary>>> {
    let summary = state.alert_repo.summary(state.seed_mock_data()).await;
    Ok(Json(ApiResponse::ok(summary)))
}

/// GET /api/alerts/:id -- Get a single alert.
pub async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<Alert>>> {
    let alert = state
        .alert_repo
        .get(id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("alert {id} not found")))?;
    Ok(Json(ApiResponse::ok(alert)))
}

/// POST /api/alerts/:id/acknowledge -- Acknowledge an alert (FR-047).
pub async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<()>>> {
    state
        .alert_repo
        .acknowledge(id)
        .await
        .map_err(AppError::BadRequest)?;
    record_alert_action(&state, id, "acknowledged").await;
    Ok(Json(ApiResponse::ok(())))
}

/// POST /api/alerts/:id/investigate -- Move to investigation (FR-047).
#[derive(Debug, Deserialize)]
pub struct InvestigateRequest {
    pub assigned_to: Option<String>,
}

pub async fn investigate_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<InvestigateRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    state
        .alert_repo
        .investigate(id, body.assigned_to)
        .await
        .map_err(AppError::BadRequest)?;
    record_alert_action(&state, id, "investigated").await;
    Ok(Json(ApiResponse::ok(())))
}

/// POST /api/alerts/:id/resolve -- Resolve an alert (FR-047).
#[derive(Debug, Deserialize)]
pub struct ResolveRequest {
    pub resolution: Option<String>,
}

pub async fn resolve_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    state
        .alert_repo
        .resolve(id, body.resolution)
        .await
        .map_err(AppError::BadRequest)?;
    record_alert_action(&state, id, "resolved").await;
    Ok(Json(ApiResponse::ok(())))
}

/// POST /api/alerts/:id/dismiss -- Dismiss an alert (FR-047).
pub async fn dismiss_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<()>>> {
    state
        .alert_repo
        .dismiss(id)
        .await
        .map_err(AppError::BadRequest)?;
    record_alert_action(&state, id, "dismissed").await;
    Ok(Json(ApiResponse::ok(())))
}

/// POST /api/alerts/:id/escalate -- Escalate an alert (FR-048).
pub async fn escalate_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<()>>> {
    state
        .alert_repo
        .escalate(id)
        .await
        .map_err(AppError::BadRequest)?;
    record_alert_action(&state, id, "escalated").await;
    Ok(Json(ApiResponse::ok(())))
}

/// GET /api/notifications -- In-app notifications with badge count (FR-009).
pub async fn list_notifications(
    State(_state): State<AppState>,
) -> AppResult<Json<ApiResponse<()>>> {
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
    State(_state): State<AppState>,
    Json(_body): Json<ThresholdsConfig>,
) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeylimeConfig;
    use crate::keylime::client::KeylimeClient;
    use crate::repository::audit::AuditFilter;
    use crate::repository::{InMemoryCacheBackend, Repositories};
    use std::sync::Arc;

    fn test_state() -> AppState {
        let config = KeylimeConfig {
            verifier_url: "http://localhost:3000".into(),
            registrar_url: "http://localhost:3001".into(),
            mtls: None,
            timeout_secs: 5,
            observation_interval_secs: 30,
            circuit_breaker: Default::default(),
        };
        let client = KeylimeClient::new(config).unwrap();
        let repos = Repositories::in_memory();
        AppState::new(
            client,
            repos.alert,
            repos.attestation,
            repos.policy,
            repos.audit,
            Arc::new(InMemoryCacheBackend::new()),
            None,
            false,
        )
    }

    #[tokio::test]
    async fn acknowledge_records_alert_action_audit_entry() {
        let state = test_state();
        let id = state
            .alert_repo
            .list(None, Some("new"), true)
            .await
            .first()
            .unwrap()
            .id;

        let _ = acknowledge_alert(State(state.clone()), Path(id))
            .await
            .unwrap();

        let entries = state
            .audit_repo
            .query(&AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "alert_action");
        assert_eq!(entries[0].resource, id.to_string());
        assert_eq!(entries[0].result, "acknowledged");
        assert_eq!(entries[0].actor, "system");
    }

    #[tokio::test]
    async fn failed_action_records_no_audit_entry() {
        let state = test_state();
        let id = state
            .alert_repo
            .list(None, Some("acknowledged"), true)
            .await
            .first()
            .unwrap()
            .id;

        let result = acknowledge_alert(State(state.clone()), Path(id)).await;

        assert!(result.is_err());
        let entries = state
            .audit_repo
            .query(&AuditFilter::default())
            .await
            .unwrap();
        assert!(entries.is_empty());
    }
}
