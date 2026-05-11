use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;

use crate::state::AppState;

use super::handlers;
use super::middleware::require_write;
use super::ws;

/// Build the complete API router with all route groups.
#[cfg(not(tarpaulin_include))]
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .nest("/api", api_routes())
        .route("/ws/events", get(ws::ws_handler))
        // TODO: GET /metrics -- Prometheus metrics endpoint (FR-063)
        // TODO: add CORS, tracing, rate limiting layers
        .with_state(state)
}

#[cfg(not(tarpaulin_include))]
fn api_routes() -> Router<AppState> {
    Router::new()
        .nest("/auth", auth_routes())
        .nest("/kpis", kpi_routes())
        .nest("/agents", agent_routes())
        .nest("/attestations", attestation_routes())
        .nest("/policies", policy_routes())
        .nest("/certificates", certificate_routes())
        .nest("/alerts", alert_routes())
        .nest("/audit-log", audit_routes())
        .nest("/compliance", compliance_routes())
        .nest("/integrations", integration_routes())
        .nest("/performance", performance_routes())
        .nest("/settings", settings_routes())
}

#[cfg(not(tarpaulin_include))]
fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(handlers::auth::login))
        .route("/callback", post(handlers::auth::callback))
        .route("/refresh", post(handlers::auth::refresh_token))
        .route("/logout", post(handlers::auth::logout))
}

#[cfg(not(tarpaulin_include))]
fn kpi_routes() -> Router<AppState> {
    Router::new().route("/", get(handlers::kpis::get_kpis))
}

#[cfg(not(tarpaulin_include))]
fn agent_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::agents::list_agents))
        .route("/search", get(handlers::agents::search_agents))
        .route("/bulk", post(handlers::agents::bulk_action))
        .route("/{id}", get(handlers::agents::get_agent))
        .route(
            "/{id}/actions/{action}",
            post(handlers::agents::agent_action),
        )
        .route("/{id}/timeline", get(handlers::agents::get_timeline))
        .route("/{id}/pcr", get(handlers::agents::get_pcr_values))
        .route("/{id}/ima-log", get(handlers::agents::get_ima_log))
        .route("/{id}/boot-log", get(handlers::agents::get_boot_log))
        .route("/{id}/certificates", get(handlers::agents::get_agent_certs))
        .route("/{id}/raw", get(handlers::agents::get_raw_data))
        .route("/{id}/raw/backend", get(handlers::agents::get_raw_backend))
        .route(
            "/{id}/raw/registrar",
            get(handlers::agents::get_raw_registrar),
        )
        .route(
            "/{id}/raw/verifier",
            get(handlers::agents::get_raw_verifier),
        )
}

#[cfg(not(tarpaulin_include))]
fn attestation_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::attestations::list_attestations))
        .route("/summary", get(handlers::attestations::get_summary))
        .route("/timeline", get(handlers::attestations::get_timeline))
        .route("/failures", get(handlers::attestations::get_failures))
        .route("/incidents", get(handlers::attestations::list_incidents))
        .route("/incidents/{id}", get(handlers::attestations::get_incident))
        .route(
            "/incidents/{id}/rollback",
            post(handlers::attestations::rollback_from_incident),
        )
        .route(
            "/pipeline/{agent_id}",
            get(handlers::attestations::get_pipeline),
        )
        .route(
            "/push-mode",
            get(handlers::attestations::get_push_mode_analytics),
        )
        .route(
            "/pull-mode",
            get(handlers::attestations::get_pull_mode_monitoring),
        )
        .route(
            "/state-machine",
            get(handlers::attestations::get_state_machine),
        )
}

#[cfg(not(tarpaulin_include))]
fn policy_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::policies::list_policies))
        .route("/", post(handlers::policies::create_policy))
        .route(
            "/assignment-matrix",
            get(handlers::policies::assignment_matrix),
        )
        .route(
            "/changes/{id}/approve",
            post(handlers::policies::approve_change),
        )
        .route("/{id}", get(handlers::policies::get_policy))
        .route("/{id}", put(handlers::policies::update_policy))
        .route("/{id}", delete(handlers::policies::delete_policy))
        .route("/{id}/versions", get(handlers::policies::list_versions))
        .route("/{id}/diff", get(handlers::policies::diff_versions))
        .route(
            "/{id}/rollback/{version}",
            post(handlers::policies::rollback_policy),
        )
        .route("/{id}/impact", post(handlers::policies::impact_analysis))
}

#[cfg(not(tarpaulin_include))]
fn certificate_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::certificates::list_certificates))
        .route("/expiry", get(handlers::certificates::expiry_summary))
        .route(
            "/expiry-summary",
            get(handlers::certificates::expiry_summary),
        )
        .route("/timeline", get(handlers::certificates::timeline))
        .route("/{id}", get(handlers::certificates::get_certificate))
        .route(
            "/{id}/download/pem",
            get(handlers::certificates::download_pem),
        )
        .route(
            "/{id}/download/der",
            get(handlers::certificates::download_der),
        )
}

#[cfg(not(tarpaulin_include))]
fn alert_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::alerts::list_alerts))
        .route("/summary", get(handlers::alerts::get_summary))
        .route("/thresholds", put(handlers::alerts::update_thresholds))
        .route("/notifications", get(handlers::alerts::list_notifications))
        .route("/{id}", get(handlers::alerts::get_alert))
        .route(
            "/{id}/acknowledge",
            post(handlers::alerts::acknowledge_alert),
        )
        .route(
            "/{id}/investigate",
            post(handlers::alerts::investigate_alert),
        )
        .route("/{id}/resolve", post(handlers::alerts::resolve_alert))
        .route("/{id}/dismiss", post(handlers::alerts::dismiss_alert))
        .route("/{id}/escalate", post(handlers::alerts::escalate_alert))
}

#[cfg(not(tarpaulin_include))]
fn audit_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::audit::list_audit_events))
        .route("/verify", get(handlers::audit::verify_chain))
        .route("/export", get(handlers::audit::export_audit_log))
}

#[cfg(not(tarpaulin_include))]
fn compliance_routes() -> Router<AppState> {
    Router::new()
        .route("/frameworks", get(handlers::compliance::list_frameworks))
        .route(
            "/reports/{framework}",
            get(handlers::compliance::get_report),
        )
        .route(
            "/reports/{framework}/export",
            post(handlers::compliance::export_report),
        )
}

#[cfg(not(tarpaulin_include))]
fn integration_routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(handlers::integrations::connectivity_status))
        .route("/durable", get(handlers::integrations::durable_backends))
        .route(
            "/revocation-channels",
            get(handlers::integrations::revocation_channels),
        )
        .route("/siem", get(handlers::integrations::siem_status))
        .route(
            "/ssh-check/{service_name}",
            get(handlers::integrations::ssh_check).layer(middleware::from_fn(require_write)),
        )
}

#[cfg(not(tarpaulin_include))]
fn performance_routes() -> Router<AppState> {
    Router::new()
        .route("/verifiers", get(handlers::performance::verifier_metrics))
        .route("/database", get(handlers::performance::database_metrics))
        .route(
            "/api-response-times",
            get(handlers::performance::api_response_times),
        )
        .route("/config", get(handlers::performance::config_drift))
        .route("/capacity", get(handlers::performance::capacity_planning))
}

#[cfg(not(tarpaulin_include))]
fn settings_routes() -> Router<AppState> {
    Router::new()
        .route("/keylime", get(handlers::settings::get_keylime))
        .route("/keylime", put(handlers::settings::update_keylime))
        .route("/certificates", get(handlers::settings::get_certificates))
        .route(
            "/certificates",
            put(handlers::settings::update_certificates),
        )
}
