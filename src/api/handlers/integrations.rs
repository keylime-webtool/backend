use std::time::Instant;

use axum::extract::{Path, State};
use axum::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::api::response::ApiResponse;
use crate::audit::logger::{AuditEntryParams, AuditSeverity};
use crate::auth::jwt::Claims;
use crate::auth::rbac::Permission;
use crate::error::{AppError, AppResult};
use crate::models::kpi::{ServiceHealth, ServiceStatus};
use crate::state::AppState;

/// SSH reachability probe result (FR-086).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCheckResult {
    pub service: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Extract the hostname from a URL string.
fn extract_host(endpoint: &str) -> Option<String> {
    Url::parse(endpoint)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
}

/// Resolve the SSH port for a named service.
fn resolve_ssh_port(state: &AppState, service_name: &str) -> u16 {
    let ssh = state.ssh_config();
    ssh.ports
        .get(service_name)
        .copied()
        .unwrap_or(ssh.default_port)
}

/// GET /api/integrations/status -- Backend connectivity status (FR-057).
pub async fn connectivity_status(
    State(state): State<AppState>,
    claims: Option<Extension<Claims>>,
) -> AppResult<Json<ApiResponse<Vec<ServiceHealth>>>> {
    let mut services = Vec::new();

    let ssh_enabled = state.ssh_config().enabled;
    let can_see_ssh = ssh_enabled
        && claims
            .as_ref()
            .map(|c| c.role.has_permission(Permission::Write))
            .unwrap_or(false);

    // Check Verifier connectivity (bypasses circuit breaker so health check is always live)
    let verifier_start = Instant::now();
    let verifier_status = match state.keylime().probe_verifier().await {
        Ok(_) => ServiceStatus::Up,
        Err(_) => ServiceStatus::Down,
    };
    let verifier_latency = verifier_start.elapsed().as_millis() as u64;
    let keylime = state.keylime();
    let verifier_endpoint = keylime.verifier_url().to_string();

    let (v_ssh_host, v_ssh_port) = if can_see_ssh {
        (
            extract_host(&verifier_endpoint),
            Some(resolve_ssh_port(&state, "verifier")),
        )
    } else {
        (None, None)
    };

    services.push(ServiceHealth {
        name: "keylime-verifier".into(),
        endpoint: verifier_endpoint,
        status: verifier_status,
        uptime_seconds: None,
        latency_ms: Some(verifier_latency),
        ssh_host: v_ssh_host,
        ssh_port: v_ssh_port,
    });

    // Check Registrar connectivity
    let registrar_start = Instant::now();
    let registrar_status = match state.keylime().probe_registrar().await {
        Ok(_) => ServiceStatus::Up,
        Err(_) => ServiceStatus::Down,
    };
    let registrar_latency = registrar_start.elapsed().as_millis() as u64;
    let registrar_endpoint = keylime.registrar_url().to_string();

    let (r_ssh_host, r_ssh_port) = if can_see_ssh {
        (
            extract_host(&registrar_endpoint),
            Some(resolve_ssh_port(&state, "registrar")),
        )
    } else {
        (None, None)
    };

    services.push(ServiceHealth {
        name: "keylime-registrar".into(),
        endpoint: registrar_endpoint,
        status: registrar_status,
        uptime_seconds: None,
        latency_ms: Some(registrar_latency),
        ssh_host: r_ssh_host,
        ssh_port: r_ssh_port,
    });

    Ok(Json(ApiResponse::ok(services)))
}

/// GET /api/integrations/ssh-check/:service_name -- SSH reachability probe (FR-086).
///
/// Performs a TCP connect to the service's SSH port with a 2-second timeout.
/// Requires Write permission (Operator+).
pub async fn ssh_check(
    State(state): State<AppState>,
    Path(service_name): Path<String>,
) -> AppResult<Json<ApiResponse<SshCheckResult>>> {
    if !state.ssh_config().enabled {
        return Err(AppError::BadRequest("SSH connectivity is disabled".into()));
    }

    let keylime = state.keylime();
    let endpoint = match service_name.as_str() {
        "verifier" => keylime.verifier_url().to_string(),
        "registrar" => keylime.registrar_url().to_string(),
        _ => {
            return Err(AppError::NotFound(format!(
                "unknown service: {service_name}"
            )));
        }
    };

    let ssh_host = extract_host(&endpoint).ok_or_else(|| {
        AppError::Internal(format!("cannot extract host from endpoint: {endpoint}"))
    })?;
    let ssh_port = resolve_ssh_port(&state, &service_name);

    let addr = format!("{ssh_host}:{ssh_port}");
    let start = Instant::now();
    let reachable = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    let latency = start.elapsed().as_millis() as u64;

    record_integration_check(
        &state,
        &service_name,
        reachable,
        if reachable { Some(latency) } else { None },
    )
    .await;

    Ok(Json(ApiResponse::ok(SshCheckResult {
        service: service_name,
        ssh_host,
        ssh_port,
        reachable,
        latency_ms: if reachable { Some(latency) } else { None },
    })))
}

/// Append an `integration_check` audit entry for an SSH probe.
///
/// Audit failures are logged but never fail the user-facing operation.
async fn record_integration_check(
    state: &AppState,
    service_name: &str,
    reachable: bool,
    latency_ms: Option<u64>,
) {
    let result = match (reachable, latency_ms) {
        (true, Some(ms)) => format!("SUCCESS ({ms}ms)"),
        (true, None) => "SUCCESS".to_string(),
        (false, _) => "UNREACHABLE".to_string(),
    };
    let severity = if reachable {
        AuditSeverity::Info
    } else {
        AuditSeverity::Warning
    };
    let params = AuditEntryParams::system(severity, "integration_check", service_name, &result);
    if let Err(e) = state.audit.record(params).await {
        tracing::warn!("failed to record audit entry for ssh-check {service_name}: {e}");
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::rbac::Role;
    use crate::config::SshConfig;
    use crate::repository::audit::AuditFilter;
    use crate::repository::{InMemoryCacheBackend, Repositories};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn extract_host_from_https_url() {
        assert_eq!(
            extract_host("https://10.0.0.1:8881"),
            Some("10.0.0.1".into())
        );
    }

    #[test]
    fn extract_host_from_hostname_url() {
        assert_eq!(
            extract_host("https://verifier.example.com:8881/v2/agents"),
            Some("verifier.example.com".into())
        );
    }

    #[test]
    fn extract_host_invalid_url() {
        assert_eq!(extract_host("not-a-url"), None);
    }

    #[test]
    fn ssh_fields_omitted_when_none() {
        let health = ServiceHealth {
            name: "verifier".into(),
            endpoint: "https://v:8881".into(),
            status: ServiceStatus::Up,
            uptime_seconds: None,
            latency_ms: Some(5),
            ssh_host: None,
            ssh_port: None,
        };
        let json = serde_json::to_value(&health).unwrap();
        assert!(json.get("ssh_host").is_none());
        assert!(json.get("ssh_port").is_none());
    }

    #[test]
    fn ssh_fields_present_when_set() {
        let health = ServiceHealth {
            name: "verifier".into(),
            endpoint: "https://v:8881".into(),
            status: ServiceStatus::Up,
            uptime_seconds: None,
            latency_ms: Some(5),
            ssh_host: Some("10.0.0.1".into()),
            ssh_port: Some(22),
        };
        let json = serde_json::to_value(&health).unwrap();
        assert_eq!(json["ssh_host"], "10.0.0.1");
        assert_eq!(json["ssh_port"], 22);
    }

    #[test]
    fn operator_has_write_permission() {
        assert!(Role::Operator.has_permission(Permission::Write));
    }

    #[test]
    fn viewer_lacks_write_permission() {
        assert!(!Role::Viewer.has_permission(Permission::Write));
    }

    #[test]
    fn ssh_check_result_serializes() {
        let result = SshCheckResult {
            service: "verifier".into(),
            ssh_host: "10.0.0.1".into(),
            ssh_port: 22,
            reachable: true,
            latency_ms: Some(3),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["service"], "verifier");
        assert_eq!(json["ssh_host"], "10.0.0.1");
        assert_eq!(json["ssh_port"], 22);
        assert_eq!(json["reachable"], true);
        assert_eq!(json["latency_ms"], 3);
    }

    #[test]
    fn ssh_check_result_omits_latency_when_unreachable() {
        let result = SshCheckResult {
            service: "registrar".into(),
            ssh_host: "10.0.0.2".into(),
            ssh_port: 22,
            reachable: false,
            latency_ms: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["reachable"], false);
        assert!(json.get("latency_ms").is_none());
    }

    #[test]
    fn ssh_config_deserialize_with_all_fields() {
        let toml_str = r#"
            enabled = true
            default_port = 22
            [ports]
            verifier = 2222
            registrar = 22
        "#;
        let cfg: SshConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.default_port, 22);
        assert_eq!(cfg.ports.get("verifier"), Some(&2222));
        assert_eq!(cfg.ports.get("registrar"), Some(&22));
    }

    #[test]
    fn ssh_config_deserialize_empty() {
        let toml_str = "";
        let cfg: SshConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.default_port, 22);
        assert!(cfg.ports.is_empty());
    }

    #[test]
    fn ssh_config_deserialize_enabled_only() {
        let toml_str = "enabled = true";
        let cfg: SshConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.default_port, 22);
        assert!(cfg.ports.is_empty());
    }

    #[test]
    fn ssh_config_custom_default_port() {
        let toml_str = r#"
            enabled = true
            default_port = 2222
        "#;
        let cfg: SshConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.default_port, 2222);
    }

    #[test]
    fn ssh_config_port_override_takes_precedence() {
        let mut ports = HashMap::new();
        ports.insert("verifier".to_string(), 2222);
        let cfg = SshConfig {
            enabled: true,
            default_port: 22,
            ports,
        };
        assert_eq!(
            cfg.ports
                .get("verifier")
                .copied()
                .unwrap_or(cfg.default_port),
            2222
        );
        assert_eq!(
            cfg.ports
                .get("registrar")
                .copied()
                .unwrap_or(cfg.default_port),
            22
        );
    }

    #[tokio::test]
    async fn ssh_check_records_integration_check_audit_entry() {
        let state = test_state_with_ssh();
        let reachable_probe = ssh_check(State(state.clone()), Path("verifier".to_string()))
            .await
            .unwrap();

        assert_eq!(reachable_probe.0.data.unwrap().service, "verifier");

        let entries = state
            .audit_repo
            .query(&AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "integration_check");
        assert_eq!(entries[0].resource, "verifier");
        assert!(
            entries[0].result == "UNREACHABLE" || entries[0].result.starts_with("SUCCESS"),
            "unexpected result: {}",
            entries[0].result
        );
    }

    #[tokio::test]
    async fn ssh_check_disabled_records_no_audit_entry() {
        let state = test_state_with_ssh();
        let state = AppState::with_ssh_config(
            state,
            SshConfig {
                enabled: false,
                default_port: 22,
                ports: HashMap::new(),
            },
        );

        let result = ssh_check(State(state.clone()), Path("verifier".to_string())).await;

        assert!(result.is_err());
        let entries = state
            .audit_repo
            .query(&AuditFilter::default())
            .await
            .unwrap();
        assert!(entries.is_empty());
    }

    fn test_state_with_ssh() -> AppState {
        let config = crate::config::KeylimeConfig {
            verifier_url: "http://localhost:3000".into(),
            registrar_url: "http://localhost:3001".into(),
            mtls: None,
            timeout_secs: 5,
            observation_interval_secs: 30,
            circuit_breaker: Default::default(),
        };
        let client = crate::keylime::client::KeylimeClient::new(config).unwrap();
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
        .with_ssh_config(SshConfig {
            enabled: true,
            default_port: 22,
            ports: HashMap::new(),
        })
    }
}
