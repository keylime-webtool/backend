use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use std::path::PathBuf;

use crate::api::response::ApiResponse;
use crate::audit::logger::{AuditEntryParams, AuditSeverity};
use crate::config::{KeylimeConfig, MtlsConfig};
use crate::error::{AppError, AppResult};
use crate::keylime::client::KeylimeClient;
use crate::state::AppState;

/// Append a `config_change` audit entry for a successful settings update.
///
/// Audit failures are logged but never fail the user-facing operation.
async fn record_config_change(state: &AppState, resource: &str) {
    let params =
        AuditEntryParams::system(AuditSeverity::Info, "config_change", resource, "SUCCESS");
    if let Err(e) = state.audit.record(params).await {
        tracing::warn!("failed to record audit entry for {resource}: {e}");
    }
}

/// Response/request body for Keylime connection settings.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeylimeSettings {
    pub verifier_url: String,
    pub registrar_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_mock_data: Option<bool>,
}

/// GET /api/settings/keylime -- return current Registrar/Verifier URLs.
pub async fn get_keylime(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<KeylimeSettings>>> {
    let kl = state.keylime();
    let settings = KeylimeSettings {
        verifier_url: kl.verifier_url().to_string(),
        registrar_url: kl.registrar_url().to_string(),
        seed_mock_data: if state.seed_mock_data() {
            Some(true)
        } else {
            None
        },
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
    validate_keylime_urls(&body.verifier_url, &body.registrar_url)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let config = KeylimeConfig {
        verifier_url: body.verifier_url.clone(),
        registrar_url: body.registrar_url.clone(),
        mtls: state.keylime().mtls_config().cloned(),
        timeout_secs: 30,
        observation_interval_secs: 30,
        circuit_breaker: Default::default(),
    };

    let new_client = KeylimeClient::new(config)?;
    state.swap_keylime(new_client);

    if let Some(seed) = body.seed_mock_data {
        state.set_seed_mock_data(seed);
        if seed {
            state.alert_repo.seed_if_empty().await;
        }
    }

    state.persist_settings();
    record_config_change(&state, "settings/keylime").await;

    let settings = KeylimeSettings {
        verifier_url: body.verifier_url,
        registrar_url: body.registrar_url,
        seed_mock_data: if state.seed_mock_data() {
            Some(true)
        } else {
            None
        },
    };
    Ok(Json(ApiResponse::ok(settings)))
}

/// Response/request body for mTLS certificate settings.
///
/// When all three paths are provided, mTLS is enabled automatically
/// (required for https:// Verifier/Registrar URLs).
/// When all paths are empty/null, mTLS is disabled.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateSettings {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_cert_path: Option<String>,
}

/// GET /api/settings/certificates -- return current mTLS certificate configuration.
pub async fn get_certificates(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<CertificateSettings>>> {
    let kl = state.keylime();
    let settings = match kl.mtls_config() {
        Some(mtls) => CertificateSettings {
            cert_path: Some(mtls.cert.display().to_string()),
            key_path: Some(mtls.key.clone()),
            ca_cert_path: Some(mtls.ca_cert.display().to_string()),
        },
        None => CertificateSettings {
            cert_path: None,
            key_path: None,
            ca_cert_path: None,
        },
    };
    Ok(Json(ApiResponse::ok(settings)))
}

/// PUT /api/settings/certificates -- update mTLS certificate configuration.
///
/// If all three paths are provided, builds an mTLS client.
/// If all are empty/null, disables mTLS.
/// Rebuilds the KeylimeClient and swaps it in.
pub async fn update_certificates(
    State(state): State<AppState>,
    Json(body): Json<CertificateSettings>,
) -> AppResult<Json<ApiResponse<CertificateSettings>>> {
    let (has_cert, has_key, has_ca) = resolve_mtls_fields(
        body.cert_path.as_deref(),
        body.key_path.as_deref(),
        body.ca_cert_path.as_deref(),
    );

    let mtls = if has_cert || has_key || has_ca {
        // If any path is provided, all three are required
        let cert_path = body
            .cert_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest("cert_path is required when configuring certificates".into())
            })?;
        let key_path = body
            .key_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest("key_path is required when configuring certificates".into())
            })?;
        let ca_cert_path = body
            .ca_cert_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest(
                    "ca_cert_path is required when configuring certificates".into(),
                )
            })?;

        for (label, path) in [("cert", cert_path), ("ca_cert", ca_cert_path)] {
            if !std::path::Path::new(path).exists() {
                return Err(AppError::BadRequest(format!(
                    "{label} file not found: {path}"
                )));
            }
        }
        if !key_path.contains("://") && !std::path::Path::new(key_path).exists() {
            return Err(AppError::BadRequest(format!(
                "key file not found: {key_path}"
            )));
        }

        Some(MtlsConfig {
            cert: PathBuf::from(cert_path),
            key: key_path.to_string(),
            ca_cert: PathBuf::from(ca_cert_path),
        })
    } else {
        None
    };

    let kl = state.keylime();
    let config = KeylimeConfig {
        verifier_url: kl.verifier_url().to_string(),
        registrar_url: kl.registrar_url().to_string(),
        mtls,
        timeout_secs: 30,
        observation_interval_secs: 30,
        circuit_breaker: Default::default(),
    };
    drop(kl);

    let new_client = KeylimeClient::new(config)?;
    state.swap_keylime(new_client);
    state.persist_settings();
    record_config_change(&state, "settings/certificates").await;

    let kl = state.keylime();
    let result = match kl.mtls_config() {
        Some(m) => CertificateSettings {
            cert_path: Some(m.cert.display().to_string()),
            key_path: Some(m.key.clone()),
            ca_cert_path: Some(m.ca_cert.display().to_string()),
        },
        None => CertificateSettings {
            cert_path: None,
            key_path: None,
            ca_cert_path: None,
        },
    };
    Ok(Json(ApiResponse::ok(result)))
}

pub(crate) fn validate_keylime_urls(verifier: &str, registrar: &str) -> Result<(), &'static str> {
    if verifier.is_empty() || registrar.is_empty() {
        return Err("verifier_url and registrar_url must not be empty");
    }
    Ok(())
}

pub(crate) fn resolve_mtls_fields(
    cert: Option<&str>,
    key: Option<&str>,
    ca: Option<&str>,
) -> (bool, bool, bool) {
    let has_cert = cert.is_some_and(|s| !s.is_empty());
    let has_key = key.is_some_and(|s| !s.is_empty());
    let has_ca = ca.is_some_and(|s| !s.is_empty());
    (has_cert, has_key, has_ca)
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
    async fn update_keylime_records_config_change_audit_entry() {
        let state = test_state();
        let body = KeylimeSettings {
            verifier_url: "http://localhost:4000".into(),
            registrar_url: "http://localhost:4001".into(),
            seed_mock_data: None,
        };

        let _ = update_keylime(State(state.clone()), Json(body))
            .await
            .unwrap();

        let entries = state
            .audit_repo
            .query(&AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "config_change");
        assert_eq!(entries[0].resource, "settings/keylime");
        assert_eq!(entries[0].result, "SUCCESS");
    }

    #[tokio::test]
    async fn rejected_update_records_no_audit_entry() {
        let state = test_state();
        let body = KeylimeSettings {
            verifier_url: String::new(),
            registrar_url: "http://localhost:4001".into(),
            seed_mock_data: None,
        };

        let result = update_keylime(State(state.clone()), Json(body)).await;

        assert!(result.is_err());
        let entries = state
            .audit_repo
            .query(&AuditFilter::default())
            .await
            .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn validate_urls_ok() {
        assert!(validate_keylime_urls("http://v:3000", "http://r:3001").is_ok());
    }

    #[test]
    fn validate_urls_empty_verifier() {
        assert!(validate_keylime_urls("", "http://r:3001").is_err());
    }

    #[test]
    fn validate_urls_empty_registrar() {
        assert!(validate_keylime_urls("http://v:3000", "").is_err());
    }

    #[test]
    fn validate_urls_both_empty() {
        assert!(validate_keylime_urls("", "").is_err());
    }

    #[test]
    fn resolve_mtls_all_present() {
        let (c, k, ca) = resolve_mtls_fields(Some("/cert"), Some("/key"), Some("/ca"));
        assert!(c && k && ca);
    }

    #[test]
    fn resolve_mtls_all_none() {
        let (c, k, ca) = resolve_mtls_fields(None, None, None);
        assert!(!c && !k && !ca);
    }

    #[test]
    fn resolve_mtls_empty_strings() {
        let (c, k, ca) = resolve_mtls_fields(Some(""), Some(""), Some(""));
        assert!(!c && !k && !ca);
    }

    #[test]
    fn resolve_mtls_partial() {
        let (c, k, ca) = resolve_mtls_fields(Some("/cert"), None, Some("/ca"));
        assert!(c && !k && ca);
    }

    #[test]
    fn keylime_settings_serde_roundtrip() {
        let settings = KeylimeSettings {
            verifier_url: "http://v:3000".into(),
            registrar_url: "http://r:3001".into(),
            seed_mock_data: None,
        };
        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: KeylimeSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.verifier_url, "http://v:3000");
        assert_eq!(deserialized.registrar_url, "http://r:3001");
        assert_eq!(deserialized.seed_mock_data, None);
    }

    #[test]
    fn keylime_settings_seed_mock_data_roundtrip() {
        let settings = KeylimeSettings {
            verifier_url: "http://v:3000".into(),
            registrar_url: "http://r:3001".into(),
            seed_mock_data: Some(true),
        };
        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: KeylimeSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.seed_mock_data, Some(true));
    }

    #[test]
    fn keylime_settings_omits_seed_mock_data_when_none() {
        let settings = KeylimeSettings {
            verifier_url: "http://v:3000".into(),
            registrar_url: "http://r:3001".into(),
            seed_mock_data: None,
        };
        let json = serde_json::to_string(&settings).unwrap();
        assert!(!json.contains("seed_mock_data"));
    }

    #[test]
    fn keylime_settings_deserializes_without_seed_field() {
        let json = r#"{"verifier_url":"http://v:3000","registrar_url":"http://r:3001"}"#;
        let deserialized: KeylimeSettings = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized.seed_mock_data, None);
    }

    #[test]
    fn certificate_settings_serde_roundtrip() {
        let settings = CertificateSettings {
            cert_path: Some("/tmp/cert.pem".into()),
            key_path: Some("pkcs11://slot=0".into()),
            ca_cert_path: None,
        };
        let json = serde_json::to_value(&settings).unwrap();
        assert_eq!(json["cert_path"], "/tmp/cert.pem");
        assert_eq!(json["key_path"], "pkcs11://slot=0");
        assert!(json["ca_cert_path"].is_null());
    }
}
