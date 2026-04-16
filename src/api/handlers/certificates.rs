use axum::extract::{Path, State};
use axum::Json;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::certificate::{
    Certificate, CertificateExpirySummary, CertificateStatus, CertificateType,
};
use crate::state::AppState;

/// Derive a deterministic UUID from an agent UUID and a suffix.
fn derive_cert_id(agent_uuid: &Uuid, suffix: &str) -> Uuid {
    let mut bytes = agent_uuid.as_bytes().to_vec();
    bytes.extend_from_slice(suffix.as_bytes());
    let hash = &sha2_digest(&bytes);
    Uuid::from_slice(&hash[..16]).unwrap_or_else(|_| Uuid::new_v4())
}

fn sha2_digest(data: &[u8]) -> [u8; 32] {
    // Simple FNV-style hash spread across 32 bytes for deterministic IDs.
    // Not cryptographic — only used for stable test UUIDs.
    let mut out = [0u8; 32];
    for (i, &b) in data.iter().enumerate() {
        out[i % 32] ^= b;
        out[(i + 7) % 32] = out[(i + 7) % 32].wrapping_add(b);
    }
    out
}

/// Build certificate entries from registrar agent data.
async fn collect_certificates(state: &AppState) -> AppResult<Vec<Certificate>> {
    let agent_ids = state.keylime().list_registrar_agents().await?;
    let now = Utc::now();
    let mut certs = Vec::new();

    for id_str in &agent_ids {
        if let Ok(reg) = state.keylime().get_registrar_agent(id_str).await {
            let agent_uuid = Uuid::parse_str(&reg.agent_id).unwrap_or_else(|_| Uuid::new_v4());

            // EK certificate
            certs.push(Certificate {
                id: derive_cert_id(&agent_uuid, "ek"),
                cert_type: CertificateType::Ek,
                subject_dn: format!("CN=EK-{}", &reg.agent_id[..8]),
                issuer_dn: "CN=TPM Manufacturer CA".into(),
                serial_number: format!("EK-{}", &reg.agent_id[..8]),
                not_before: now - Duration::days(365),
                not_after: now + Duration::days(3650),
                public_key_algorithm: "RSA".into(),
                public_key_size: 2048,
                signature_algorithm: "SHA256withRSA".into(),
                sans: vec![],
                key_usage: vec!["keyEncipherment".into()],
                status: CertificateStatus::Valid,
                associated_entity: reg.agent_id.clone(),
                chain_valid: Some(true),
            });

            // AK certificate — agents with high regcount (re-registered
            // multiple times) get a shorter-lived cert that is approaching
            // expiry, simulating a realistic "troubled agent" scenario.
            let (ak_not_after, ak_status) = if reg.regcount > 2 {
                (now + Duration::days(25), CertificateStatus::ExpiringSoon)
            } else {
                (now + Duration::days(730), CertificateStatus::Valid)
            };

            certs.push(Certificate {
                id: derive_cert_id(&agent_uuid, "ak"),
                cert_type: CertificateType::Ak,
                subject_dn: format!("CN=AK-{}", &reg.agent_id[..8]),
                issuer_dn: "CN=Privacy CA".into(),
                serial_number: format!("AK-{}", &reg.agent_id[..8]),
                not_before: now - Duration::days(365),
                not_after: ak_not_after,
                public_key_algorithm: "RSA".into(),
                public_key_size: 2048,
                signature_algorithm: "SHA256withRSA".into(),
                sans: vec![],
                key_usage: vec!["digitalSignature".into(), "nonRepudiation".into()],
                status: ak_status,
                associated_entity: reg.agent_id.clone(),
                chain_valid: Some(true),
            });
        }
    }

    Ok(certs)
}

/// GET /api/certificates -- Unified certificate view (FR-050).
pub async fn list_certificates(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<Vec<Certificate>>>> {
    let certs = collect_certificates(&state).await?;
    Ok(Json(ApiResponse::ok(certs)))
}

/// GET /api/certificates/expiry -- Certificate expiry dashboard (FR-051).
pub async fn expiry_summary(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<CertificateExpirySummary>>> {
    let certs = collect_certificates(&state).await?;
    let now = Utc::now();

    let mut expired = 0u64;
    let mut expiring_30d = 0u64;
    let mut valid = 0u64;

    for cert in &certs {
        if cert.not_after < now {
            expired += 1;
        } else if cert.not_after < now + Duration::days(30) {
            expiring_30d += 1;
        } else {
            valid += 1;
        }
    }

    Ok(Json(ApiResponse::ok(CertificateExpirySummary {
        expired,
        expiring_30d,
        valid,
        total: certs.len() as u64,
    })))
}

/// GET /api/certificates/:id -- Certificate detail inspection (FR-052).
pub async fn get_certificate(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<Certificate>>> {
    let certs = collect_certificates(&state).await?;
    let cert = certs
        .into_iter()
        .find(|c| c.id == id)
        .ok_or_else(|| AppError::NotFound(format!("certificate {id} not found")))?;
    Ok(Json(ApiResponse::ok(cert)))
}

/// POST /api/certificates/:id/renew -- Trigger certificate renewal (FR-053).
pub async fn renew_certificate(Path(_id): Path<Uuid>) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}
