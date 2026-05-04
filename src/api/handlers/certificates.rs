use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::response::{ApiResponse, PaginatedResponse};
use crate::error::{AppError, AppResult};
use crate::keylime::cert_parser;
use crate::keylime::models::RegistrarAgent;
use crate::models::certificate::{
    AgentCertSummary, Certificate, CertificateExpirySummary, CertificateTimelineEntry,
    CertificateType, ExpiryCategory, ExpiryTimelineEntry, ValidationStatus,
};
use crate::state::AppState;
use crate::storage::cache::CacheNamespace;

/// Derive a deterministic UUID from an agent UUID and a suffix.
fn derive_cert_id(agent_uuid: &Uuid, suffix: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(agent_uuid.as_bytes());
    hasher.update(suffix.as_bytes());
    let hash = hasher.finalize();
    Uuid::from_slice(&hash[..16]).unwrap_or_else(|_| Uuid::new_v4())
}

/// Build a single certificate entry from raw registrar data.
fn build_cert_entry(
    agent_uuid: &Uuid,
    raw_data: &str,
    cert_type: CertificateType,
    agent_id_str: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Certificate {
    let suffix = cert_type.suffix();

    match cert_parser::try_parse_x509(raw_data) {
        Some(parsed) => {
            let chain_valid = if cert_type == CertificateType::Ek {
                cert_parser::validate_ek_chain(&parsed.der_data)
            } else {
                None
            };
            let status = cert_parser::compute_status(parsed.not_after, now);
            let expiry_category = cert_parser::compute_expiry_category(parsed.not_after, now);
            Certificate {
                id: derive_cert_id(agent_uuid, suffix),
                agent_id: *agent_uuid,
                cert_type,
                subject_dn: parsed.subject_dn,
                issuer_dn: parsed.issuer_dn,
                serial_number: parsed.serial_number,
                not_before: parsed.not_before,
                not_after: parsed.not_after,
                public_key_algorithm: parsed.public_key_algorithm,
                public_key_size: parsed.public_key_size,
                signature_algorithm: parsed.signature_algorithm,
                sans: parsed.sans,
                key_usage: parsed.key_usage,
                extended_key_usage: parsed.extended_key_usage,
                status,
                expiry_category,
                associated_entity: agent_id_str.to_string(),
                validation_status: ValidationStatus::from_chain_valid(chain_valid),
                chain_valid,
                chain: vec![],
                raw_pem: Some(parsed.pem_data),
                raw_der: Some(parsed.der_data),
            }
        }
        None => {
            let short = &agent_id_str[..8.min(agent_id_str.len())];
            let label = suffix.to_uppercase();
            let not_after = now + Duration::days(3650);
            let status = cert_parser::compute_status(not_after, now);
            let expiry_category = cert_parser::compute_expiry_category(not_after, now);
            Certificate {
                id: derive_cert_id(agent_uuid, suffix),
                agent_id: *agent_uuid,
                cert_type,
                subject_dn: format!("CN={label}-{short}"),
                issuer_dn: "Unknown (raw public key)".into(),
                serial_number: format!("{label}-{short}"),
                not_before: now - Duration::days(365),
                not_after,
                public_key_algorithm: "RSA".into(),
                public_key_size: 2048,
                signature_algorithm: "Unknown".into(),
                sans: vec![],
                key_usage: vec![],
                extended_key_usage: vec![],
                status,
                expiry_category,
                associated_entity: agent_id_str.to_string(),
                validation_status: ValidationStatus::Unknown,
                chain_valid: None,
                chain: vec![],
                raw_pem: None,
                raw_der: None,
            }
        }
    }
}

/// Collect certificates for a single agent from registrar data.
pub fn collect_agent_certs(
    reg: &RegistrarAgent,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Certificate> {
    let agent_uuid = Uuid::parse_str(&reg.agent_id).unwrap_or_else(|_| Uuid::new_v4());
    let mut certs = Vec::new();

    // EK certificate -- prefer ekcert (X.509) over ek_tpm (public key)
    let ek_source = reg
        .ekcert
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&reg.ek_tpm);
    certs.push(build_cert_entry(
        &agent_uuid,
        ek_source,
        CertificateType::Ek,
        &reg.agent_id,
        now,
    ));

    // AK certificate
    certs.push(build_cert_entry(
        &agent_uuid,
        &reg.aik_tpm,
        CertificateType::Ak,
        &reg.agent_id,
        now,
    ));

    // mTLS certificate (only if present; real Keylime returns "disabled" when not configured)
    if let Some(ref mtls) = reg.mtls_cert {
        if !mtls.is_empty() && mtls != "disabled" {
            certs.push(build_cert_entry(
                &agent_uuid,
                mtls,
                CertificateType::MTls,
                &reg.agent_id,
                now,
            ));
        }
    }

    certs
}

/// Build certificate entries from all registrar agents.
async fn collect_certificates(state: &AppState) -> AppResult<Vec<Certificate>> {
    let agent_ids = state.keylime().list_registrar_agents().await?;
    let now = Utc::now();
    let mut certs = Vec::new();

    for id_str in &agent_ids {
        if let Ok(reg) = state.keylime().get_registrar_agent(id_str).await {
            certs.extend(collect_agent_certs(&reg, now));
        }
    }

    Ok(certs)
}

/// Build certificate summaries for a single agent (used by agent detail).
pub fn build_agent_cert_summaries(
    reg: &RegistrarAgent,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<AgentCertSummary> {
    collect_agent_certs(reg, now)
        .into_iter()
        .map(|c| {
            let days_until = (c.not_after - now).num_days();
            AgentCertSummary {
                cert_type: c.cert_type,
                status: c.status,
                expiry_category: c.expiry_category,
                not_after: c.not_after,
                days_until_expiry: days_until,
                chain_valid: c.chain_valid,
                validation_status: c.validation_status,
            }
        })
        .collect()
}

/// Compute expiry summary from a slice of certificates at a given time.
pub fn compute_expiry_summary(
    certs: &[Certificate],
    now: chrono::DateTime<chrono::Utc>,
) -> CertificateExpirySummary {
    let mut expired = 0u64;
    let mut expiring_30d = 0u64;
    let mut expiring_90d = 0u64;
    let mut valid = 0u64;
    let mut weekly_buckets = [0u64; 13];

    for cert in certs {
        if cert.not_after < now {
            expired += 1;
        } else {
            let days_until = (cert.not_after - now).num_days().max(0) as usize;
            if days_until < 30 {
                expiring_30d += 1;
                expiring_90d += 1;
            } else if days_until < 90 {
                expiring_90d += 1;
            } else {
                valid += 1;
            }
            if days_until < 91 {
                let week_idx = days_until / 7;
                if week_idx < 13 {
                    weekly_buckets[week_idx] += 1;
                }
            }
        }
    }

    let timeline_90d: Vec<ExpiryTimelineEntry> = (0..13)
        .map(|i| {
            let week_start = now + Duration::days(i * 7);
            let week_end = now + Duration::days((i + 1) * 7);
            ExpiryTimelineEntry {
                week_start,
                week_end,
                count: weekly_buckets[i as usize],
            }
        })
        .collect();

    CertificateExpirySummary {
        expired,
        expiring_30d,
        expiring_90d,
        valid,
        total: certs.len() as u64,
        timeline_90d,
    }
}

#[derive(Debug, Deserialize)]
pub struct CertListParams {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    #[serde(rename = "type")]
    pub cert_type: Option<String>,
    pub expiry_category: Option<String>,
}

/// GET /api/certificates -- Unified certificate view (FR-050).
pub async fn list_certificates(
    State(state): State<AppState>,
    Query(params): Query<CertListParams>,
) -> AppResult<Json<ApiResponse<PaginatedResponse<Certificate>>>> {
    let mut certs = collect_certificates(&state).await?;

    // Filter by type
    if let Some(ref type_filter) = params.cert_type {
        if let Some(ct) = CertificateType::from_str_loose(type_filter) {
            certs.retain(|c| c.cert_type == ct);
        }
    }

    // Filter by expiry category
    if let Some(ref cat_filter) = params.expiry_category {
        if let Ok(cat) =
            serde_json::from_value::<ExpiryCategory>(serde_json::Value::String(cat_filter.clone()))
        {
            certs.retain(|c| c.expiry_category == cat);
        }
    }

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(100).min(500);
    let total_items = certs.len() as u64;
    let total_pages = (total_items + page_size - 1) / page_size.max(1);
    let start = ((page - 1) * page_size) as usize;
    let items: Vec<Certificate> = certs
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();

    Ok(Json(ApiResponse::ok(PaginatedResponse {
        items,
        page,
        page_size,
        total_items,
        total_pages,
    })))
}

/// GET /api/certificates/expiry -- Certificate expiry dashboard (FR-051).
pub async fn expiry_summary(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<CertificateExpirySummary>>> {
    if let Some(cache) = state.cache() {
        if let Ok(Some(cached)) = cache
            .get(CacheNamespace::Certificates, "expiry_summary")
            .await
        {
            if let Ok(summary) = serde_json::from_str::<CertificateExpirySummary>(&cached) {
                return Ok(Json(ApiResponse::ok(summary)));
            }
        }
    }

    let certs = collect_certificates(&state).await?;
    let now = Utc::now();
    let summary = compute_expiry_summary(&certs, now);

    if let Some(cache) = state.cache() {
        if let Ok(json) = serde_json::to_string(&summary) {
            let _ = cache
                .set(CacheNamespace::Certificates, "expiry_summary", &json)
                .await;
        }
    }

    Ok(Json(ApiResponse::ok(summary)))
}

/// GET /api/certificates/timeline -- 90-day expiry timeline (FR-051).
pub async fn timeline(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<Vec<CertificateTimelineEntry>>>> {
    let certs = collect_certificates(&state).await?;
    let now = Utc::now();

    let mut entries = Vec::new();
    for i in 0..13i64 {
        let week_start = now + Duration::days(i * 7);
        let week_end = now + Duration::days((i + 1) * 7);

        let mut count = 0u64;
        for cert in &certs {
            if cert.not_after >= week_start && cert.not_after < week_end {
                count += 1;
            }
        }

        if count > 0 {
            let cat = cert_parser::compute_expiry_category(week_start, now);
            entries.push(CertificateTimelineEntry {
                date: week_start.format("%Y-%m-%d").to_string(),
                count,
                expiry_category: cat,
            });
        }
    }

    Ok(Json(ApiResponse::ok(entries)))
}

/// GET /api/certificates/:id -- Certificate detail by cert UUID (FR-052).
pub async fn get_certificate(
    State(state): State<AppState>,
    Path(cert_id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<Certificate>>> {
    let certs = collect_certificates(&state).await?;

    let cert = certs
        .into_iter()
        .find(|c| c.id == cert_id)
        .ok_or_else(|| AppError::NotFound(format!("certificate {cert_id} not found")))?;

    Ok(Json(ApiResponse::ok(cert)))
}

/// GET /api/certificates/:id/download/pem -- PEM export (FR-052).
pub async fn download_pem(
    State(state): State<AppState>,
    Path(cert_id): Path<Uuid>,
) -> AppResult<Response> {
    let certs = collect_certificates(&state).await?;

    let cert = certs
        .into_iter()
        .find(|c| c.id == cert_id)
        .ok_or_else(|| AppError::NotFound(format!("certificate {cert_id} not found")))?;

    let pem = cert.raw_pem.ok_or_else(|| {
        AppError::NotFound("PEM data not available (raw public key, not X.509)".into())
    })?;

    Ok(([(header::CONTENT_TYPE, "application/x-pem-file")], pem).into_response())
}

/// GET /api/certificates/:id/download/der -- DER export (FR-052).
pub async fn download_der(
    State(state): State<AppState>,
    Path(cert_id): Path<Uuid>,
) -> AppResult<Response> {
    let certs = collect_certificates(&state).await?;

    let cert = certs
        .into_iter()
        .find(|c| c.id == cert_id)
        .ok_or_else(|| AppError::NotFound(format!("certificate {cert_id} not found")))?;

    let der = cert.raw_der.ok_or_else(|| {
        AppError::NotFound("DER data not available (raw public key, not X.509)".into())
    })?;

    Ok(([(header::CONTENT_TYPE, "application/pkix-cert")], der).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_cert(days_until_expiry: i64) -> Certificate {
        let now = Utc::now();
        let not_after = now + Duration::days(days_until_expiry);
        Certificate {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            cert_type: CertificateType::Ek,
            subject_dn: "CN=test".into(),
            issuer_dn: "CN=ca".into(),
            serial_number: "1".into(),
            not_before: now - Duration::days(365),
            not_after,
            public_key_algorithm: "RSA".into(),
            public_key_size: 2048,
            signature_algorithm: "SHA256withRSA".into(),
            sans: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            status: cert_parser::compute_status(not_after, now),
            expiry_category: cert_parser::compute_expiry_category(not_after, now),
            associated_entity: "agent-1".into(),
            validation_status: ValidationStatus::Unknown,
            chain_valid: None,
            chain: vec![],
            raw_pem: None,
            raw_der: None,
        }
    }

    #[test]
    fn expiry_bucketing_expired() {
        let now = Utc::now();
        let certs = vec![make_cert(-10)];
        let summary = compute_expiry_summary(&certs, now);
        assert_eq!(summary.expired, 1);
        assert_eq!(summary.expiring_30d, 0);
        assert_eq!(summary.expiring_90d, 0);
        assert_eq!(summary.valid, 0);
        assert_eq!(summary.total, 1);
    }

    #[test]
    fn expiry_bucketing_expiring_30d() {
        let now = Utc::now();
        let certs = vec![make_cert(15)];
        let summary = compute_expiry_summary(&certs, now);
        assert_eq!(summary.expired, 0);
        assert_eq!(summary.expiring_30d, 1);
        assert_eq!(summary.expiring_90d, 1);
        assert_eq!(summary.valid, 0);
    }

    #[test]
    fn expiry_bucketing_expiring_90d() {
        let now = Utc::now();
        let certs = vec![make_cert(60)];
        let summary = compute_expiry_summary(&certs, now);
        assert_eq!(summary.expired, 0);
        assert_eq!(summary.expiring_30d, 0);
        assert_eq!(summary.expiring_90d, 1);
        assert_eq!(summary.valid, 0);
    }

    #[test]
    fn expiry_bucketing_valid() {
        let now = Utc::now();
        let certs = vec![make_cert(365)];
        let summary = compute_expiry_summary(&certs, now);
        assert_eq!(summary.expired, 0);
        assert_eq!(summary.expiring_30d, 0);
        assert_eq!(summary.expiring_90d, 0);
        assert_eq!(summary.valid, 1);
    }

    #[test]
    fn expiry_bucketing_mixed() {
        let now = Utc::now();
        let certs = vec![
            make_cert(-5),
            make_cert(10),
            make_cert(50),
            make_cert(200),
            make_cert(500),
        ];
        let summary = compute_expiry_summary(&certs, now);
        assert_eq!(summary.expired, 1);
        assert_eq!(summary.expiring_30d, 1);
        assert_eq!(summary.expiring_90d, 2);
        assert_eq!(summary.valid, 2);
        assert_eq!(summary.total, 5);
    }

    #[test]
    fn timeline_has_13_entries() {
        let now = Utc::now();
        let certs: Vec<Certificate> = vec![];
        let summary = compute_expiry_summary(&certs, now);
        assert_eq!(summary.timeline_90d.len(), 13);
    }

    #[test]
    fn timeline_places_cert_in_correct_week() {
        let now = Utc::now();
        let certs = vec![make_cert(10)];
        let summary = compute_expiry_summary(&certs, now);
        assert_eq!(summary.timeline_90d[1].count, 1);
        assert_eq!(summary.timeline_90d[0].count, 0);
        assert_eq!(summary.timeline_90d[2].count, 0);
    }

    #[test]
    fn derive_cert_id_is_deterministic() {
        let uuid = Uuid::parse_str("d432fbb3-d2f1-4a97-9ef7-75bd81c00000").unwrap();
        let id1 = derive_cert_id(&uuid, "ek");
        let id2 = derive_cert_id(&uuid, "ek");
        assert_eq!(id1, id2);

        let id3 = derive_cert_id(&uuid, "ak");
        assert_ne!(id1, id3);
    }

    #[test]
    fn cert_type_from_str_loose_rejects_invalid() {
        assert!(CertificateType::from_str_loose("iak").is_none());
        assert!(CertificateType::from_str_loose("idevid").is_none());
        assert!(CertificateType::from_str_loose("server").is_none());
        assert!(CertificateType::from_str_loose("").is_none());
    }

    #[test]
    fn make_cert_has_correct_expiry_category() {
        let c = make_cert(365);
        assert_eq!(c.expiry_category, ExpiryCategory::Valid);

        let c = make_cert(60);
        assert_eq!(c.expiry_category, ExpiryCategory::Warning90d);

        let c = make_cert(15);
        assert_eq!(c.expiry_category, ExpiryCategory::Warning30d);

        let c = make_cert(3);
        assert_eq!(c.expiry_category, ExpiryCategory::Critical7d);

        let c = make_cert(-1);
        assert_eq!(c.expiry_category, ExpiryCategory::Expired);
    }
}
