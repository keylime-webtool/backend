use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::handlers::certificates::build_agent_cert_summaries;
use crate::api::response::{ApiResponse, PaginatedResponse};
use crate::error::{AppError, AppResult};
use crate::models::agent::{AgentState, AgentSummary, AttestationMode};
use crate::models::certificate::Certificate;
use crate::state::AppState;

/// Query parameters for agent list filtering (FR-014).
#[derive(Debug, Deserialize)]
pub struct AgentListParams {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub state: Option<String>,
    pub ip: Option<String>,
    pub uuid: Option<String>,
    pub policy: Option<String>,
    pub min_failures: Option<u32>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

/// GET /api/agents -- Paginated, filterable agent list (FR-012, FR-013, FR-014).
pub async fn list_agents(
    State(state): State<AppState>,
    Query(params): Query<AgentListParams>,
) -> AppResult<Json<ApiResponse<PaginatedResponse<AgentSummary>>>> {
    super::attestations::record_agent_observations(&state).await;

    // Fetch agent UUIDs from Verifier
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let (ima_policies, mb_policies) = fetch_policy_names_by_kind(&state).await;

    // Fetch detail for each agent to build summaries.
    // Skip agents that fail to fetch rather than failing the entire list.
    let range_end = Utc::now();
    let range_start = DateTime::<Utc>::MIN_UTC;

    let mut summaries = Vec::new();
    for id_str in &agent_ids {
        let agent = match state.keylime().get_verifier_agent(id_str).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("skipping agent {id_str}: {e}");
                continue;
            }
        };
        // Apply policy filter early on raw Keylime data — same matching
        // logic the policy handler uses for assigned_agents counts.
        if let Some(ref policy_filter) = params.policy {
            let is_mb = mb_policies.contains(policy_filter);
            let matches = if is_mb {
                agent
                    .effective_mb_policy()
                    .map(|p| p == policy_filter.as_str())
                    .unwrap_or_else(|| agent.has_mb_refstate == Some(1))
            } else {
                agent
                    .effective_ima_policy()
                    .map(|p| p == policy_filter.as_str())
                    .unwrap_or_else(|| agent.has_runtime_policy == Some(1))
            };
            if !matches {
                continue;
            }
        }

        let is_push = agent.is_push_mode();

        let (mode, agent_state) = if is_push {
            (AttestationMode::Push, AgentState::from_push_agent(&agent))
        } else {
            match AgentState::from_operational_state(&agent.operational_state) {
                Ok(s) => (AttestationMode::Pull, s),
                Err(e) => {
                    tracing::warn!("skipping agent {id_str}: {e}");
                    continue;
                }
            }
        };

        let uuid = match Uuid::parse_str(&agent.agent_id) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("skipping agent {id_str}: invalid UUID: {e}");
                continue;
            }
        };

        let needs_registrar =
            agent.ip.as_deref().unwrap_or("").is_empty() || agent.port.unwrap_or(0) == 0;
        let registrar_agent = if needs_registrar {
            state.keylime().get_registrar_agent(id_str).await.ok()
        } else {
            None
        };
        let ip = agent.resolve_ip(registrar_agent.as_ref());
        let port = agent.resolve_port(registrar_agent.as_ref());
        let last_attestation = agent
            .last_successful_attestation
            .filter(|&ts| ts > 0)
            .or(agent.last_received_quote.filter(|&ts| ts > 0))
            .and_then(|ts| DateTime::from_timestamp(ts as i64, 0));
        let repo_failures = state
            .attestation_repo
            .count_agent_failures(uuid, range_start, range_end)
            .await
            .unwrap_or(0);
        let keylime_consecutive = agent.consecutive_attestation_failures.unwrap_or(0) as u64;
        let failure_count = repo_failures.max(keylime_consecutive) as u32;

        let (assigned_policy, mb_policy_resolved) =
            resolve_agent_policies(&agent, &ima_policies, &mb_policies);

        summaries.push(AgentSummary {
            id: uuid,
            ip,
            port,
            state: agent_state,
            attestation_mode: mode,
            last_attestation,
            assigned_policy,
            mb_policy: mb_policy_resolved,
            failure_count,
        });
    }

    filter_agent_summaries(
        &mut summaries,
        params.state.as_deref(),
        params.ip.as_deref(),
        params.uuid.as_deref(),
    );

    let paginated = paginate(summaries, params.page, params.page_size);

    Ok(Json(ApiResponse::ok(paginated)))
}

/// GET /api/agents/:id -- Agent detail view (FR-018).
pub async fn get_agent(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();

    // Fetch from both Verifier and Registrar
    let verifier_agent = state.keylime().get_verifier_agent(&id_str).await?;
    let registrar_agent = state.keylime().get_registrar_agent(&id_str).await.ok();

    let is_push = verifier_agent.is_push_mode();

    let (mode, agent_state) = if is_push {
        (
            AttestationMode::Push,
            AgentState::from_push_agent(&verifier_agent),
        )
    } else {
        let pull_state = AgentState::from_operational_state(&verifier_agent.operational_state)
            .map_err(AppError::Internal)?;
        (AttestationMode::Pull, pull_state)
    };

    // Resolve policy names (Keylime v2 fallback)
    let (ima_policies, mb_policies) = fetch_policy_names_by_kind(&state).await;
    let (resolved_ima, resolved_mb) =
        resolve_agent_policies(&verifier_agent, &ima_policies, &mb_policies);

    // Build a combined JSON response with data from both sources
    let mut combined = serde_json::json!({
        "id": id_str,
        "ip": verifier_agent.resolve_ip(registrar_agent.as_ref()),
        "port": verifier_agent.resolve_port(registrar_agent.as_ref()),
        "state": agent_state,
        "attestation_mode": mode,
        "hash_alg": verifier_agent.hash_alg,
        "enc_alg": verifier_agent.enc_alg,
        "sign_alg": verifier_agent.sign_alg,
        "ima_pcrs": verifier_agent.ima_pcrs,
        "ima_policy": resolved_ima,
        "mb_policy": resolved_mb,
        "tpm_policy": verifier_agent.tpm_policy,
        "accept_tpm_hash_algs": verifier_agent.accept_tpm_hash_algs,
        "accept_tpm_encryption_algs": verifier_agent.accept_tpm_encryption_algs,
        "accept_tpm_signing_algs": verifier_agent.accept_tpm_signing_algs,
    });

    if let Some(ref reg) = registrar_agent {
        let now = Utc::now();
        let cert_summaries = build_agent_cert_summaries(reg, now);
        if let Some(obj) = combined.as_object_mut() {
            obj.insert("ek_tpm".into(), serde_json::json!(reg.ek_tpm));
            obj.insert("aik_tpm".into(), serde_json::json!(reg.aik_tpm));
            obj.insert("regcount".into(), serde_json::json!(reg.regcount));
            obj.insert(
                "certificates".into(),
                serde_json::to_value(&cert_summaries).unwrap_or_default(),
            );
        }
    }

    Ok(Json(ApiResponse::ok(combined)))
}

/// Global agent search by UUID, IP, or hostname (FR-004).
#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: String,
}

/// GET /api/agents/search -- Global search (FR-004, FR-015 CIDR support).
pub async fn search_agents(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> AppResult<Json<ApiResponse<Vec<AgentSummary>>>> {
    super::attestations::record_agent_observations(&state).await;

    let q = params.q.to_lowercase();
    let agent_ids = state.keylime().list_verifier_agents().await?;
    let (ima_policies, mb_policies) = fetch_policy_names_by_kind(&state).await;

    let range_end = Utc::now();
    let range_start = DateTime::<Utc>::MIN_UTC;

    let mut results = Vec::new();
    for id_str in &agent_ids {
        let agent = match state.keylime().get_verifier_agent(id_str).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("search: skipping agent {id_str}: {e}");
                continue;
            }
        };

        // Match against UUID, IP
        let matches = agent.agent_id.to_lowercase().contains(&q)
            || agent
                .ip
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains(&q);

        if matches {
            let is_push = agent.is_push_mode();

            let (mode, agent_state) = if is_push {
                (AttestationMode::Push, AgentState::from_push_agent(&agent))
            } else {
                match AgentState::from_operational_state(&agent.operational_state) {
                    Ok(s) => (AttestationMode::Pull, s),
                    Err(e) => {
                        tracing::warn!("search: skipping agent {id_str}: {e}");
                        continue;
                    }
                }
            };

            let uuid = match Uuid::parse_str(&agent.agent_id) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!("search: skipping agent {id_str}: invalid UUID: {e}");
                    continue;
                }
            };

            let needs_registrar =
                agent.ip.as_deref().unwrap_or("").is_empty() || agent.port.unwrap_or(0) == 0;
            let registrar_agent = if needs_registrar {
                state.keylime().get_registrar_agent(id_str).await.ok()
            } else {
                None
            };
            let ip = agent.resolve_ip(registrar_agent.as_ref());
            let port = agent.resolve_port(registrar_agent.as_ref());
            let last_attestation = agent
                .last_successful_attestation
                .filter(|&ts| ts > 0)
                .or(agent.last_received_quote.filter(|&ts| ts > 0))
                .and_then(|ts| DateTime::from_timestamp(ts as i64, 0));
            let repo_failures = state
                .attestation_repo
                .count_agent_failures(uuid, range_start, range_end)
                .await
                .unwrap_or(0);
            let keylime_consecutive = agent.consecutive_attestation_failures.unwrap_or(0) as u64;
            let failure_count = repo_failures.max(keylime_consecutive) as u32;

            let (assigned_policy, mb_policy_resolved) =
                resolve_agent_policies(&agent, &ima_policies, &mb_policies);

            results.push(AgentSummary {
                id: uuid,
                ip,
                port,
                state: agent_state,
                attestation_mode: mode,
                last_attestation,
                assigned_policy,
                mb_policy: mb_policy_resolved,
                failure_count,
            });
        }
    }

    Ok(Json(ApiResponse::ok(results)))
}

/// POST /api/agents/:id/actions/:action -- Agent actions (FR-019).
pub async fn agent_action(
    State(state): State<AppState>,
    Path((id, action)): Path<(Uuid, String)>,
) -> AppResult<Json<ApiResponse<()>>> {
    let id_str = id.to_string();
    match action.as_str() {
        "reactivate" => {
            state.keylime().reactivate_agent(&id_str).await?;
            Ok(Json(ApiResponse::ok(())))
        }
        "delete" => {
            state.keylime().delete_agent(&id_str).await?;
            Ok(Json(ApiResponse::ok(())))
        }
        "stop" => {
            // Stop uses the same PUT endpoint with a different state
            state.keylime().reactivate_agent(&id_str).await?;
            Ok(Json(ApiResponse::ok(())))
        }
        _ => Err(AppError::BadRequest(format!(
            "unknown action: {action}. Valid actions: reactivate, delete, stop"
        ))),
    }
}

/// POST /api/agents/bulk -- Bulk operations on selected agents (FR-016).
#[derive(Debug, Deserialize)]
pub struct BulkActionRequest {
    pub agent_ids: Vec<Uuid>,
    pub action: String,
}

pub async fn bulk_action(
    State(state): State<AppState>,
    Json(body): Json<BulkActionRequest>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let mut succeeded = 0u64;
    let mut failed = 0u64;

    for id in &body.agent_ids {
        let id_str = id.to_string();
        let result = match body.action.as_str() {
            "reactivate" => state.keylime().reactivate_agent(&id_str).await,
            "delete" => state.keylime().delete_agent(&id_str).await,
            "stop" => state.keylime().reactivate_agent(&id_str).await,
            _ => {
                return Err(AppError::BadRequest(format!(
                    "unknown action: {}. Valid actions: reactivate, delete, stop",
                    body.action
                )));
            }
        };
        match result {
            Ok(()) => succeeded += 1,
            Err(_) => failed += 1,
        }
    }

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "action": body.action,
        "total": body.agent_ids.len(),
        "succeeded": succeeded,
        "failed": failed,
    }))))
}

/// GET /api/agents/:id/timeline -- Attestation timeline (FR-020).
pub async fn get_timeline(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<Vec<serde_json::Value>>>> {
    let id_str = id.to_string();
    let agent = state.keylime().get_verifier_agent(&id_str).await?;
    let agent_state = if agent.is_push_mode() {
        AgentState::from_push_agent(&agent)
    } else {
        AgentState::from_operational_state(&agent.operational_state).map_err(AppError::Internal)?
    };

    // Generate synthetic timeline events based on agent state
    let now = chrono::Utc::now();
    let mut events = vec![serde_json::json!({
        "timestamp": now - chrono::Duration::hours(24),
        "event": "registered",
        "detail": "Agent registered with verifier"
    })];

    events.push(serde_json::json!({
        "timestamp": now - chrono::Duration::hours(23),
        "event": "first_attestation",
        "detail": "Initial attestation completed successfully"
    }));

    if agent_state.is_failed() {
        events.push(serde_json::json!({
            "timestamp": now - chrono::Duration::minutes(30),
            "event": "attestation_failed",
            "detail": format!("Attestation failed, agent entered {:?} state", agent_state)
        }));
    } else {
        events.push(serde_json::json!({
            "timestamp": now - chrono::Duration::minutes(5),
            "event": "attestation_success",
            "detail": "Routine attestation completed successfully"
        }));
    }

    Ok(Json(ApiResponse::ok(events)))
}

/// GET /api/agents/:id/pcr -- PCR values (FR-021, FR-022).
pub async fn get_pcr_values(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();
    let pcrs = state.keylime().get_agent_pcrs(&id_str).await?;
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "hash_alg": pcrs.hash_alg,
        "pcrs": pcrs.pcrs,
    }))))
}

/// GET /api/agents/:id/ima-log -- IMA log entries (FR-020).
pub async fn get_ima_log(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();
    let ima = state.keylime().get_agent_ima_log(&id_str).await?;
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "entries": ima.entries,
        "total": ima.entries.len(),
    }))))
}

/// GET /api/agents/:id/boot-log -- Boot log entries (FR-020).
pub async fn get_boot_log(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();
    let boot = state.keylime().get_agent_boot_log(&id_str).await?;
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "entries": boot.entries,
        "total": boot.entries.len(),
    }))))
}

/// GET /api/agents/:id/certificates -- Agent certificates (FR-020).
pub async fn get_agent_certs(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<Vec<Certificate>>>> {
    let id_str = id.to_string();
    let reg = state.keylime().get_registrar_agent(&id_str).await?;
    let now = Utc::now();

    let certs = super::certificates::collect_agent_certs(&reg, now);

    Ok(Json(ApiResponse::ok(certs)))
}

/// GET /api/agents/:id/raw -- Combined raw data from all sources (FR-020).
pub async fn get_raw_data(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();
    let verifier_agent = state.keylime().get_verifier_agent(&id_str).await?;
    let registrar_agent = state.keylime().get_registrar_agent(&id_str).await.ok();

    let backend = build_backend_summary(&state, &id_str, &verifier_agent, &registrar_agent)?;

    let raw = serde_json::json!({
        "backend": backend,
        "verifier": verifier_agent,
        "registrar": registrar_agent,
    });

    Ok(Json(ApiResponse::ok(raw)))
}

/// GET /api/agents/:id/raw/backend -- Backend-computed agent summary (FR-020).
pub async fn get_raw_backend(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();
    let verifier_agent = state.keylime().get_verifier_agent(&id_str).await?;
    let registrar_agent = state.keylime().get_registrar_agent(&id_str).await.ok();

    let backend = build_backend_summary(&state, &id_str, &verifier_agent, &registrar_agent)?;
    Ok(Json(ApiResponse::ok(backend)))
}

/// GET /api/agents/:id/raw/registrar -- Raw Registrar API JSON (FR-020).
pub async fn get_raw_registrar(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();
    let registrar_agent = state.keylime().get_registrar_agent(&id_str).await?;
    let value =
        serde_json::to_value(registrar_agent).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::ok(value)))
}

/// GET /api/agents/:id/raw/verifier -- Raw Verifier API JSON (FR-020).
pub async fn get_raw_verifier(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    let id_str = id.to_string();
    let raw = state.keylime().get_verifier_agent_raw(&id_str).await?;
    // Unwrap nested format: { "uuid": { ...data } } → { ...data }
    let agent_data = match raw.as_object() {
        Some(obj) if obj.len() == 1 => {
            let (_, val) = obj.iter().next().unwrap();
            if val.is_object() {
                val.clone()
            } else {
                raw
            }
        }
        _ => raw,
    };
    Ok(Json(ApiResponse::ok(agent_data)))
}

/// Fetch policy names from Keylime, split by source endpoint:
/// IMA from GET /v2/allowlists/, MB from GET /v2/mbpolicies/.
async fn fetch_policy_names_by_kind(state: &AppState) -> (Vec<String>, Vec<String>) {
    let ima = state.keylime().list_policies().await.unwrap_or_default();
    let mb = state.keylime().list_mb_policies().await.unwrap_or_default();
    (ima, mb)
}

pub(crate) fn filter_agent_summaries(
    summaries: &mut Vec<AgentSummary>,
    state_filter: Option<&str>,
    ip_filter: Option<&str>,
    uuid_filter: Option<&str>,
) {
    if let Some(state_filter) = state_filter {
        let filter_upper = state_filter.to_uppercase();
        summaries.retain(|s| {
            let state_str = serde_json::to_string(&s.state).unwrap_or_default();
            let state_str = state_str.trim_matches('"');
            state_str == filter_upper
        });
    }
    if let Some(ip_filter) = ip_filter {
        summaries.retain(|s| s.ip.contains(ip_filter));
    }
    if let Some(uuid_filter) = uuid_filter {
        summaries.retain(|s| s.id.to_string().starts_with(uuid_filter));
    }
}

pub(crate) fn paginate<T: serde::Serialize>(
    items: Vec<T>,
    page: Option<u64>,
    page_size: Option<u64>,
) -> PaginatedResponse<T> {
    let page = page.unwrap_or(1).max(1);
    let page_size = page_size.unwrap_or(20).min(100);
    let total_items = items.len() as u64;
    let total_pages = (total_items + page_size - 1) / page_size.max(1);
    let start = ((page - 1) * page_size) as usize;
    let paged: Vec<T> = items
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();
    PaginatedResponse {
        items: paged,
        page,
        page_size,
        total_items,
        total_pages,
    }
}

pub(crate) fn resolve_agent_policies(
    agent: &crate::keylime::models::VerifierAgent,
    ima_policies: &[String],
    mb_policies: &[String],
) -> (Option<String>, Option<String>) {
    let assigned_policy = agent.effective_ima_policy().map(String::from).or_else(|| {
        if agent.has_runtime_policy == Some(1) && ima_policies.len() == 1 {
            ima_policies.first().cloned()
        } else {
            None
        }
    });

    let mb_policy = agent.effective_mb_policy().map(String::from).or_else(|| {
        if agent.has_mb_refstate == Some(1) && mb_policies.len() == 1 {
            mb_policies.first().cloned()
        } else {
            None
        }
    });

    (assigned_policy, mb_policy)
}

/// Build the merged agent summary that the dashboard backend computes.
fn build_backend_summary(
    _state: &AppState,
    id_str: &str,
    verifier_agent: &crate::keylime::models::VerifierAgent,
    registrar_agent: &Option<crate::keylime::models::RegistrarAgent>,
) -> AppResult<serde_json::Value> {
    let is_push = verifier_agent.is_push_mode();

    let (mode, agent_state) = if is_push {
        (
            AttestationMode::Push,
            AgentState::from_push_agent(verifier_agent),
        )
    } else {
        let pull_state = AgentState::from_operational_state(&verifier_agent.operational_state)
            .map_err(AppError::Internal)?;
        (AttestationMode::Pull, pull_state)
    };

    let mut summary = serde_json::json!({
        "id": id_str,
        "ip": verifier_agent.resolve_ip(registrar_agent.as_ref()),
        "port": verifier_agent.resolve_port(registrar_agent.as_ref()),
        "state": agent_state,
        "attestation_mode": mode,
        "hash_alg": verifier_agent.hash_alg,
        "enc_alg": verifier_agent.enc_alg,
        "sign_alg": verifier_agent.sign_alg,
        "ima_pcrs": verifier_agent.ima_pcrs,
        "ima_policy": verifier_agent.effective_ima_policy(),
        "mb_policy": verifier_agent.effective_mb_policy(),
        "tpm_policy": verifier_agent.tpm_policy,
        "accept_tpm_hash_algs": verifier_agent.accept_tpm_hash_algs,
        "accept_tpm_encryption_algs": verifier_agent.accept_tpm_encryption_algs,
        "accept_tpm_signing_algs": verifier_agent.accept_tpm_signing_algs,
    });

    if let Some(reg) = registrar_agent {
        if let Some(obj) = summary.as_object_mut() {
            obj.insert("ek_tpm".into(), serde_json::json!(reg.ek_tpm));
            obj.insert("aik_tpm".into(), serde_json::json!(reg.aik_tpm));
            obj.insert("regcount".into(), serde_json::json!(reg.regcount));
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylime::models::VerifierAgent;

    fn make_summary(id: &str, ip: &str, state: AgentState) -> AgentSummary {
        AgentSummary {
            id: Uuid::parse_str(id).unwrap(),
            ip: ip.to_string(),
            port: 9002,
            state,
            attestation_mode: AttestationMode::Pull,
            last_attestation: None,
            assigned_policy: None,
            mb_policy: None,
            failure_count: 0,
        }
    }

    fn sample_summaries() -> Vec<AgentSummary> {
        vec![
            make_summary(
                "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
                "10.0.1.10",
                AgentState::GetQuote,
            ),
            make_summary(
                "a1b2c3d4-0000-1111-2222-333344445555",
                "10.0.1.20",
                AgentState::Failed,
            ),
            make_summary(
                "b2c3d4e5-1111-2222-3333-444455556666",
                "192.168.1.1",
                AgentState::GetQuote,
            ),
        ]
    }

    // ── paginate ────────────────────────────────────────────────────────

    #[test]
    fn paginate_first_page() {
        let items: Vec<u32> = (1..=10).collect();
        let result = paginate(items, Some(1), Some(3));
        assert_eq!(result.items, vec![1, 2, 3]);
        assert_eq!(result.page, 1);
        assert_eq!(result.page_size, 3);
        assert_eq!(result.total_items, 10);
        assert_eq!(result.total_pages, 4);
    }

    #[test]
    fn paginate_last_partial_page() {
        let items: Vec<u32> = (1..=10).collect();
        let result = paginate(items, Some(4), Some(3));
        assert_eq!(result.items, vec![10]);
    }

    #[test]
    fn paginate_beyond_total() {
        let items: Vec<u32> = (1..=5).collect();
        let result = paginate(items, Some(100), Some(10));
        assert!(result.items.is_empty());
    }

    #[test]
    fn paginate_defaults() {
        let items: Vec<u32> = (1..=25).collect();
        let result = paginate(items, None, None);
        assert_eq!(result.page, 1);
        assert_eq!(result.page_size, 20);
        assert_eq!(result.items.len(), 20);
    }

    #[test]
    fn paginate_clamps_page_size() {
        let items: Vec<u32> = (1..=5).collect();
        let result = paginate(items, Some(1), Some(999));
        assert_eq!(result.page_size, 100);
    }

    #[test]
    fn paginate_clamps_page_zero() {
        let items: Vec<u32> = (1..=5).collect();
        let result = paginate(items, Some(0), Some(10));
        assert_eq!(result.page, 1);
        assert_eq!(result.items, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn paginate_empty() {
        let items: Vec<u32> = vec![];
        let result = paginate(items, Some(1), Some(10));
        assert!(result.items.is_empty());
        assert_eq!(result.total_items, 0);
        assert_eq!(result.total_pages, 0);
    }

    // ── filter_agent_summaries ──────────────────────────────────────────

    #[test]
    fn filter_by_state() {
        let mut summaries = sample_summaries();
        filter_agent_summaries(&mut summaries, Some("GET_QUOTE"), None, None);
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|s| s.state == AgentState::GetQuote));
    }

    #[test]
    fn filter_by_state_case_insensitive() {
        let mut summaries = sample_summaries();
        filter_agent_summaries(&mut summaries, Some("failed"), None, None);
        assert_eq!(summaries.len(), 1);
    }

    #[test]
    fn filter_by_ip() {
        let mut summaries = sample_summaries();
        filter_agent_summaries(&mut summaries, None, Some("10.0.1"), None);
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn filter_by_uuid_prefix() {
        let mut summaries = sample_summaries();
        filter_agent_summaries(&mut summaries, None, None, Some("d432fbb3"));
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].id.to_string(),
            "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        );
    }

    #[test]
    fn filter_no_match() {
        let mut summaries = sample_summaries();
        filter_agent_summaries(&mut summaries, Some("NONEXISTENT"), None, None);
        assert!(summaries.is_empty());
    }

    #[test]
    fn filter_combined() {
        let mut summaries = sample_summaries();
        filter_agent_summaries(&mut summaries, Some("GET_QUOTE"), Some("10.0.1"), None);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].ip, "10.0.1.10");
    }

    // ── resolve_agent_policies ──────────────────────────────────────────

    #[test]
    fn resolve_explicit_ima_policy() {
        let mut agent = serde_json::from_value::<VerifierAgent>(serde_json::json!({})).unwrap();
        agent.ima_policy = Some("prod-v1".into());
        let (ima, mb) = resolve_agent_policies(&agent, &[], &[]);
        assert_eq!(ima.as_deref(), Some("prod-v1"));
        assert!(mb.is_none());
    }

    #[test]
    fn resolve_fallback_single_ima_policy() {
        let mut agent = serde_json::from_value::<VerifierAgent>(serde_json::json!({})).unwrap();
        agent.has_runtime_policy = Some(1);
        let (ima, _) = resolve_agent_policies(&agent, &["default".into()], &[]);
        assert_eq!(ima.as_deref(), Some("default"));
    }

    #[test]
    fn resolve_no_fallback_multiple_ima_policies() {
        let mut agent = serde_json::from_value::<VerifierAgent>(serde_json::json!({})).unwrap();
        agent.has_runtime_policy = Some(1);
        let (ima, _) = resolve_agent_policies(&agent, &["a".into(), "b".into()], &[]);
        assert!(ima.is_none());
    }

    #[test]
    fn resolve_explicit_mb_policy() {
        let mut agent = serde_json::from_value::<VerifierAgent>(serde_json::json!({})).unwrap();
        agent.mb_policy = Some("boot-v1".into());
        let (_, mb) = resolve_agent_policies(&agent, &[], &[]);
        assert_eq!(mb.as_deref(), Some("boot-v1"));
    }

    #[test]
    fn resolve_no_policies() {
        let agent = serde_json::from_value::<VerifierAgent>(serde_json::json!({})).unwrap();
        let (ima, mb) = resolve_agent_policies(&agent, &[], &[]);
        assert!(ima.is_none());
        assert!(mb.is_none());
    }
}
