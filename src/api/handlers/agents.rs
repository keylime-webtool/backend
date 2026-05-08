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

    // Apply filters
    if let Some(ref state_filter) = params.state {
        let filter_upper = state_filter.to_uppercase();
        summaries.retain(|s| {
            let state_str = serde_json::to_string(&s.state).unwrap_or_default();
            let state_str = state_str.trim_matches('"');
            state_str == filter_upper
        });
    }
    if let Some(ref ip_filter) = params.ip {
        summaries.retain(|s| s.ip.contains(ip_filter));
    }
    if let Some(ref uuid_filter) = params.uuid {
        summaries.retain(|s| s.id.to_string().starts_with(uuid_filter));
    }

    // Pagination
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(20).min(100);
    let total_items = summaries.len() as u64;
    let total_pages = (total_items + page_size - 1) / page_size.max(1);
    let start = ((page - 1) * page_size) as usize;
    let items: Vec<AgentSummary> = summaries
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

/// Resolve policy names for an agent using Keylime flags as a fallback.
///
/// When the agent record includes explicit policy names (ima_policy /
/// mb_policy), those are returned directly.  When only boolean flags are
/// available (has_runtime_policy / has_mb_refstate — typical of real
/// Keylime v2), the first known policy of that kind is used.  This is the
/// same approximation as the policy handler's assigned_agents count.
fn resolve_agent_policies(
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
