use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::api::response::{ApiResponse, PaginatedResponse};
use crate::audit::logger::{AuditEntry, AuditSeverity};
use crate::error::{AppError, AppResult};
use crate::repository::audit::AuditFilter;
use crate::state::AppState;

const DEFAULT_PAGE_SIZE: u64 = 25;
const MAX_PAGE_SIZE: u64 = 100;
const CSV_COLUMNS: [&str; 11] = [
    "id",
    "timestamp",
    "severity",
    "actor",
    "action",
    "resource",
    "source_ip",
    "user_agent",
    "result",
    "previous_hash",
    "entry_hash",
];

/// Query parameters for audit log filtering (FR-042).
#[derive(Debug, Deserialize)]
pub struct AuditLogParams {
    pub severity: Option<String>,
    pub action: Option<String>,
    pub actor: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub format: Option<String>,
}

impl AuditLogParams {
    fn to_filter(&self) -> AuditFilter {
        AuditFilter {
            severity: self.severity.clone(),
            action: self.action.clone(),
            actor: self.actor.clone(),
            start: self.start.clone(),
            end: self.end.clone(),
        }
    }
}

/// GET /api/audit-log -- Searchable, paginated audit event log (FR-042, FR-043).
#[cfg(not(tarpaulin_include))]
pub async fn list_audit_events(
    State(state): State<AppState>,
    Query(params): Query<AuditLogParams>,
) -> AppResult<Json<ApiResponse<PaginatedResponse<AuditEntry>>>> {
    let entries = state.audit_repo.query(&params.to_filter()).await?;

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let total_items = entries.len() as u64;
    let total_pages = total_items.div_ceil(page_size);
    let start = ((page - 1) * page_size) as usize;
    let items: Vec<AuditEntry> = entries
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

/// Result of a hash chain integrity check (FR-061).
#[derive(Debug, Serialize)]
pub struct ChainVerificationStatus {
    pub verified: bool,
    pub total_entries: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_entry_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// GET /api/audit-log/verify -- Verify hash chain integrity (FR-061).
///
/// Returns 200 with `verified: true` when the chain is intact, and 409 with
/// `verified: false` plus the broken entry id when tampering is detected.
#[cfg(not(tarpaulin_include))]
pub async fn verify_chain(State(state): State<AppState>) -> AppResult<Response> {
    let total_entries = state.audit_repo.query(&AuditFilter::default()).await?.len() as u64;

    match state.audit_repo.verify_chain().await {
        Ok(()) => Ok(Json(ApiResponse::ok(ChainVerificationStatus {
            verified: true,
            total_entries,
            broken_entry_id: None,
            reason: None,
        }))
        .into_response()),
        Err(err) => Ok((
            StatusCode::CONFLICT,
            Json(ChainVerificationStatus {
                verified: false,
                total_entries,
                broken_entry_id: broken_entry_id_from(&err),
                reason: Some(err.to_string()),
            }),
        )
            .into_response()),
    }
}

/// GET /api/audit-log/export -- Export audit log as CSV (default) or JSON (FR-042).
#[cfg(not(tarpaulin_include))]
pub async fn export_audit_log(
    State(state): State<AppState>,
    Query(params): Query<AuditLogParams>,
) -> AppResult<Response> {
    let format = params.format.as_deref().unwrap_or("csv");
    if !matches!(format, "csv" | "json") {
        return Err(AppError::BadRequest(format!(
            "unsupported export format '{format}': expected 'csv' or 'json'"
        )));
    }

    let entries = state.audit_repo.export(&params.to_filter()).await?;
    let filename = format!("audit-log-{}.{format}", Utc::now().format("%Y%m%dT%H%M%SZ"));

    match format {
        "json" => Ok((
            [
                (CONTENT_TYPE, "application/json".to_string()),
                (
                    CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{filename}\""),
                ),
            ],
            serde_json::to_string_pretty(&entries).map_err(|e| {
                AppError::Internal(format!("audit export serialization failed: {e}"))
            })?,
        )
            .into_response()),
        _ => Ok((
            [
                (CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (
                    CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{filename}\""),
                ),
            ],
            entries_to_csv(&entries),
        )
            .into_response()),
    }
}

/// Recover the broken entry id from a chain verification failure.
///
/// `AuditRepository::verify_chain` flattens `ChainVerificationError` into an
/// `AppError` message ("... hash chain broken at entry 3" or
/// "... entry 3 has been tampered with"), so the id is parsed back out of
/// the message text.
fn broken_entry_id_from(err: &AppError) -> Option<u64> {
    const MARKER: &str = "entry ";
    let message = err.to_string();
    let start = message.rfind(MARKER)? + MARKER.len();
    let digits: String = message[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn severity_label(severity: &AuditSeverity) -> String {
    serde_json::to_string(severity)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_string())
}

/// Quote a CSV field per RFC 4180 when it contains a delimiter, quote,
/// or line break.
fn quote_csv_field(field: &str) -> String {
    let needs_quoting = field.contains(',') || field.contains('"') || field.contains('\n');
    if needs_quoting {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn entry_to_csv_row(entry: &AuditEntry) -> String {
    let fields = [
        entry.id.to_string(),
        entry.timestamp.to_rfc3339(),
        severity_label(&entry.severity),
        entry.actor.clone(),
        entry.action.clone(),
        entry.resource.clone(),
        entry.source_ip.clone(),
        entry.user_agent.clone().unwrap_or_default(),
        entry.result.clone(),
        entry.previous_hash.clone(),
        entry.entry_hash.clone(),
    ];
    fields
        .iter()
        .map(|f| quote_csv_field(f))
        .collect::<Vec<_>>()
        .join(",")
}

fn entries_to_csv(entries: &[AuditEntry]) -> String {
    let mut csv = CSV_COLUMNS.join(",");
    for entry in entries {
        csv.push('\n');
        csv.push_str(&entry_to_csv_row(entry));
    }
    csv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::logger::{AuditEntryParams, AuditLogger};
    use crate::config::KeylimeConfig;
    use crate::keylime::client::KeylimeClient;
    use crate::repository::sqlite::test_db;
    use crate::repository::Repositories;
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
            Arc::new(crate::repository::InMemoryCacheBackend::new()),
            None,
            false,
        )
    }

    async fn sqlite_state() -> AppState {
        let config = KeylimeConfig {
            verifier_url: "http://localhost:3000".into(),
            registrar_url: "http://localhost:3001".into(),
            mtls: None,
            timeout_secs: 5,
            observation_interval_secs: 30,
            circuit_breaker: Default::default(),
        };
        let client = KeylimeClient::new(config).unwrap();
        let db = test_db().await;
        let repos = db.repositories();
        AppState::new(
            client,
            repos.alert,
            repos.attestation,
            repos.policy,
            repos.audit,
            Arc::new(crate::repository::InMemoryCacheBackend::new()),
            None,
            false,
        )
    }

    fn params() -> AuditLogParams {
        AuditLogParams {
            severity: None,
            action: None,
            actor: None,
            start: None,
            end: None,
            page: None,
            page_size: None,
            format: None,
        }
    }

    async fn record_entries(state: &AppState, actions: &[&str]) {
        for action in actions {
            state
                .audit
                .record(AuditEntryParams::system(
                    AuditSeverity::Info,
                    action,
                    "test-resource",
                    "SUCCESS",
                ))
                .await
                .unwrap();
        }
    }

    async fn body_string(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn list_returns_all_entries_with_default_pagination() {
        let state = test_state();
        record_entries(&state, &["LOGIN", "READ", "UPDATE"]).await;

        let response = list_audit_events(State(state), Query(params()))
            .await
            .unwrap()
            .0;

        let page = response.data.unwrap();
        assert_eq!(page.items.len(), 3);
        assert_eq!(page.page, 1);
        assert_eq!(page.page_size, 25);
        assert_eq!(page.total_items, 3);
        assert_eq!(page.total_pages, 1);
    }

    #[tokio::test]
    async fn list_applies_requested_pagination() {
        let state = test_state();
        record_entries(&state, &["A", "B", "C", "D", "E"]).await;

        let mut query = params();
        query.page = Some(2);
        query.page_size = Some(2);

        let response = list_audit_events(State(state), Query(query))
            .await
            .unwrap()
            .0;

        let page = response.data.unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].action, "C");
        assert_eq!(page.page, 2);
        assert_eq!(page.page_size, 2);
        assert_eq!(page.total_items, 5);
        assert_eq!(page.total_pages, 3);
    }

    #[tokio::test]
    async fn list_caps_page_size() {
        let state = test_state();
        record_entries(&state, &["A"; 3]).await;

        let mut query = params();
        query.page_size = Some(10_000);

        let response = list_audit_events(State(state), Query(query))
            .await
            .unwrap()
            .0;

        let page = response.data.unwrap();
        assert_eq!(page.page_size, MAX_PAGE_SIZE);
    }

    #[tokio::test]
    async fn sqlite_list_filters_by_action_actor_and_severity() {
        let state = sqlite_state().await;
        record_entries(&state, &["LOGIN", "READ", "UPDATE"]).await;
        state
            .audit
            .record(AuditEntryParams::system(
                AuditSeverity::Warning,
                "READ",
                "test-resource",
                "SUCCESS",
            ))
            .await
            .unwrap();

        let mut by_action = params();
        by_action.action = Some("LOGIN".into());
        let page = list_audit_events(State(state.clone()), Query(by_action))
            .await
            .unwrap()
            .0
            .data
            .unwrap();
        assert_eq!(page.total_items, 1);
        assert_eq!(page.items[0].action, "LOGIN");

        let mut by_severity = params();
        by_severity.severity = Some("WARNING".into());
        let page = list_audit_events(State(state.clone()), Query(by_severity))
            .await
            .unwrap()
            .0
            .data
            .unwrap();
        assert_eq!(page.total_items, 1);
        assert_eq!(page.items[0].severity, AuditSeverity::Warning);

        let mut by_actor = params();
        by_actor.actor = Some("system".into());
        let page = list_audit_events(State(state.clone()), Query(by_actor))
            .await
            .unwrap()
            .0
            .data
            .unwrap();
        assert_eq!(page.total_items, 4);
    }

    #[tokio::test]
    async fn sqlite_list_filters_by_date_range() {
        let state = sqlite_state().await;
        record_entries(&state, &["A", "B"]).await;

        let mut in_range = params();
        in_range.start = Some("2000-01-01T00:00:00Z".into());
        in_range.end = Some("2999-01-01T00:00:00Z".into());
        let page = list_audit_events(State(state.clone()), Query(in_range))
            .await
            .unwrap()
            .0
            .data
            .unwrap();
        assert_eq!(page.total_items, 2);

        let mut after_range = params();
        after_range.start = Some("3000-01-01T00:00:00Z".into());
        let page = list_audit_events(State(state.clone()), Query(after_range))
            .await
            .unwrap()
            .0
            .data
            .unwrap();
        assert_eq!(page.total_items, 0);
    }

    #[tokio::test]
    async fn verify_chain_reports_intact_chain() {
        let state = test_state();
        record_entries(&state, &["A", "B"]).await;

        let response = verify_chain(State(state)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body["success"], true);
        assert_eq!(body["data"]["verified"], true);
        assert_eq!(body["data"]["total_entries"], 2);
        assert!(body["data"].get("broken_entry_id").is_none());
    }

    async fn append_rogue_entry(state: &AppState) {
        let mut rogue_logger = AuditLogger::new(Some("wrong_hash".into()), 2);
        let rogue = rogue_logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Critical,
            actor: "attacker",
            action: "DELETE",
            resource: "evidence",
            source_ip: "10.0.0.99",
            user_agent: None,
            result: "SUCCESS",
        });
        state.audit_repo.append(rogue).await.unwrap();
    }

    #[tokio::test]
    async fn verify_chain_returns_409_for_broken_chain() {
        let state = test_state();
        record_entries(&state, &["A"]).await;
        append_rogue_entry(&state).await;

        let response = verify_chain(State(state)).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body["verified"], false);
        assert_eq!(body["total_entries"], 2);
        assert_eq!(body["broken_entry_id"], 2);
        assert!(body["reason"].as_str().unwrap().contains("broken"));
    }

    #[tokio::test]
    async fn sqlite_verify_chain_returns_409_for_broken_chain() {
        let state = sqlite_state().await;
        record_entries(&state, &["A"]).await;
        append_rogue_entry(&state).await;

        let response = verify_chain(State(state)).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body["verified"], false);
        assert_eq!(body["broken_entry_id"], 2);
    }

    #[tokio::test]
    async fn verify_chain_on_empty_log_is_verified() {
        let state = test_state();

        let response = verify_chain(State(state)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body["data"]["verified"], true);
        assert_eq!(body["data"]["total_entries"], 0);
    }

    #[tokio::test]
    async fn export_defaults_to_csv_attachment() {
        let state = test_state();
        record_entries(&state, &["LOGIN"]).await;

        let response = export_audit_log(State(state), Query(params()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(headers[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/csv"));
        assert!(headers[CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment; filename=\"audit-log-"));

        let csv = body_string(response).await;
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "id,timestamp,severity,actor,action,resource,source_ip,user_agent,result,previous_hash,entry_hash"
        );
        assert!(lines[1].contains(",system,LOGIN,"));
    }

    #[tokio::test]
    async fn export_json_returns_json_attachment() {
        let state = test_state();
        record_entries(&state, &["LOGIN"]).await;

        let mut query = params();
        query.format = Some("json".into());

        let response = export_audit_log(State(state), Query(query)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");

        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["action"], "LOGIN");
    }

    #[tokio::test]
    async fn export_rejects_unsupported_format() {
        let state = test_state();

        let mut query = params();
        query.format = Some("pdf".into());

        let err = export_audit_log(State(state), Query(query))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn sqlite_export_respects_filters() {
        let state = sqlite_state().await;
        record_entries(&state, &["LOGIN", "READ"]).await;

        let mut query = params();
        query.action = Some("READ".into());
        query.format = Some("json".into());

        let response = export_audit_log(State(state), Query(query)).await.unwrap();

        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["action"], "READ");
    }

    #[test]
    fn broken_entry_id_parses_broken_chain_message() {
        let err =
            AppError::Internal("chain verification failed: hash chain broken at entry 7".into());
        assert_eq!(broken_entry_id_from(&err), Some(7));
    }

    #[test]
    fn broken_entry_id_parses_tampered_entry_message() {
        let err =
            AppError::Internal("chain verification failed: entry 12 has been tampered with".into());
        assert_eq!(broken_entry_id_from(&err), Some(12));
    }

    #[test]
    fn broken_entry_id_returns_none_without_digits() {
        let err = AppError::Internal("chain verification failed".into());
        assert_eq!(broken_entry_id_from(&err), None);
    }

    #[test]
    fn csv_fields_with_special_characters_are_quoted() {
        assert_eq!(quote_csv_field("plain"), "plain");
        assert_eq!(quote_csv_field("a,b"), "\"a,b\"");
        assert_eq!(quote_csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_rows_quote_user_agent_with_commas() {
        let mut logger = AuditLogger::new(None, 1);
        let entry = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "system",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: Some("Mozilla/5.0 (X11, Linux)"),
            result: "SUCCESS",
        });

        let row = entry_to_csv_row(&entry);
        assert!(row.contains("\"Mozilla/5.0 (X11, Linux)\""));
    }

    #[tokio::test]
    async fn in_memory_and_sqlite_states_both_record() {
        let memory_state = test_state();
        record_entries(&memory_state, &["A"]).await;
        assert_eq!(
            memory_state
                .audit_repo
                .query(&AuditFilter::default())
                .await
                .unwrap()
                .len(),
            1
        );

        let sqlite_state = sqlite_state().await;
        record_entries(&sqlite_state, &["A"]).await;
        assert_eq!(
            sqlite_state
                .audit_repo
                .query(&AuditFilter::default())
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
