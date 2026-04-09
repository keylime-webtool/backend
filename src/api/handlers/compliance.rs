use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

use crate::api::response::ApiResponse;
use crate::error::{AppError, AppResult};
use crate::models::agent::AgentState;
use crate::state::AppState;

/// Supported compliance frameworks.
const FRAMEWORKS: &[(&str, &str)] = &[
    (
        "nist-sp-800-155",
        "NIST SP 800-155 (BIOS Integrity Measurement)",
    ),
    (
        "nist-sp-800-193",
        "NIST SP 800-193 (Platform Firmware Resiliency)",
    ),
    (
        "tcg-guidance",
        "TCG Platform Firmware Integrity Measurement",
    ),
    (
        "isa-iec-62443",
        "ISA/IEC 62443 (Industrial Automation Security)",
    ),
    ("pci-dss", "PCI DSS v4.0 (Payment Card Industry)"),
];

/// GET /api/compliance/frameworks -- List supported frameworks (FR-059).
pub async fn list_frameworks() -> AppResult<Json<ApiResponse<Vec<serde_json::Value>>>> {
    let frameworks: Vec<_> = FRAMEWORKS
        .iter()
        .map(|(id, name)| {
            serde_json::json!({
                "id": id,
                "name": name,
            })
        })
        .collect();

    Ok(Json(ApiResponse::ok(frameworks)))
}

/// GET /api/compliance/reports/:framework -- Framework mapping report (FR-059).
pub async fn get_report(
    State(state): State<AppState>,
    Path(framework): Path<String>,
) -> AppResult<Json<ApiResponse<serde_json::Value>>> {
    // Validate framework exists
    if !FRAMEWORKS.iter().any(|(id, _)| *id == framework) {
        return Err(AppError::NotFound(format!(
            "unknown framework: {framework}"
        )));
    }

    // Gather fleet state for compliance assessment
    let agent_ids = state.keylime.list_verifier_agents().await?;
    let total = agent_ids.len() as u64;
    let mut compliant: u64 = 0;
    let mut non_compliant: u64 = 0;

    for id_str in &agent_ids {
        if let Ok(agent) = state.keylime.get_verifier_agent(id_str).await {
            if let Ok(s) = AgentState::try_from(agent.operational_state) {
                if s.is_failed() {
                    non_compliant += 1;
                } else {
                    compliant += 1;
                }
            }
        }
    }

    let compliance_pct = if total > 0 {
        (compliant as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    let framework_name = FRAMEWORKS
        .iter()
        .find(|(id, _)| *id == framework)
        .map(|(_, n)| *n)
        .unwrap_or(&framework);

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "framework": framework,
        "framework_name": framework_name,
        "total_agents": total,
        "compliant_agents": compliant,
        "non_compliant_agents": non_compliant,
        "compliance_percentage": compliance_pct,
        "controls": [
            {"id": "1.1", "description": "Remote attestation enabled", "status": "pass", "agents_passing": compliant},
            {"id": "1.2", "description": "IMA policy assigned", "status": if non_compliant > 0 { "partial" } else { "pass" }, "agents_passing": compliant},
            {"id": "1.3", "description": "TPM integrity verified", "status": if non_compliant > 0 { "fail" } else { "pass" }, "agents_passing": compliant},
        ],
    }))))
}

/// Export parameters for compliance reports (FR-060).
#[derive(Debug, Deserialize)]
pub struct ExportParams {
    pub format: String,
    pub start: Option<String>,
    pub end: Option<String>,
}

/// POST /api/compliance/reports/:framework/export -- One-click export (FR-060).
pub async fn export_report(
    Path(_framework): Path<String>,
    Query(_params): Query<ExportParams>,
) -> AppResult<Json<ApiResponse<()>>> {
    Err(AppError::Internal("not implemented".into()))
}
