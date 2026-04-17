use serde::{Deserialize, Serialize};

/// Agent list results from Verifier/Registrar `GET /v2/agents/`.
#[derive(Debug, Deserialize)]
pub struct AgentListResults {
    #[serde(default)]
    pub uuids: Vec<String>,
}

/// Raw agent data as returned by the Keylime Verifier v2 API.
///
/// Fields use `#[serde(default)]` because the exact set of fields varies
/// across Keylime versions — missing fields must not break deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierAgent {
    pub agent_id: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub operational_state: i32,
    #[serde(default)]
    pub v: Option<String>,
    #[serde(default)]
    pub tpm_policy: Option<String>,
    #[serde(default)]
    pub ima_policy: Option<String>,
    #[serde(default)]
    pub mb_policy: Option<String>,
    #[serde(default)]
    pub hash_alg: String,
    #[serde(default)]
    pub enc_alg: String,
    #[serde(default)]
    pub sign_alg: String,
    #[serde(default)]
    pub ima_pcrs: Vec<u8>,
    #[serde(default)]
    pub accept_tpm_hash_algs: Vec<String>,
    #[serde(default)]
    pub accept_tpm_encryption_algs: Vec<String>,
    #[serde(default)]
    pub accept_tpm_signing_algs: Vec<String>,
    // Push-mode specific fields (present only for push agents)
    #[serde(default)]
    pub accept_attestations: Option<bool>,
    #[serde(default)]
    pub attestation_count: Option<u64>,
    #[serde(default)]
    pub consecutive_attestation_failures: Option<u32>,
}

/// Raw agent data from the Keylime Registrar API.
///
/// All fields except `agent_id` use `#[serde(default)]` so that missing
/// or renamed fields in newer/older Keylime versions don't break parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrarAgent {
    pub agent_id: String,
    #[serde(default)]
    pub ek_tpm: String,
    #[serde(default)]
    pub aik_tpm: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub regcount: u32,
}

/// Verifier API response wrapper.
#[derive(Debug, Deserialize)]
pub struct VerifierResponse<T> {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub status: String,
    pub results: T,
}

/// Push-mode (v3) attestation evidence submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushEvidence {
    pub agent_id: String,
    pub nonce: String,
    pub quote: String,
    pub ima_log: Option<String>,
    pub boot_log: Option<String>,
}

/// Keylime runtime policy (allowlist) as stored in the Verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePolicy {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub tpm_policy: Option<serde_json::Value>,
    #[serde(default)]
    pub runtime_policy: Option<serde_json::Value>,
    #[serde(default)]
    pub runtime_policy_key: Option<String>,
}

/// PCR values response from Verifier API (FR-021/022).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrResults {
    #[serde(default)]
    pub hash_alg: String,
    #[serde(default)]
    pub pcrs: std::collections::HashMap<String, String>,
}

/// A single IMA log entry (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaLogEntry {
    #[serde(default)]
    pub pcr: u8,
    #[serde(default)]
    pub template_hash: String,
    #[serde(default)]
    pub template_name: String,
    #[serde(default)]
    pub filedata_hash: String,
    #[serde(default)]
    pub filename: String,
}

/// IMA log response from Verifier API (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaLogResults {
    #[serde(default)]
    pub entries: Vec<ImaLogEntry>,
}

/// A single measured boot log event (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootLogEntry {
    #[serde(default)]
    pub pcr: u8,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub event_data: String,
}

/// Boot log response from Verifier API (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootLogResults {
    #[serde(default)]
    pub entries: Vec<BootLogEntry>,
}
