use serde::{Deserialize, Serialize};

/// Agent list results from Verifier/Registrar `GET /v2/agents/`.
#[derive(Debug, Deserialize)]
pub struct AgentListResults {
    pub uuids: Vec<String>,
}

/// Raw agent data as returned by the Keylime Verifier v2 API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierAgent {
    pub agent_id: String,
    pub ip: String,
    pub port: u16,
    pub operational_state: i32,
    pub v: Option<String>,
    pub tpm_policy: Option<String>,
    pub ima_policy: Option<String>,
    pub mb_policy: Option<String>,
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub ima_pcrs: Vec<u8>,
    pub accept_tpm_hash_algs: Vec<String>,
    pub accept_tpm_encryption_algs: Vec<String>,
    pub accept_tpm_signing_algs: Vec<String>,
}

/// Raw agent data from the Keylime Registrar API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrarAgent {
    pub agent_id: String,
    pub ek_tpm: String,
    pub aik_tpm: String,
    pub ip: String,
    pub port: u16,
    pub regcount: u32,
}

/// Verifier API response wrapper.
#[derive(Debug, Deserialize)]
pub struct VerifierResponse<T> {
    pub code: i32,
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
    pub name: String,
    pub tpm_policy: Option<serde_json::Value>,
    pub runtime_policy: Option<serde_json::Value>,
    pub runtime_policy_key: Option<String>,
}

/// PCR values response from Verifier API (FR-021/022).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrResults {
    pub hash_alg: String,
    pub pcrs: std::collections::HashMap<String, String>,
}

/// A single IMA log entry (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaLogEntry {
    pub pcr: u8,
    pub template_hash: String,
    pub template_name: String,
    pub filedata_hash: String,
    pub filename: String,
}

/// IMA log response from Verifier API (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaLogResults {
    pub entries: Vec<ImaLogEntry>,
}

/// A single measured boot log event (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootLogEntry {
    pub pcr: u8,
    pub event_type: String,
    pub digest: String,
    pub event_data: String,
}

/// Boot log response from Verifier API (FR-020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootLogResults {
    pub entries: Vec<BootLogEntry>,
}
