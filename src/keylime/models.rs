use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Agent list results from Verifier/Registrar `GET /v2/agents/`.
///
/// The Keylime API returns `uuids` as a nested array: `[["uuid1"], ["uuid2"]]`.
#[derive(Debug, Deserialize)]
pub struct AgentListResults {
    #[serde(default)]
    pub uuids: Vec<Vec<String>>,
}

/// Raw agent data as returned by the Keylime Verifier v2 API.
///
/// The real Keylime response nests agent data under the UUID key inside
/// `results`, so callers parse `results` as a `HashMap<String, VerifierAgent>`
/// and extract the entry.  All fields use `#[serde(default)]` because the
/// exact set of fields varies across Keylime versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierAgent {
    /// Populated by the caller from the map key — not in the JSON body.
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Can be an integer (e.g. 1) or a string (e.g. "Start") depending
    /// on the Keylime version.  Use `VerifierAgent::parse_state()` to convert.
    #[serde(default)]
    pub operational_state: serde_json::Value,
    #[serde(default)]
    pub v: Option<String>,
    #[serde(default)]
    pub tpm_policy: Option<String>,
    #[serde(default)]
    pub meta_data: Option<String>,
    #[serde(default)]
    pub has_mb_refstate: Option<i32>,
    #[serde(default)]
    pub has_runtime_policy: Option<i32>,
    // Legacy fields — present in some Keylime versions
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
    #[serde(default)]
    pub verifier_id: Option<String>,
    #[serde(default)]
    pub verifier_ip: Option<String>,
    #[serde(default)]
    pub verifier_port: Option<u16>,
    #[serde(default)]
    pub severity_level: Option<serde_json::Value>,
    #[serde(default)]
    pub last_event_id: Option<serde_json::Value>,
    #[serde(default)]
    pub attestation_count: Option<u64>,
    #[serde(default)]
    pub last_received_quote: Option<u64>,
    #[serde(default)]
    pub last_successful_attestation: Option<u64>,
    #[serde(default)]
    pub attestation_status: Option<String>,
    // Push-mode specific fields (present only for push agents)
    #[serde(default)]
    pub accept_attestations: Option<bool>,
    #[serde(default)]
    pub consecutive_attestation_failures: Option<u32>,
    #[serde(default)]
    pub attestation_period: Option<String>,
    #[serde(default)]
    pub maximum_attestation_interval: Option<String>,
}

impl VerifierAgent {
    /// Detect whether this agent is running in push mode.
    ///
    /// Handles multiple Keylime versions:
    /// - Explicit `accept_attestations` field (some versions/Mockoon)
    /// - Real Keylime push agents: `ip`/`port` are null and
    ///   `attestation_count` is tracked
    pub fn is_push_mode(&self) -> bool {
        // Explicit push flag (present in some Keylime versions)
        if self.accept_attestations.is_some() {
            return true;
        }
        // Real Keylime push agents have no ip/port (agent pushes to
        // verifier) and report attestation_count.
        self.ip.is_none() && self.port.is_none() && self.attestation_count.is_some()
    }

    /// Resolve the agent's IP with fallback: `ip` → `verifier_ip` → registrar ip → `""`.
    pub fn resolve_ip(&self, registrar: Option<&RegistrarAgent>) -> String {
        self.ip
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| self.verifier_ip.clone().filter(|s| !s.is_empty()))
            .or_else(|| registrar.and_then(|r| r.ip.clone().filter(|s| !s.is_empty())))
            .unwrap_or_default()
    }

    /// Resolve the agent's port with fallback: `port` → registrar port → `0`.
    pub fn resolve_port(&self, registrar: Option<&RegistrarAgent>) -> u16 {
        self.port
            .filter(|&p| p != 0)
            .or_else(|| registrar.and_then(|r| r.port.filter(|&p| p != 0)))
            .unwrap_or_default()
    }

    /// Parse `operational_state` from the Keylime JSON — handles both
    /// integer values (older versions) and string names (newer versions).
    pub fn parse_state_str(&self) -> String {
        match &self.operational_state {
            serde_json::Value::Number(n) => {
                let i = n.as_i64().unwrap_or(-1) as i32;
                match i {
                    0 => "Registered",
                    1 => "Start",
                    2 => "Saved",
                    3 => "GetQuote",
                    4 => "Retry",
                    5 => "ProvideV",
                    7 => "Failed",
                    8 => "Terminated",
                    9 => "InvalidQuote",
                    10 => "TenantFailed",
                    _ => "Unknown",
                }
                .to_string()
            }
            serde_json::Value::String(s) => s.clone(),
            _ => "Unknown".to_string(),
        }
    }
}

/// Raw agent data from the Keylime Registrar API.
///
/// Like VerifierAgent, the Registrar nests agent data under the UUID key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrarAgent {
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub ek_tpm: String,
    #[serde(default)]
    pub aik_tpm: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub regcount: u32,
    #[serde(default)]
    pub mtls_cert: Option<String>,
    #[serde(default)]
    pub ekcert: Option<String>,
    #[serde(default)]
    pub operational_state: Option<String>,
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
    pub pcrs: HashMap<String, String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn default_verifier() -> VerifierAgent {
        serde_json::from_value(serde_json::json!({})).unwrap()
    }

    fn registrar_with(ip: Option<&str>, port: Option<u16>) -> RegistrarAgent {
        RegistrarAgent {
            ip: ip.map(String::from),
            port,
            ..serde_json::from_value(serde_json::json!({})).unwrap()
        }
    }

    #[test]
    fn resolve_ip_prefers_verifier_ip() {
        let agent = VerifierAgent {
            ip: Some("10.0.0.1".into()),
            verifier_ip: Some("10.0.0.2".into()),
            ..default_verifier()
        };
        let reg = registrar_with(Some("10.0.0.3"), None);
        assert_eq!(agent.resolve_ip(Some(&reg)), "10.0.0.1");
    }

    #[test]
    fn resolve_ip_falls_back_to_verifier_ip() {
        let agent = VerifierAgent {
            verifier_ip: Some("10.0.0.2".into()),
            ..default_verifier()
        };
        assert_eq!(agent.resolve_ip(None), "10.0.0.2");
    }

    #[test]
    fn resolve_ip_falls_back_to_registrar() {
        let agent = default_verifier();
        let reg = registrar_with(Some("127.0.0.1"), None);
        assert_eq!(agent.resolve_ip(Some(&reg)), "127.0.0.1");
    }

    #[test]
    fn resolve_ip_returns_empty_when_all_none() {
        let agent = default_verifier();
        assert_eq!(agent.resolve_ip(None), "");
    }

    #[test]
    fn resolve_ip_skips_empty_strings() {
        let agent = VerifierAgent {
            ip: Some("".into()),
            verifier_ip: Some("".into()),
            ..default_verifier()
        };
        let reg = registrar_with(Some("10.0.0.5"), None);
        assert_eq!(agent.resolve_ip(Some(&reg)), "10.0.0.5");
    }

    #[test]
    fn resolve_port_prefers_verifier() {
        let agent = VerifierAgent {
            port: Some(9002),
            ..default_verifier()
        };
        let reg = registrar_with(None, Some(9003));
        assert_eq!(agent.resolve_port(Some(&reg)), 9002);
    }

    #[test]
    fn resolve_port_falls_back_to_registrar() {
        let agent = default_verifier();
        let reg = registrar_with(None, Some(9003));
        assert_eq!(agent.resolve_port(Some(&reg)), 9003);
    }

    #[test]
    fn resolve_port_skips_zero() {
        let agent = VerifierAgent {
            port: Some(0),
            ..default_verifier()
        };
        let reg = registrar_with(None, Some(9003));
        assert_eq!(agent.resolve_port(Some(&reg)), 9003);
    }

    #[test]
    fn resolve_port_returns_zero_when_all_none() {
        let agent = default_verifier();
        assert_eq!(agent.resolve_port(None), 0);
    }
}
