//! Integration tests using Mockoon to simulate Keylime Verifier and Registrar APIs.
//!
//! These tests require:
//! - `cargo test --features testing` to compile
//! - `MOCKOON_VERIFIER=1` env var (Verifier mock on port 3000)
//! - `MOCKOON_REGISTRAR=1` env var (Registrar mock on port 3001)
//!
//! Run via: `bash tests/mockoon_tests.sh`

#![cfg(feature = "mockoon")]

use std::collections::HashMap;

use keylime_webtool_backend::keylime::models::{
    RegistrarAgent, RuntimePolicy, VerifierAgent, VerifierResponse,
};

const VERIFIER_BASE: &str = "http://localhost:3000";
const REGISTRAR_BASE: &str = "http://localhost:3001";

// ---------------------------------------------------------------------------
// Verifier tests (port 3000)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mockoon_verifier_list_agents() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{VERIFIER_BASE}/v2/agents/"))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], 200);
    assert_eq!(body["status"], "Success");

    let uuids = body["results"]["uuids"].as_array().unwrap();
    assert_eq!(uuids.len(), 7);
    // Real Keylime API returns nested arrays: [["uuid1"], ["uuid2"], ...]
    assert!(uuids
        .iter()
        .any(|u| u[0] == "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"));
    assert!(uuids
        .iter()
        .any(|u| u[0] == "a1b2c3d4-0000-1111-2222-333344445555"));
    assert!(uuids
        .iter()
        .any(|u| u[0] == "f7e6d5c4-b3a2-9180-7654-321098765432"));
    assert!(uuids
        .iter()
        .any(|u| u[0] == "b2c3d4e5-a1b0-8765-4321-fedcba987654"));
    assert!(uuids
        .iter()
        .any(|u| u[0] == "c5d6e7f8-a9b0-4321-8765-abcdef012345"));
    assert!(uuids
        .iter()
        .any(|u| u[0] == "e6f7a8b9-c0d1-2345-6789-aabbccddeeff"));
    assert!(uuids
        .iter()
        .any(|u| u[0] == "d1e2f3a4-b5c6-7890-1234-567890abcdef"));
}

#[tokio::test]
async fn test_mockoon_verifier_healthy_agent() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    assert_eq!(resp.status(), 200);

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    assert_eq!(body.code, 200);
    let agent_id = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.10".to_string()));
    assert_eq!(agent.port, Some(9002));
    // operational_state 3 = GET_QUOTE (healthy)
    assert_eq!(agent.operational_state, serde_json::json!(3));
    assert_eq!(agent.hash_alg, "sha256");
    assert_eq!(agent.ima_policy.as_deref(), Some("production-v1"));
    assert!(agent.mb_policy.is_none());
}

#[tokio::test]
async fn test_mockoon_verifier_failed_agent() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/a1b2c3d4-0000-1111-2222-333344445555"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    let agent_id = "a1b2c3d4-0000-1111-2222-333344445555";
    let agent = body.results.get(agent_id).expect("agent not in results");
    // operational_state 7 = FAILED
    assert_eq!(agent.operational_state, serde_json::json!(7));
    assert_eq!(agent.ip, Some("10.0.1.20".to_string()));
}

#[tokio::test]
async fn test_mockoon_verifier_push_mode_agent() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/f7e6d5c4-b3a2-9180-7654-321098765432"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    let agent_id = "f7e6d5c4-b3a2-9180-7654-321098765432";
    let agent = body.results.get(agent_id).expect("agent not in results");
    // Push-mode agent: operational_state 5 = PROVIDE_V, but has push-specific fields
    assert_eq!(agent.operational_state, serde_json::json!(5));
    assert_eq!(agent.hash_alg, "sha384");
    assert_eq!(agent.ima_policy.as_deref(), Some("staging-v2"));
    assert_eq!(agent.mb_policy.as_deref(), Some("measured-boot-v1"));
    assert!(agent.ima_pcrs.contains(&10));
    assert!(agent.ima_pcrs.contains(&14));
    // Push-specific fields: healthy push agent
    assert_eq!(agent.accept_attestations, Some(true));
    assert_eq!(agent.attestation_count, Some(42));
    assert_eq!(agent.consecutive_attestation_failures, Some(0));
}

#[tokio::test]
async fn test_mockoon_verifier_push_mode_failed_agent() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/b2c3d4e5-a1b0-8765-4321-fedcba987654"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    let agent_id = "b2c3d4e5-a1b0-8765-4321-fedcba987654";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.40".to_string()));
    // Push-specific fields: failed push agent (timeout + consecutive failures)
    assert_eq!(agent.accept_attestations, Some(false));
    assert_eq!(agent.attestation_count, Some(15));
    assert_eq!(agent.consecutive_attestation_failures, Some(3));
}

#[tokio::test]
async fn test_mockoon_verifier_push_mode_ok_agent_2() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/c5d6e7f8-a9b0-4321-8765-abcdef012345"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    let agent_id = "c5d6e7f8-a9b0-4321-8765-abcdef012345";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.50".to_string()));
    assert_eq!(agent.operational_state, serde_json::json!(5));
    assert_eq!(agent.hash_alg, "sha256");
    assert_eq!(agent.ima_policy.as_deref(), Some("production-v1"));
    assert!(agent.mb_policy.is_none());
    // Push-specific fields: healthy push agent
    assert_eq!(agent.accept_attestations, Some(true));
    assert_eq!(agent.attestation_count, Some(78));
    assert_eq!(agent.consecutive_attestation_failures, Some(0));
}

#[tokio::test]
async fn test_mockoon_verifier_agent_not_found() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/00000000-0000-0000-0000-000000000000"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_mockoon_verifier_list_policies() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{VERIFIER_BASE}/v2/allowlists/"))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let names = body["results"]["runtimepolicy names"].as_array().unwrap();
    assert_eq!(names.len(), 2);
    assert!(names.iter().any(|n| n == "production-v1"));
    assert!(names.iter().any(|n| n == "staging-v2"));

    // MB policies are served from a separate endpoint
    let resp = client
        .get(format!("{VERIFIER_BASE}/v2/mbpolicies/"))
        .send()
        .await
        .expect("Failed to reach Verifier mock mbpolicies");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let mb_names = body["results"]["mbpolicy names"].as_array().unwrap();
    assert_eq!(mb_names.len(), 1);
    assert!(mb_names.iter().any(|n| n == "measured-boot-v1"));
}

#[tokio::test]
async fn test_mockoon_verifier_get_policy() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{VERIFIER_BASE}/v2/allowlists/production-v1"))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    assert_eq!(resp.status(), 200);

    let body: VerifierResponse<RuntimePolicy> = resp.json().await.unwrap();
    assert_eq!(body.results.name, "production-v1");
    assert!(body.results.tpm_policy.is_some());
    assert!(body.results.runtime_policy.is_some());
}

// ---------------------------------------------------------------------------
// Registrar tests (port 3001)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mockoon_registrar_version() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{REGISTRAR_BASE}/version"))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["results"]["current_version"], "2.1");
    let versions = body["results"]["supported_versions"].as_array().unwrap();
    assert!(versions.iter().any(|v| v == "2.0"));
    assert!(versions.iter().any(|v| v == "2.1"));
}

#[tokio::test]
async fn test_mockoon_registrar_list_agents() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{REGISTRAR_BASE}/v2/agents/"))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let uuids = body["results"]["uuids"].as_array().unwrap();
    assert_eq!(uuids.len(), 6);
}

#[tokio::test]
async fn test_mockoon_registrar_agent_detail() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    assert_eq!(resp.status(), 200);

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent_id = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.10".to_string()));
    assert_eq!(agent.port, Some(9002));
    assert_eq!(agent.regcount, 1);
    assert!(!agent.ek_tpm.is_empty());
    assert!(!agent.aik_tpm.is_empty());

    // FR-050: Healthy agent should have ekcert (X.509) and mtls_cert
    assert!(
        agent.ekcert.as_ref().is_some_and(|s| !s.is_empty()),
        "healthy agent should have an ekcert field"
    );
    assert!(
        agent.mtls_cert.as_ref().is_some_and(|s| !s.is_empty()),
        "healthy agent should have an mtls_cert field"
    );
}

#[tokio::test]
async fn test_mockoon_registrar_failed_agent_detail() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/a1b2c3d4-0000-1111-2222-333344445555"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent_id = "a1b2c3d4-0000-1111-2222-333344445555";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.20".to_string()));
    // Failed agent has higher regcount (re-registered multiple times)
    assert_eq!(agent.regcount, 3);
}

#[tokio::test]
async fn test_mockoon_registrar_push_agent_detail() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/f7e6d5c4-b3a2-9180-7654-321098765432"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent_id = "f7e6d5c4-b3a2-9180-7654-321098765432";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.30".to_string()));
    assert_eq!(agent.regcount, 1);
}

#[tokio::test]
async fn test_mockoon_registrar_push_failed_agent_detail() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/b2c3d4e5-a1b0-8765-4321-fedcba987654"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent_id = "b2c3d4e5-a1b0-8765-4321-fedcba987654";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.40".to_string()));
    assert_eq!(agent.regcount, 2);
}

#[tokio::test]
async fn test_mockoon_registrar_push_ok_agent_2_detail() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/c5d6e7f8-a9b0-4321-8765-abcdef012345"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent_id = "c5d6e7f8-a9b0-4321-8765-abcdef012345";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.50".to_string()));
    assert_eq!(agent.regcount, 1);
}

// ---------------------------------------------------------------------------
// Push-mode agent that stopped attesting — exercises Timeout state detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mockoon_verifier_push_timeout_agent() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/d1e2f3a4-b5c6-7890-1234-567890abcdef"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    let agent_id = "d1e2f3a4-b5c6-7890-1234-567890abcdef";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.60".to_string()));
    assert_eq!(agent.port, Some(9002));
    assert_eq!(agent.accept_attestations, Some(true));
    assert_eq!(agent.attestation_count, Some(25));
    assert_eq!(agent.last_successful_attestation, Some(1700000000));
    assert_eq!(agent.maximum_attestation_interval, Some("60".to_string()));
    assert_eq!(agent.consecutive_attestation_failures, Some(0));
}

// ---------------------------------------------------------------------------
// Push-mode agent with null ip/port — exercises registrar IP fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mockoon_verifier_push_null_ip_agent() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{VERIFIER_BASE}/v2/agents/e6f7a8b9-c0d1-2345-6789-aabbccddeeff"
        ))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    let agent_id = "e6f7a8b9-c0d1-2345-6789-aabbccddeeff";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(
        agent.ip, None,
        "verifier should return null ip for this push agent"
    );
    assert_eq!(
        agent.port, None,
        "verifier should return null port for this push agent"
    );
    assert_eq!(
        agent.verifier_ip,
        Some("127.0.0.1".to_string()),
        "verifier_ip should be populated for push agents"
    );
    assert_eq!(
        agent.verifier_port,
        Some(8881),
        "verifier_port should be populated for push agents"
    );
    assert_eq!(agent.accept_attestations, Some(true));
    assert_eq!(agent.attestation_count, Some(5));
}

#[tokio::test]
async fn test_mockoon_verifier_push_timeout_state_computation() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();
    let agent_id = "d1e2f3a4-b5c6-7890-1234-567890abcdef";
    let resp = client
        .get(format!("{VERIFIER_BASE}/v2/agents/{agent_id}"))
        .send()
        .await
        .expect("Failed to reach Verifier mock");

    let body: VerifierResponse<HashMap<String, VerifierAgent>> = resp.json().await.unwrap();
    let agent = body.results.get(agent_id).expect("agent not in results");

    let state = keylime_webtool_backend::models::agent::AgentState::from_push_agent(agent);
    assert_eq!(
        state,
        keylime_webtool_backend::models::agent::AgentState::Timeout,
        "agent with stale last_successful_attestation should compute as Timeout"
    );

    let serialized = serde_json::to_string(&state).unwrap();
    assert_eq!(serialized, "\"TIMEOUT\"");
}

#[tokio::test]
async fn test_mockoon_timeout_state_filter_excludes_other_states() {
    if std::env::var("MOCKOON_VERIFIER").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER not set");
        return;
    }

    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{VERIFIER_BASE}/v2/agents/"))
        .send()
        .await
        .expect("Failed to reach Verifier mock");
    let body: serde_json::Value = resp.json().await.unwrap();
    let uuids = body["results"]["uuids"].as_array().unwrap();

    let mut timeout_agents = Vec::new();
    let mut non_timeout_agents = Vec::new();

    for entry in uuids {
        let id = entry[0].as_str().unwrap();
        let resp = client
            .get(format!("{VERIFIER_BASE}/v2/agents/{id}"))
            .send()
            .await
            .unwrap();
        if resp.status() != 200 {
            continue;
        }
        let agent_body: VerifierResponse<HashMap<String, VerifierAgent>> =
            resp.json().await.unwrap();
        let agent = match agent_body.results.values().next() {
            Some(a) => a.clone(),
            None => continue,
        };

        let state = if agent.is_push_mode() {
            keylime_webtool_backend::models::agent::AgentState::from_push_agent(&agent)
        } else {
            keylime_webtool_backend::models::agent::AgentState::from_operational_state(
                &agent.operational_state,
            )
            .unwrap()
        };

        let state_str = serde_json::to_string(&state).unwrap();
        let state_str = state_str.trim_matches('"').to_string();

        if state_str == "TIMEOUT" {
            timeout_agents.push(id.to_string());
        } else {
            non_timeout_agents.push((id.to_string(), state_str));
        }
    }

    assert!(
        !timeout_agents.is_empty(),
        "mock fleet should contain at least one TIMEOUT agent"
    );
    assert!(
        !non_timeout_agents.is_empty(),
        "mock fleet should contain agents in non-TIMEOUT states"
    );

    for (id, state_str) in &non_timeout_agents {
        assert_ne!(
            state_str, "TIMEOUT",
            "agent {id} should not be in TIMEOUT state"
        );
    }
}

#[tokio::test]
async fn test_mockoon_registrar_push_null_ip_agent_detail() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/e6f7a8b9-c0d1-2345-6789-aabbccddeeff"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent_id = "e6f7a8b9-c0d1-2345-6789-aabbccddeeff";
    let agent = body.results.get(agent_id).expect("agent not in results");
    assert_eq!(agent.ip, Some("10.0.1.60".to_string()));
    assert_eq!(agent.port, Some(9002));
    assert_eq!(agent.regcount, 1);
}

#[tokio::test]
async fn test_mockoon_resolve_ip_falls_back_to_registrar() {
    if std::env::var("MOCKOON_VERIFIER").is_err() || std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_VERIFIER and MOCKOON_REGISTRAR both required");
        return;
    }

    let client = reqwest::Client::new();
    let agent_id = "e6f7a8b9-c0d1-2345-6789-aabbccddeeff";

    let v_resp = client
        .get(format!("{VERIFIER_BASE}/v2/agents/{agent_id}"))
        .send()
        .await
        .expect("Failed to reach Verifier mock");
    let v_body: VerifierResponse<HashMap<String, VerifierAgent>> = v_resp.json().await.unwrap();
    let verifier_agent = v_body.results.get(agent_id).unwrap();

    let r_resp = client
        .get(format!("{REGISTRAR_BASE}/v2/agents/{agent_id}"))
        .send()
        .await
        .expect("Failed to reach Registrar mock");
    let r_body: VerifierResponse<HashMap<String, RegistrarAgent>> = r_resp.json().await.unwrap();
    let registrar_agent = r_body.results.get(agent_id).unwrap();

    // Registrar has the real agent ip/port; verifier_ip/verifier_port are
    // the verifier server's own address and must NOT be used.
    assert_eq!(
        verifier_agent.resolve_ip(Some(registrar_agent)),
        "10.0.1.60",
        "resolve_ip should fall back to registrar ip"
    );
    assert_eq!(
        verifier_agent.resolve_port(Some(registrar_agent)),
        9002,
        "resolve_port should fall back to registrar port"
    );

    // Without registrar, no ip/port available (verifier_ip/verifier_port are ignored)
    assert_eq!(
        verifier_agent.resolve_ip(None),
        "",
        "resolve_ip(None) should return empty when no registrar"
    );
    assert_eq!(
        verifier_agent.resolve_port(None),
        0,
        "resolve_port(None) should return 0 when no registrar"
    );
}

// ---------------------------------------------------------------------------
// Certificate parsing tests (FR-050/051/052)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mockoon_healthy_agent_ekcert_is_parseable_x509() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent = body
        .results
        .get("d432fbb3-d2f1-4a97-9ef7-75bd81c00000")
        .unwrap();

    let ekcert = agent.ekcert.as_deref().expect("ekcert should be present");
    let parsed = keylime_webtool_backend::keylime::cert_parser::try_parse_x509(ekcert);
    assert!(parsed.is_some(), "ekcert should parse as valid X.509");

    let info = parsed.unwrap();
    assert!(
        info.subject_dn.contains("Test EK Certificate"),
        "subject DN should contain 'Test EK Certificate', got: {}",
        info.subject_dn
    );
    assert!(
        info.issuer_dn.contains("TPM Manufacturer"),
        "issuer DN should contain 'TPM Manufacturer', got: {}",
        info.issuer_dn
    );
    assert!(!info.serial_number.is_empty());
    assert_eq!(info.public_key_algorithm, "RSA");
}

#[tokio::test]
async fn test_mockoon_healthy_agent_mtls_cert_is_parseable_x509() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent = body
        .results
        .get("d432fbb3-d2f1-4a97-9ef7-75bd81c00000")
        .unwrap();

    let mtls = agent
        .mtls_cert
        .as_deref()
        .expect("mtls_cert should be present");
    let parsed = keylime_webtool_backend::keylime::cert_parser::try_parse_x509(mtls);
    assert!(parsed.is_some(), "mtls_cert should parse as valid X.509");

    let info = parsed.unwrap();
    assert!(
        info.subject_dn.contains("agent-d432fbb3"),
        "subject DN should reference the agent, got: {}",
        info.subject_dn
    );
}

#[tokio::test]
async fn test_mockoon_ek_tpm_public_key_not_parseable_as_x509() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{REGISTRAR_BASE}/v2/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        ))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent = body
        .results
        .get("d432fbb3-d2f1-4a97-9ef7-75bd81c00000")
        .unwrap();

    // ek_tpm is a public key (not X.509) — should not parse as a certificate
    let parsed = keylime_webtool_backend::keylime::cert_parser::try_parse_x509(&agent.ek_tpm);
    assert!(
        parsed.is_none(),
        "bare public key should not parse as X.509"
    );
}

#[tokio::test]
async fn test_mockoon_failed_agent_has_expired_ekcert() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let agent_id = "a1b2c3d4-0000-1111-2222-333344445555";
    let resp = client
        .get(format!("{REGISTRAR_BASE}/v2/agents/{agent_id}"))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent = body.results.get(agent_id).unwrap();

    let ekcert = agent
        .ekcert
        .as_deref()
        .expect("failed agent should have ekcert");
    let parsed = keylime_webtool_backend::keylime::cert_parser::try_parse_x509(ekcert);
    assert!(parsed.is_some(), "ekcert should parse as valid X.509");

    let info = parsed.unwrap();
    assert!(
        info.subject_dn.contains("Expired EK Certificate"),
        "subject DN should contain 'Expired EK Certificate', got: {}",
        info.subject_dn
    );

    let now = chrono::Utc::now();
    let status = keylime_webtool_backend::keylime::cert_parser::compute_status(info.not_after, now);
    assert_eq!(
        status,
        keylime_webtool_backend::models::certificate::CertificateStatus::Expired,
        "failed agent's ekcert should be expired"
    );
}

#[tokio::test]
async fn test_mockoon_push_agent_has_warning_ekcert() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let client = reqwest::Client::new();
    let agent_id = "f7e6d5c4-b3a2-9180-7654-321098765432";
    let resp = client
        .get(format!("{REGISTRAR_BASE}/v2/agents/{agent_id}"))
        .send()
        .await
        .expect("Failed to reach Registrar mock");

    let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
    let agent = body.results.get(agent_id).unwrap();

    let ekcert = agent
        .ekcert
        .as_deref()
        .expect("push agent should have ekcert");
    let parsed = keylime_webtool_backend::keylime::cert_parser::try_parse_x509(ekcert);
    assert!(parsed.is_some(), "ekcert should parse as valid X.509");

    let info = parsed.unwrap();
    assert!(
        info.subject_dn.contains("Warning EK Certificate"),
        "subject DN should contain 'Warning EK Certificate', got: {}",
        info.subject_dn
    );

    let now = chrono::Utc::now();
    let category =
        keylime_webtool_backend::keylime::cert_parser::compute_expiry_category(info.not_after, now);
    assert!(
        matches!(
            category,
            keylime_webtool_backend::models::certificate::ExpiryCategory::Warning90d
                | keylime_webtool_backend::models::certificate::ExpiryCategory::Warning30d
        ),
        "push agent's ekcert should be in a warning category, got: {category:?}"
    );
}

#[tokio::test]
async fn test_mockoon_all_agents_have_ekcert() {
    if std::env::var("MOCKOON_REGISTRAR").is_err() {
        eprintln!("Skipping: MOCKOON_REGISTRAR not set");
        return;
    }

    let agent_ids = [
        "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
        "a1b2c3d4-0000-1111-2222-333344445555",
        "f7e6d5c4-b3a2-9180-7654-321098765432",
        "b2c3d4e5-a1b0-8765-4321-fedcba987654",
        "c5d6e7f8-a9b0-4321-8765-abcdef012345",
        "e6f7a8b9-c0d1-2345-6789-aabbccddeeff",
    ];

    let client = reqwest::Client::new();
    for agent_id in agent_ids {
        let resp = client
            .get(format!("{REGISTRAR_BASE}/v2/agents/{agent_id}"))
            .send()
            .await
            .expect("Failed to reach Registrar mock");

        let body: VerifierResponse<HashMap<String, RegistrarAgent>> = resp.json().await.unwrap();
        let agent = body.results.get(agent_id).unwrap();

        assert!(
            agent.ekcert.as_ref().is_some_and(|s| !s.is_empty()),
            "agent {agent_id} should have an ekcert"
        );
        let parsed = keylime_webtool_backend::keylime::cert_parser::try_parse_x509(
            agent.ekcert.as_deref().unwrap(),
        );
        assert!(
            parsed.is_some(),
            "agent {agent_id}'s ekcert should parse as X.509"
        );

        assert!(
            agent.mtls_cert.as_ref().is_some_and(|s| !s.is_empty()),
            "agent {agent_id} should have an mtls_cert"
        );
        let parsed = keylime_webtool_backend::keylime::cert_parser::try_parse_x509(
            agent.mtls_cert.as_deref().unwrap(),
        );
        assert!(
            parsed.is_some(),
            "agent {agent_id}'s mtls_cert should parse as X.509"
        );
    }
}
