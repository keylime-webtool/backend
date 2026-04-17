//! Integration tests using Mockoon to simulate Keylime Verifier and Registrar APIs.
//!
//! These tests require:
//! - `cargo test --features testing` to compile
//! - `MOCKOON_VERIFIER=1` env var (Verifier mock on port 3000)
//! - `MOCKOON_REGISTRAR=1` env var (Registrar mock on port 3001)
//!
//! Run via: `bash tests/mockoon_tests.sh`

#![cfg(feature = "mockoon")]

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
    assert_eq!(uuids.len(), 5);
    assert!(uuids
        .iter()
        .any(|u| u == "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"));
    assert!(uuids
        .iter()
        .any(|u| u == "a1b2c3d4-0000-1111-2222-333344445555"));
    assert!(uuids
        .iter()
        .any(|u| u == "f7e6d5c4-b3a2-9180-7654-321098765432"));
    assert!(uuids
        .iter()
        .any(|u| u == "b2c3d4e5-a1b0-8765-4321-fedcba987654"));
    assert!(uuids
        .iter()
        .any(|u| u == "c5d6e7f8-a9b0-4321-8765-abcdef012345"));
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

    let body: VerifierResponse<VerifierAgent> = resp.json().await.unwrap();
    assert_eq!(body.code, 200);
    assert_eq!(
        body.results.agent_id,
        "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
    );
    assert_eq!(body.results.ip, Some("10.0.1.10".to_string()));
    assert_eq!(body.results.port, Some(9002));
    // operational_state 3 = GET_QUOTE (healthy)
    assert_eq!(body.results.operational_state, serde_json::json!(3));
    assert_eq!(body.results.hash_alg, "sha256");
    assert_eq!(body.results.ima_policy.as_deref(), Some("production-v1"));
    assert!(body.results.mb_policy.is_none());
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

    let body: VerifierResponse<VerifierAgent> = resp.json().await.unwrap();
    // operational_state 7 = FAILED
    assert_eq!(body.results.operational_state, serde_json::json!(7));
    assert_eq!(body.results.ip, Some("10.0.1.20".to_string()));
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

    let body: VerifierResponse<VerifierAgent> = resp.json().await.unwrap();
    // Push-mode agent: operational_state 5 = PROVIDE_V, but has push-specific fields
    assert_eq!(body.results.operational_state, serde_json::json!(5));
    assert_eq!(body.results.hash_alg, "sha384");
    assert_eq!(body.results.ima_policy.as_deref(), Some("staging-v2"));
    assert_eq!(body.results.mb_policy.as_deref(), Some("measured-boot-v1"));
    assert!(body.results.ima_pcrs.contains(&10));
    assert!(body.results.ima_pcrs.contains(&14));
    // Push-specific fields: healthy push agent
    assert_eq!(body.results.accept_attestations, Some(true));
    assert_eq!(body.results.attestation_count, Some(42));
    assert_eq!(body.results.consecutive_attestation_failures, Some(0));
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

    let body: VerifierResponse<VerifierAgent> = resp.json().await.unwrap();
    assert_eq!(
        body.results.agent_id,
        "b2c3d4e5-a1b0-8765-4321-fedcba987654"
    );
    assert_eq!(body.results.ip, Some("10.0.1.40".to_string()));
    // Push-specific fields: failed push agent (timeout + consecutive failures)
    assert_eq!(body.results.accept_attestations, Some(false));
    assert_eq!(body.results.attestation_count, Some(15));
    assert_eq!(body.results.consecutive_attestation_failures, Some(3));
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

    let body: VerifierResponse<VerifierAgent> = resp.json().await.unwrap();
    assert_eq!(
        body.results.agent_id,
        "c5d6e7f8-a9b0-4321-8765-abcdef012345"
    );
    assert_eq!(body.results.ip, Some("10.0.1.50".to_string()));
    assert_eq!(body.results.operational_state, serde_json::json!(5));
    assert_eq!(body.results.hash_alg, "sha256");
    assert_eq!(body.results.ima_policy.as_deref(), Some("production-v1"));
    assert!(body.results.mb_policy.is_none());
    // Push-specific fields: healthy push agent
    assert_eq!(body.results.accept_attestations, Some(true));
    assert_eq!(body.results.attestation_count, Some(78));
    assert_eq!(body.results.consecutive_attestation_failures, Some(0));
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
    let names = body["results"]["policy_names"].as_array().unwrap();
    assert_eq!(names.len(), 3);
    assert!(names.iter().any(|n| n == "production-v1"));
    assert!(names.iter().any(|n| n == "staging-v2"));
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
    assert_eq!(uuids.len(), 5);
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

    let body: VerifierResponse<RegistrarAgent> = resp.json().await.unwrap();
    assert_eq!(
        body.results.agent_id,
        "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
    );
    assert_eq!(body.results.ip, Some("10.0.1.10".to_string()));
    assert_eq!(body.results.port, Some(9002));
    assert_eq!(body.results.regcount, 1);
    assert!(!body.results.ek_tpm.is_empty());
    assert!(!body.results.aik_tpm.is_empty());
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

    let body: VerifierResponse<RegistrarAgent> = resp.json().await.unwrap();
    assert_eq!(
        body.results.agent_id,
        "a1b2c3d4-0000-1111-2222-333344445555"
    );
    assert_eq!(body.results.ip, Some("10.0.1.20".to_string()));
    // Failed agent has higher regcount (re-registered multiple times)
    assert_eq!(body.results.regcount, 3);
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

    let body: VerifierResponse<RegistrarAgent> = resp.json().await.unwrap();
    assert_eq!(
        body.results.agent_id,
        "f7e6d5c4-b3a2-9180-7654-321098765432"
    );
    assert_eq!(body.results.ip, Some("10.0.1.30".to_string()));
    assert_eq!(body.results.regcount, 1);
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

    let body: VerifierResponse<RegistrarAgent> = resp.json().await.unwrap();
    assert_eq!(
        body.results.agent_id,
        "b2c3d4e5-a1b0-8765-4321-fedcba987654"
    );
    assert_eq!(body.results.ip, Some("10.0.1.40".to_string()));
    assert_eq!(body.results.regcount, 2);
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

    let body: VerifierResponse<RegistrarAgent> = resp.json().await.unwrap();
    assert_eq!(
        body.results.agent_id,
        "c5d6e7f8-a9b0-4321-8765-abcdef012345"
    );
    assert_eq!(body.results.ip, Some("10.0.1.50".to_string()));
    assert_eq!(body.results.regcount, 1);
}
