# keylime-webtool-backend

Rust backend for the Keylime Monitoring Dashboard -- a web-based security operations platform providing centralized monitoring, management, and compliance capabilities for [Keylime](https://keylime.dev/) remote attestation infrastructure.

## Build

```bash
cargo build              # dev build
cargo build --release    # release build
```

## Tests

### Unit tests

```bash
cargo test               # run all unit tests
cargo test <test_name>   # run a single test
```

### Mockoon integration tests

Integration tests use [Mockoon](https://mockoon.com/) to simulate Keylime Verifier and Registrar APIs. The mock data lives in `test-data/`.

**Automated (recommended):**

```bash
bash tests/mockoon_tests.sh
```

This starts both mock servers, runs the tests, and cleans up automatically.

**Manual step-by-step:**

```bash
# 1. Install mockoon-cli (if not already installed)
npm install -g @mockoon/cli

# 2. Start the Verifier mock (port 3000) and Registrar mock (port 3001)
mockoon-cli start --data test-data/verifier.json --port 3000 &
mockoon-cli start --data test-data/registrar.json --port 3001 &

# 3. Run the integration tests
MOCKOON_VERIFIER=1 MOCKOON_REGISTRAR=1 cargo test --features mockoon test_mockoon -- --nocapture

# 4. Stop the mock servers
pkill -f mockoon-cli
```

You can also run Verifier or Registrar tests independently:

```bash
# Verifier tests only
MOCKOON_VERIFIER=1 cargo test --features mockoon test_mockoon_verifier -- --nocapture

# Registrar tests only
MOCKOON_REGISTRAR=1 cargo test --features mockoon test_mockoon_registrar -- --nocapture
```

**Using the Mockoon desktop app:**

1. Open Mockoon and import the mock files via **File > Open environment**:
   - `test-data/verifier.json` (runs on port 3000)
   - `test-data/registrar.json` (runs on port 3001)
2. Click the **Start** button (green play icon) for each environment
3. Run the tests from a terminal:
   ```bash
   MOCKOON_VERIFIER=1 MOCKOON_REGISTRAR=1 cargo test --features mockoon test_mockoon -- --nocapture
   ```
4. The Mockoon GUI will show each request in its log panel, letting you inspect request/response details, headers, and timing in real time

**Manual testing with curl:**

Start both Mockoon mocks and the backend, then use `curl` to test the API:

```bash
# Terminal 1: start the Verifier mock
mockoon-cli start --data test-data/verifier.json --port 3000

# Terminal 2: start the Registrar mock
mockoon-cli start --data test-data/registrar.json --port 3001

# Terminal 3: start the backend (defaults to localhost:3000/3001)
RUST_LOG=info cargo run

# Terminal 4: query the API
# List all agents
curl http://localhost:8080/api/agents | jq

# Get a specific agent (Pull mode, GET_QUOTE state)
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000 | jq

# Get a failed agent (Pull mode, FAILED state)
curl http://localhost:8080/api/agents/a1b2c3d4-0000-1111-2222-333344445555 | jq

# Get a push-mode agent (Push mode, PASS state)
curl http://localhost:8080/api/agents/f7e6d5c4-b3a2-9180-7654-321098765432 | jq

# Get a failed push-mode agent (Push mode, FAIL state)
curl http://localhost:8080/api/agents/b2c3d4e5-a1b0-8765-4321-fedcba987654 | jq

# Fleet KPIs
curl http://localhost:8080/api/kpis | jq

# Search agents by UUID or IP
curl "http://localhost:8080/api/agents/search?q=10.0.1" | jq

# List all policies
curl http://localhost:8080/api/policies | jq

# Get a specific policy
curl http://localhost:8080/api/policies/production-v1 | jq

# Agent state distribution
curl http://localhost:8080/api/attestations/state-machine | jq

# Backend connectivity status (Verifier + Registrar health)
curl http://localhost:8080/api/integrations/status | jq

# Agent detail tabs (timeline, PCR, IMA, boot log, certs, raw)
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/timeline | jq
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/pcr | jq
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/ima-log | jq
curl http://localhost:8080/api/agents/f7e6d5c4-b3a2-9180-7654-321098765432/boot-log | jq
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/certificates | jq
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/raw | jq
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/raw/backend | jq
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/raw/registrar | jq
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/raw/verifier | jq

# Attestation analytics (supports ?range=1h|6h|24h|7d|30d)
curl "http://localhost:8080/api/attestations/summary?range=30d" | jq
curl "http://localhost:8080/api/attestations/timeline?range=24h" | jq
curl http://localhost:8080/api/attestations | jq
curl http://localhost:8080/api/attestations/failures | jq

# Verification pipeline for healthy vs failed agent
curl http://localhost:8080/api/attestations/pipeline/d432fbb3-d2f1-4a97-9ef7-75bd81c00000 | jq
curl http://localhost:8080/api/attestations/pipeline/a1b2c3d4-0000-1111-2222-333344445555 | jq

# Push/pull mode analytics
curl http://localhost:8080/api/attestations/push-mode | jq
curl http://localhost:8080/api/attestations/pull-mode | jq

# Policy assignment matrix and impact analysis
curl http://localhost:8080/api/policies/assignment-matrix | jq
curl -X POST http://localhost:8080/api/policies/production-v1/impact | jq

# Certificates
curl http://localhost:8080/api/certificates | jq
curl http://localhost:8080/api/certificates/expiry | jq

# Performance
curl http://localhost:8080/api/performance/verifiers | jq
curl http://localhost:8080/api/performance/database | jq
curl http://localhost:8080/api/performance/api-response-times | jq
curl http://localhost:8080/api/performance/config | jq
curl http://localhost:8080/api/performance/capacity | jq

# Compliance
curl http://localhost:8080/api/compliance/frameworks | jq
curl http://localhost:8080/api/compliance/reports/nist-sp-800-155 | jq

# Integrations (durable, revocation, SIEM)
curl http://localhost:8080/api/integrations/durable | jq
curl http://localhost:8080/api/integrations/revocation-channels | jq
curl http://localhost:8080/api/integrations/siem | jq

# Agent actions (reactivate, stop, delete)
curl -X POST http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/actions/reactivate | jq
curl -X POST http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/actions/stop | jq
curl -X POST -H "Content-Type: application/json" \
  -d '{"agent_ids":["d432fbb3-d2f1-4a97-9ef7-75bd81c00000"],"action":"reactivate"}' \
  http://localhost:8080/api/agents/bulk | jq

# Alerts
curl http://localhost:8080/api/alerts | jq
curl "http://localhost:8080/api/alerts?severity=critical" | jq
curl http://localhost:8080/api/alerts/summary | jq
curl http://localhost:8080/api/alerts/a0000001-0000-4000-8000-000000000001 | jq
curl -X POST http://localhost:8080/api/alerts/a0000001-0000-4000-8000-000000000001/acknowledge | jq
curl -X POST -H "Content-Type: application/json" \
  -d '{"assigned_to":"analyst@example.com"}' \
  http://localhost:8080/api/alerts/a0000001-0000-4000-8000-000000000002/investigate | jq
curl -X POST -H "Content-Type: application/json" \
  -d '{"resolution":"Root cause identified"}' \
  http://localhost:8080/api/alerts/a0000001-0000-4000-8000-000000000005/resolve | jq
curl -X POST http://localhost:8080/api/alerts/a0000001-0000-4000-8000-000000000003/dismiss | jq
curl -X POST http://localhost:8080/api/alerts/a0000001-0000-4000-8000-000000000001/escalate | jq
curl http://localhost:8080/api/alerts/notifications | jq                    # stub
curl -X PUT -H "Content-Type: application/json" \
  -d '{"attestation_success_rate":0.95,"cert_expiry_days":30}' \
  http://localhost:8080/api/alerts/thresholds | jq                          # stub

# Certificate details (ID from the /api/certificates list)
CERT_ID=$(curl -sf http://localhost:8080/api/certificates | jq -r '.data[0].id')
curl http://localhost:8080/api/certificates/$CERT_ID | jq
curl -X POST http://localhost:8080/api/certificates/$CERT_ID/renew | jq    # stub

# Audit log (stubs -- not yet implemented)
curl http://localhost:8080/api/audit-log | jq
curl http://localhost:8080/api/audit-log/verify | jq
curl http://localhost:8080/api/audit-log/export | jq

# Settings
curl http://localhost:8080/api/settings/keylime | jq
curl -X PUT -H "Content-Type: application/json" \
  -d '{"verifier_url":"http://localhost:3000","registrar_url":"http://localhost:3001"}' \
  http://localhost:8080/api/settings/keylime | jq
curl http://localhost:8080/api/settings/certificates | jq
curl -X PUT -H "Content-Type: application/json" -d '{}' \
  http://localhost:8080/api/settings/certificates | jq

# Attestation incidents (stubs -- not yet implemented)
curl http://localhost:8080/api/attestations/incidents | jq
curl http://localhost:8080/api/attestations/incidents/00000000-0000-4000-8000-000000000001 | jq
curl -X POST http://localhost:8080/api/attestations/incidents/00000000-0000-4000-8000-000000000001/rollback | jq

# Policy management (stubs -- not yet implemented)
curl -X POST -H "Content-Type: application/json" \
  -d '{"name":"test-policy","kind":"ima","content":"..."}' \
  http://localhost:8080/api/policies | jq
curl -X PUT -H "Content-Type: application/json" \
  -d '{"content":"..."}' \
  http://localhost:8080/api/policies/production-v1 | jq
curl -X DELETE http://localhost:8080/api/policies/production-v1 | jq
curl http://localhost:8080/api/policies/production-v1/versions | jq
curl http://localhost:8080/api/policies/production-v1/diff | jq
curl -X POST http://localhost:8080/api/policies/production-v1/rollback/1 | jq
curl -X POST http://localhost:8080/api/policies/changes/change-001/approve | jq

# Compliance export (stub)
curl -X POST "http://localhost:8080/api/compliance/reports/nist-sp-800-155/export?format=pdf" | jq

# Authentication (stubs -- not yet implemented)
curl -X POST http://localhost:8080/api/auth/login | jq
curl -X POST -H "Content-Type: application/json" \
  -d '{"code":"auth-code","state":"csrf-state"}' \
  http://localhost:8080/api/auth/callback | jq
curl -X POST http://localhost:8080/api/auth/refresh | jq
curl -X POST http://localhost:8080/api/auth/logout | jq

# WebSocket (real-time events -- use websocat or similar tool)
# websocat ws://localhost:8080/ws/events
```

The backend reads `KEYLIME_VERIFIER_URL` and `KEYLIME_REGISTRAR_URL` environment variables (defaulting to `http://localhost:3000` and `http://localhost:3001`).

### Mock fleet

The mock data defines a fleet of 6 agents in different states:

| Agent UUID | Mode | State | Description |
|-----------|------|-------|-------------|
| `d432fbb3-d2f1-4a97-9ef7-75bd81c00000` | Pull | GET_QUOTE | Healthy agent, IMA policy `production-v1` |
| `a1b2c3d4-0000-1111-2222-333344445555` | Pull | FAILED | Failed agent, IMA policy `production-v1`, regcount=3 |
| `f7e6d5c4-b3a2-9180-7654-321098765432` | Push | PASS | Healthy push-mode agent, IMA `staging-v2` + MB `measured-boot-v1`, attestation_count=42 |
| `b2c3d4e5-a1b0-8765-4321-fedcba987654` | Push | FAIL | Failed push-mode agent, IMA `production-v1`, attestation timeout + 3 consecutive failures |
| `c5d6e7f8-a9b0-4321-8765-abcdef012345` | Push | PASS | Healthy push-mode agent, IMA policy `production-v1`, attestation_count=78 |
| `e6f7a8b9-c0d1-2345-6789-aabbccddeeff` | Push | PASS | Null ip/port push agent (registrar fallback), IMA `production-v1`, attestation_count=5 |

Policies are served from two Keylime API endpoints: IMA policies from `GET /v2/allowlists/` (`production-v1`, `staging-v2`) and measured boot policies from `GET /v2/mbpolicies/` (`measured-boot-v1`).

Since there is no attestation history table yet, the `/api/attestations/summary` endpoint derives event-level stats from agent states: push-mode agents contribute their `attestation_count` and `consecutive_attestation_failures`, while pull-mode agents count as a single event each. The `/api/attestations/timeline` endpoint distributes these totals across hourly buckets with deterministic variation so the chart looks natural.

## Linting

```bash
cargo clippy -- -D warnings   # lint (treat warnings as errors)
cargo fmt                      # format code
cargo fmt -- --check           # check formatting without modifying
```

## License

Apache-2.0
