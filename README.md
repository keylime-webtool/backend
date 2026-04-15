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
```

The backend reads `KEYLIME_VERIFIER_URL` and `KEYLIME_REGISTRAR_URL` environment variables (defaulting to `http://localhost:3000` and `http://localhost:3001`).

### Mock fleet

The mock data defines a fleet of 5 agents in different states:

| Agent UUID | Mode | State | Description |
|-----------|------|-------|-------------|
| `d432fbb3-d2f1-4a97-9ef7-75bd81c00000` | Pull | GET_QUOTE | Healthy agent, IMA policy `production-v1` |
| `a1b2c3d4-0000-1111-2222-333344445555` | Pull | FAILED | Failed agent, regcount=3 |
| `f7e6d5c4-b3a2-9180-7654-321098765432` | Push | PASS | Healthy push-mode agent, measured boot + IMA policies, attestation_count=42 |
| `b2c3d4e5-a1b0-8765-4321-fedcba987654` | Push | FAIL | Failed push-mode agent, attestation timeout + 3 consecutive failures |
| `c5d6e7f8-a9b0-4321-8765-abcdef012345` | Push | PASS | Healthy push-mode agent, IMA policy `production-v1`, attestation_count=78 |

## Linting

```bash
cargo clippy -- -D warnings   # lint (treat warnings as errors)
cargo fmt                      # format code
cargo fmt -- --check           # check formatting without modifying
```

## License

Apache-2.0
