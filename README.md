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

# Get a specific agent (healthy agent)
curl http://localhost:8080/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000 | jq

# Get a failed agent
curl http://localhost:8080/api/agents/a1b2c3d4-0000-1111-2222-333344445555 | jq

# Get a push-mode agent
curl http://localhost:8080/api/agents/f7e6d5c4-b3a2-9180-7654-321098765432 | jq

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
```

The backend reads `KEYLIME_VERIFIER_URL` and `KEYLIME_REGISTRAR_URL` environment variables (defaulting to `http://localhost:3000` and `http://localhost:3001`).

### Mock fleet

The mock data defines a fleet of 3 agents in different states:

| Agent UUID | Verifier State | Description |
|-----------|---------------|-------------|
| `d432fbb3-d2f1-4a97-9ef7-75bd81c00000` | GET_QUOTE (3) | Healthy agent, IMA policy `production-v1` |
| `a1b2c3d4-0000-1111-2222-333344445555` | FAILED (7) | Failed agent, regcount=3 |
| `f7e6d5c4-b3a2-9180-7654-321098765432` | PROVIDE_V (5) | Push-mode agent, measured boot + IMA policies |

## Linting

```bash
cargo clippy -- -D warnings   # lint (treat warnings as errors)
cargo fmt                      # format code
cargo fmt -- --check           # check formatting without modifying
```

## License

Apache-2.0
