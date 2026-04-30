#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end integration test: starts Mockoon mocks + backend, then runs
# every curl command documented in README.md and validates the responses.
#
# Usage:
#   bash tests/curl_integration_test.sh              # full: start mocks + backend + test
#   bash tests/curl_integration_test.sh --url http://myhost:8080
#   bash tests/curl_integration_test.sh --no-mocks   # test only against already-running services
#   bash tests/curl_integration_test.sh --no-mocks --url http://myhost:8080

set -euo pipefail

GIT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── option parsing ──────────────────────────────────────────────────────

NO_MOCKS=false
BACKEND_URL="http://localhost:8080"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-mocks)
            NO_MOCKS=true
            shift
            ;;
        --url)
            BACKEND_URL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--no-mocks] [--url URL]"
            echo ""
            echo "  --no-mocks  Skip starting Mockoon mocks and backend; test against"
            echo "              already-running services (Mockoon desktop, real deployment, etc.)"
            echo "  --url URL   Backend base URL (default: http://localhost:8080)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (use --help for usage)"
            exit 1
            ;;
    esac
done

VERIFIER_PORT=3000
REGISTRAR_PORT=3001

PASSED=0
FAILED=0
TOTAL=0

# ── helpers ──────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
# shellcheck disable=SC2329  # invoked indirectly (available for future tests)
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

start_mockoon_server() {
    local name="$1"
    local data_file="$2"
    local port="$3"

    if curl -s --connect-timeout 2 "http://localhost:${port}" > /dev/null 2>&1; then
        echo "-------- ${name} already running on port ${port}"
        return 0
    fi

    if ! command -v mockoon-cli &> /dev/null; then
        echo "Error: mockoon-cli is not installed"
        echo "Install it with: npm install -g @mockoon/cli"
        exit 1
    fi

    if [ ! -f "$data_file" ]; then
        echo "Error: ${name} configuration file not found at ${data_file}"
        exit 1
    fi

    echo "-------- Starting ${name} on port ${port}"
    mockoon-cli start --data "$data_file" --port "$port" &
    local pid=$!

    for _ in $(seq 1 15); do
        if curl -s --connect-timeout 1 "http://localhost:${port}" > /dev/null 2>&1; then
            echo "${name} is up (PID ${pid})"
            eval "MOCKOON_${name}_PID=${pid}"
            return 0
        fi
        sleep 1
    done

    echo "Error: Timed out waiting for ${name} to start"
    kill "$pid" 2>/dev/null || true
    exit 1
}

wait_for_backend() {
    echo "-------- Waiting for backend at ${BACKEND_URL}..."
    for _ in $(seq 1 30); do
        if curl -s --connect-timeout 1 "${BACKEND_URL}/api/kpis" > /dev/null 2>&1; then
            echo "Backend is up"
            return 0
        fi
        sleep 1
    done
    echo "Error: Timed out waiting for backend to start"
    exit 1
}

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [ "$NO_MOCKS" = true ]; then
        return
    fi
    echo ""
    echo "-------- Cleaning up"
    [ -n "${BACKEND_PID:-}" ]           && kill "$BACKEND_PID" 2>/dev/null || true
    [ -n "${MOCKOON_VERIFIER_PID:-}" ]  && kill "$MOCKOON_VERIFIER_PID" 2>/dev/null || true
    [ -n "${MOCKOON_REGISTRAR_PID:-}" ] && kill "$MOCKOON_REGISTRAR_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}

trap cleanup EXIT

# Run a single test case.
#   $1 = test name
#   $2 = curl URL (appended to BACKEND_URL)
#   $3 = optional jq filter to validate (default: checks .status == "success")
run_test() {
    local name="$1"
    local url="$2"
    local filter="${3:-.success}"
    local expected="${4:-true}"

    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "${name}"

    local response
    response=$(curl -sf "${BACKEND_URL}${url}" 2>&1) || {
        red "FAIL (HTTP error)"
        FAILED=$((FAILED + 1))
        return
    }

    local actual
    actual=$(echo "$response" | jq -r "$filter" 2>/dev/null) || {
        red "FAIL (invalid JSON)"
        FAILED=$((FAILED + 1))
        return
    }

    if [ "$actual" = "$expected" ]; then
        green "PASS"
        PASSED=$((PASSED + 1))
    else
        red "FAIL (expected '${expected}', got '${actual}')"
        FAILED=$((FAILED + 1))
    fi
}

# Run a POST test case (empty body).
run_post_test() {
    local name="$1"
    local url="$2"
    local filter="${3:-.success}"
    local expected="${4:-true}"

    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "${name}"

    local response
    response=$(curl -sf -X POST "${BACKEND_URL}${url}" 2>&1) || {
        red "FAIL (HTTP error)"
        FAILED=$((FAILED + 1))
        return
    }

    local actual
    actual=$(echo "$response" | jq -r "$filter" 2>/dev/null) || {
        red "FAIL (invalid JSON)"
        FAILED=$((FAILED + 1))
        return
    }

    if [ "$actual" = "$expected" ]; then
        green "PASS"
        PASSED=$((PASSED + 1))
    else
        red "FAIL (expected '${expected}', got '${actual}')"
        FAILED=$((FAILED + 1))
    fi
}

# Run a POST test with JSON body.
run_json_post_test() {
    local name="$1"
    local url="$2"
    local body="$3"
    local filter="${4:-.success}"
    local expected="${5:-true}"

    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "${name}"

    local response
    response=$(curl -sf -X POST -H "Content-Type: application/json" \
        -d "$body" "${BACKEND_URL}${url}" 2>&1) || {
        red "FAIL (HTTP error)"
        FAILED=$((FAILED + 1))
        return
    }

    local actual
    actual=$(echo "$response" | jq -r "$filter" 2>/dev/null) || {
        red "FAIL (invalid JSON)"
        FAILED=$((FAILED + 1))
        return
    }

    if [ "$actual" = "$expected" ]; then
        green "PASS"
        PASSED=$((PASSED + 1))
    else
        red "FAIL (expected '${expected}', got '${actual}')"
        FAILED=$((FAILED + 1))
    fi
}

# Run a PUT test with JSON body.
run_put_test() {
    local name="$1"
    local url="$2"
    local body="$3"
    local filter="${4:-.success}"
    local expected="${5:-true}"

    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "${name}"

    local response
    response=$(curl -sf -X PUT -H "Content-Type: application/json" \
        -d "$body" "${BACKEND_URL}${url}" 2>&1) || {
        red "FAIL (HTTP error)"
        FAILED=$((FAILED + 1))
        return
    }

    local actual
    actual=$(echo "$response" | jq -r "$filter" 2>/dev/null) || {
        red "FAIL (invalid JSON)"
        FAILED=$((FAILED + 1))
        return
    }

    if [ "$actual" = "$expected" ]; then
        green "PASS"
        PASSED=$((PASSED + 1))
    else
        red "FAIL (expected '${expected}', got '${actual}')"
        FAILED=$((FAILED + 1))
    fi
}

# Run a test for a stub/not-implemented endpoint.
# Expects the endpoint to return JSON with .success == false.
#   $1 = test name
#   $2 = HTTP method (GET, POST, PUT, DELETE)
#   $3 = URL path
#   $4 = optional JSON body
run_stub_test() {
    local name="$1"
    local method="$2"
    local url="$3"
    local body="${4:-}"

    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "${name} (stub)"

    local curl_args=(-s -X "$method")
    if [ -n "$body" ]; then
        curl_args+=(-H "Content-Type: application/json" -d "$body")
    fi

    local response
    response=$(curl "${curl_args[@]}" "${BACKEND_URL}${url}" 2>&1)

    local success
    success=$(echo "$response" | jq -r ".success" 2>/dev/null) || {
        red "FAIL (invalid JSON)"
        FAILED=$((FAILED + 1))
        return
    }

    if [ "$success" = "false" ]; then
        green "PASS"
        PASSED=$((PASSED + 1))
    else
        red "FAIL (expected stub, got success=${success})"
        FAILED=$((FAILED + 1))
    fi
}

# ── main ─────────────────────────────────────────────────────────────────

MOCKOON_VERIFIER_PID=""
MOCKOON_REGISTRAR_PID=""
BACKEND_PID=""

echo "======== Keylime Webtool Backend – curl integration tests ========"
if [ "$NO_MOCKS" = true ]; then
    echo "  Mode: --no-mocks (testing against ${BACKEND_URL})"
fi
echo ""

if [ "$NO_MOCKS" = false ]; then
    # 0. Fail fast if the backend port is already in use
    if curl -s --connect-timeout 2 "${BACKEND_URL}" > /dev/null 2>&1; then
        echo "Error: ${BACKEND_URL} is already in use."
        echo "Stop the running backend first, or use --no-mocks to test against it."
        exit 1
    fi

    # 1. Start Mockoon mocks
    start_mockoon_server "VERIFIER"  "${GIT_ROOT}/test-data/verifier.json"  "$VERIFIER_PORT"
    start_mockoon_server "REGISTRAR" "${GIT_ROOT}/test-data/registrar.json" "$REGISTRAR_PORT"

    # 2. Build and start the backend
    echo "-------- Building backend"
    cd "$GIT_ROOT"
    cargo build --quiet 2>&1

    echo "-------- Starting backend"
    RUST_LOG=info cargo run --quiet &
    BACKEND_PID=$!

    wait_for_backend
fi

# 3. Run tests
echo ""
echo "-------- Running curl integration tests"
echo ""

# -- Agent endpoints --
echo "  Agents"
echo "  ------"
run_test "List all agents"              "/api/agents"
run_test "  list contains push agent with PASS state" \
    "/api/agents" \
    '[.data.items[] | select(.id == "f7e6d5c4-b3a2-9180-7654-321098765432") | .state] | .[0]' "PASS"
run_test "  list contains push agent with Push mode" \
    "/api/agents" \
    '[.data.items[] | select(.id == "f7e6d5c4-b3a2-9180-7654-321098765432") | .attestation_mode] | .[0]' "Push"
run_test "Get healthy agent (GET_QUOTE)" \
    "/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
run_test "  state = GET_QUOTE"          \
    "/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000" \
    ".data.state" "GET_QUOTE"
run_test "  mode = Pull"                \
    "/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000" \
    ".data.attestation_mode" "Pull"
run_test "Get failed agent (FAILED)"    \
    "/api/agents/a1b2c3d4-0000-1111-2222-333344445555"
run_test "  state = FAILED"             \
    "/api/agents/a1b2c3d4-0000-1111-2222-333344445555" \
    ".data.state" "FAILED"
run_test "  mode = Pull"                \
    "/api/agents/a1b2c3d4-0000-1111-2222-333344445555" \
    ".data.attestation_mode" "Pull"
run_test "Get push-mode agent (PASS)"   \
    "/api/agents/f7e6d5c4-b3a2-9180-7654-321098765432"
run_test "  state = PASS"               \
    "/api/agents/f7e6d5c4-b3a2-9180-7654-321098765432" \
    ".data.state" "PASS"
run_test "  mode = Push"                \
    "/api/agents/f7e6d5c4-b3a2-9180-7654-321098765432" \
    ".data.attestation_mode" "Push"
run_test "Get failed push-mode agent (FAIL)" \
    "/api/agents/b2c3d4e5-a1b0-8765-4321-fedcba987654"
run_test "  state = FAIL"               \
    "/api/agents/b2c3d4e5-a1b0-8765-4321-fedcba987654" \
    ".data.state" "FAIL"
run_test "  mode = Push"                \
    "/api/agents/b2c3d4e5-a1b0-8765-4321-fedcba987654" \
    ".data.attestation_mode" "Push"
NULLIP_ID="e6f7a8b9-c0d1-2345-6789-aabbccddeeff"
run_test "Get null-ip push agent (registrar fallback)" \
    "/api/agents/${NULLIP_ID}"
run_test "  ip falls back to registrar" \
    "/api/agents/${NULLIP_ID}" \
    ".data.ip" "10.0.1.60"
run_test "  port falls back to registrar" \
    "/api/agents/${NULLIP_ID}" \
    ".data.port" "9002"
run_test "  list port via registrar fallback" \
    "/api/agents" \
    '[.data.items[] | select(.id == "e6f7a8b9-c0d1-2345-6789-aabbccddeeff") | .port] | .[0]' "9002"
run_test "  list ip via registrar fallback" \
    "/api/agents" \
    '[.data.items[] | select(.id == "e6f7a8b9-c0d1-2345-6789-aabbccddeeff") | .ip] | .[0]' "10.0.1.60"
run_test "  list port present for healthy agent" \
    "/api/agents" \
    '[.data.items[] | select(.id == "d432fbb3-d2f1-4a97-9ef7-75bd81c00000") | .port] | .[0]' "9002"
run_test "Search agents by IP"          "/api/agents/search?q=10.0.1"
echo ""

# -- Agent detail tabs (Phase 2) --
echo "  Agent Detail Tabs"
echo "  -----------------"
HEALTHY_ID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
FAILED_ID="a1b2c3d4-0000-1111-2222-333344445555"
PUSH_ID="f7e6d5c4-b3a2-9180-7654-321098765432"
PUSH_FAILED_ID="b2c3d4e5-a1b0-8765-4321-fedcba987654"
run_test "Timeline (healthy)"           "/api/agents/${HEALTHY_ID}/timeline"
run_test "Timeline (failed)"            "/api/agents/${FAILED_ID}/timeline"
run_test "PCR values"                   "/api/agents/${HEALTHY_ID}/pcr"
run_test "IMA log"                      "/api/agents/${HEALTHY_ID}/ima-log"
run_test "Boot log"                     "/api/agents/${PUSH_ID}/boot-log"
run_test "Certificates"                 "/api/agents/${HEALTHY_ID}/certificates"
run_test "Raw data (combined)"           "/api/agents/${HEALTHY_ID}/raw"
run_test "  combined has backend key"    "/api/agents/${HEALTHY_ID}/raw" \
    ".data.backend | has(\"id\")" "true"
run_test "  combined has verifier key"   "/api/agents/${HEALTHY_ID}/raw" \
    ".data | has(\"verifier\")" "true"
run_test "  combined has registrar key"  "/api/agents/${HEALTHY_ID}/raw" \
    ".data | has(\"registrar\")" "true"
run_test "Raw data (push failed)"       "/api/agents/${PUSH_FAILED_ID}/raw"
run_test "Raw backend"                  "/api/agents/${HEALTHY_ID}/raw/backend"
run_test "  backend ip"                 "/api/agents/${HEALTHY_ID}/raw/backend" \
    ".data.ip" "10.0.1.10"
run_test "Raw registrar"                "/api/agents/${HEALTHY_ID}/raw/registrar"
run_test "  registrar ek_tpm present"   "/api/agents/${HEALTHY_ID}/raw/registrar" \
    "(.data.ek_tpm | length) > 0" "true"
run_test "Raw verifier"                 "/api/agents/${HEALTHY_ID}/raw/verifier"
run_test "  verifier hash_alg"          "/api/agents/${HEALTHY_ID}/raw/verifier" \
    ".data.hash_alg" "sha256"
run_test "Raw backend null-ip fallback" "/api/agents/${NULLIP_ID}/raw/backend" \
    ".data.ip" "10.0.1.60"
echo ""

# -- KPI endpoint --
echo "  KPIs"
echo "  ----"
run_test "Fleet KPIs"                   "/api/kpis"
echo ""

# -- Policy endpoints --
echo "  Policies"
echo "  --------"
run_test "List all policies"            "/api/policies"
run_test "Get specific policy"          "/api/policies/production-v1"
run_test "Policy assignment matrix"     "/api/policies/assignment-matrix"
run_post_test "Impact analysis (production-v1)" \
    "/api/policies/production-v1/impact"
echo ""

# -- Attestation endpoints --
echo "  Attestations"
echo "  ------------"
run_test "Agent state distribution"     "/api/attestations/state-machine"
run_test "Attestation summary"          "/api/attestations/summary"
run_test "Attestation timeline"         "/api/attestations/timeline"
run_test "Attestation history"          "/api/attestations"
run_test "Failure categorization"       "/api/attestations/failures"
run_test "Verification pipeline (healthy)" \
    "/api/attestations/pipeline/${HEALTHY_ID}"
run_test "Verification pipeline (failed)" \
    "/api/attestations/pipeline/${FAILED_ID}"
run_test "Push mode analytics"          "/api/attestations/push-mode"
run_test "Pull mode monitoring"         "/api/attestations/pull-mode"
echo ""

# -- Certificate endpoints --
echo "  Certificates"
echo "  ------------"
run_test "List certificates"            "/api/certificates"
run_test "Certificate expiry summary"   "/api/certificates/expiry"
echo ""

# -- Integration endpoints --
echo "  Integrations"
echo "  ------------"
run_test "Backend connectivity status"  "/api/integrations/status"
run_test "Durable backends"             "/api/integrations/durable"
run_test "Revocation channels"          "/api/integrations/revocation-channels"
run_test "SIEM status"                  "/api/integrations/siem"
echo ""

# -- Performance endpoints --
echo "  Performance"
echo "  -----------"
run_test "Verifier metrics"             "/api/performance/verifiers"
run_test "Database metrics"             "/api/performance/database"
run_test "API response times"           "/api/performance/api-response-times"
run_test "Config drift"                 "/api/performance/config"
run_test "Capacity planning"            "/api/performance/capacity"
echo ""

# -- Compliance endpoints --
echo "  Compliance"
echo "  ----------"
run_test "List frameworks"              "/api/compliance/frameworks"
run_test "Compliance report (NIST)"     "/api/compliance/reports/nist-sp-800-155"
echo ""

# -- Agent actions --
echo "  Agent Actions"
echo "  -------------"
run_post_test "Reactivate agent"            "/api/agents/${HEALTHY_ID}/actions/reactivate"
run_post_test "Stop agent"                  "/api/agents/${PUSH_ID}/actions/stop"
run_json_post_test "Bulk action (reactivate)" \
    "/api/agents/bulk" \
    "{\"agent_ids\":[\"${FAILED_ID}\"],\"action\":\"reactivate\"}" \
    ".data.action" "reactivate"
echo ""

# -- Alert endpoints --
echo "  Alerts"
echo "  ------"
ALERT_NEW="a0000001-0000-4000-8000-000000000001"
ALERT_ACKED="a0000001-0000-4000-8000-000000000002"
ALERT_CERT="a0000001-0000-4000-8000-000000000003"
ALERT_INVESTIGATING="a0000001-0000-4000-8000-000000000005"
run_test "List alerts"                      "/api/alerts"
run_test "  filter by severity"             "/api/alerts?severity=critical"
run_test "Alert summary"                    "/api/alerts/summary"
run_test "Get alert by ID"                  "/api/alerts/${ALERT_NEW}"
run_post_test "Acknowledge alert"           "/api/alerts/${ALERT_NEW}/acknowledge"
run_json_post_test "Investigate alert" \
    "/api/alerts/${ALERT_CERT}/investigate" '{}'
run_json_post_test "Resolve alert" \
    "/api/alerts/${ALERT_INVESTIGATING}/resolve" '{}'
run_post_test "Dismiss alert"               "/api/alerts/${ALERT_ACKED}/dismiss"
run_post_test "Escalate alert"              "/api/alerts/${ALERT_NEW}/escalate"
run_stub_test "Alert notifications"  "GET"  "/api/alerts/notifications"
run_stub_test "Update thresholds"    "PUT"  "/api/alerts/thresholds" \
    '{"attestation_success_rate":0.95}'
echo ""

# -- Audit log endpoints (stubs) --
echo "  Audit Log"
echo "  ---------"
run_stub_test "List audit events"    "GET"  "/api/audit-log"
run_stub_test "Verify audit chain"   "GET"  "/api/audit-log/verify"
run_stub_test "Export audit log"     "GET"  "/api/audit-log/export"
echo ""

# -- Settings endpoints --
echo "  Settings"
echo "  --------"
run_test "Get Keylime settings"             "/api/settings/keylime"
run_test "  verifier_url present"           "/api/settings/keylime" \
    "(.data.verifier_url | length) > 0" "true"
run_put_test "Update Keylime settings" \
    "/api/settings/keylime" \
    '{"verifier_url":"http://localhost:3000","registrar_url":"http://localhost:3001"}'
run_test "Get certificate settings"         "/api/settings/certificates"
run_put_test "Update certificate settings" \
    "/api/settings/certificates" '{}'
echo ""

# -- Certificate details --
echo "  Certificate Details"
echo "  -------------------"
CERT_ID=$(curl -sf "${BACKEND_URL}/api/certificates" 2>/dev/null | jq -r '.data.items[0].id // empty' 2>/dev/null) || true
if [ -n "$CERT_ID" ] && [ "$CERT_ID" != "null" ]; then
    run_test "Get certificate by ID"             "/api/certificates/${CERT_ID}"
else
    echo "  (skipped -- no certificate IDs available)"
fi
echo ""

# -- Attestation incidents (stubs) --
echo "  Attestation Incidents"
echo "  ---------------------"
INCIDENT_ID="00000000-0000-4000-8000-000000000001"
run_stub_test "List incidents"        "GET"  "/api/attestations/incidents"
run_stub_test "Get incident"          "GET"  "/api/attestations/incidents/${INCIDENT_ID}"
run_stub_test "Rollback incident"     "POST" "/api/attestations/incidents/${INCIDENT_ID}/rollback"
echo ""

# -- Policy management (stubs) --
echo "  Policy Management"
echo "  -----------------"
run_stub_test "Create policy"         "POST" "/api/policies" \
    '{"name":"test-policy","kind":"ima","content":"..."}'
run_stub_test "Update policy"         "PUT"  "/api/policies/production-v1" \
    '{"content":"..."}'
run_stub_test "Delete policy"         "DELETE" "/api/policies/production-v1"
run_stub_test "List policy versions"  "GET"  "/api/policies/production-v1/versions"
run_stub_test "Diff policy versions"  "GET"  "/api/policies/production-v1/diff"
run_stub_test "Rollback policy"       "POST" "/api/policies/production-v1/rollback/1"
run_stub_test "Approve policy change" "POST" "/api/policies/changes/change-001/approve"
echo ""

# -- Compliance export (stub) --
echo "  Compliance Export"
echo "  -----------------"
run_stub_test "Export report"         "POST" "/api/compliance/reports/nist-sp-800-155/export?format=pdf"
echo ""

# -- Auth endpoints (stubs) --
echo "  Authentication"
echo "  --------------"
run_stub_test "Login"                 "POST" "/api/auth/login"
run_stub_test "Auth callback"         "POST" "/api/auth/callback" \
    '{"code":"test","state":"test"}'
run_stub_test "Refresh token"         "POST" "/api/auth/refresh"
run_stub_test "Logout"                "POST" "/api/auth/logout"
echo ""

# 4. Summary
echo "======== Results ========"
echo "  Total:  ${TOTAL}"
green "  Passed: ${PASSED}"
if [ "$FAILED" -gt 0 ]; then
    red   "  Failed: ${FAILED}"
else
    echo  "  Failed: 0"
fi
echo "========================="

exit "$FAILED"
