#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end integration test: starts Mockoon mocks + backend, then runs
# every curl command documented in README.md and validates the responses.

set -euo pipefail

GIT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VERIFIER_PORT=3000
REGISTRAR_PORT=3001
BACKEND_PORT=8080
BACKEND_URL="http://localhost:${BACKEND_PORT}"

PASSED=0
FAILED=0
TOTAL=0

# ── helpers ──────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
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
    echo "-------- Waiting for backend on port ${BACKEND_PORT}..."
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

cleanup() {
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

# ── main ─────────────────────────────────────────────────────────────────

MOCKOON_VERIFIER_PID=""
MOCKOON_REGISTRAR_PID=""
BACKEND_PID=""

echo "======== Keylime Webtool Backend – curl integration tests ========"
echo ""

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

# 3. Run tests
echo ""
echo "-------- Running curl integration tests"
echo ""

# -- Agent endpoints --
echo "  Agents"
echo "  ------"
run_test "List all agents"              "/api/agents"
run_test "Get healthy agent (GET_QUOTE)" \
    "/api/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
run_test "Get failed agent (FAILED)"    \
    "/api/agents/a1b2c3d4-0000-1111-2222-333344445555"
run_test "Get push-mode agent (PROVIDE_V)" \
    "/api/agents/f7e6d5c4-b3a2-9180-7654-321098765432"
run_test "Search agents by IP"          "/api/agents/search?q=10.0.1"
echo ""

# -- Agent detail tabs (Phase 2) --
echo "  Agent Detail Tabs"
echo "  -----------------"
HEALTHY_ID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
FAILED_ID="a1b2c3d4-0000-1111-2222-333344445555"
PUSH_ID="f7e6d5c4-b3a2-9180-7654-321098765432"
run_test "Timeline (healthy)"           "/api/agents/${HEALTHY_ID}/timeline"
run_test "Timeline (failed)"            "/api/agents/${FAILED_ID}/timeline"
run_test "PCR values"                   "/api/agents/${HEALTHY_ID}/pcr"
run_test "IMA log"                      "/api/agents/${HEALTHY_ID}/ima-log"
run_test "Boot log"                     "/api/agents/${PUSH_ID}/boot-log"
run_test "Certificates"                 "/api/agents/${HEALTHY_ID}/certificates"
run_test "Raw data"                     "/api/agents/${HEALTHY_ID}/raw"
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
