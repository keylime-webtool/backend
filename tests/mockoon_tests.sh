#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Script to run Mockoon-based Keylime API integration tests.
# Starts Mockoon servers for both Verifier (port 3000) and Registrar (port 3001),
# then runs integration tests that exercise the backend against these mocks.

set -euo pipefail

GIT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

start_mockoon_server() {
    local name="$1"
    local data_file="$2"
    local port="$3"

    # Check if already running (e.g., in CI)
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

    # Wait for server to be ready
    echo "Waiting for ${name} on port ${port}..."
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

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    echo "-------- Cleaning up Mockoon servers"
    [ -n "${MOCKOON_VERIFIER_PID:-}" ] && kill "$MOCKOON_VERIFIER_PID" 2>/dev/null || true
    [ -n "${MOCKOON_REGISTRAR_PID:-}" ] && kill "$MOCKOON_REGISTRAR_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}

trap cleanup EXIT

MOCKOON_VERIFIER_PID=""
MOCKOON_REGISTRAR_PID=""

# Start both mock servers
start_mockoon_server "VERIFIER" "${GIT_ROOT}/test-data/verifier.json" 3000
start_mockoon_server "REGISTRAR" "${GIT_ROOT}/test-data/registrar.json" 3001

# Run integration tests
echo "-------- Running Mockoon integration tests"
cd "$GIT_ROOT"
RUST_BACKTRACE=1 RUST_LOG=info \
    MOCKOON_VERIFIER=1 \
    MOCKOON_REGISTRAR=1 \
    cargo test --features mockoon test_mockoon -- --nocapture

TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "-------- Mockoon integration tests PASSED"
else
    echo "-------- Mockoon integration tests FAILED with exit code $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
