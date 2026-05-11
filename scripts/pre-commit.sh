#!/bin/bash
# pre-commit.sh — Local pre-commit checks mirroring CI workflows.
#
# Runs the same checks as the GitHub Actions pipelines:
#   - rust.yml          (formatting, clippy, build, tests)
#   - compile-no-warnings.yml (strict RUSTFLAGS + strict clippy)
#   - cargo-audit.yml   (security audit)
#   - cargo-machete.yml (unused dependencies)
#   - shellcheck.yml    (shell script linting)
#   - curl-integration.yaml (end-to-end curl tests)
#   - coverage.yml      (cargo-tarpaulin code coverage)
#
# Usage:
#   bash scripts/pre-commit.sh          # run all checks
#   bash scripts/pre-commit.sh --quick  # skip slow checks (audit, machete)
#
# To install as a git pre-commit hook:
#   ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit

set -euo pipefail

# ── Colours (disabled when stdout is not a terminal) ──────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' RESET=''
fi

# ── Helpers ───────────────────────────────────────────────────────────
pass() { echo -e "  ${GREEN}PASS${RESET}  $1"; }
fail() { echo -e "  ${RED}FAIL${RESET}  $1"; }
skip() { echo -e "  ${YELLOW}SKIP${RESET}  $1 ($2)"; }
header() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

ERRORS=0

run_check() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label"
        # Re-run to show output on failure
        echo ""
        "$@" 2>&1 || true
        echo ""
        ERRORS=$((ERRORS + 1))
    fi
}

run_check_once() {
    local label="$1"
    shift
    local output
    if output=$("$@" 2>&1); then
        pass "$label"
    else
        fail "$label"
        echo ""
        echo "$output"
        echo ""
        ERRORS=$((ERRORS + 1))
    fi
}

# ── Parse arguments ──────────────────────────────────────────────────
QUICK=0
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--quick]"
            exit 1
            ;;
    esac
done

# ── Move to repo root ───────────────────────────────────────────────
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
cd "$REPO_ROOT"

echo -e "${BOLD}Running pre-commit checks ...${RESET}"

# ── 1. Formatting (rust.yml) ─────────────────────────────────────────
header "Formatting"
run_check "cargo fmt" cargo fmt --all -- --check

# ── 2. Clippy lints (rust.yml) ───────────────────────────────────────
header "Clippy"
run_check "clippy (basic)" cargo clippy -- -D warnings

# ── 3. Strict compilation — no warnings (compile-no-warnings.yml) ────
header "Compilation (no warnings)"
run_check "cargo build (-D warnings)" \
    env RUSTFLAGS="-D warnings" cargo build
run_check "cargo test (-D warnings)" \
    env RUSTFLAGS="-D warnings" cargo test
run_check "clippy --all-features --all-targets" \
    cargo clippy --all-features --all-targets -- -D clippy::all -D warnings
run_check "clippy --all-features --all-targets --tests" \
    cargo clippy --all-features --all-targets --tests -- -D clippy::all -D warnings

# ── 4. Security audit (cargo-audit.yml) ──────────────────────────────
header "Dependency checks"
if [ "$QUICK" -eq 1 ]; then
    skip "cargo audit" "--quick mode"
elif command -v cargo-audit >/dev/null 2>&1; then
    run_check "cargo audit" cargo audit
else
    skip "cargo audit" "cargo-audit not installed"
fi

# ── 5. Unused dependencies (cargo-machete.yml) ──────────────────────
if [ "$QUICK" -eq 1 ]; then
    skip "cargo machete" "--quick mode"
elif command -v cargo-machete >/dev/null 2>&1; then
    run_check "cargo machete" cargo machete
else
    skip "cargo machete" "cargo-machete not installed"
fi

# ── 6. ShellCheck (shellcheck.yml) ───────────────────────────────────
header "ShellCheck"
if command -v shellcheck >/dev/null 2>&1; then
    SHELL_SCRIPTS=()
    while IFS= read -r -d '' f; do
        SHELL_SCRIPTS+=("$f")
    done < <(find tests scripts -name '*.sh' -print0 2>/dev/null)

    if [ ${#SHELL_SCRIPTS[@]} -gt 0 ]; then
        run_check "shellcheck (${#SHELL_SCRIPTS[@]} scripts)" \
            shellcheck "${SHELL_SCRIPTS[@]}"
    else
        skip "shellcheck" "no .sh files found"
    fi
else
    skip "shellcheck" "shellcheck not installed"
fi

# ── 7. Curl integration tests (curl-integration.yaml) ───────────────
header "Curl integration tests"
if [ "$QUICK" -eq 1 ]; then
    skip "curl integration" "--quick mode"
elif ! command -v mockoon-cli >/dev/null 2>&1; then
    skip "curl integration" "mockoon-cli not installed"
elif ! command -v jq >/dev/null 2>&1; then
    skip "curl integration" "jq not installed"
else
    run_check_once "curl integration" bash tests/curl_integration_test.sh
fi

# ── 8. Code coverage (coverage.yml) ─────────────────────────────────
header "Code coverage"
if [ "$QUICK" -eq 1 ]; then
    skip "cargo tarpaulin" "--quick mode"
elif ! command -v cargo-tarpaulin >/dev/null 2>&1; then
    skip "cargo tarpaulin" "cargo-tarpaulin not installed"
else
    if cargo tarpaulin -o Json -o Xml --output-dir coverage/ >/dev/null 2>&1; then
        COV=$(jq '.coverage' coverage/tarpaulin-report.json 2>/dev/null \
            | grep -oE "[0-9]{1,3}\.[0-9]{0,2}" || echo "?")
        pass "cargo tarpaulin (line coverage: ${COV}%)"
    else
        fail "cargo tarpaulin"
        cargo tarpaulin -o Json -o Xml --output-dir coverage/ 2>&1 || true
        echo ""
        ERRORS=$((ERRORS + 1))
    fi
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All checks passed.${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}${ERRORS} check(s) failed.${RESET}"
    exit 1
fi
