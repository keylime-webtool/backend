#!/usr/bin/env bash
# verify.sh — Run all commit checks: code quality + commit message.
#
# Combines the pre-commit checks (formatting, clippy, build, tests, audit)
# with the Signed-off-by verification on the latest commit.
#
# Usage:
#   bash scripts/verify.sh          # run all checks
#   bash scripts/verify.sh --quick  # skip slow checks (audit, machete)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours (disabled when stdout is not a terminal) ──────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' BOLD='' RESET=''
fi

overall=0

# ── 1. Code quality checks (pre-commit) ──────────────────────────────
echo -e "${BOLD}=== Code quality checks ===${RESET}"
echo ""
if ! bash "$SCRIPT_DIR/pre-commit.sh" "$@"; then
    overall=1
fi

echo ""

# ── 2. Signed-off-by check (last commit) ─────────────────────────────
echo -e "${BOLD}=== Commit message checks ===${RESET}"
echo ""

if git rev-parse HEAD &>/dev/null; then
    LAST_MSG=$(git log -1 --format='%B')
    SHORT=$(git log -1 --format='%h %s' | head -c 72)

    printf "  %-20s" "Signed-off-by"
    if echo "$LAST_MSG" | grep -qP '^Signed-off-by: .+ <.+>'; then
        echo -e "${GREEN}OK${RESET}  ($SHORT)"
    else
        echo -e "${RED}FAIL${RESET}  ($SHORT)"
        overall=1
    fi
else
    printf "  %-20s" "Signed-off-by"
    echo "SKIP (no commits)"
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────
if [ "$overall" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All checks passed.${RESET}"
else
    echo -e "${RED}${BOLD}Some checks failed.${RESET}"
    exit 1
fi
