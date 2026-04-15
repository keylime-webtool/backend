#!/usr/bin/env bash
# check-signed-commits.sh — Verify a commit message carries a Signed-off-by line.
#
# Used as a local commit-msg hook:
#   bash scripts/check-signed-commits.sh <commit-msg-file>
#
# CI validation is handled by the org-wide reusable workflow at:
#   keylime-webtool/.github/.github/workflows/signed-commits.yml

set -euo pipefail

# ── Colours (disabled when stdout is not a terminal) ──────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' BOLD='' RESET=''
fi

die() { echo -e "${RED}${BOLD}ERROR:${RESET} $*" >&2; exit 1; }

COMMIT_MSG_FILE="${1:-}"
[ -n "$COMMIT_MSG_FILE" ] || die "Usage: $0 <commit-msg-file>"
[ -f "$COMMIT_MSG_FILE" ] || die "File not found: $COMMIT_MSG_FILE"

MSG=$(cat "$COMMIT_MSG_FILE")

echo -e "${BOLD}Checking Signed-off-by...${RESET}"
echo ""

if echo "$MSG" | grep -qP '^Signed-off-by: .+ <.+>'; then
    echo -e "  commit message  ${GREEN}OK${RESET}"
    echo ""
    echo -e "${GREEN}${BOLD}Signed-off-by present.${RESET}"
else
    echo -e "  commit message  ${RED}MISSING Signed-off-by${RESET}"
    echo ""
    echo -e "${RED}Commit message must include a Signed-off-by line.${RESET}"
    echo ""
    echo "Add it with:  git commit -s"
    echo "Or amend:     git commit --amend -s"
    exit 1
fi
