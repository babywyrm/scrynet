#!/bin/bash
# Agent Smith pre-commit hook — fail on CRITICAL findings
#
# Usage:
#   Option A: Copy to .git/hooks/pre-commit
#     cp examples/pre-commit-hook.sh .git/hooks/pre-commit
#     chmod +x .git/hooks/pre-commit
#
#   Option B: Use with pre-commit framework (see .pre-commit-config.yaml)
#
# Set AGENTSMITH_PATH to the Agent Smith repo (default: ../agentsmith).
# Set AGENTSMITH_FAIL_ON to CRITICAL or HIGH (default: CRITICAL).

set -e
REPO_ROOT="${1:-.}"
AGENTSMITH_PATH="${AGENTSMITH_PATH:-../agentsmith}"
FAIL_ON="${AGENTSMITH_FAIL_ON:-CRITICAL}"
SCANNER="${AGENTSMITH_PATH}/scanner"
PYTHON_SCRIPT="${AGENTSMITH_PATH}/agentsmith.py"

if [ ! -f "$PYTHON_SCRIPT" ]; then
  echo "Agent Smith not found at $AGENTSMITH_PATH. Set AGENTSMITH_PATH."
  exit 1
fi

if [ ! -f "$SCANNER" ]; then
  echo "Scanner binary not found. Run: cd $AGENTSMITH_PATH && ./scripts/setup.sh"
  exit 1
fi

python3 "$PYTHON_SCRIPT" static "$REPO_ROOT" "$SCANNER" --fail-on "$FAIL_ON"
