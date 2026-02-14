#!/usr/bin/env bash
# Run the MCP test client against the Agent Smith MCP server (test-through).
# Starts the server in the background if not already running, runs the
# automated test suite, then exits. Use for CI or local validation.
#
# Usage:
#   ./scripts/run_mcp_tests.sh              # default repo (DVWA if present)
#   ./scripts/run_mcp_tests.sh --all        # include scan_hybrid (needs API key)
#   ./scripts/run_mcp_tests.sh --repo /path/to/repo
#   ./scripts/run_mcp_tests.sh --json       # JSON output for CI
#   ./scripts/run_mcp_tests.sh -v           # verbose (cost, debug log)
#
# Optional: set AGENTSMITH_MCP_TEST_TARGET=http://localhost:9001/sse to add
# a scan_mcp test (e.g. with DVMCP running). See docs/MCP_SCANNING.md.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

PY="${PROJECT_ROOT}/.venv/bin/python"
PORT="${AGENTSMITH_MCP_PORT:-2266}"
HEALTH_URL="http://127.0.0.1:${PORT}/health"
MCP_LOG="${PROJECT_ROOT}/.mcp_server.log"
SERVER_PID=""

# ---------------------------------------------------------------------------
# Ensure venv and MCP deps
# ---------------------------------------------------------------------------
if [ ! -f "$PY" ]; then
    echo "❌ Virtual environment not found. Run: ./scripts/setup.sh"
    exit 1
fi
"$PY" -c "import mcp" 2>/dev/null || {
    echo "Installing MCP dependencies..."
    "$PY" -m pip install -r mcp_server/requirements.txt --quiet
}

# ---------------------------------------------------------------------------
# Start MCP server if not already running
# ---------------------------------------------------------------------------
if curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null | grep -q 200; then
    echo "✓ MCP server already running on port ${PORT}"
else
    echo "Starting MCP server on port ${PORT}..."
    "$PY" -m mcp_server --no-auth --port "$PORT" >> "$MCP_LOG" 2>&1 &
    SERVER_PID=$!
fi

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Wait for server
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null | grep -q 200; then
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "❌ Server did not become ready. Check .mcp_server.log"
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# Run test client (test mode)
# ---------------------------------------------------------------------------
URL="http://127.0.0.1:${PORT}/sse"
CLIENT_ARGS=("--url" "$URL")

# Default repo if DVWA exists and --repo not in user args
if ! printf '%s\n' "$@" | grep -q '^--repo$'; then
    DEFAULT_REPO="${PROJECT_ROOT}/tests/test_targets/DVWA"
    if [ -d "$DEFAULT_REPO" ]; then
        CLIENT_ARGS+=("--repo" "$DEFAULT_REPO")
    fi
fi

"$PY" -m mcp_server.test_client test "${CLIENT_ARGS[@]}" "$@"
exit $?
