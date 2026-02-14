#!/bin/bash
# One-command setup + MCP server + interactive client (macOS/Linux)
# Runs full setup if needed, starts the MCP server in the background,
# then drops you into the MCP client shell. When you exit the client,
# the server is stopped.
#
# Usage:
#   ./scripts/run_mcp_shell.sh                    # use default repo (DVWA if present)
#   ./scripts/run_mcp_shell.sh --repo /path/to/repo
#   ./scripts/run_mcp_shell.sh --debug             # start server in debug mode
#
# Prerequisites: Python 3, Go (optional; needed for hybrid scans). On macOS: Xcode CLI or Go from go.dev.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

PY="${PROJECT_ROOT}/.venv/bin/python"
PORT="${AGENTSMITH_MCP_PORT:-2266}"
HEALTH_URL="http://127.0.0.1:${PORT}/health"

# ---------------------------------------------------------------------------
# Step 1: Ensure environment is set up
# ---------------------------------------------------------------------------
echo ""
echo "🕶️  Agent Smith MCP — ready-to-go shell"
echo "========================================"
echo ""
# Remind: Bedrock hybrid scans need the server to see the same env as your CLI
if [ "${AGENTSMITH_PROVIDER}" = "bedrock" ]; then
    echo "  💡 Bedrock: server will use AWS_REGION=${AWS_REGION:-<not set>} AWS_PROFILE=${AWS_PROFILE:-<not set>}"
    echo ""
fi

if [ ! -d ".venv" ]; then
    echo "  Running full setup (Go + Python venv)..."
    ./scripts/setup.sh
    echo ""
else
    echo "  ✓ Virtual environment found"
    # Ensure MCP dependencies are installed
    "$PY" -c "import mcp" 2>/dev/null || {
        echo "  Installing MCP dependencies..."
        "$PY" -m pip install -r mcp_server/requirements.txt --quiet
        echo "  ✓ MCP dependencies installed"
    }
fi

if [ ! -x "./scanner" ]; then
    echo "  ⚠️  Scanner binary not found. Hybrid scans will fail."
    echo "     Run: ./scripts/setup.sh --go"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 2: Start MCP server in background (or use existing one on same port)
# ---------------------------------------------------------------------------
MCP_LOG="${PROJECT_ROOT}/.mcp_server.log"
SERVER_PID=""
SERVER_OPTS="--no-auth --port $PORT"
if printf '%s\n' "$@" | grep -q '^--debug$'; then
    SERVER_OPTS="$SERVER_OPTS --debug"
    echo "  Debug mode: server will log at DEBUG level"
fi

# If something is already serving on the port, use it (avoid "address already in use")
if curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null | grep -q 200; then
    echo "  Port ${PORT} already in use — using existing server."
else
    echo "  Starting MCP server on port ${PORT} (log: .mcp_server.log)..."
    "$PY" -m mcp_server $SERVER_OPTS >> "$MCP_LOG" 2>&1 &
    SERVER_PID=$!
fi

# Stop only the server we started when this script exits
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Wait for server to be ready
echo "  Waiting for server..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null | grep -q 200; then
        echo "  ✓ Server ready"
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "  ❌ Server did not become ready. Check port ${PORT} and .mcp_server.log"
        echo "     If port is in use, kill the process: lsof -i :${PORT} then kill <pid>"
        exit 1
    fi
    sleep 1
done
echo ""

# ---------------------------------------------------------------------------
# Step 3: Drop into MCP client (interact mode)
# ---------------------------------------------------------------------------
CLIENT_ARGS=("--url" "http://127.0.0.1:${PORT}/sse")

# Default repo if none passed and DVWA test target exists
if ! printf '%s\n' "$@" | grep -q '^--repo$'; then
    DEFAULT_REPO="${PROJECT_ROOT}/tests/test_targets/DVWA"
    if [ -d "$DEFAULT_REPO" ]; then
        CLIENT_ARGS+=("--repo" "$DEFAULT_REPO")
    fi
fi

echo "  Launching MCP client (type 'help' at mcp> for commands)..."
echo ""

"$PY" -m mcp_server.test_client interact "${CLIENT_ARGS[@]}" "$@"
