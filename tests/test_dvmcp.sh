#!/usr/bin/env bash
# ============================================================================
# Agent Smith — DVMCP (Damn Vulnerable MCP) Test Suite
#
# Launches the DVMCP challenge servers, scans each one with scan_mcp,
# and reports findings. Auto-starts the Agent Smith MCP server if not running.
#
# Requires: DVMCP cloned at tests/test_targets/DVMCP
#
# Usage:
#   ./tests/test_dvmcp.sh              # scan all 10 challenges
#   ./tests/test_dvmcp.sh 1 8 9        # scan specific challenges
#   ./tests/test_dvmcp.sh --json       # JSON output for CI/regression
#   ./tests/test_dvmcp.sh --setup-only # just start DVMCP servers
#   ./tests/test_dvmcp.sh --kill       # just kill DVMCP servers
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DVMCP_DIR="$PROJECT_ROOT/tests/test_targets/DVMCP"
VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python"
AGENTSMITH_PORT="${AGENTSMITH_MCP_PORT:-2266}"
AGENTSMITH_URL="${AGENTSMITH_URL:-http://localhost:${AGENTSMITH_PORT}/sse}"
HEALTH_URL="http://127.0.0.1:${AGENTSMITH_PORT}/health"
MCP_LOG="$PROJECT_ROOT/.mcp_server.log"
SERVER_PID=""

# Colors
BOLD="\033[1m"
DIM="\033[2m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

# ============================================================================
# Challenge data (no associative arrays — compatible with Bash 3)
# ============================================================================

challenge_name() {
    case "$1" in
        1)  echo "Basic Prompt Injection" ;;
        2)  echo "Tool Poisoning" ;;
        3)  echo "Excessive Permission Scope" ;;
        4)  echo "Rug Pull Attack" ;;
        5)  echo "Tool Shadowing" ;;
        6)  echo "Indirect Prompt Injection" ;;
        7)  echo "Token Theft" ;;
        8)  echo "Malicious Code Execution" ;;
        9)  echo "Remote Access Control" ;;
        10) echo "Multi-Vector Attack" ;;
    esac
}

challenge_port() {
    echo $((9000 + $1))
}

challenge_path() {
    case "$1" in
        1)  echo "challenges/easy/challenge1/server_sse.py" ;;
        2)  echo "challenges/easy/challenge2/server_sse.py" ;;
        3)  echo "challenges/easy/challenge3/server_sse.py" ;;
        4)  echo "challenges/medium/challenge4/server_sse.py" ;;
        5)  echo "challenges/medium/challenge5/server_sse.py" ;;
        6)  echo "challenges/medium/challenge6/server_sse.py" ;;
        7)  echo "challenges/medium/challenge7/server_sse.py" ;;
        8)  echo "challenges/hard/challenge8/server_sse.py" ;;
        9)  echo "challenges/hard/challenge9/server_sse.py" ;;
        10) echo "challenges/hard/challenge10/server_sse.py" ;;
    esac
}

# ============================================================================
# Helpers
# ============================================================================

log()  { echo -e "${BOLD}[agentsmith]${RESET} $*"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }
err()  { echo -e "  ${RED}✗${RESET} $*"; }

ensure_mcp_server() {
    # Start MCP server if not already running
    if curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null | grep -q 200; then
        ok "Agent Smith MCP server is healthy"
        return
    fi
    log "Starting Agent Smith MCP server on port ${AGENTSMITH_PORT}..."
    cd "$PROJECT_ROOT"
    "$VENV_PYTHON" -m mcp_server --no-auth --port "$AGENTSMITH_PORT" >> "$MCP_LOG" 2>&1 &
    SERVER_PID=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null | grep -q 200; then
            ok "Agent Smith MCP server is healthy"
            return
        fi
        sleep 1
    done
    err "Server did not become ready. Check $MCP_LOG"
    exit 1
}

check_prereqs() {
    if [ ! -d "$DVMCP_DIR" ]; then
        err "DVMCP not found at $DVMCP_DIR"
        log "Clone it with: git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git tests/test_targets/DVMCP"
        exit 1
    fi

    if [ ! -f "$VENV_PYTHON" ]; then
        err "Python venv not found at $VENV_PYTHON"
        exit 1
    fi

    ensure_mcp_server
}

setup_dvmcp_dirs() {
    mkdir -p /tmp/dvmcp_challenge3/public /tmp/dvmcp_challenge3/private
    mkdir -p /tmp/dvmcp_challenge4/state
    mkdir -p /tmp/dvmcp_challenge6/user_uploads
    mkdir -p /tmp/dvmcp_challenge8/sensitive
    mkdir -p /tmp/dvmcp_challenge10/config

    echo '{"weather_tool_calls": 0}' > /tmp/dvmcp_challenge4/state/state.json
    echo "Welcome to the public directory!" > /tmp/dvmcp_challenge3/public/welcome.txt
    echo "CONFIDENTIAL: Employee Salary Information" > /tmp/dvmcp_challenge3/private/employee_salaries.txt
    echo "SYSTEM CONFIG" > /tmp/dvmcp_challenge10/config/system.conf
    echo '{"admin_token": "test-jwt-token"}' > /tmp/dvmcp_challenge10/config/tokens.json
}

start_challenge() {
    local num=$1
    local port
    port=$(challenge_port "$num")
    local path
    path=$(challenge_path "$num")
    local name
    name=$(challenge_name "$num")

    # Check if port is already in use
    if lsof -i ":$port" >/dev/null 2>&1; then
        warn "Port $port already in use, skipping Challenge $num"
        return 0
    fi

    cd "$DVMCP_DIR"
    "$VENV_PYTHON" "$path" >/dev/null 2>&1 &
    local pid=$!
    DVMCP_PIDS="$DVMCP_PIDS $pid"
    echo -e "  ${DIM}Challenge $num${RESET} ($name) → port $port [pid $pid]"
    return 0
}

kill_dvmcp() {
    log "Stopping DVMCP servers..."
    local port
    for port in 9001 9002 9003 9004 9005 9006 9007 9008 9009 9010; do
        local pid
        pid=$(lsof -ti ":$port" 2>/dev/null || true)
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Also kill tracked PIDs
    for pid in $DVMCP_PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    ok "DVMCP servers stopped"
}

scan_challenge() {
    local num=$1
    local port
    port=$(challenge_port "$num")
    local name
    name=$(challenge_name "$num")
    local url="http://localhost:$port/sse"

    if [ "$JSON_OUTPUT" != "true" ]; then
        echo ""
        echo -e "${BOLD}━━━ Challenge $num: $name (port $port) ━━━${RESET}"
    fi

    # Quick check if server is responding
    if ! curl -s "http://localhost:$port/" >/dev/null 2>&1; then
        [ "$JSON_OUTPUT" != "true" ] && err "Server on port $port not responding, skipping"
        echo "${num}|0|?|0|Server not responding" >> "$SCOREBOARD_FILE"
        return 1
    fi

    # Call scan_mcp via the Agent Smith MCP server
    local result
    result=$("$VENV_PYTHON" -c "
import asyncio, json, sys

async def scan():
    from mcp.client.sse import sse_client
    from mcp import ClientSession

    ctx = sse_client('$AGENTSMITH_URL')
    streams = await ctx.__aenter__()
    session = ClientSession(streams[0], streams[1])
    await session.__aenter__()
    await session.initialize()

    result = await session.call_tool('scan_mcp', {
        'target_url': '$url',
        'transport': 'sse',
        'timeout': 10,
    })

    await session.__aexit__(None, None, None)
    await ctx.__aexit__(None, None, None)

    data = json.loads(result.content[0].text)
    return data

try:
    data = asyncio.run(scan())
    print(json.dumps(data))
except Exception as e:
    print(json.dumps({'error': str(e)}))
" 2>/dev/null)

    if echo "$result" | "$VENV_PYTHON" -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'error' not in d else 1)" 2>/dev/null; then
        # Parse and emit scoreboard line
        echo "$result" | "$VENV_PYTHON" -c "
import sys, json
d = json.load(sys.stdin)
s = d.get('summary', {})
risk = s.get('risk_score', '?')
total = s.get('total_findings', 0)
print(f\"${num}|1|{risk}|{total}|\")
" 2>/dev/null >> "$SCOREBOARD_FILE"
        # Display results (unless JSON mode)
        if [ "$JSON_OUTPUT" != "true" ]; then
        echo "$result" | "$VENV_PYTHON" -c "
import sys, json

d = json.load(sys.stdin)
s = d.get('summary', {})
risk = s.get('risk_score', '?')
total = s.get('total_findings', 0)
by_sev = s.get('by_severity', {})
tools = d.get('tools', [])
findings = d.get('findings', [])

colors = {'CRITICAL': '\033[0;31m', 'HIGH': '\033[0;31m', 'MEDIUM': '\033[0;33m', 'LOW': '\033[0;36m', 'INFO': '\033[2m', 'CLEAN': '\033[0;32m'}
R = '\033[0m'
B = '\033[1m'

risk_c = colors.get(risk, '')
print(f'  {B}Risk:{R}     {risk_c}{risk}{R}')
print(f'  {B}Findings:{R} {total}')

parts = []
for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
    if sev in by_sev:
        parts.append(f'{colors[sev]}{sev}: {by_sev[sev]}{R}')
if parts:
    print(f'  {B}Severity:{R} {\", \".join(parts)}')

print(f'  {B}Tools:{R}    {s.get(\"total_tools\", 0)}  Resources: {s.get(\"total_resources\", 0)}  Prompts: {s.get(\"total_prompts\", 0)}')

if tools:
    names = ', '.join(t['name'] for t in tools[:5])
    more = f' +{len(tools)-5} more' if len(tools) > 5 else ''
    print(f'  {B}Exposed:{R}  {names}{more}')

sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
findings.sort(key=lambda f: sev_order.get(f.get('severity', 'INFO'), 5))
for f in findings[:5]:
    sev = f.get('severity', '?')
    c = colors.get(sev, '')
    title = f.get('title', '?')[:65]
    tool = f.get('tool', f.get('resource', ''))
    loc = f' ({tool})' if tool else ''
    print(f'  {c}[{sev}]{R} {title}{loc}')
if len(findings) > 5:
    print(f'  \033[2m... and {len(findings) - 5} more\033[0m')
"
        fi
        return 0
    else
        local error
        error=$(echo "$result" | "$VENV_PYTHON" -c "import sys,json; print(json.load(sys.stdin).get('error','unknown'))" 2>/dev/null || echo "parse error")
        echo "${num}|0|?|0|$error" >> "$SCOREBOARD_FILE"
        [ "$JSON_OUTPUT" != "true" ] && err "Scan failed: $error"
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

DVMCP_PIDS=""
SCOREBOARD_FILE=""

cleanup_mcp() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log "Stopping Agent Smith MCP server (pid $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

trap 'kill_dvmcp; cleanup_mcp; [ -n "$SCOREBOARD_FILE" ] && rm -f "$SCOREBOARD_FILE"' EXIT

# Parse args
CHALLENGES=""
SETUP_ONLY=false
KILL_ONLY=false
JSON_OUTPUT=false

for arg in "$@"; do
    case "$arg" in
        --setup-only) SETUP_ONLY=true ;;
        --kill)       KILL_ONLY=true ;;
        --json)       JSON_OUTPUT=true ;;
        [0-9]*)       CHALLENGES="$CHALLENGES $arg" ;;
        *)            echo "Usage: $0 [--setup-only|--kill|--json] [challenge_numbers...]"; exit 1 ;;
    esac
done

# Default: all 10 challenges
if [ -z "$CHALLENGES" ]; then
    CHALLENGES="1 2 3 4 5 6 7 8 9 10"
fi

if $KILL_ONLY; then
    kill_dvmcp
    exit 0
fi

# Count challenges
NUM_CHALLENGES=0
for _ in $CHALLENGES; do NUM_CHALLENGES=$((NUM_CHALLENGES + 1)); done

echo ""
echo -e "${BOLD}Agent Smith — DVMCP Security Scan${RESET}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Scanner:    ${CYAN}$AGENTSMITH_URL${RESET}"
echo -e "  DVMCP:      ${DIM}$DVMCP_DIR${RESET}"
echo -e "  Challenges: $NUM_CHALLENGES"
echo ""

check_prereqs

# When --json, send all non-JSON output to stderr so stdout is clean for CI
if [ "$JSON_OUTPUT" = "true" ]; then
    exec 3>&1
    exec 1>&2
fi

# Setup DVMCP data directories
log "Setting up DVMCP test data..."
setup_dvmcp_dirs
ok "Test data ready"

# Start challenge servers
log "Starting DVMCP challenge servers..."
for num in $CHALLENGES; do
    start_challenge "$num"
done

# Wait for servers to be ready
echo -e "  ${DIM}Waiting for servers to start...${RESET}"
sleep 4

if $SETUP_ONLY; then
    ok "DVMCP servers running. Press Ctrl+C to stop."
    wait
    exit 0
fi

# Scoreboard temp file (used by scan_challenge)
SCOREBOARD_FILE=$(mktemp)

# Scan each challenge
log "Scanning DVMCP challenges..."
PASSED=0
FAILED=0

for num in $CHALLENGES; do
    if scan_challenge "$num"; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

# Scoreboard and summary
CHALLENGE_NAMES="Basic Prompt Injection|Tool Poisoning|Excessive Permission Scope|Rug Pull Attack|Tool Shadowing|Indirect Prompt Injection|Token Theft|Malicious Code Execution|Remote Access Control|Multi-Vector Attack"
if [ "$JSON_OUTPUT" = "true" ]; then
    exec 1>&3
    "$VENV_PYTHON" -c "
import json
names = '$CHALLENGE_NAMES'.split('|')
challenges = []
for line in open('$SCOREBOARD_FILE'):
    parts = line.strip().split('|', 4)
    if len(parts) < 5:
        continue
    num, passed, risk, total, err = int(parts[0]), parts[1] == '1', parts[2], int(parts[3]) if parts[3].isdigit() else 0, parts[4] or None
    name = names[num - 1] if 1 <= num <= len(names) else f'Challenge {num}'
    challenges.append({
        'challenge': num,
        'name': name,
        'port': 9000 + num,
        'passed': passed,
        'risk_score': risk,
        'total_findings': total,
        'error': err
    })
print(json.dumps({'challenges': challenges, 'summary': {'passed': $PASSED, 'failed': $FAILED, 'total': $NUM_CHALLENGES}}, indent=2))
"
else
    echo ""
    echo -e "${BOLD}━━━ Scoreboard ━━━${RESET}"
    while IFS='|' read -r num passed risk total err; do
        if [ "$passed" = "1" ]; then
            echo -e "  Challenge $num: ${GREEN}✓${RESET} (risk=$risk, findings=$total)"
        else
            echo -e "  Challenge $num: ${RED}✗${RESET} ${err:-$risk}"
        fi
    done < "$SCOREBOARD_FILE"
    echo ""
    echo -e "${BOLD}━━━ Summary ━━━${RESET}"
    echo -e "  Scanned:  $NUM_CHALLENGES challenges"
    echo -e "  Passed:   ${GREEN}$PASSED${RESET}"
    if [ "$FAILED" -gt 0 ]; then
        echo -e "  Failed:   ${RED}$FAILED${RESET}"
    fi
    echo ""
fi

# Cleanup happens via trap
