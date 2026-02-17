# Agent Smith MCP Server

Model Context Protocol (MCP) server that exposes Agent Smith's security scanning and AI analysis tools over HTTP. Supports both **SSE** and **Streamable HTTP** transports.

**→ [../QUICKSTART.md](../QUICKSTART.md)** — MCP shell commands (use cases 9–12) alongside CLI.

## Quick Start

**Recommended:** One-command setup + server + interactive client:

```bash
./scripts/run_mcp_shell.sh
# At mcp> prompt: scan_hybrid {"preset": "mcp"}, scan_mcp 9001, dvmcp, etc.
# The script stops any existing server and starts fresh so your env (CLAUDE_API_KEY) is picked up.
```

**Manual:** Start server only (for Cursor/IDE integration):

```bash
pip install -r mcp_server/requirements.txt
python3 -m mcp_server --no-auth
```

**Production:** Use auth token:

```bash
export AGENTSMITH_MCP_TOKEN=your-secret-token
python3 -m mcp_server
```

The server starts on **port 2266** by default with both SSE and Streamable HTTP transports.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (no auth required) |
| `/ready` | GET | Readiness check — verifies scanner binary (no auth required) |
| `/sse` | GET | SSE transport for MCP clients |
| `/messages/` | POST | SSE message handler |
| `/mcp/` | POST | Streamable HTTP transport for MCP clients |

## Available Tools

### Static Analysis (no API key needed)

| Tool | Description |
|------|-------------|
| `scan_static` | Scan a whole repository with 70+ OWASP rules |
| `scan_file` | Scan a single file — ideal for checking the file you're editing |
| `detect_tech_stack` | Detect languages, frameworks, entry points, and security risks |
| `list_presets` | List available scan preset configurations |

### Results & Filtering

| Tool | Description |
|------|-------------|
| `summarize_results` | Summarize existing scan results with severity counts, cost, and artifacts |
| `list_findings` | Browse findings filtered by severity, source, with pagination |

### MCP Server Security

| Tool | Description |
|------|-------------|
| `scan_mcp` | Security-scan a remote MCP server: enumerate tools/resources, check auth, analyze for dangerous capabilities and injection vectors |

See [docs/MCP_SCANNING.md](../docs/MCP_SCANNING.md) for the full scanning guide with architecture diagrams, DVMCP walkthrough, and security checks reference. Ideas for future improvements: [mcp_server/ROADMAP.md](ROADMAP.md).

### AI-Powered (requires `CLAUDE_API_KEY` or Bedrock)

| Tool | Description |
|------|-------------|
| `scan_hybrid` | Full hybrid scan combining static + AI analysis with payloads and annotations |
| `explain_finding` | Deep-dive explanation of a vulnerability: attack scenarios, CWE, OWASP category |
| `get_fix` | AI-generated code fix with before/after code, explanation, and test suggestion |

## Connecting Clients

### Cursor IDE

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "agentsmith": {
      "url": "http://localhost:2266/mcp/"
    }
  }
}
```

Or use the SSE transport:

```json
{
  "mcpServers": {
    "agentsmith": {
      "url": "http://localhost:2266/sse"
    }
  }
}
```

Reload Cursor after editing (Cmd+Shift+P → "Developer: Reload Window").

### Other MCP Clients

Any MCP-compatible client can connect via:
- **Streamable HTTP**: `POST http://localhost:2266/mcp/`
- **SSE**: `GET http://localhost:2266/sse`

## Test Client

The built-in test client validates the server and provides an interactive REPL.

### One-Command Setup (Recommended)

```bash
# Start server + interactive client (log written to .mcp_server.log)
./scripts/run_mcp_shell.sh

# Same, with server debug logging
./scripts/run_mcp_shell.sh --debug

# Run automated test suite
./scripts/run_mcp_tests.sh
./scripts/run_mcp_tests.sh --all    # include scan_hybrid (needs API key)
./scripts/run_mcp_tests.sh --json   # JSON output for CI
```

### Direct Client Usage

```bash
# Run automated test suite (server must already be running)
python3 -m mcp_server.test_client test

# Include AI-powered tools (needs CLAUDE_API_KEY)
python3 -m mcp_server.test_client test --all

# Test a single tool
python3 -m mcp_server.test_client test --tool scan_file

# Interactive REPL — call tools manually
python3 -m mcp_server.test_client interact

# List all tools with full schemas
python3 -m mcp_server.test_client list

# Benchmark latency
python3 -m mcp_server.test_client benchmark

# JSON output for CI/CD
python3 -m mcp_server.test_client test --json

# Point at a different repo
python3 -m mcp_server.test_client test --repo /path/to/repo
```

### Watching Live Progress (Tail the Log)

When using `run_mcp_shell.sh` or `run_mcp_tests.sh`, the server writes to `.mcp_server.log` in the project root. During long scans (e.g. `scan_hybrid`), the orchestrator streams its output to this log in real time.

**In a second terminal:**

```bash
tail -f .mcp_server.log
```

You'll see:
- API calls and token usage
- Prioritization and file selection
- Per-file analysis progress
- Any orchestrator errors (404/400, credential issues, etc.)

### Debug Mode

| What | How |
|------|-----|
| **Server debug** | `./scripts/run_mcp_shell.sh --debug` or `python3 -m mcp_server --debug` — enables DEBUG-level logging for the MCP server itself |
| **Orchestrator debug** | `export AGENTSMITH_MCP_DEBUG=1` before starting the server — `scan_hybrid` passes `--debug` to the orchestrator subprocess and includes `debug_log` in the response |
| **Both** | Use `--debug` on the shell script and set `AGENTSMITH_MCP_DEBUG=1` for full visibility |

### Interactive REPL Commands

When in `interact` mode, type `help` at the `mcp>` prompt for the full list. Quick reference:

| Command | Description |
|---------|-------------|
| `scan_static` | Static scan (repo auto-filled) |
| `scan_hybrid` | Hybrid scan; use `{"preset": "mcp"}` for 2 files (~1 min) |
| `summary` | Summarize last scan (severity counts, cost, artifacts) |
| `findings [N]` | List findings from last scan (default 20) |
| `annotations` | Show annotations from last scan |
| `payloads` | Show payload files from last scan |
| `scan_mcp` or `scan_mcp {"target_url": "..."}` | Security-scan a remote MCP server (prompts for URL if omitted) |
| `verbose` | Toggle verbose output (no truncation) |
| `repo [path]` | Show or set default repo |
| `status` | Show session config (server, repo, last output dir) |
| `last` | Show last result as full JSON |
| `quit` | Exit |

### Scan MCP Servers from the Shell

Yes — you can run `scan_mcp` directly from the interactive shell. It's the intended workflow.

```bash
# Terminal 1: Start shell (server + client)
./scripts/run_mcp_shell.sh

# Terminal 2 (optional): Start DVMCP targets for practice
./tests/test_dvmcp.sh --setup-only

# Back in Terminal 1, at mcp> prompt:
scan_mcp {"target_url": "http://localhost:9001/sse"}   # DVMCP challenge 1
scan_mcp {"target_url": "http://localhost:2266/sse"}   # Self-scan (audit your own server)
```

Type `scan_mcp` alone — if DVMCP is running on port 9001, it defaults to `http://localhost:9001/sse`; otherwise you'll be prompted for the URL. See [docs/MCP_SCANNING.md](../docs/MCP_SCANNING.md) for the full DVMCP walkthrough and security checks reference.

### Test Client Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTSMITH_MCP_READ_TIMEOUT` | `660` | Read timeout in seconds (11 min for long scans) |
| `AGENTSMITH_MCP_NOPAGER` | — | Set to `1` to disable paging (less) for long output |
| `AGENTSMITH_MCP_TEST_TARGET` | — | If set, adds `scan_mcp` test against this URL (e.g. `http://localhost:9001/sse` for DVMCP) |

## Configuration

All configuration via environment variables:

### Required (Production)

| Variable | Description |
|----------|-------------|
| `AGENTSMITH_MCP_TOKEN` | Bearer token for authentication |

### AI Provider

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTSMITH_PROVIDER` | `anthropic` | AI provider: `anthropic` or `bedrock` |
| `CLAUDE_API_KEY` | — | API key (when provider is `anthropic`) |
| `CLAUDE_MODEL` | `haiku` | Model to use: `opus`, `sonnet`, `haiku`, or full ID |
| `AWS_REGION` | `us-east-1` | AWS region (when provider is `bedrock`) |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTSMITH_MCP_HOST` | `0.0.0.0` | Host to bind to |
| `AGENTSMITH_MCP_PORT` | `2266` | Port to listen on |
| `AGENTSMITH_ALLOWED_PATHS` | cwd | Comma-separated allowed scan paths |
| `AGENTSMITH_CORS_ORIGINS` | `http://localhost:*` | CORS allowed origins |
| `AGENTSMITH_MCP_DEBUG` | — | Set to `1` or `true` to pass `--debug` to orchestrator in `scan_hybrid`; includes `debug_log` in response |
| `AGENTSMITH_HYBRID_TIMEOUT` | `600` | Timeout in seconds for `scan_hybrid` subprocess |

### Path Security

By default, the server only allows scanning files under the **current working directory** where it was started. To scan other directories:

```bash
# Allow scanning multiple directories
export AGENTSMITH_ALLOWED_PATHS="/home/user/projects,/home/user/repos"

# Allow everything under home
export AGENTSMITH_ALLOWED_PATHS="/home/user"

python3 -m mcp_server --no-auth
```

## CLI Options

```
python3 -m mcp_server [options]

Options:
  --port PORT          Port to listen on (default: 2266)
  --host HOST          Host to bind to (default: 0.0.0.0)
  --transport MODE     Transport: sse, http, or both (default: both)
  --no-auth            Disable bearer token auth (dev only)
  --debug              Enable debug logging
```

## Security

- **Bearer token auth**: All non-health endpoints require `Authorization: Bearer <token>`. Server refuses to start without `AGENTSMITH_MCP_TOKEN` unless `--no-auth` is used.
- **Path validation**: All `repo_path` and `file_path` parameters are resolved and checked against `AGENTSMITH_ALLOWED_PATHS`. Directory traversal via `..` is blocked.
- **File size limits**: Single-file operations limited to 1 MB. AI context limited to 100 KB.
- **Input limits**: String parameters have max length enforcement. Findings capped at 500 per request.
- **No open-by-default**: Auth is mandatory in production mode.
- **MCP scanner isolation**: `scan_mcp` runs the target connection in a subprocess to prevent async context leaks between the server and the scanned target.

### What `scan_mcp` Checks

| Check | What it catches | CWE |
|-------|----------------|-----|
| Transport security | HTTP vs HTTPS | CWE-319 |
| Authentication | No-auth servers | CWE-306 |
| Command/code execution | Tools with exec/shell/eval patterns | CWE-78 |
| File write/delete | Filesystem mutation tools | CWE-73 |
| Network/SSRF | Tools that fetch arbitrary URLs | CWE-918 |
| Database access | Raw SQL/query tools | CWE-89 |
| File read / path traversal | Unconstrained path parameters | CWE-22 |
| Environment access | Tools exposing env vars/config | CWE-200 |
| Auth/authz control | Tools managing permissions/tokens | CWE-287 |
| Credential exposure | Password/token/secret in parameters | CWE-522 |
| Excessive permissions | Tools combining read+write+delete | CWE-250 |
| Tool poisoning | Hidden instructions in descriptions | CWE-94 |
| Weak input validation | Missing maxLength, enum, min/max | CWE-20 |
| Sensitive resources | Resources with secret/key/password URIs | CWE-200 |

## Architecture

```
MCP Client (Cursor, Claude Desktop, custom)
    │
    ├── Streamable HTTP (/mcp/)
    │   └── StreamableHTTPSessionManager
    │
    ├── SSE (/sse + /messages/)
    │   └── SseServerTransport
    │
    v
mcp_server/server.py  (Starlette + uvicorn)
    │
    ├── auth.py          Bearer token middleware
    ├── config.py         Environment-based configuration
    └── tools.py          10 tool definitions + handlers
            │
            ├── scan_static       → Go scanner binary (70+ OWASP rules)
            ├── scan_file         → Go scanner (single file)
            ├── scan_hybrid       → orchestrator.py (static + AI)
            ├── detect_tech_stack → lib/universal_detector.py
            ├── summarize_results → output/ JSON files
            ├── list_findings     → output/ JSON files
            ├── list_presets      → lib/config.py
            ├── explain_finding   → Claude AI (detailed vulnerability explanation)
            ├── get_fix           → Claude AI (code fix generation)
            └── scan_mcp          → MCP client (connect + enumerate + analyze)
```

## Examples

### Health Check

```bash
curl http://localhost:2266/health
# {"status":"healthy","service":"agentsmith-mcp","tools":10}
```

### Scan a Single File via curl + MCP

```bash
# Via Streamable HTTP
curl -X POST http://localhost:2266/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}'
```

### Interactive Testing

```bash
python3 -m mcp_server.test_client interact

mcp> scan_file {"file_path": "/path/to/file.py"}
mcp> scan_mcp {"target_url": "http://localhost:2266/sse"}
mcp> explain_finding {"file_path": "/path/to/file.py", "description": "SQL injection", "line_number": 42}
mcp> get_fix {"file_path": "/path/to/file.py", "description": "hardcoded password on line 15"}
```

### DVMCP Test Suite (Damn Vulnerable MCP)

Scan deliberately vulnerable MCP servers ([DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server)):

```bash
# Clone DVMCP (one time)
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git tests/test_targets/DVMCP

# Scan all 10 challenges (launches servers, scans, reports, cleans up)
./tests/test_dvmcp.sh

# Scan specific challenges only
./tests/test_dvmcp.sh 1 8 9

# Just start the DVMCP servers (for manual testing)
./tests/test_dvmcp.sh --setup-only

# Kill all DVMCP servers
./tests/test_dvmcp.sh --kill
```

### Bedrock Provider

```bash
AGENTSMITH_PROVIDER=bedrock \
AWS_REGION=us-east-1 \
AGENTSMITH_MCP_TOKEN=secret \
python3 -m mcp_server
```
