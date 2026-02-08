# Agent Smith MCP Server

Model Context Protocol (MCP) server that exposes Agent Smith's security scanning tools over SSE (Server-Sent Events) HTTP transport.

## Quick Start

```bash
# Install MCP dependencies
pip install -r mcp_server/requirements.txt

# Start the server (dev mode, no auth)
python3 -m mcp_server --no-auth

# Start with authentication (production)
export AGENTSMITH_MCP_TOKEN=your-secret-token
python3 -m mcp_server
```

The server starts on port 2266 by default.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (no auth required) |
| `/ready` | GET | Readiness check - verifies scanner binary (no auth required) |
| `/sse` | GET | SSE connection for MCP clients |
| `/messages/` | POST | MCP message handler |

## Available Tools

| Tool | Description |
|------|-------------|
| `scan_static` | Run static analysis with 70+ OWASP rules (no API key needed) |
| `scan_hybrid` | Full hybrid scan: static + AI analysis (requires API key or Bedrock) |
| `detect_tech_stack` | Detect languages, frameworks, entry points, and security risks |
| `summarize_results` | Summarize existing scan output with severity counts and cost |
| `list_findings` | Get findings filtered by severity, source, with pagination |
| `list_presets` | List available scan preset configurations |

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
| `CLAUDE_API_KEY` | - | API key (when provider is `anthropic`) |
| `AWS_REGION` | `us-east-1` | AWS region (when provider is `bedrock`) |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTSMITH_MCP_HOST` | `0.0.0.0` | Host to bind to |
| `AGENTSMITH_MCP_PORT` | `2266` | Port to listen on |
| `AGENTSMITH_ALLOWED_PATHS` | cwd | Comma-separated allowed repo paths |
| `AGENTSMITH_CORS_ORIGINS` | `http://localhost:*` | CORS allowed origins |

## CLI Options

```
python3 -m mcp_server [options]

Options:
  --port PORT    Port to listen on (default: 2266)
  --host HOST    Host to bind to (default: 0.0.0.0)
  --no-auth      Disable bearer token auth (dev only)
  --debug        Enable debug logging
```

## Security

- **Bearer token auth**: All non-health endpoints require `Authorization: Bearer <token>`. Server refuses to start without `AGENTSMITH_MCP_TOKEN` unless `--no-auth` is used.
- **Path validation**: All `repo_path` parameters are resolved and checked against `AGENTSMITH_ALLOWED_PATHS`. Directory traversal via `..` is blocked.
- **Input limits**: String parameters have max length enforcement. Finding results are capped at 500 per request.
- **No open-by-default**: Auth is mandatory in production mode.

## Examples

### Test with curl

```bash
# Health check
curl http://localhost:2266/health

# Readiness check
curl http://localhost:2266/ready

# SSE connection (will stream events)
curl -N http://localhost:2266/sse
```

### Bedrock Provider

```bash
# Use AWS Bedrock instead of direct Anthropic API
AGENTSMITH_PROVIDER=bedrock \
AWS_REGION=us-east-1 \
AGENTSMITH_MCP_TOKEN=secret \
python3 -m mcp_server
```

### EKS Deployment (Future)

The server is designed for container deployment:
- `/health` and `/ready` endpoints for k8s probes
- All config via environment variables
- Stateless design (output goes to filesystem or could be adapted for S3)
- Binds to `0.0.0.0` by default

## Architecture

```
MCP Client (Claude, Cursor, custom)
    |
    | SSE (HTTP)
    v
mcp_server/server.py  (Starlette + uvicorn)
    |
    +-- auth.py        (Bearer token middleware)
    +-- tools.py       (Tool definitions + handlers)
    |       |
    |       +-- scan_static    --> Go scanner binary
    |       +-- scan_hybrid    --> orchestrator.py
    |       +-- detect_tech    --> lib/universal_detector.py
    |       +-- summarize      --> output/ JSON files
    |       +-- list_findings  --> output/ JSON files
    |       +-- list_presets   --> lib/config.py
    |
    +-- config.py      (Environment-based configuration)
```
