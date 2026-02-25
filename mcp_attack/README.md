# mcp_attack — MCP Red Teaming Scanner

Standalone MCP security scanner for red teaming and auditing. Not yet integrated into the main Agent Smith codebase. Use with [DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server) or any MCP server.

## Install

**Option A — Use project venv (recommended):**
```bash
cd agentsmith                    # project root
source .venv/bin/activate        # or: source scripts/activate.sh
python3 mcp_attack/mcp_audit.py --targets http://localhost:2266
```

**Option B — Standalone venv:**
```bash
cd agentsmith/mcp_attack
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 mcp_audit.py --targets http://localhost:2266
```

## Usage

```bash
# From inside mcp_attack/ (or anywhere)
python3 mcp_audit.py --targets http://localhost:2266

# From project root (agentsmith/)
python3 mcp_attack/mcp_audit.py --targets http://localhost:2266
python3 -m mcp_attack --targets http://localhost:2266

# DVMCP port range (challenges 1–10)
python3 mcp_audit.py --port-range localhost:9001-9010 --verbose

# Targets from file (one URL per line)
python3 mcp_audit.py --targets-file urls.txt

# Built-in public targets (DVMCP localhost)
python3 mcp_audit.py --public-targets

# JSON report
python3 mcp_audit.py --port-range localhost:9001-9010 --json report.json

# Debug output
python3 mcp_audit.py --targets http://localhost:2266 --debug
```

**Note:** Use `python3` (not `python`). If dependencies are missing, use the project venv: `source .venv/bin/activate` from the agentsmith root, or `pip install httpx rich` in a venv.

## Structure

```
mcp_attack/
├── core/           # Models, session, enumerator, constants
├── patterns/       # Regex rules for injection, poisoning, etc.
├── checks/         # Security checks (injection, theft, execution, rate_limit, prompt_leakage, supply_chain, …)
├── data/           # Built-in public_targets.txt
├── k8s/            # Kubernetes internal checks (optional)
├── reporting/      # Console + JSON output
├── tests/          # Pytest suite
├── scanner.py      # Orchestration
├── cli.py          # Argument parsing
└── __main__.py     # Entry point
```

## Tests

```bash
# From project root
python -m pytest mcp_attack/tests/ -v
```

## Testing with DVMCP

1. Clone DVMCP: `git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git tests/test_targets/DVMCP`
2. Start DVMCP: `./tests/test_dvmcp.sh --setup-only`
3. Run scanner: `python -m mcp_attack --port-range localhost:9001-9010 --verbose`

## Exit Code

Exits 1 if any CRITICAL or HIGH findings; 0 otherwise.
