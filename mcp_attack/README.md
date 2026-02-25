# mcp_attack — MCP Red Teaming Scanner

Standalone MCP security scanner for red teaming and auditing. Not yet integrated into the main Agent Smith codebase. Use with [DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server) or any MCP server.

**See [CHANGELOG.md](CHANGELOG.md) for recent changes and planned work.**

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

# Differential scan (compare to baseline)
python3 mcp_audit.py --targets http://localhost:9001 --baseline baseline.json

# Save baseline for future differential scans
python3 mcp_audit.py --targets http://localhost:9001 --save-baseline baseline.json

# Debug output
python3 mcp_audit.py --targets http://localhost:2266 --debug
```

**Note:** Use `python3` (not `python`). If dependencies are missing, use the project venv: `source .venv/bin/activate` from the agentsmith root, or `pip install httpx rich` in a venv.

## Quickstart Scenarios

Copy-paste commands for common workflows. All assume you're in the agentsmith root with `source .venv/bin/activate` (or `source scripts/activate.sh`).

### 1. Single target scan

```bash
python3 -m mcp_attack --targets http://localhost:2266
```

Scan one MCP server. Use your own MCP server URL or Agent Smith MCP (port 2266) for a self-audit.

### 2. DeepWiki (remote, no-auth)

```bash
python3 -m mcp_attack --targets https://mcp.deepwiki.com/mcp
```

Scans [DeepWiki](https://docs.devin.ai/work-with-devin/deepwiki-mcp) — a public MCP server. Use `/mcp` (Streamable HTTP), not `/sse` (deprecated).

### 3. DVMCP port range (all challenges)

```bash
# Start DVMCP first: ./tests/test_dvmcp.sh --setup-only
python3 -m mcp_attack --port-range localhost:9001-9010 --verbose
```

Scans DVMCP challenges 1–10. Add `--json report.json` to save findings.

### 4. Targets from file

```bash
echo "http://localhost:9001/sse" > urls.txt
echo "http://localhost:9002/sse" >> urls.txt
python3 -m mcp_attack --targets-file urls.txt
```

One URL per line; `#` comments ignored.

### 5. Built-in public targets

```bash
python3 -m mcp_attack --public-targets
```

Uses `mcp_attack/data/public_targets.txt` (DVMCP localhost:9001–9005). Run DVMCP first.

### 6. JSON report

```bash
python3 -m mcp_attack --port-range localhost:9001-9010 --json dvmcp_report.json
```

Writes full report to JSON. Output path is gitignored.

### 7. Differential scan (baseline → compare)

```bash
# First scan: save baseline
python3 -m mcp_attack --targets http://localhost:9001 --save-baseline baseline.json

# Later: compare against baseline (detects new/removed/modified tools)
python3 -m mcp_attack --targets http://localhost:9001 --baseline baseline.json
```

Reports added/removed/modified tools, resources, prompts. New tools flagged as MEDIUM for review.

### 8. Run tests

```bash
python -m pytest mcp_attack/tests/ -v
```

38 tests: checks (rate_limit, prompt_leakage, supply_chain), CLI, diff, patterns.

### 9. Debug mode

```bash
python3 -m mcp_attack --targets http://localhost:2266 --debug
```

Verbose output for troubleshooting.

---

## Differential Scanning

Compare current scan to a saved baseline to detect changes (new tools, removed tools, modified descriptions):

```bash
# First scan: save baseline
python3 mcp_audit.py --targets http://localhost:9001 --save-baseline baseline.json

# Later: compare against baseline
python3 mcp_audit.py --targets http://localhost:9001 --baseline baseline.json
```

Reports added/removed/modified tools, resources, and prompts. New tools are flagged as MEDIUM findings for security review.

## Structure

```
mcp_attack/
├── core/           # Models, session, enumerator, constants
├── patterns/       # Regex rules for injection, poisoning, etc.
├── checks/         # Security checks (injection, theft, execution, rate_limit, prompt_leakage, supply_chain, …)
├── data/           # Built-in public_targets.txt
├── diff.py         # Differential scanning (baseline save/load, diff)
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

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and planned work.
