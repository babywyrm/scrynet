# Agent Smith Quick Start

Copy-paste commands for the most common use cases. For detailed workflows and explanations, see [docs/USE_CASES.md](docs/USE_CASES.md).

**Prerequisites:** Run `./scripts/setup.sh` and `source scripts/activate.sh`. For AI modes, `export CLAUDE_API_KEY="sk-ant-..."`.

---

## CLI Use Cases

### 1. Quick static scan (no API key)

```bash
python3 agentsmith.py static . --severity HIGH
```

~5 sec · Free · CI/CD, pre-commit, quick audits

---

### 2. List options & detect tech stack

```bash
python3 orchestrator.py --list-presets
python3 orchestrator.py --list-profiles
python3 orchestrator.py ./myapp --detect-tech-stack
```

First-time setup, exploring a new codebase

---

### 3. CTF fast recon

```bash
python3 orchestrator.py ./ctf-challenge ./scanner --preset ctf-fast
```

~1–2 min · ~$0.02–0.03 · Top 8 files · Quick wins

---

### 4. Full CTF analysis

```bash
python3 orchestrator.py ./ctf-challenge ./scanner --preset ctf --show-chains
```

~3–5 min · ~$0.06–0.10 · Top 15 files · Attack chains, payloads

---

### 5. Targeted vulnerability hunt

```bash
python3 orchestrator.py ./webapp ./scanner --preset ctf \
  --question "find SQL injection in database queries and API endpoints" \
  --show-chains --top 8
```

~2–3 min · Focused on specific vuln types

---

### 6. Production security audit

```bash
python3 orchestrator.py ./production-app ./scanner \
  --preset security-audit \
  --output-dir ./reports/prod-audit
```

~10–20 min · ~$0.15–0.30 · All files · OWASP + Code Review

---

### 7. CI/CD gate

```bash
python3 orchestrator.py ./src ./scanner --preset quick --severity HIGH --output-dir ./security-reports
```

~30–60 sec · ~$0.01–0.02 · JSON for automation

---

### 8. Resume interrupted review

```bash
python3 agentsmith.py analyze . --list-reviews
python3 agentsmith.py analyze ./app "question" --resume-last
python3 agentsmith.py analyze ./app --resume-review abc123
```

Large codebases, interrupted scans

---

### Framework-Specific Scans

```bash
# Spring Boot / Java microservices
python3 orchestrator.py ./spring-app ./scanner --profile springboot,owasp --prioritize --prioritize-top 25

# C++ / Conan native code (memory safety, supply-chain)
python3 orchestrator.py ./cpp-project ./scanner --profile cpp_conan --prioritize --prioritize-top 30

# Flask / Python web app (SSTI, SQLAlchemy, debug mode)
python3 orchestrator.py ./flask-app ./scanner --profile flask,owasp --prioritize --prioritize-top 20
```

~3-10 min · Profile-specific prioritization automatically guides file selection

---

## MCP Shell Use Cases

Start the interactive shell:

```bash
./scripts/run_mcp_shell.sh
```

At the `mcp>` prompt:

### 9. Hybrid scan (static + AI)

```
mcp> scan_hybrid preset=mcp
mcp> scan_hybrid profile=springboot preset=quick
```

2 files · ~1 min · Good for Cursor/IDE integration

---

### 10. Static scan only (no API key)

```
mcp> scan_static
```

Uses default repo. Fast, free.

---

### 11. Scan another MCP server

```
mcp> scan_mcp {"target_url": "http://localhost:9001/sse"}
```

DVMCP, or audit any MCP server. Type `scan_mcp` alone to be prompted for URL.

---

### 12. List findings & summary

```
mcp> summary
mcp> findings 20
```

After a scan: severity counts, cost, top N findings.

---

## Preset quick reference

| Preset        | Files | Time      | Cost      |
|---------------|-------|-----------|-----------|
| `mcp`         | 2     | ~1 min    | ~$0.01    |
| `quick`       | 10    | ~1 min    | ~$0.02    |
| `ctf-fast`    | 8     | ~2 min    | ~$0.03    |
| `ctf`         | 15    | ~3–5 min  | ~$0.06–0.10 |
| `security-audit` | ALL | ~10–20 min | ~$0.15–0.30 |
| `pentest`     | 20    | ~5–10 min | ~$0.15–0.25 |

---

## More

- **Detailed workflows:** [docs/USE_CASES.md](docs/USE_CASES.md)
- **MCP server:** [mcp_server/README.md](mcp_server/README.md)
- **CI / pre-commit:** [examples/README.md](examples/README.md)
