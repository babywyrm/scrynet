# MCP Scanner Roadmap

Ideas and planned improvements for the Agent Smith MCP server and `scan_mcp` tool. Not a commitment — just a living backlog.

## Done (see docs/STRETCH_GOALS.md)

- Example CI config (`examples/ci-gate.yml`), pre-commit hook (`examples/pre-commit-hook.sh`)
- SARIF export, whitelist/ignore (`.scannerignore`, `--ignore-rules`)

## Current State

- **10 tools** exposed: scan_static, scan_file, scan_hybrid, detect_tech_stack, summarize_results, list_findings, list_presets, explain_finding, get_fix, scan_mcp
- **scan_mcp** does static analysis of MCP server surface: enumerate tools/resources/prompts, run 14+ heuristics, return risk score + findings
- **DVMCP** integration for testing against deliberately vulnerable targets

## Known Limitations (from docs/MCP_SCANNING.md)

- Static analysis only — does not call tools or test for actual exploitation
- Cannot detect runtime behavior changes (e.g., rug pull attacks after N calls)
- Tool poisoning detection relies on keyword patterns, not semantic analysis
- Resource content is not inspected (only URI and metadata)

---

## Projected Table of Advancements

Organized by phase. Effort: **T** = Trivial, **L** = Low, **M** = Medium, **H** = High.

### Phase 1 — Quick Wins (T/L, high impact)

| Advancement | Effort | Description |
|-------------|--------|-------------|
| **SARIF output** | L | Export scan_mcp findings as SARIF for IDE/CI integration |
| **CI-friendly exit codes** | L | Option to exit non-zero when `risk_score` ≥ CRITICAL or HIGH |
| **Example CI config** | T | GitHub Actions / GitLab CI snippet for scan_mcp in README or `examples/` |
| **`scan_mcp` shortcut with default** | T | If DVMCP running, `scan_mcp` (no args) defaults to `http://localhost:9001/sse` |
| **Whitelist / ignore patterns** | L | Config (file or env) to suppress known false positives per finding ID or pattern |
| **DVMCP scoreboard** | L | Auto-run all 10 DVMCP challenges, report pass/fail per challenge, optional JSON output |

### Phase 2 — scan_mcp Enhancements (L/M)

| Advancement | Effort | Description |
|-------------|--------|-------------|
| **Batch scan mode** | L | `scan_mcp` accepts list of URLs or path to file; scan multiple servers in one run |
| **Batch scan from shell** | L | `scan_mcp url1 url2` or `scan_mcp_batch urls.txt` in interactive REPL |
| **More auth types** | L | Support API key header, X-API-Key, OAuth flow hints beyond Bearer token |
| **Differential scanning** | M | Store baseline (JSON), diff on re-scan — detect tool/resource definition changes over time |
| **Resource content sampling** | M | Optional: fetch resource content for sensitive URIs, flag exposed secrets/keys |
| **Prompt-injection pattern check** | L | Add heuristics for "ignore previous instructions", "disregard", etc. in tool descriptions |

### Phase 3 — Deeper Analysis (M/H)

| Advancement | Effort | Description |
|-------------|--------|-------------|
| **AI-powered description analysis** | M | Use Claude to detect subtle tool poisoning, hidden instructions, misleading descriptions |
| **Active probing mode** | H | Safe, non-destructive tool calls (e.g., read-only with sandboxed args) to verify findings |
| **agentgateway integration** | H | Use [agentgateway](https://github.com/agentgateway/agentgateway) for runtime traffic analysis |
| **Schema drift detection** | M | Compare tool params across scans; flag new required params, removed params, type changes |

### Phase 4 — Platform & Ecosystem (L/H)

| Advancement | Effort | Description |
|-------------|--------|-------------|
| **Pre-commit / CI hook** | L | Example script: scan your own MCP server before merge; fail on CRITICAL |
| **Metrics endpoint** | L | Prometheus `/metrics` for request counts, scan latency, tool usage |
| **Docker image** | L | Official `agentsmith-mcp` image for easy deployment |
| **WebSocket transport** | H | Support MCP over WebSocket when spec stabilizes |
| **Video walkthrough** | — | Short demo: run_mcp_shell → scan_mcp → DVMCP (docs/YouTube) |

### Phase 5 — Research & Exploration

| Advancement | Effort | Description |
|-------------|--------|-------------|
| **Runtime behavior detection** | H | Detect rug-pull style attacks (tool behavior changes after N calls) — requires stateful probing |
| **CVE / advisory check** | M | Check server version or metadata against known MCP-related CVEs (if registry exists) |
| **Property-based tests** | M | Fuzz scan_mcp heuristics; golden-file tests for DVMCP outputs |

---

## Ideas Backlog (Unprioritized)

- Rate limiting per client on MCP server
- Request/response audit logging (opt-in, for compliance)
- VSCode extension for Cursor integration (beyond .cursor/mcp.json)
- Terraform/Pulumi module for cloud deployment
- Slack/Teams webhook on critical findings (scan_hybrid + scan_mcp)

---

## Already Done (for reference)

- Real-time orchestrator output via `tail -f .mcp_server.log`
- `AGENTSMITH_MCP_DEBUG` for orchestrator debug
- `mcp` preset for fast MCP-optimized scans
- DVMCP test suite (`test_dvmcp.sh`)
- Interactive shell with `scan_mcp` from `mcp>` prompt
- Self-scan (audit your own server)
- MCP client docs (tail log, debug mode, scan_mcp from shell)

---

*Last updated: 2025-02*
