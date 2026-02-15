# Agent Smith — Stretch Goals & Holistic Improvements

A consolidated view of improvement opportunities across the tool. Prioritized by impact and effort.

---

## Summary: What's Done

| Area | Status |
|------|--------|
| Static → Prioritization | ✓ Done (PromptFactory uses static_findings) |
| Node/Mongoose/Modern rules | ✓ Done (Prisma, React, Go, Ruby, Java, Python) |
| MCP shell (repo, findings source) | ✓ Done (scan_static persists, output_dir shown) |
| Rules validation | ✓ Done (scripts/validate_rules.py) |
| Rules changelog | ✓ Done |
| Tech-stack-aware rules | ✓ Done (rules_node/rules_python loaded when detected) |
| SARIF export | ✓ Done (--output sarif) |
| Whitelist/ignore | ✓ Done (.scannerignore, --ignore-rules) |
| Pre-commit example | ✓ Done (examples/pre-commit-hook.sh) |

---

## Tier 1 — Quick Wins (T/L effort, high impact)

### 1.1 CTF prioritization + static findings ✓
**Done.** `CTFPromptFactory.prioritization()` now accepts `static_findings` (optional). Mirrors `PromptFactory`; callers can pass when available.

### 1.2 SARIF export for scan_mcp
**From MCP ROADMAP.** Export scan_mcp findings as SARIF for IDE/CI (VS Code, GitHub Code Scanning).

### 1.3 CI-friendly exit codes ✓
**Done.** `agentsmith.py static --fail-on HIGH` (or CRITICAL) passes `--exit-high` to the Go scanner; exits 1 if any HIGH/CRITICAL findings. Go scanner now exits on both severities.

### 1.4 Example CI config ✓
**Done.** `examples/ci-gate.yml` — GitHub Actions workflow for static scan with `--fail-on HIGH`.

### 1.5 Whitelist / ignore patterns ✓
**Done.** `.scannerignore` (lines `rule:RuleName`), `--ignore-rules`, and `AGENTSMITH_IGNORE_RULES` env var.

---

## Tier 2 — Medium Effort, High Value

### 2.1 Tech-stack-aware rule loading ✓
**Done.** If `package.json` → load `rules_node.json`. If `requirements.txt` → load `rules_python.json`. Reduces noise and adds framework-specific patterns (child_process, vm, pickle, yaml).

### 2.2 Batch scan_mcp
**From MCP ROADMAP.** `scan_mcp url1 url2` or `scan_mcp_batch urls.txt`. Scan multiple MCP servers in one run.

### 2.3 DVMCP scoreboard
Auto-run all 10 DVMCP challenges, report pass/fail per challenge, optional JSON output. Good for regression testing.

### 2.4 Narrow Axios/Go SSRF rules
**From Static Strategy Phase 5.** Current rules flag every `axios.get()` / `http.Get()` — very noisy. Narrow to dynamic URL (template literal, variable) to reduce false positives.

### 2.5 Pre-commit / CI hook example ✓
**Done.** `examples/pre-commit-hook.sh` and `examples/.pre-commit-config.yaml` — scan repo before commit, fail on CRITICAL (or HIGH via `AGENTSMITH_FAIL_ON`).

---

## Tier 3 — Larger Investments

### 3.1 Context-aware rules (Static Strategy Phase 3)
Rules that require "source + sink" — e.g., `req.body` flowing into `findByIdAndUpdate`. Needs multi-line or AST analysis (Semgrep-style).

### 3.2 Differential MCP scanning
**From MCP ROADMAP.** Store baseline (JSON), diff on re-scan — detect tool/resource definition changes over time.

### 3.3 AI-powered MCP description analysis
**From MCP ROADMAP.** Use Claude to detect subtle tool poisoning, hidden instructions, misleading descriptions.

### 3.4 Docker image
**From MCP ROADMAP.** Official `agentsmith-mcp` image for easy deployment.

### 3.5 Metrics endpoint
**From MCP ROADMAP.** Prometheus `/metrics` for request counts, scan latency, tool usage.

### 3.6 Attack chain profiling (advanced, opt-in)
**Design.** The engine logically pieces together an entire attack chain through a target. Not default—enabled via `--show-chains` or a dedicated `profile_attack_chains` mode.

**Existing pieces:**
- `lib/taint_tracker.py` — `TaintAnalyzer`, `TaintTracker` (source → sink)
- `lib/flow_visualizer.py` — ASCII diagrams for taint flows
- `orchestrator.run_attack_chain_analysis()` — `--show-chains` flag

**Proposed extension:**
- AI-driven synthesis of findings + taint flows into coherent attack paths
- Multi-step chains (e.g. XSS → session theft → admin access)
- Optional "attack path profiling" mode that builds full paths from entry points to crown jewels
- Output: structured attack chains (JSON/Markdown) with step-by-step exploitability

---

## Tier 4 — Research & Exploration

- Runtime behavior detection (rug-pull style attacks)
- Active probing mode for scan_mcp (safe, non-destructive tool calls)
- CVE / advisory check for MCP-related vulnerabilities
- WebSocket transport when MCP spec stabilizes

---

## Recommended Next Steps

1. ~~**CTF + static findings** (1.1)~~ ✓ Done.
2. ~~**CI exit codes** (1.3)~~ ✓ Done.
3. ~~**Example CI config** (1.4)~~ ✓ Done.
4. ~~**Whitelist/ignore** (1.5)~~ ✓ Done.
5. ~~**SARIF export** (1.2)~~ ✓ Done.
6. ~~**Pre-commit example** (2.5)~~ ✓ Done.
7. **Narrow Axios/Go SSRF rules** (2.4) — Reduce false positives on static URLs.

---

## References

- [MCP ROADMAP](../mcp_server/ROADMAP.md)
- [STATIC_SCANNER_STRATEGY](STATIC_SCANNER_STRATEGY.md)
- [rules/CHANGELOG](../rules/CHANGELOG.md)
