# mcp_attack Changelog

All notable changes to this submodule are documented here.

## [Unreleased] - 2026-02

### Added

- **Differential scanning**
  - `--baseline FILE` — Compare current scan to saved baseline
  - `--save-baseline FILE` — Save current scan as baseline for future comparison
  - Reports added/removed/modified tools, resources, prompts
  - New tools flagged as MEDIUM findings for security review
  - `mcp_attack/diff.py` — `load_baseline`, `save_baseline`, `diff_against_baseline`, `print_diff_report`

- **New security checks**
  - `check_rate_limit` — Flags tools that suggest unbounded or unthrottled usage (e.g. "unlimited requests", "no rate limit")
  - `check_prompt_leakage` — Flags tools that may echo, log, or expose user prompts or internal instructions
  - `check_supply_chain` — Flags tools that install packages from user-controlled or dynamic URLs (e.g. `curl | bash`, "user-provided URL")

- **New pattern sets**
  - `RATE_LIMIT_PATTERNS` — 5 patterns for rate-limit abuse
  - `PROMPT_LEAKAGE_PATTERNS` — 8 patterns for prompt exposure
  - `SUPPLY_CHAIN_PATTERNS` — 9 patterns for supply-chain risks

- **CLI options**
  - `--targets-file FILE` — Read target URLs from file (one per line, `#` comments ignored)
  - `--public-targets` — Use built-in list in `data/public_targets.txt` (DVMCP localhost URLs)

- **Data**
  - `data/public_targets.txt` — Built-in targets for DVMCP (localhost:9001–9005)

- **Test suite**
  - `tests/` — Pytest suite (38 tests) for checks, CLI, patterns, diff, and integration

### Changed

- `parse_args()` now accepts optional `args` for testability
- **Streamable HTTP support** — Scanner now handles MCP servers using Streamable HTTP (e.g. DeepWiki at `https://mcp.deepwiki.com/mcp`). Accepts `application/json` and `text/event-stream` responses; parses SSE-formatted POST responses.

---

## Planned

### Quick wins

- **DVMCP scoreboard** — Auto-run all 10 DVMCP challenges, report pass/fail per challenge, optional JSON output
- **Batch scan** — `scan_mcp url1 url2` or `scan_mcp_batch urls.txt` from main Agent Smith

### Medium effort

- ~~**Differential MCP scanning**~~ — ✓ Done. `--baseline` and `--save-baseline`
- **AI-powered MCP description analysis** — Use Claude to detect subtle tool poisoning, hidden instructions, misleading descriptions
- **SARIF export** — Export findings as SARIF for IDE/CI (VS Code, GitHub Code Scanning)

### Larger investments

- **Docker image** — Official `agentsmith-mcp` image for easy deployment
- **Metrics endpoint** — Prometheus `/metrics` for request counts, scan latency, tool usage
- **Attack chain profiling** — AI-driven synthesis of findings into multi-step attack paths
- **MCP registry** — Curated list of public MCP servers for periodic scanning
- **Fuzzing / live probing** — Malformed MCP messages, injection payloads into tool names/descriptions
