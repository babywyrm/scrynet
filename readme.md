# Agent Smith - Unified Security Scanner

> Do you hate reviews?  
> Do you love CTFs?  
> Do you hate java controllers?  
> Do you love having more time to not look at screens?  
> Do you miss the 90s?

---

**Agent Smith** is a comprehensive, multi-mode security scanning tool that combines fast static analysis with AI-powered contextual analysis. It supports multiple scanning modes optimized for different use cases, from quick CI/CD checks to deep security audits.

**→ [QUICKSTART.md](QUICKSTART.md)** — Copy-paste commands for the top 12 use cases (CLI + MCP shell).

## What's New

- **AI Prioritization**: Automatically selects top N most relevant files (saves time & API costs)
- **Payload Generation**: Creates Red/Blue team payloads for vulnerability verification
- **Code Annotations**: Shows vulnerable code with inline fixes and recommendations
- **Rich UI**: Beautiful colors, spinners, and progress bars with real-time feedback
- **Multiple Export Formats**: JSON, CSV, Markdown, and HTML reports
- **Precise Location Tracking**: File paths and line numbers in all outputs
- **Unified CLI**: Single entry point (`agentsmith.py`) for all modes
- **Auto-loaded Rules**: 70+ OWASP rules from `rules/`; tech-stack-aware (Node/Python rules when detected)
- **Preset System**: 7 optimized presets for common workflows (`--preset mcp`, `--preset ctf`, `--preset pentest`, etc.)
- **Smart Defaults**: Auto-prioritization, auto-deduplication, and smart top-n

## Features

### Core Capabilities

- **Multi-Language Support**: Go, JavaScript, Python, Java, PHP, HTML, YAML, Helm templates
- **Multiple Scanning Modes**: Static-only, AI-powered analysis, CTF-focused, and hybrid
- **OWASP Top 10 Coverage**: 70+ security rules across 5 rule files
- **AI-Powered Analysis**: Claude AI integration for contextual vulnerability detection
- **Smart Prioritization**: AI selects most relevant files (saves time & cost)
- **Payload Generation**: Red/Blue team payloads for verification
- **Code Annotations**: Inline code fixes and recommendations
- **Rich UI**: Colors, spinners, progress bars, real-time feedback
- **Review State Management**: Resume interrupted reviews, track progress
- **API Caching**: Speed up repeated runs with intelligent caching
- **Cost Tracking**: Monitor API usage and costs
- **Multiple Output Formats**: Console, HTML, Markdown, JSON, CSV
- **Precise Tracking**: File paths and line numbers in all outputs

## Installation

### Quick Setup (Recommended)

```bash
git clone https://github.com/babywyrm/agentsmith.git
cd agentsmith

# Run the setup script (builds Go scanner + Python environment)
./scripts/setup.sh

# Activate the environment
source scripts/activate.sh

# Set your API key (required for AI-powered modes)
export CLAUDE_API_KEY="sk-ant-api03-..."
```

The setup script handles everything:
- Detects and builds the Go scanner binary
- Creates a Python virtual environment
- Installs all Python dependencies
- Verifies the environment is ready

### Manual Setup

If you prefer manual setup:

```bash
# 1. Build the Go scanner binary (requires Go 1.21+)
go build -o scanner agentsmith.go

# 2. Set up Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Set your API key
export CLAUDE_API_KEY="sk-ant-api03-..."
```

### Setup Options

```bash
./scripts/setup.sh             # Full setup (Go + Python)
./scripts/setup.sh --python    # Python-only (skip Go build)
./scripts/setup.sh --go        # Go-only (build scanner binary)
```

## Usage

Agent Smith provides a unified entry point with multiple scanning modes:

### Unified Entry Point

**`agentsmith.py` is the main entry point for all Agent Smith operations.**

```bash
python3 agentsmith.py <mode> [options]
```

### Available Modes

#### 1. Static Mode (Fast, Free)

Fast static analysis using only the Go scanner - perfect for CI/CD:

```bash
python3 agentsmith.py static /path/to/repo --severity HIGH --output json
```

**Features:**
- No API costs
- Very fast execution
- CI/CD friendly
- Custom rule sets

**Options:**
- `--rules`: Comma-separated rule files
- `--severity`: Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
- `--output`: Output format (text, json, markdown, sarif)
- `--verbose`: Show remediation advice
- `--git-diff`: Scan only changed files
- `--ignore`: Comma-separated glob patterns
- `--ignore-rules`: Suppress specific rules (or use `.scannerignore`)
- `--fail-on`: Exit 1 on CRITICAL/HIGH (for CI gates)

#### 2. Analyze Mode (AI-Powered)

Comprehensive AI analysis with multi-stage pipeline:

```bash
python3 agentsmith.py analyze /path/to/repo "find security vulnerabilities" \
  --generate-payloads \
  --top-n 10 \
  --enable-review-state
```

**Features:**
- Multi-stage analysis (Prioritization -> Deep Dive -> Synthesis)
- Review state management
- API caching
- Cost tracking
- Multiple output formats

**Key Options:**
- `--ctf-mode`: Enable CTF-focused analysis (see CTF Mode below)
- `--generate-payloads`: Generate exploitation/test payloads
- `--annotate-code`: Add code annotations with fixes
- `--top-n N`: Limit to top N findings
- `--enable-review-state`: Enable review state tracking
- `--resume-last`: Auto-resume last matching review
- `--include-yaml`: Include YAML files
- `--include-helm`: Include Helm templates
- `--format`: Output formats (console, html, markdown, json)

#### 3. CTF Mode (Exploitation-Focused)

Optimized for Capture The Flag challenges:

```bash
python3 agentsmith.py ctf /path/to/ctf "find all vulnerabilities" \
  --generate-payloads \
  --top-n 10
```

**Features:**
- Prioritizes entry points (login, upload, APIs)
- Focuses on exploitable vulnerabilities
- Generates CTF-ready exploitation payloads
- Highlights potential flags and secrets
- Separate cache namespace

#### 4. Hybrid Mode (Static + AI) -- **RECOMMENDED**

Combines fast static scanning with AI analysis - best of both worlds:

```bash
python3 orchestrator.py /path/to/repo ./scanner \
  --profile owasp \
  --prioritize \
  --prioritize-top 20 \
  --question "find SQL injection vulnerabilities" \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html markdown \
  --output-dir ./reports \
  --verbose
```

**Features:**
- Runs Go scanner + AI analysis
- **Auto-loaded Rules**: All 70+ rules from `rules/` loaded automatically
- **AI Prioritization**: Selects top N most relevant files (saves time & cost)
- **Payload Generation**: Creates Red/Blue team payloads for verification
- **Code Annotations**: Shows vulnerable code with inline fixes
- Merges and deduplicates findings
- Multiple AI profiles
- Threat modeling support
- **Rich UI**: Colors, spinners, progress bars, real-time feedback
- **Multiple Export Formats**: JSON, CSV, Markdown, HTML

**Key Options:**
- `--profile`: AI analysis profiles (comma-separated, default: owasp)
- `--preset`: Use a preset configuration (mcp, quick, ctf, ctf-fast, security-audit, pentest, compliance)
- `--prioritize`: Enable AI prioritization (HIGHLY RECOMMENDED for 50+ files)
- `--prioritize-top N`: Number of files to prioritize (default: 15)
- `--question "..."`: Guides prioritization (be specific!)
- `--generate-payloads`: Generate Red/Blue team payloads
- `--annotate-code`: Generate annotated code snippets
- `--top-n N`: Number of findings for payloads/annotations (default: 5)
- `--static-rules`: Override auto-loaded rules with custom rule files
- `--export-format`: Report formats (json, csv, markdown, html)
- `--output-dir`: Custom output directory (default: ./output)
- `--severity`: Minimum severity filter
- `--threat-model`: Perform threat modeling
- `--parallel`: Run AI analysis in parallel
- `--verbose`: Show colors, spinners, and detailed progress
- `--show-quick-wins`: Highlight most exploitable findings

### Presets

One-command configurations for common workflows:

```bash
# MCP-optimized (2 files, ~1 min — for MCP shell / Cursor)
python3 orchestrator.py /path/to/repo ./scanner --preset mcp

# Quick scan (fast, minimal output)
python3 orchestrator.py /path/to/repo ./scanner --preset quick

# CTF challenge analysis
python3 orchestrator.py /path/to/repo ./scanner --preset ctf

# Full security audit
python3 orchestrator.py /path/to/repo ./scanner --preset security-audit

# Penetration testing
python3 orchestrator.py /path/to/repo ./scanner --preset pentest

# List all presets
python3 orchestrator.py --list-presets
```

## Examples

### Quick Security Scan

```bash
# Fast static scan
python3 agentsmith.py static . --severity HIGH

# Comprehensive AI analysis
python3 agentsmith.py analyze . "find security vulnerabilities" \
  --top-n 5 \
  --generate-payloads
```

### CTF Challenge Analysis

```bash
python3 agentsmith.py ctf ./ctf-challenge \
  "find all exploitable vulnerabilities" \
  --ctf-mode \
  --generate-payloads \
  --top-n 15 \
  --max-files 20
```

### Resume Previous Review

```bash
# List available reviews
python3 agentsmith.py analyze . --list-reviews

# Resume last matching review
python3 agentsmith.py analyze /path/to/repo "question" --resume-last

# Resume by ID
python3 agentsmith.py analyze /path/to/repo --resume-review abc123def456
```

### Hybrid Analysis (Recommended)

```bash
# Focused SQL Injection Hunt with Prioritization
python3 orchestrator.py /path/to/repo ./scanner \
  --profile owasp \
  --prioritize \
  --prioritize-top 20 \
  --question "find SQL injection vulnerabilities in database queries" \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html markdown \
  --verbose

# Comprehensive Security Audit
python3 orchestrator.py /path/to/repo ./scanner \
  --profile owasp \
  --prioritize \
  --prioritize-top 25 \
  --question "find authentication bypass and broken access control" \
  --generate-payloads \
  --annotate-code \
  --top-n 15 \
  --export-format json html \
  --output-dir ./security-reports \
  --verbose

# Fast Parallel Analysis (Large Repos)
python3 orchestrator.py /path/to/repo ./scanner \
  --profile owasp \
  --prioritize \
  --prioritize-top 15 \
  --parallel \
  --verbose
```

## Static Rules

Agent Smith includes 70+ security rules organized into 5 rule files:

```
rules/
├── rules_core.json          # Core OWASP Top 10 rules (injection, XSS, auth, etc.)
├── rules_secrets.json       # Secret/credential detection
├── rules_infra.json         # Infrastructure security (TLS, headers, CORS)
├── rules_cicd.json          # CI/CD pipeline security
└── rules_supplychain.json   # Supply chain / dependency security
```

### Auto-Loading

In hybrid mode (`orchestrator.py`), all rule files from `rules/` are **automatically loaded**. No need to specify `--static-rules` unless you want to use custom rules.

### Custom Rules

You can provide your own rule files or override the defaults:

```bash
# Use only custom rules
python3 orchestrator.py /path/to/repo ./scanner \
  --static-rules ./my-rules.json

# Use multiple custom rule files
python3 orchestrator.py /path/to/repo ./scanner \
  --static-rules ./rules/rules_core.json,./my-extra-rules.json
```

### Rule Format

Each rule file is a JSON array:

```json
[
  {
    "name": "SQL Injection",
    "pattern": "(?i)query.*\\+.*request",
    "severity": "HIGH",
    "category": "A03",
    "description": "SQL injection via string concatenation",
    "remediation": "Use parameterized queries."
  }
]
```

### Regenerating Rules from Go Source

The `rules.go` file contains the master rule definitions. To regenerate JSON rule files:

```bash
go run gen_rule_json.go rules.go > rules/rules_core.json
```

## Project Structure

```
agentsmith/
│
├── agentsmith.py              # Main CLI entry point — unified mode dispatcher
├── orchestrator.py            # Hybrid static + AI orchestrator (recommended)
├── smart_analyzer.py          # AI-powered multi-stage analyzer
├── ctf_analyzer.py            # CTF-focused analyzer
├── summarize.py               # Scan results summarizer
│
├── agentsmith.go              # Go scanner source code
├── rules.go                   # Master rule definitions (Go)
├── gen_rule_json.go           # Rule JSON generator
├── go.mod / go.sum            # Go module files
├── scanner                    # Go scanner binary (built by scripts/setup.sh)
│
├── lib/                       # Shared Python library
│   ├── ai_provider.py         # Claude / Bedrock client factory
│   ├── model_registry.py      # AI model configuration & pricing
│   ├── prompts.py             # Prompt factories
│   ├── common.py              # Utilities, normalization, retry logic
│   ├── models.py              # Data models
│   ├── config.py              # Presets and smart defaults
│   ├── output_manager.py      # Output formatting & exports
│   ├── agentsmith_context.py  # Caching & review state
│   ├── universal_detector.py  # Tech stack detection
│   └── ...
│
├── mcp_server/                # MCP Server (SSE + Streamable HTTP)
│   ├── server.py              # Server entry point (both transports)
│   ├── tools.py               # 10 tool definitions & handlers
│   ├── auth.py                # Bearer token middleware
│   ├── config.py              # Server configuration
│   ├── test_client.py         # Interactive REPL + test suite
│   ├── requirements.txt       # MCP-specific dependencies
│   └── README.md              # MCP server documentation
│
├── rules/                     # Static analysis rules (auto-loaded)
│   ├── rules_core.json        # Core OWASP Top 10 rules
│   ├── rules_secrets.json     # Secret/credential detection
│   ├── rules_infra.json       # Infrastructure security
│   ├── rules_cicd.json        # CI/CD pipeline security
│   └── rules_supplychain.json # Supply chain security
│
├── prompts/                   # AI prompt templates (per profile)
│   ├── owasp_profile.txt
│   ├── ctf_enhanced_profile.txt
│   ├── attacker_profile.txt
│   └── ...
│
├── scripts/                   # Setup & utility scripts
│   ├── setup.sh               # Full setup (Go + Python)
│   ├── activate.sh            # Quick environment activation
│   ├── run_mcp_shell.sh       # One-command: setup + MCP server + interactive client
│   ├── run_mcp_tests.sh       # Start MCP server if needed, run test suite
│   ├── run_trufflehog.sh      # TruffleHog secrets scan (pre-commit check)
│   └── setup_test_targets.sh  # Clone vulnerable test targets
│
├── tests/                     # Test suite (223 tests)
│   ├── test_dvmcp.sh          # DVMCP MCP security scan suite
│   └── test_targets/          # Vulnerable apps (gitignored)
│       ├── DVWA/
│       ├── DVMCP/
│       └── ...
│
├── docs/                      # Documentation (see docs/README.md for index)
│   ├── USE_CASES.md           # Simple to complex workflows
│   ├── ADVANCED_EXAMPLES.md  # Multi-profile, deduplication
│   ├── MCP_SCANNING.md       # scan_mcp, DVMCP walkthrough
│   ├── PROFILES.md           # AI profile guide
│   ├── REVIEW_STATE.md       # Caching, resume, checkpoints
│   └── CHANGELOG.md          # Release history
│
├── requirements.txt           # Python dependencies
├── readme.md                  # This file
└── .cursor/mcp.json           # Cursor MCP client config
```

## Review State & Caching

### Review State Management

Agent Smith can save and resume analysis sessions:

```bash
# Start with state tracking
python3 agentsmith.py analyze /path/to/repo "question" --enable-review-state

# Resume last review
python3 agentsmith.py analyze /path/to/repo "question" --resume-last

# List all reviews
python3 agentsmith.py analyze . --list-reviews
```

**Features:**
- Automatic checkpointing at each stage
- Change detection (warns if codebase changed)
- Context file generation for Cursor/Claude
- Progress tracking

### API Caching

Caching speeds up repeated runs:

```bash
# View cache stats
python3 agentsmith.py analyze . --cache-info

# Clear cache
python3 agentsmith.py analyze . --cache-clear

# Prune old entries
python3 agentsmith.py analyze . --cache-prune 30
```

Cache location: `.agentsmith_cache/`
- Reviews: `.agentsmith_cache/reviews/`
- API Cache: `.agentsmith_cache/api_cache/` (namespaced by mode)

## Cost Tracking

After each AI-powered run, you'll see a cost summary:

```
API Usage Summary
+--------------+---------+
| Metric       | Value   |
+--------------+---------+
| API Calls    | 15      |
| Cache Hits   | 8       |
| Total Tokens | 57,680  |
| Estimated Cost | $0.052|
+--------------+---------+
```

**Tips:**
- Cache hits don't count toward token usage
- Resume reviews to maximize cache hits
- Use `--no-cache` to force fresh API calls

## Intended Use Cases

| Use Case | Command | When |
|----------|---------|------|
| **Hybrid scan (CLI)** | `python3 orchestrator.py /path ./scanner --preset quick` | Full static + AI analysis from terminal |
| **MCP shell (interactive)** | `./scripts/run_mcp_shell.sh` → `scan_hybrid`, `scan_mcp`, etc. at `mcp>` | Cursor integration, ad-hoc scans, MCP server auditing |
| **Static only** | `python3 agentsmith.py static . --severity HIGH` | CI/CD, no API key |
| **AI deep dive** | `python3 agentsmith.py analyze . "question" --prioritize` | Comprehensive review with review state |

## Tips for Effective Scanning

1. **For CI/CD**: Use `static` mode with `--severity HIGH` and `--fail-on HIGH` for fast, free checks. See `examples/ci-gate.yml` and `examples/pre-commit-hook.sh`.
2. **For Deep Reviews**: Use `analyze` mode with `--enable-review-state`
3. **For CTF Challenges**: Use `ctf` mode for quick vulnerability discovery
4. **For Comprehensive Analysis**: Use `orchestrator.py` or `agentsmith.py hybrid` with `--prioritize` (RECOMMENDED)
5. **For MCP/Cursor**: Use `./scripts/run_mcp_shell.sh` — scan repos and MCP servers from the interactive shell
6. **Save Time & Cost**: Always use `--prioritize` for repos with 50+ files
7. **Be Specific**: Use detailed `--question` for better prioritization results
8. **Get Actionable Results**: Combine `--generate-payloads` + `--annotate-code` for full context
9. **Start Focused**: Begin with `--severity HIGH` to tackle critical issues first
10. **Reduce Noise**: Use `--ignore` or `.scannerignore` to exclude test files
11. **Resume Reviews**: Use `--resume-last` to continue where you left off

### Understanding Prioritization

- `--prioritize-top N`: AI selects top N files to analyze (saves time/cost)
  - Example: `--prioritize-top 20` analyzes 20 most relevant files
- `--top-n N`: Generate payloads/annotations for top N findings
  - Example: `--top-n 10` creates payloads for 10 most critical issues
- `--question "..."`: Guides AI prioritization (be specific!)
  - Good: `"find SQL injection in user input handling"`
  - Bad: `"find bugs"`

## Help & Examples

```bash
# Standard help
python3 agentsmith.py <mode> --help

# Comprehensive examples (analyze mode)
python3 agentsmith.py analyze --help-examples

# Orchestrator help (hybrid mode)
python3 orchestrator.py --help

# List available presets
python3 orchestrator.py --list-presets

# List available AI profiles
python3 orchestrator.py --list-profiles
```

### Direct Script Access

You can also run scripts directly (advanced usage):

```bash
# AI analyzer (called by agentsmith.py analyze)
python3 smart_analyzer.py /path/to/repo "question"

# CTF analyzer (called by agentsmith.py ctf)
python3 ctf_analyzer.py /path/to/ctf "question"

# Hybrid orchestrator (use directly for all features)
python3 orchestrator.py /path/to/repo ./scanner --profile owasp
```

**Note:** For most users, `agentsmith.py` is the recommended entry point.

## MCP Server

Agent Smith includes an MCP (Model Context Protocol) server that exposes scanning tools over SSE for integration with Claude, Cursor, and custom clients.

### Quick Start

```bash
# Install MCP dependencies
pip install -r mcp_server/requirements.txt

# Start the server (dev mode)
python3 -m mcp_server --no-auth

# One-command flows (stops existing server, starts fresh with current env)
./scripts/run_mcp_shell.sh              # Setup + server + interactive client
./scripts/run_mcp_shell.sh --debug       # Same, with server debug logging
./scripts/run_mcp_shell.sh --no-restart  # Connect to existing server (don't restart)
./scripts/run_mcp_tests.sh               # Start server, run automated test suite
./scripts/run_mcp_tests.sh --repo /path  # Use specific repo for tests

# During long scans: tail -f .mcp_server.log (in another terminal) to see live progress

# Start with authentication (production)
export AGENTSMITH_MCP_TOKEN=your-secret-token
python3 -m mcp_server --port 2266
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `scan_static` | Static analysis with 70+ OWASP rules (no API key needed) |
| `scan_hybrid` | Full hybrid scan: static + AI analysis |
| `detect_tech_stack` | Detect languages, frameworks, and security risks |
| `summarize_results` | Summarize existing scan output |
| `list_findings` | Get findings filtered by severity/source |
| `list_presets` | List available scan presets |
| `scan_mcp` | Security-scan remote MCP servers (enumerate tools, check auth, analyze risks) |

**Scan MCP from the shell:** `./scripts/run_mcp_shell.sh` → at `mcp>` type `scan_mcp 9001` or `dvmcp` for all 10 DVMCP challenges. See [docs/MCP_SCANNING.md](docs/MCP_SCANNING.md).

### AI Provider Support

Agent Smith supports both direct Anthropic API and AWS Bedrock:

```bash
# Direct Anthropic API (default)
export AGENTSMITH_PROVIDER=anthropic
export CLAUDE_API_KEY=sk-ant-...

# AWS Bedrock
export AGENTSMITH_PROVIDER=bedrock
export AWS_REGION=us-east-1
```

See [mcp_server/README.md](mcp_server/README.md) for full MCP documentation. [docs/README.md](docs/README.md) indexes all docs.

## Architecture

Agent Smith uses a modular architecture:

- **Entry Point**: `agentsmith.py` - Unified CLI dispatcher
- **Analyzers**: `smart_analyzer.py`, `ctf_analyzer.py` - AI-powered analysis
- **Orchestrator**: `orchestrator.py` - Hybrid static + AI
- **MCP Server**: `mcp_server/` - SSE-based Model Context Protocol server
- **AI Provider**: `lib/ai_provider.py` - Anthropic API / AWS Bedrock abstraction
- **Library**: `lib/` - Shared modules (common, models, output, context, prompts)
- **Scanner**: `scanner` - Fast Go-based static analyzer
- **Rules**: `rules/` - JSON rule files (auto-loaded by orchestrator)

## Security & Privacy

### Never Commit These Files

Agent Smith outputs may contain sensitive information. The following are automatically gitignored:

- `output/` - All analysis results
- `test-reports/`, `security-reports/`, `*-reports/` - Custom report directories
- `**/payloads/`, `**/annotations/` - Generated payloads and annotations
- `**/*_findings.*` - All finding reports (JSON, CSV, MD, HTML)
- `.agentsmith_cache/` - API cache and review state
- `.env`, `*.key`, `*secret*` - Configuration and secrets

### API Key Security

- **Never commit** your `CLAUDE_API_KEY` to the repository
- Use environment variables: `export CLAUDE_API_KEY="sk-ant-api03-..."`
- The `.gitignore` file protects against accidental commits
- All outputs are gitignored by default
- **MCP server**: `run_mcp_shell.sh` stops any existing server and starts fresh so your current env (CLAUDE_API_KEY, etc.) is picked up

### Verifying Before Commit

```bash
# Check what would be committed
git status

# Verify no secrets in staged files
git diff --cached | grep -i "api.*key\|secret\|password" || echo "No secrets found"

# TruffleHog secrets scan (excludes .venv, output, test_targets)
./scripts/run_trufflehog.sh

# Check for large output files
git status --porcelain | grep -E "(output|report|findings)" || echo "No output files staged"
```

## Quick Start

See **[QUICKSTART.md](QUICKSTART.md)** for copy-paste commands. TL;DR:

**Fast static scan (no API key needed):**
```bash
python3 agentsmith.py static . --severity HIGH
```

**Comprehensive AI analysis (requires API key):**
```bash
export CLAUDE_API_KEY="your_key_here"
python3 orchestrator.py . ./scanner \
  --profile owasp \
  --prioritize \
  --prioritize-top 20 \
  --question "find security vulnerabilities" \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --verbose
```

**Get help:**
```bash
python3 agentsmith.py --help
python3 orchestrator.py --help
```
