# Smart Code Analyzer ..beta..

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Powered by](https://img.shields.io/badge/Powered%20by-Claude%203.5%20Haiku-orange.svg)

An AI-powered, multi-stage script for deep, contextual analysis of codebases using the Anthropic Claude 3.5 Haiku API (cost-effective for batch analysis).
This tool goes beyond simple file-by-file scanning to provide **holistic, synthesized insights** and **optional testing payloads** for both Red and Blue teams.

---

## Overview

Typical static analysis runs on every file, regardless of context — often producing noise.
**Smart Code Analyzer** works differently:

1. **Prioritization** – The AI scans the repo's structure to find the most relevant files for your query.
2. **Deep Dive** – It runs a targeted file-by-file analysis on only the prioritized subset.
3. **Synthesis** – Findings are aggregated into a **dynamic, context-aware final report**:

   * Security questions → **Threat Model**
   * Performance questions → **Performance Profile**
   * Refactoring questions → **Architectural Review**
4. **Optional Payload Generation** – If enabled, creates **verification** (Red Team) and **defense** (Blue Team) payloads for the top findings.
5. **Optional YAML/YML Mode** – Skip YAML by default to reduce noise. Use `--include-yaml` to analyze YAML/YML files (e.g., CI/CD workflows, Helm charts) when needed.

---

## Key Features

* **Multi-Stage AI Pipeline** – Combines breadth and depth in analysis.
* **Context-Aware Summaries** – Tailored to your question type.
* **Red/Blue Payloads** – Generate test payloads for validation & defense.
* **Multiple Output Formats** – Console, HTML, Markdown.
* **YAML/YML Toggle** – Analyze YAML/YML files only on demand.
* **Verbose & Debug Modes** – Detailed output or raw API responses for dev/debug use.
* **Top-N Control** – Limit the number of findings to focus on critical items.
* **Review State Management** – Resume interrupted reviews, track progress, manage checkpoints.
* **API Caching** – Speed up repeated runs with intelligent response caching.
* **Cost Tracking** – Monitor API usage and estimate costs in real-time.
* **Detailed Review Reports** – Print past reviews with code snippets and fix suggestions.
* **CTF Mode** – Optimized analysis mode for Capture The Flag challenges, focusing on exploitable vulnerabilities and quick wins.

---

## Installation

1. **Python 3.8+**
2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   Or manually:
   ```bash
   pip install rich anthropic typing-inspection
   ```
3. **Set your Anthropic API key**:

   ```bash
   export CLAUDE_API_KEY="your_api_key_here"
   ```

---

## Usage

### Quick Help
```bash
# Standard help
python3 smart__.py -h

# Comprehensive examples and scenarios
python3 smart__.py --help-examples
```

The `--help-examples` flag shows:
- Common usage scenarios
- CTF mode examples and workflows
- Review state management examples
- Cache management commands
- Workflow examples
- Troubleshooting tips
- Best practices

### Basic Usage

```bash
usage: smart__.py [-h] [--cache-dir CACHE_DIR] [--no-cache]
                  [--save-conversations] [--include-yaml] [--include-helm]
                  [--max-file-bytes MAX_FILE_BYTES] [--max-files MAX_FILES]
                  [--prioritize-top PRIORITIZE_TOP]
                  [--format [{console,html,markdown,json} ...]]
                  [--model MODEL] [--max-tokens MAX_TOKENS]
                  [--temperature TEMPERATURE] [--max-retries MAX_RETRIES]
                  [--top-n TOP_N] [--threshold {HIGH,MEDIUM}]
                  [--generate-payloads] [--annotate-code] [-v] [--debug]
                  [--optimize] [--focus [{typing,readability,security,performance,pythonic} ...]]
                  [--optimize-output DIR] [--diff] [--include-exts [INCLUDE_EXTS ...]]
                  [--ignore-dirs [IGNORE_DIRS ...]] [--cache-info] [--cache-list]
                  [--cache-prune DAYS] [--cache-clear] [--cache-export FILE]
                  [--enable-review-state] [--resume-last] [--resume-review REVIEW_ID]
                  [--list-reviews] [--review-status REVIEW_ID]
                  [--print-review REVIEW_ID] [--verbose-review] [--ctf-mode] [--help-examples]
                  repo_path [question]

positional arguments:
  repo_path             Path to the repository to analyze
  question              Analysis question (prompts if not provided)

options:
  -h, --help            Show this help message and exit
  -v, --verbose         Print findings inline with code context
  --debug               Print raw API responses
  --format [{console,html,markdown,json} ...]
                        Output format(s) (default: console)
  --top-n TOP_N         Number of items for payload/annotation generation (default: 5)
  --generate-payloads   Generate Red/Blue payloads
  --annotate-code       Generate annotated code snippets for top findings
  --include-yaml        Include .yaml/.yml files
  --include-helm        Include Helm templates
  --enable-review-state
                        Enable review state tracking for resuming reviews
  --resume-last         Resume the most recent review matching the current repo
  --resume-review REVIEW_ID
                        Resume an existing review by review ID
  --list-reviews        List all available reviews and exit
  --review-status REVIEW_ID
                        Show status of a specific review and exit
  --print-review REVIEW_ID
                        Print full report of a specific review and exit
  --verbose-review      Show all findings with code snippets and detailed recommendations
                        (use with --print-review)
  --ctf-mode           Enable CTF mode: optimized for quick vulnerability discovery and
                        exploitation (Capture The Flag). Uses specialized prompts focused on
                        exploitable vulnerabilities, quick wins, and CTF patterns.
  --help-examples       Show comprehensive usage examples and scenarios
```

---

## Examples

#### 1. **Basic Interactive Scan**

```bash
python3 smart__.py /path/to/repo
```

#### 2. **CTF Mode - Quick Vulnerability Discovery**

```bash
# CTF mode is optimized for Capture The Flag challenges
# Focuses on exploitable vulnerabilities and quick wins
python3 smart__.py /path/to/ctf-challenge \
  "find all vulnerabilities and flags" \
  --ctf-mode \
  --top-n 10 \
  --generate-payloads
```

**CTF Mode Features:**
- Prioritizes entry points (login, upload, API endpoints, config files)
- Focuses on exploitable vulnerabilities over theoretical ones
- Generates CTF-ready exploitation payloads with expected results
- Provides exploitation roadmaps with priority rankings
- Highlights potential flags, secrets, and hardcoded credentials
- Uses separate cache namespace (`ctf/`) to avoid mixing with regular analysis

**When to Use CTF Mode:**
- CTF challenges and competitions
- Penetration testing exercises
- Quick vulnerability discovery
- Security training scenarios
- When you need exploitation-focused analysis

#### 3. **Security Threat Model + Payloads**

```bash
python3 smart__.py /path/to/app \
  "Threat model for injection & auth vulnerabilities" \
  --generate-payloads --top-n 3
```

#### 3. **Performance Profile with Verbose Output**

```bash
python3 smart__.py /path/to/app \
  "Find performance bottlenecks" -v
```

#### 4. **Architectural Review to HTML & Markdown**

```bash
python3 smart__.py /path/to/app \
  "Review architecture" --format html markdown --output review
```

#### 5. **Including YAML Files in the Scan**

```bash
python3 smart__.py /path/to/app \
  "Review GitHub Actions for security risks" --include-yaml
```

#### 6. **Security Analysis with Review State Tracking**

```bash
python3 smart__.py /path/to/app \
  "Find all injection vulnerabilities" \
  --generate-payloads \
  --top-n 5 \
  --enable-review-state
```

#### 7. **Resume a Previous Review**

```bash
# List available reviews
python3 smart__.py . --list-reviews

# Resume by ID
python3 smart__.py /path/to/app --resume-review <review_id>

# Auto-resume last matching review
python3 smart__.py /path/to/app "your question" --resume-last
```

#### 8. **Print Detailed Review Report**

```bash
# Print basic review summary
python3 smart__.py . --print-review <review_id>

# Print detailed review with code snippets and fix suggestions
python3 smart__.py . --print-review <review_id> --verbose-review
```

---

## Notes on YAML/YML Analysis

* **By default**, `.yaml` and `.yml` files are **excluded** to avoid irrelevant CI/CD noise.
* Use `--include-yaml` when:

  * Reviewing **GitHub Actions**, **GitLab CI**, **Helm charts**, **Kubernetes manifests**.
  * Performing **infrastructure-as-code** audits.

---

## Review State & Context Management

The analyzer includes a unified context management system for:
- **Resuming reviews**: Pick up where you left off
- **API caching**: Speed up repeated runs with cached responses
- **Cost tracking**: Monitor API usage and costs
- **Change detection**: Automatically detect codebase changes

### Quick Start

**Start a review with state tracking:**
```bash
python3 smart__.py /path/to/repo "your question" --enable-review-state
```

**Resume a previous review:**
```bash
# By ID
python3 smart__.py /path/to/repo --resume-review <review_id>

# Auto-detect (same repo structure)
python3 smart__.py /path/to/repo "your question" --resume-last
```

**List and manage reviews:**
```bash
# List all reviews
python3 smart__.py . --list-reviews

# Show status of a specific review
python3 smart__.py . --review-status <review_id>

# Resume the last matching review
python3 smart__.py . --resume-last
```

**Print review reports:**
```bash
# Print basic summary
python3 smart__.py . --print-review <review_id>

# Print detailed report with code snippets and annotations
python3 smart__.py . --print-review <review_id> --verbose-review
```

### How It Works

- **Directory Fingerprinting**: Creates a stable hash of your codebase structure (paths, sizes, mtimes)
- **Change Detection**: Automatically detects if codebase changed since last review
- **Checkpoints**: Saves progress at each stage (prioritization, deep dive, synthesis)
- **Stage Skipping**: Automatically skips completed stages when resuming
- **Context Files**: Generates human-readable Markdown files for Cursor/Claude

### Cache Management

```bash
# Show cache statistics
python3 smart__.py . --cache-info

# List recent cache entries
python3 smart__.py . --cache-list

# Prune entries older than N days
python3 smart__.py . --cache-prune 14

# Clear all cache
python3 smart__.py . --cache-clear
```

### Cache vs Review State

- **Review State** = Continuity for humans and AI: checkpoints, context markdown, resume flow
- **Cache** = Performance: stores API responses, auto-reused when inputs match

They are separate but complementary:
- Review state files: `.scrynet_cache/reviews/`
- Cache entries: `.scrynet_cache/api_cache/<repo_fingerprint>/<model>/`

### Troubleshooting

- **"No reviews found"**: Start a review with `--enable-review-state` or resume by ID
- **Cache grows large**: Use `--cache-prune 30` monthly
- **Different path, same repo**: Use `--resume-review <review_id>` to resume any review
- **Bypass cache**: Add `--no-cache` to force fresh API calls

---

## Advanced Usage

### Model Selection

```bash
# Use a different Claude model
python3 smart__.py . "question" --model claude-3-5-sonnet-20241022

# Adjust max tokens
python3 smart__.py . "question" --max-tokens 8000

# Set temperature (0.0 = deterministic)
python3 smart__.py . "question" --temperature 0.0
```

### File Filtering

```bash
# Only analyze specific file extensions
python3 smart__.py . "question" --include-exts py,go,js

# Ignore specific directories
python3 smart__.py . "question" --ignore-dirs tests,node_modules
```

### Review State Options

```bash
# Enable review state tracking
python3 smart__.py . "question" --enable-review-state

# Resume a specific review
python3 smart__.py . --resume-review abc123

# Resume last matching review automatically
python3 smart__.py . "question" --resume-last
```

### Code Optimization (Optional)

```bash
# Analyze Python files for code quality improvements
python3 smart__.py . "question" --optimize

# Focus on specific areas
python3 smart__.py . "question" --optimize --focus typing security

# Generate optimized code files
python3 smart__.py . "question" --optimize --optimize-output ./optimized
```

---

## Architecture

The analyzer has been refactored into a modular architecture for better maintainability:

### Core Modules

- **`smart__.py`** – Main orchestrator script that coordinates all stages
- **`models.py`** – Data models (`Finding`, `AnalysisReport`)
- **`output_manager.py`** – Handles all output formatting (console, HTML, Markdown)
- **`common.py`** – Shared utilities (retry logic, file scanning, JSON parsing)
- **`prompts.py`** – Prompt templates for different analysis stages
- **`scrynet_context.py`** – Unified context management library (reviews, cache, cost tracking)
- **`help_examples.py`** – Comprehensive usage examples and scenarios

### Context Management Library

The `scrynet_context` module provides:
- **ReviewContextManager**: Single interface for all context operations
- **Type-safe dataclasses**: ReviewState, ReviewCheckpoint, CachedResponse
- **Automatic namespacing**: Cache organized by repo fingerprint and model
- **Cost tracking**: Built-in token usage and cost estimation
- **Change detection**: Compares directory fingerprints to detect codebase changes

### Directory Structure

```
gowasp/beta/
├── smart__.py              # Main analyzer script
├── models.py               # Data models
├── output_manager.py       # Output formatting
├── common.py               # Shared utilities
├── prompts.py              # Prompt templates
├── scrynet_context.py      # Context management library
├── help_examples.py        # Usage examples
├── requirements.txt        # Python dependencies
├── readme.md              # This file
├── tests/                  # Test scripts and examples
│   ├── test_context_lib.py
│   ├── scrynet_context_example.py
│   └── ...
└── .scrynet_cache/         # Cache and review state (created at runtime)
    ├── reviews/            # Review state files
    │   ├── <review_id>.json
    │   └── _<review_id>_context.md  # Human-readable context
    └── api_cache/          # Cached API responses
        └── <repo_fp>/<model>/
            └── <hash>.json
```

### Test Scripts

Test scripts and examples are located in the `tests/` subdirectory:
- `test_context_lib.py` – Unit tests for context management
- `scrynet_context_example.py` – Usage examples for the context library

---

## Cost Tracking

The analyzer tracks API usage and provides cost estimates:

```
API Usage Summary:
  API Calls: 15
  Cache Hits: 8
  Input Tokens: 45,230
  Output Tokens: 12,450
  Total Tokens: 57,680
  Estimated Cost: $0.052
```

Costs are tracked per session and reset on each run. Cache hits don't count toward token usage.

---

## Recent Improvements

### Modular Architecture (Latest)
- Extracted data models into `models.py`
- Separated output management into `output_manager.py`
- Consolidated utilities into `common.py`
- Created unified context library `scrynet_context.py`
- Added comprehensive help examples module

### Review Reporting
- Added `--print-review` flag to display past review summaries
- Added `--verbose-review` flag for detailed reports with code snippets
- Enhanced review state management with better change detection
- Improved checkpoint system for stage resumption

### Performance & Reliability
- Optimized cache lookups (removed expensive fingerprint computation)
- Added detailed debug logging for API calls
- Improved error handling and retry logic
- Better progress feedback during long-running operations

---

## License

Part of the SCRYNET project.
