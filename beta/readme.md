
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

1. **Prioritization** – The AI scans the repo’s structure to find the most relevant files for your query.
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
* **Color Output** – Auto-detected, with `--no-color` override.

---

## Installation

1. **Python 3.8+**
2. **Install dependencies**:

   ```bash
   pip install rich anthropic
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
- Review state management examples
- Cache management commands
- Workflow examples
- Troubleshooting tips
- Best practices

```
usage: smart_analyzer.py [-h] [-v] [--debug]
                         [--format [{console,html,markdown} ...]]
                         [-o OUTPUT] [--no-color]
                         [--top-n TOP_N] [--generate-payloads]
                         [--include-yaml]
                         repo_path [question]

positional arguments:
  repo_path             Path to the repository to analyze
  question              Analysis question (prompts if not provided)

options:
  -h, --help            Show this help message and exit.
  -v, --verbose         Print detailed findings as they are found.
  --debug               Print raw API responses for every call.
  --format [{console,html,markdown} ...]
                        Output format(s).
  -o, --output          Base output filename (suffixes added automatically).
  --no-color            Disable colorized output.
  --top-n TOP_N         Limit summary and payload generation to top N findings.
  --generate-payloads   Generate Red/Blue team payloads for top findings.
  --include-yaml        Include YAML/YML files in analysis (disabled by default).
```

---

## Examples

#### 1. **Basic Interactive Scan**

```bash
python3 smart_analyzer.py /path/to/repo
```

#### 2. **Security Threat Model + Payloads**

```bash
python3 smart_analyzer.py /path/to/app \
  "Threat model for injection & auth vulnerabilities" \
  --generate-payloads --top-n 3
```

#### 3. **Performance Profile with Verbose Output**

```bash
python3 smart_analyzer.py /path/to/app \
  "Find performance bottlenecks" -v
```

#### 4. **Architectural Review to HTML & Markdown**

```bash
python3 smart_analyzer.py /path/to/app \
  "Review architecture" --format html markdown --output review
```

#### 5. **Including YAML Files in the Scan**

```bash
python3 smart_analyzer.py /path/to/app \
  "Review GitHub Actions for security risks" --include-yaml
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
python3 smart__.py /path/to/repo "your question" --enable-review-state
# If a matching review exists, you'll be prompted to resume
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

# Export cache manifest
python3 smart__.py . --cache-export manifest.json
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

---

## Architecture

The analyzer uses a unified context library (`scrynet_context`) that provides:
- **ReviewContextManager**: Single interface for all context operations
- **Type-safe dataclasses**: ReviewState, ReviewCheckpoint, CachedResponse
- **Automatic namespacing**: Cache organized by repo fingerprint and model
- **Cost tracking**: Built-in token usage and cost estimation

### Directory Structure

```
.scrynet_cache/
├── reviews/              # Review state files
│   ├── <review_id>.json
│   └── _<review_id>_context.md  # Human-readable context
└── api_cache/            # Cached API responses
    └── <repo_fp>/<model>/
        └── <hash>.json
```

---

## Examples

### Security Analysis with Payloads

```bash
python3 smart__.py /path/to/app \
  "Find all injection vulnerabilities" \
  --generate-payloads \
  --top-n 5 \
  --enable-review-state
```

### Performance Review

```bash
python3 smart__.py /path/to/app \
  "Identify performance bottlenecks" \
  -v \
  --format html markdown \
  --output performance_review
```

### Resume Interrupted Review

```bash
# Start a review
python3 smart__.py /path/to/app "security audit" --enable-review-state

# Later, resume it
python3 smart__.py /path/to/app --resume-review <review_id>
# Or auto-resume
python3 smart__.py /path/to/app "security audit" --resume-last
```

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

## License

Part of the SCRYNET project.
