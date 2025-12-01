#!/usr/bin/env python3
"""
Help Examples Module for SCRYNET Smart Analyzer

Provides comprehensive usage examples and scenarios for all features.
Can be displayed via --help-examples flag or imported for interactive help.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

console = Console()


def print_help_examples():
    """Print comprehensive usage examples and scenarios."""
    
    examples = """
# SCRYNET Smart Analyzer - Usage Examples

## Quick Start

### Basic Security Scan
```bash
python3 smart__.py /path/to/repo "find all security vulnerabilities"
```

### Security Scan with Payloads
```bash
python3 smart__.py /path/to/repo "find injection vulnerabilities" \\
  --generate-payloads --top-n 5
```

### CTF Mode - Quick Vulnerability Discovery
```bash
# CTF mode is optimized for Capture The Flag challenges
# Focuses on exploitable vulnerabilities and quick wins
python3 smart__.py /path/to/ctf-challenge "find all vulnerabilities and flags" \\
  --ctf-mode \\
  --top-n 10 \\
  --generate-payloads
```

---

## Review State Management

### Starting a Review with State Tracking
```bash
# Start a new review (saves state for resuming later)
python3 smart__.py WebGoat/src/ "find security vulnerabilities" \\
  --enable-review-state
```

### Resuming a Previous Review

**Option 1: Auto-resume last matching review**
```bash
python3 smart__.py WebGoat/src/ "find security vulnerabilities" \\
  --resume-last
```

**Option 2: Resume by review ID**
```bash
# First, list reviews to get the ID
python3 smart__.py . --list-reviews

# Then resume
python3 smart__.py WebGoat/src/ --resume-review abc123def456
```

**Option 3: Auto-detect and prompt**
```bash
# If a matching review exists, you'll be prompted
python3 smart__.py WebGoat/src/ "find security vulnerabilities" \\
  --enable-review-state
```

### Managing Reviews

**List all reviews:**
```bash
python3 smart__.py . --list-reviews
```

**Check status of a specific review:**
```bash
python3 smart__.py . --review-status abc123def456
```

**View context file (for Cursor/Claude):**
```bash
cat .scrynet_cache/reviews/_abc123def456_context.md
```

---

## Cache Management

### View Cache Statistics
```bash
python3 smart__.py . --cache-info
```

### List Recent Cache Entries
```bash
python3 smart__.py . --cache-list
```

### Prune Old Cache (older than 14 days)
```bash
python3 smart__.py . --cache-prune 14
```

### Clear All Cache
```bash
python3 smart__.py . --cache-clear
```

### Export Cache Manifest
```bash
python3 smart__.py . --cache-export cache_manifest.json
```

---

## CTF Mode - Capture The Flag Analysis

CTF mode is specifically optimized for finding exploitable vulnerabilities quickly in CTF challenges. It uses specialized prompts focused on:
- Quick wins and high-impact vulnerabilities
- Exploitation paths and payloads
- Common CTF patterns (SQL injection, command injection, file inclusion, etc.)
- Hardcoded secrets and flags
- Authentication bypasses

### CTF Quick Scan
```bash
python3 smart__.py /path/to/ctf-challenge \\
  "find all security vulnerabilities and flags" \\
  --ctf-mode \\
  --top-n 10 \\
  --generate-payloads \\
  --max-files 20
```

### CTF Focused on Entry Points
```bash
python3 smart__.py /path/to/ctf-challenge \\
  "find the top entry points for exploitation" \\
  --ctf-mode \\
  --prioritize-top 5 \\
  --generate-payloads \\
  --threshold HIGH
```

### CTF with Full Exploitation Roadmap
```bash
python3 smart__.py /path/to/ctf-challenge \\
  "find all exploitable vulnerabilities" \\
  --ctf-mode \\
  --top-n 15 \\
  --generate-payloads \\
  --annotate-code \\
  --enable-review-state
```

**CTF Mode Features:**
- Prioritizes entry points (login, upload, API endpoints)
- Focuses on exploitable vulnerabilities over theoretical ones
- Generates CTF-ready exploitation payloads
- Provides exploitation roadmaps with priority rankings
- Highlights potential flags and secrets
- Uses separate cache namespace (`ctf/`) to avoid mixing with regular analysis

**When to Use CTF Mode:**
- CTF challenges and competitions
- Penetration testing exercises
- Quick vulnerability discovery
- Security training scenarios
- When you need exploitation-focused analysis

---

## Common Security Analysis Scenarios

### 1. Comprehensive Security Audit
```bash
python3 smart__.py /path/to/app \\
  "find all security vulnerabilities and suggest remediations" \\
  --top-n 10 \\
  --generate-payloads \\
  --annotate-code \\
  --enable-review-state \\
  --max-files 20
```

### 2. Focused Injection Vulnerability Scan
```bash
python3 smart__.py /path/to/app \\
  "find SQL injection and XSS vulnerabilities" \\
  --top-n 5 \\
  --generate-payloads \\
  --threshold HIGH \\
  --enable-review-state
```

### 3. Authentication & Authorization Review
```bash
python3 smart__.py /path/to/app \\
  "review authentication and authorization mechanisms" \\
  --top-n 8 \\
  --generate-payloads \\
  --enable-review-state
```

### 4. Performance Analysis
```bash
python3 smart__.py /path/to/app \\
  "identify performance bottlenecks" \\
  -v \\
  --format html markdown \\
  --output performance_review
```

### 5. Code Quality Review
```bash
python3 smart__.py /path/to/python/repo \\
  "review code quality and suggest improvements" \\
  --optimize \\
  --focus typing security readability \\
  --optimize-output ./optimized_code \\
  --diff
```

---

## Advanced Usage

### Custom Model Selection
```bash
python3 smart__.py /path/to/repo "analyze code" \\
  --model claude-3-5-sonnet-20241022 \\
  --max-tokens 8000 \\
  --temperature 0.0
```

### File Filtering
```bash
# Only analyze specific file types
python3 smart__.py /path/to/repo "find vulnerabilities" \\
  --include-exts py go js java

# Exclude specific directories
python3 smart__.py /path/to/repo "find vulnerabilities" \\
  --ignore-dirs tests node_modules vendor
```

### Including YAML/Helm Files
```bash
# Analyze CI/CD workflows and Kubernetes configs
python3 smart__.py /path/to/repo \\
  "review GitHub Actions and K8s configs for security" \\
  --include-yaml \\
  --include-helm
```

### Verbose Debug Mode
```bash
python3 smart__.py /path/to/repo "find vulnerabilities" \\
  --debug \\
  -v \\
  --enable-review-state
```

---

## Workflow Examples

### Complete Security Review Workflow

**Step 1: Initial Review**
```bash
python3 smart__.py WebGoat/src/ \\
  "comprehensive security audit" \\
  --enable-review-state \\
  --generate-payloads \\
  --top-n 10 \\
  --max-files 15
```

**Step 2: Review the Results**
- Check the output files (HTML, Markdown, JSON)
- Review the context file: `.scrynet_cache/reviews/_<review_id>_context.md`
- Use the context file in Cursor/Claude for follow-up questions

**Step 3: Resume if Interrupted**
```bash
python3 smart__.py WebGoat/src/ \\
  "comprehensive security audit" \\
  --resume-last
```

**Step 4: Check Cache Usage**
```bash
python3 smart__.py . --cache-info
```

### Iterative Analysis Workflow

**First Pass: Quick Overview**
```bash
python3 smart__.py /path/to/repo "security overview" \\
  --top-n 5 \\
  --enable-review-state \\
  --max-files 10
```

**Second Pass: Deep Dive on Critical Issues**
```bash
python3 smart__.py /path/to/repo \\
  "deep dive on CRITICAL and HIGH impact vulnerabilities" \\
  --resume-last \\
  --threshold HIGH \\
  --generate-payloads \\
  --annotate-code
```

---

## Change Detection

When you resume a review and the codebase has changed, you'll see:

```
⚠ Codebase has changed since this review was created!
Original fingerprint: a1b2c3d4...
Current fingerprint:  e5f6g7h8...

How would you like to proceed?
  [1] Re-analyze changed files (recommended)
  [2] Continue with old analysis (may be outdated)
  [3] Start fresh review
```

**Recommendation:** Choose option [1] to re-analyze with the updated codebase.

---

## Cost Tracking

After each run, you'll see a cost summary:

```
API Usage Summary
┌──────────────┬─────────┐
│ Metric       │ Value   │
├──────────────┼─────────┤
│ API Calls    │ 15      │
│ Cache Hits   │ 8       │
│ Total Tokens │ 57,680  │
│ Estimated Cost │ $0.052│
└──────────────┴─────────┘
```

**Tips:**
- Cache hits don't count toward token usage
- Resume reviews to maximize cache hits
- Use `--cache-info` to see cache statistics

---

## Output Formats

### Multiple Formats
```bash
python3 smart__.py /path/to/repo "analyze" \\
  --format console html markdown json \\
  --output analysis_report
```

This creates:
- `analysis_report.html` - Formatted HTML report
- `analysis_report.md` - Markdown report
- `analysis_report.json` - Machine-readable JSON

---

## Troubleshooting

### "No reviews found"
- Make sure you used `--enable-review-state` on the first run
- Or use `--resume-review <id>` with a specific review ID

### Cache not working
- Check cache with `--cache-info`
- Verify `--no-cache` flag is not set
- Cache is namespaced by repo fingerprint and model

### Want to start completely fresh
```bash
# Clear everything
rm -rf .scrynet_cache/*

# Or just clear cache (keep reviews)
rm -rf .scrynet_cache/api_cache/*
```

### Review state not resuming
- Check that the codebase fingerprint matches (same files, sizes, mtimes)
- Use `--list-reviews` to see available reviews
- Use `--review-status <id>` to check a review's state

---

## Best Practices

1. **Always use `--enable-review-state`** for important reviews
2. **Use `--resume-last`** to continue where you left off
3. **Check cache stats** regularly with `--cache-info`
4. **Prune old cache** monthly with `--cache-prune 30`
5. **Review context files** in Cursor/Claude for continuity
6. **Start with fewer files** (`--max-files 10`) for initial exploration
7. **Use `--top-n`** to focus on the most critical findings
8. **Generate payloads** for actionable remediation guidance

---

## Integration with Cursor/Claude

1. Run analysis with `--enable-review-state`
2. Open the context file: `.scrynet_cache/reviews/_<review_id>_context.md`
3. Use it as a prompt anchor in Cursor/Claude:
   ```
   "Continue the security review from this context: [paste context file]"
   ```
4. The context file includes:
   - Review question and status
   - Files analyzed
   - Findings summary
   - Checkpoints and progress
   - Synthesis report

---

For more information, see `readme.md` in the beta directory.
"""
    
    console.print(Panel(
        Markdown(examples),
        title="[bold cyan]SCRYNET Smart Analyzer - Usage Examples[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))


def print_quick_reference():
    """Print a quick reference table of common commands."""
    
    table = Table(title="Quick Reference", show_header=True, header_style="bold magenta")
    table.add_column("Task", style="cyan", width=30)
    table.add_column("Command", style="green", width=60)
    
    table.add_row(
        "Basic security scan",
        "python3 smart__.py <repo> \"find vulnerabilities\""
    )
    table.add_row(
        "CTF mode (quick wins)",
        "python3 smart__.py <repo> \"find vulnerabilities\" --ctf-mode --generate-payloads"
    )
    table.add_row(
        "Start review with state",
        "python3 smart__.py <repo> \"question\" --enable-review-state"
    )
    table.add_row(
        "Resume last review",
        "python3 smart__.py <repo> \"question\" --resume-last"
    )
    table.add_row(
        "Resume by ID",
        "python3 smart__.py <repo> --resume-review <id>"
    )
    table.add_row(
        "List reviews",
        "python3 smart__.py . --list-reviews"
    )
    table.add_row(
        "Cache info",
        "python3 smart__.py . --cache-info"
    )
    table.add_row(
        "Clear cache",
        "python3 smart__.py . --cache-clear"
    )
    table.add_row(
        "With payloads",
        "python3 smart__.py <repo> \"question\" --generate-payloads --top-n 5"
    )
    table.add_row(
        "Verbose + debug",
        "python3 smart__.py <repo> \"question\" -v --debug"
    )
    table.add_row(
        "Multiple formats",
        "python3 smart__.py <repo> \"question\" --format html markdown --output report"
    )
    
    console.print("\n")
    console.print(table)


if __name__ == "__main__":
    print_help_examples()
    print("\n")
    print_quick_reference()



