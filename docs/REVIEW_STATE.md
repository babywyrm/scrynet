# Review State and Cache

> **Note**: Implementation in `lib/agentsmith_context.py`; used by `agentsmith.py analyze` and `agentsmith.py ctf`.

This guide explains how to preserve context across sessions, resume prior reviews, and manage the cache system.

## What you get
- Persistent review state with checkpoints (prioritization, deep dive, synthesis)
- Human-readable context files for Cursor/Claude
- Namespaced cache per repo/model to speed up repeated runs
- CLI tools to list, resume, and manage reviews and cache

---

## Quick Start

1) Start a review with state tracking

```bash
# Using agentsmith.py analyze mode (recommended)
python3 agentsmith.py analyze /path/to/repo "your question" --enable-review-state

# Store cache in target repo (portable, survives cd)
python3 agentsmith.py analyze /path/to/repo "your question" --enable-review-state --cache-in-repo
```

2) Resume a prior review

- By ID:
```bash
python3 agentsmith.py analyze /path/to/repo --resume-review <review_id>
```
- Auto-detect by directory (same repo structure):
```bash
python3 agentsmith.py analyze /path/to/repo "your question" --enable-review-state
# If a matching review exists, you'll be prompted to resume
```

3) List and inspect reviews

```bash
# List available reviews (most recent first)
python3 agentsmith.py analyze . --list-reviews
```

4) Open the saved context in your editor

```
<cache_dir>/reviews/_<review_id>_context.md
```
Default `cache_dir` is `.agentsmith_cache`; with `--cache-in-repo` it's `target_repo/.agentsmith/`.

---

## How Review State matching works

- Matching relies on a directory fingerprint. When the repo is a git repository, the fingerprint incorporates `git rev-parse HEAD` for more reliable "same codebase" detection. Otherwise it uses paths, file sizes, and mtimes.
- If you run from the same repo path (or one with the same structure), `--enable-review-state` will detect an existing review and prompt to resume.
- You can always resume explicitly with `--resume-review <review_id>` regardless of path.

---

## Checkpoints saved
- Prioritization: which files were selected
- Deep dive: findings collected and files analyzed
- Synthesis: final report string and lengths

These are visible in the status and in the context file under your cache dir.

---

## Cache (performance) vs Review State (continuity)

- Review State = continuity for humans and AI: checkpoints, context markdown, resume flow.
- Cache = performance for repeated prompts: stores API responses, auto-reused when inputs match.

They are separate but complementary:
- Review state: `<cache_dir>/reviews/`
- Cache entries: `<cache_dir>/<repo_fingerprint>/<model>/`

---

## Cache Management Commands

All commands exit after performing the requested action.

```bash
# Show cache statistics
python3 agentsmith.py analyze . --cache-info

# Clear all cache entries
python3 agentsmith.py analyze . --cache-clear
```

For prune, list, and export: use `python3 smart_analyzer.py . --cache-prune 14`, `--cache-list`, `--cache-export`.

### Storage options
- **Default**: `.agentsmith_cache/` in current working directory
- **In-repo**: `--cache-in-repo` stores in `target_repo/.agentsmith/` (portable, add to .gitignore)

### Namespacing details
- Cache is namespaced by (repo_fingerprint, model)
- Keys are SHA256 of: `stage|file|prompt`
- If fingerprinting cannot be computed, a fallback hash of `repo_path` is used

---

## End-to-End Testing Checklist

1) Populate cache & create a review
```bash
python3 agentsmith.py analyze /path/to/repo "security quick pass" --enable-review-state
```
Expect: analysis runs; Review ID printed; cache dir created.

2) Verify review exists
```bash
python3 agentsmith.py analyze . --list-reviews
```

3) Validate cache reuse
```bash
python3 agentsmith.py analyze /path/to/repo "security quick pass" --enable-review-state
```
Expect: "Cache hit" messages for stages on repeat runs.

4) Inspect cache
```bash
python3 agentsmith.py analyze . --cache-info
```

5) Clear cache
```bash
python3 agentsmith.py analyze . --cache-clear
```

6) Auto-detect resume
```bash
python3 agentsmith.py analyze /path/to/repo "security quick pass" --enable-review-state
# If a matching review exists, you'll be prompted to resume
```

---

## Troubleshooting

- "No reviews found": You ran without `--enable-review-state`. Start a review with that flag or resume by ID.
- Cache grows large: use `python3 smart_analyzer.py . --cache-prune 30` monthly.
- Different path, same repo: `--resume-review <review_id>` always works; `--enable-review-state` will only auto-detect if fingerprints match.
- Bypass cache: add `--no-cache` to force fresh API calls.

