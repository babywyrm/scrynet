# SCRYNET Context Library

> **Location**: The implementation is in `lib/scrynet_context.py`, not a standalone package.

A unified, type-safe Python library for managing review context, API caching, and cost tracking in the SCRYNET code analysis system.

## Overview

The `scrynet_context` module (in `lib/scrynet_context.py`) provides a single, cohesive interface for:

- **Review State Management**: Create, resume, and track code review sessions
- **API Response Caching**: Namespaced caching with automatic key generation
- **Cost Tracking**: Real-time API usage and cost estimation
- **Directory Fingerprinting**: Detect codebase changes between reviews
- **Checkpoint System**: Save and restore review progress at any stage

## Features

✅ **Unified API**: Single `ReviewContextManager` class for all operations  
✅ **Type Safety**: Full type hints with dataclasses and frozen types  
✅ **Error Handling**: Comprehensive logging and graceful error recovery  
✅ **Namespaced Caching**: Automatic cache organization by repo/model  
✅ **Change Detection**: Fingerprint-based codebase change detection  
✅ **Cost Tracking**: Built-in token usage and cost estimation  
✅ **Context Files**: Auto-generated Markdown context for Cursor/Claude  

## Quick Start

```python
from lib.scrynet_context import ReviewContextManager

# Initialize
ctx = ReviewContextManager(
    cache_dir=".scrynet_cache",
    use_cache=True,
    enable_cost_tracking=True
)

# Create a review
review = ctx.create_review(
    repo_path=".",
    question="Find all security vulnerabilities"
)

# Cache an API response
cached = ctx.get_cached_response(
    stage="deep_dive",
    prompt="Analyze this code",
    repo_path=".",
    model="claude-3-5-haiku-20241022"
)

if not cached:
    # Make API call and save
    response = make_api_call(prompt)
    ctx.save_response(
        stage="deep_dive",
        prompt=prompt,
        raw_response=response,
        repo_path=".",
        model="claude-3-5-haiku-20241022",
        input_tokens=1000,
        output_tokens=500
    )

# Track costs
ctx.track_cost(input_tokens=1000, output_tokens=500, cached=False)
summary = ctx.get_cost_summary("claude-3-5-haiku-20241022")
```

## Architecture

### Directory Structure

```
.scrynet_cache/
├── reviews/              # Review state files
│   ├── <review_id>.json  # Review state (JSON)
│   └── _<review_id>_context.md  # Human-readable context
└── api_cache/            # Cached API responses
    └── <repo_fp>/        # Namespaced by repo fingerprint
        └── <model>/      # Namespaced by model
            └── <hash>.json  # Cached responses
```

### Core Classes

#### `ReviewContextManager`

Main entry point for all operations. Handles:
- Review lifecycle (create, load, save, resume)
- API response caching with namespacing
- Cost tracking and reporting
- Directory fingerprinting
- Cache management (prune, clear, stats)

#### `ReviewState`

Represents a complete review session:
- `review_id`: Unique identifier
- `repo_path`: Repository being analyzed
- `dir_fingerprint`: Codebase fingerprint
- `question`: Analysis question
- `status`: "in_progress", "completed", "paused"
- `checkpoints`: List of stage checkpoints
- `findings`: List of security findings
- `synthesis`: Final analysis report

#### `ReviewCheckpoint`

Represents a saved point in the review:
- `stage`: Stage name ("prioritization", "deep_dive", "synthesis")
- `timestamp`: When checkpoint was created
- `data`: Stage-specific data
- `files_analyzed`: List of files processed
- `findings_count`: Number of findings at this stage

#### `CachedResponse`

Represents a cached API response:
- `stage`: Analysis stage
- `prompt`: Original prompt
- `raw_response`: Raw API response
- `parsed`: Parsed response (dict)
- `timestamp`: When cached
- `input_tokens`, `output_tokens`: Token counts

#### `CostTracker`

Tracks API usage and costs:
- `input_tokens`, `output_tokens`: Token counts
- `api_calls`, `cache_hits`: Call statistics
- `estimate_cost()`: Cost estimation by model
- `summary()`: Full usage summary

## API Reference

### Review Management

```python
# Create a new review
review = ctx.create_review(repo_path, question, dir_fingerprint=None)

# Load an existing review
review = ctx.load_review(review_id)

# Find matching review by fingerprint
review_id = ctx.find_matching_review(repo_path, dir_fingerprint=None)

# Save review state (auto-called, but can be explicit)
ctx.save_review(review)

# Add a checkpoint
ctx.add_checkpoint(review_id, stage, data, files_analyzed=None, findings_count=0)

# Update findings
ctx.update_findings(review_id, findings)  # List of Finding objects or dicts

# Update synthesis
ctx.update_synthesis(review_id, synthesis_text)

# Mark as completed
ctx.mark_completed(review_id)

# List all reviews
reviews = ctx.list_reviews(status=None)  # Optional status filter
```

### Caching

```python
# Get cached response
cached = ctx.get_cached_response(
    stage="deep_dive",
    prompt="...",
    file="example.py",  # Optional
    repo_path=".",  # Optional (for namespacing)
    model="claude-3-5-haiku-20241022"  # Optional (for namespacing)
)

# Save response to cache
ctx.save_response(
    stage="deep_dive",
    prompt="...",
    raw_response="...",
    parsed={"findings": []},  # Optional
    file="example.py",  # Optional
    repo_path=".",  # Optional
    model="claude-3-5-haiku-20241022",  # Optional
    input_tokens=1000,
    output_tokens=500
)
```

### Cost Tracking

```python
# Track API usage
ctx.track_cost(input_tokens=1000, output_tokens=500, cached=False)

# Get summary
summary = ctx.get_cost_summary("claude-3-5-haiku-20241022")
# Returns: {
#   "api_calls": 10,
#   "cache_hits": 5,
#   "input_tokens": 50000,
#   "output_tokens": 25000,
#   "total_tokens": 75000,
#   "estimated_cost_usd": 0.12
# }

# Reset tracking
ctx.reset_cost_tracking()
```

### Directory Fingerprinting

```python
# Compute fingerprint
fingerprint = ctx.compute_dir_fingerprint(repo_path)

# Detect changes
changed, current_fp = ctx.detect_changes(repo_path, stored_fingerprint)
if changed:
    print(f"Codebase changed: {stored_fingerprint[:8]} -> {current_fp[:8]}")
```

### Cache Management

```python
# Get cache statistics
stats = ctx.cache_stats()
# Returns: {"dir": "...", "files": 100, "bytes": 1024000, "bytes_mb": 1.0}

# List cache entries
entries = ctx.list_cache_entries(limit=50)

# Prune old entries
deleted = ctx.prune_cache(days=30)  # Delete entries older than 30 days

# Clear all cache
deleted = ctx.clear_cache()
```

## Usage Patterns

### Pattern 1: Create and Resume Review

```python
# Check for existing review
matching_id = ctx.find_matching_review(repo_path)
if matching_id:
    review = ctx.load_review(matching_id)
    # Check for changes
    changed, current_fp = ctx.detect_changes(repo_path, review.dir_fingerprint)
    if changed:
        # Handle codebase changes
        print("Codebase changed, re-analyzing...")
        review.dir_fingerprint = current_fp
        review.checkpoints = []  # Clear checkpoints
        ctx.save_review(review)
else:
    # Create new review
    review = ctx.create_review(repo_path, question)
```

### Pattern 2: Cache-Aware API Calls

```python
def analyze_with_cache(ctx, stage, prompt, file=None, repo_path=None, model=None):
    # Check cache first
    cached = ctx.get_cached_response(stage, prompt, file, repo_path, model)
    if cached:
        return cached.parsed
    
    # Make API call
    response = make_api_call(prompt)
    parsed = parse_response(response)
    
    # Save to cache
    ctx.save_response(
        stage, prompt, response, parsed,
        file, repo_path, model,
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens
    )
    
    # Track costs
    ctx.track_cost(
        response.usage.input_tokens,
        response.usage.output_tokens,
        cached=False
    )
    
    return parsed
```

### Pattern 3: Stage Checkpointing

```python
# Check if stage already completed
checkpoint = next(
    (cp for cp in review.checkpoints if cp.stage == "prioritization"),
    None
)

if checkpoint:
    # Load from checkpoint
    prioritized_files = checkpoint.data.get("prioritized_files", [])
else:
    # Run stage
    prioritized_files = run_prioritization_stage(...)
    
    # Save checkpoint
    ctx.add_checkpoint(
        review.review_id,
        "prioritization",
        {"prioritized_files": prioritized_files},
        files_analyzed=[str(f) for f in files]
    )
```

## Error Handling

The library uses Python's logging module for error reporting. All operations are designed to fail gracefully:

- **File I/O errors**: Logged as warnings, operations return `None` or empty lists
- **Invalid data**: Raises `ValueError` with descriptive messages
- **Missing reviews**: Raises `FileNotFoundError` with review ID
- **Cache failures**: Logged as warnings, operations continue without cache

## Type Safety

All classes use:
- **Dataclasses**: For structured data with validation
- **Frozen dataclasses**: For immutable checkpoint and response objects
- **Type hints**: Full type annotations throughout
- **Optional types**: Clear indication of nullable values

## Performance Considerations

- **Lazy directory scanning**: Fingerprints computed only when needed
- **Efficient hashing**: SHA256 truncated to 16 chars for keys
- **Namespaced storage**: Prevents cache collisions
- **JSON serialization**: Fast, human-readable storage format

## Integration

The library is designed to be a drop-in replacement for the existing `ReviewStateManager` and `CacheManager` classes in `smart_analyzer.py`. Migration path:

1. Replace `ReviewStateManager` with `ReviewContextManager`
2. Replace `CacheManager` with `ReviewContextManager` caching methods
3. Use `CostTracker` from the library instead of local class
4. Update imports and method calls

## Example: Full Review Session

See `scrynet_context_example.py` for a complete working example.

## License

Part of the SCRYNET project.

