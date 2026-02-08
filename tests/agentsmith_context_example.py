#!/usr/bin/env python3
"""
Example usage of the Agent Smith Context Library.

This demonstrates how to use ReviewContextManager for:
- Creating and resuming reviews
- Caching API responses
- Tracking costs
- Managing review state
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from lib.agentsmith_context import ReviewContextManager

# Initialize the context manager
ctx = ReviewContextManager(
    cache_dir=".agentsmith_cache",
    use_cache=True,
    enable_cost_tracking=True
)

# Example 1: Create a new review
repo_path = Path(".")
question = "Find all security vulnerabilities"

review = ctx.create_review(repo_path, question)
print(f"Created review: {review.review_id}")

# Example 2: Check for existing review
matching_id = ctx.find_matching_review(repo_path)
if matching_id:
    print(f"Found matching review: {matching_id}")
    review = ctx.load_review(matching_id)
    print(f"Status: {review.status}")

# Example 3: Detect codebase changes
if review:
    changed, current_fp = ctx.detect_changes(repo_path, review.dir_fingerprint)
    if changed:
        print(f"⚠ Codebase changed! {review.dir_fingerprint[:8]} -> {current_fp[:8]}")

# Example 4: Add a checkpoint
ctx.add_checkpoint(
    review.review_id,
    stage="prioritization",
    data={"prioritized_files": ["file1.py", "file2.py"]},
    files_analyzed=["file1.py", "file2.py"],
    findings_count=0
)

# Example 5: Cache an API response
cached = ctx.get_cached_response(
    stage="deep_dive",
    prompt="Analyze this code for security issues",
    file="example.py",
    repo_path=repo_path,
    model="claude-3-5-haiku-20241022"
)

if cached:
    print(f"Cache hit! Using cached response from {cached.timestamp}")
else:
    # Simulate API call
    response = "This is a simulated API response"
    ctx.save_response(
        stage="deep_dive",
        prompt="Analyze this code for security issues",
        raw_response=response,
        parsed={"findings": []},
        file="example.py",
        repo_path=repo_path,
        model="claude-3-5-haiku-20241022",
        input_tokens=100,
        output_tokens=50
    )
    print("Saved response to cache")

# Example 6: Track costs
ctx.track_cost(input_tokens=1000, output_tokens=500, cached=False)
ctx.track_cost(input_tokens=200, output_tokens=100, cached=True)  # Cache hit

summary = ctx.get_cost_summary("claude-3-5-haiku-20241022")
print(f"\nCost Summary:")
print(f"  API Calls: {summary['api_calls']}")
print(f"  Cache Hits: {summary['cache_hits']}")
print(f"  Total Tokens: {summary['total_tokens']}")
print(f"  Estimated Cost: ${summary['estimated_cost_usd']:.4f}")

# Example 7: Update findings
findings = [
    {"file_path": "file1.py", "finding": "SQL injection", "impact": "HIGH"},
    {"file_path": "file2.py", "finding": "XSS vulnerability", "impact": "MEDIUM"},
]
ctx.update_findings(review.review_id, findings)

# Example 8: Update synthesis
synthesis = "Found 2 security vulnerabilities requiring immediate attention."
ctx.update_synthesis(review.review_id, synthesis)

# Example 9: List all reviews
all_reviews = ctx.list_reviews()
print(f"\nTotal reviews: {len(all_reviews)}")
for r in all_reviews[:5]:  # Show first 5
    print(f"  - {r.review_id}: {r.status} ({r.question[:50]}...)")

# Example 10: Cache management
cache_stats = ctx.cache_stats()
print(f"\nCache Stats:")
print(f"  Files: {cache_stats['files']}")
print(f"  Size: {cache_stats['bytes_mb']} MB")

# Example 11: Mark review as completed
ctx.mark_completed(review.review_id)
print(f"\n✓ Review {review.review_id} marked as completed")

