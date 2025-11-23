#!/usr/bin/env python3
"""
Quick test script for scrynet_context library.
Tests core functionality without requiring API calls.
"""

import tempfile
import shutil
from pathlib import Path
from scrynet_context import ReviewContextManager, ReviewState

def test_basic_functionality():
    """Test basic library functionality."""
    print("=" * 60)
    print("Testing SCRYNET Context Library")
    print("=" * 60)
    
    # Create temporary cache directory
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "test_cache"
        
        # Initialize context manager
        print("\n[1] Initializing ReviewContextManager...")
        ctx = ReviewContextManager(
            cache_dir=str(cache_dir),
            use_cache=True,
            enable_cost_tracking=True
        )
        print(f"    ✓ Cache directory: {ctx.cache_dir}")
        print(f"    ✓ Reviews dir: {ctx.reviews_dir}")
        print(f"    ✓ Cache base: {ctx.cache_base}")
        
        # Test directory fingerprinting
        print("\n[2] Testing directory fingerprinting...")
        test_repo = Path(__file__).parent  # Use beta directory
        fp1 = ctx.compute_dir_fingerprint(test_repo)
        fp2 = ctx.compute_dir_fingerprint(test_repo)
        assert fp1 == fp2, "Fingerprints should be deterministic"
        print(f"    ✓ Fingerprint computed: {fp1[:8]}...")
        print(f"    ✓ Fingerprint is deterministic")
        
        # Test change detection
        print("\n[3] Testing change detection...")
        changed, current_fp = ctx.detect_changes(test_repo, fp1)
        assert not changed, "Should detect no changes"
        assert current_fp == fp1, "Fingerprints should match"
        print(f"    ✓ No changes detected (as expected)")
        
        # Test review creation
        print("\n[4] Testing review creation...")
        review = ctx.create_review(test_repo, "Test question")
        assert review.review_id is not None
        assert review.status == "in_progress"
        assert review.dir_fingerprint == fp1
        print(f"    ✓ Review created: {review.review_id}")
        print(f"    ✓ Status: {review.status}")
        print(f"    ✓ Fingerprint matches: {review.dir_fingerprint[:8]}...")
        
        # Test review loading
        print("\n[5] Testing review loading...")
        loaded = ctx.load_review(review.review_id)
        assert loaded.review_id == review.review_id
        assert loaded.question == review.question
        print(f"    ✓ Review loaded successfully")
        
        # Test checkpoint system
        print("\n[6] Testing checkpoint system...")
        ctx.add_checkpoint(
            review.review_id,
            "prioritization",
            {"prioritized_files": ["file1.py", "file2.py"]},
            files_analyzed=["file1.py", "file2.py"],
            findings_count=0
        )
        loaded = ctx.load_review(review.review_id)
        assert len(loaded.checkpoints) == 1
        assert loaded.checkpoints[0].stage == "prioritization"
        print(f"    ✓ Checkpoint added: {loaded.checkpoints[0].stage}")
        
        # Test finding matching review
        print("\n[7] Testing review matching...")
        matching_id = ctx.find_matching_review(test_repo)
        assert matching_id == review.review_id
        print(f"    ✓ Found matching review: {matching_id}")
        
        # Test caching
        print("\n[8] Testing API response caching...")
        # Should not be cached
        cached = ctx.get_cached_response(
            "test_stage",
            "test prompt",
            repo_path=test_repo,
            model="test-model"
        )
        assert cached is None, "Should not be cached yet"
        print(f"    ✓ Cache miss (expected)")
        
        # Save a response
        saved = ctx.save_response(
            "test_stage",
            "test prompt",
            "test response",
            parsed={"result": "success"},
            repo_path=test_repo,
            model="test-model",
            input_tokens=100,
            output_tokens=50
        )
        assert saved is not None
        print(f"    ✓ Response saved to cache")
        
        # Should now be cached
        cached = ctx.get_cached_response(
            "test_stage",
            "test prompt",
            repo_path=test_repo,
            model="test-model"
        )
        assert cached is not None, "Should be cached now"
        assert cached.raw_response == "test response"
        print(f"    ✓ Cache hit! Response retrieved")
        
        # Test cost tracking
        print("\n[9] Testing cost tracking...")
        ctx.track_cost(input_tokens=1000, output_tokens=500, cached=False)
        ctx.track_cost(input_tokens=200, output_tokens=100, cached=True)
        summary = ctx.get_cost_summary("claude-3-5-haiku-20241022")
        assert summary["api_calls"] == 1
        assert summary["cache_hits"] == 2  # One from cache retrieval, one explicit
        assert summary["input_tokens"] == 1000
        assert summary["output_tokens"] == 500
        print(f"    ✓ API calls: {summary['api_calls']}")
        print(f"    ✓ Cache hits: {summary['cache_hits']}")
        print(f"    ✓ Total tokens: {summary['total_tokens']}")
        print(f"    ✓ Estimated cost: ${summary['estimated_cost_usd']:.6f}")
        
        # Test updating findings
        print("\n[10] Testing findings update...")
        findings = [
            {"file_path": "file1.py", "finding": "Test issue", "impact": "HIGH"},
        ]
        ctx.update_findings(review.review_id, findings)
        loaded = ctx.load_review(review.review_id)
        assert len(loaded.findings) == 1
        print(f"    ✓ Findings updated: {len(loaded.findings)} finding(s)")
        
        # Test updating synthesis
        print("\n[11] Testing synthesis update...")
        synthesis = "Test synthesis text"
        ctx.update_synthesis(review.review_id, synthesis)
        loaded = ctx.load_review(review.review_id)
        assert loaded.synthesis == synthesis
        print(f"    ✓ Synthesis updated")
        
        # Test listing reviews
        print("\n[12] Testing review listing...")
        reviews = ctx.list_reviews()
        assert len(reviews) >= 1
        assert any(r.review_id == review.review_id for r in reviews)
        print(f"    ✓ Found {len(reviews)} review(s)")
        
        # Test cache stats
        print("\n[13] Testing cache statistics...")
        stats = ctx.cache_stats()
        assert stats["files"] >= 1  # At least our test cache entry
        print(f"    ✓ Cache files: {stats['files']}")
        print(f"    ✓ Cache size: {stats['bytes_mb']} MB")
        
        # Test marking as completed
        print("\n[14] Testing review completion...")
        ctx.mark_completed(review.review_id)
        loaded = ctx.load_review(review.review_id)
        assert loaded.status == "completed"
        print(f"    ✓ Review marked as completed")
        
        # Test context file generation
        print("\n[15] Testing context file generation...")
        context_file = ctx.reviews_dir / f"_{review.review_id}_context.md"
        assert context_file.exists(), "Context file should be generated"
        content = context_file.read_text()
        assert review.review_id in content
        assert "Test question" in content
        print(f"    ✓ Context file generated: {context_file.name}")
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        return True

if __name__ == "__main__":
    try:
        test_basic_functionality()
        print("\n🎉 Library is working correctly!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

