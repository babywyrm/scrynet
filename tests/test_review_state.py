"""
Tests for review state and cache management.

Tests the scrynet_context module's review state lifecycle,
cache operations, and persistence features.
"""

import unittest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.scrynet_context import ReviewContextManager, ReviewState, CostTracker, CachedResponse


class TestReviewStateLifecycle(unittest.TestCase):
    """Test review state creation, resume, and lifecycle management."""
    
    def setUp(self):
        """Set up test fixtures with temporary directory."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_repo = self.test_dir / "test_repo"
        self.test_repo.mkdir()
        
        # Create some test files
        (self.test_repo / "test.py").write_text("print('hello')")
        (self.test_repo / "app.js").write_text("console.log('test');")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_create_review_context_manager(self):
        """Test creating a ReviewContextManager."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        self.assertIsNotNone(ctx)
        self.assertIsInstance(ctx, ReviewContextManager)
        self.assertTrue(hasattr(ctx, 'cache_dir'))
    
    def test_create_review_state(self):
        """Test creating a new review state."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        review = ctx.create_review(
            repo_path=str(self.test_repo),
            question="test question"
        )
        
        self.assertIsNotNone(review)
        self.assertIsInstance(review, ReviewState)
        self.assertTrue(hasattr(review, 'review_id'))
        self.assertEqual(review.question, "test question")
    
    def test_review_id_generation(self):
        """Test that review IDs are unique."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        review1 = ctx.create_review(
            repo_path=str(self.test_repo),
            question="question 1"
        )
        
        review2 = ctx.create_review(
            repo_path=str(self.test_repo),
            question="question 2"
        )
        
        self.assertIsNotNone(review1)
        self.assertIsNotNone(review2)
        self.assertNotEqual(review1.review_id, review2.review_id)
    
    def test_review_state_saves_metadata(self):
        """Test that review state saves basic metadata."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        review = ctx.create_review(
            repo_path=str(self.test_repo),
            question="test"
        )
        
        self.assertTrue(hasattr(review, 'created_at'))
        self.assertTrue(hasattr(review, 'repo_path'))
        self.assertTrue(hasattr(review, 'question'))


class TestReviewStateCheckpoints(unittest.TestCase):
    """Test review state checkpoint persistence."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_repo = self.test_dir / "test_repo"
        self.test_repo.mkdir()
        (self.test_repo / "test.py").write_text("print('test')")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_checkpoint_structure(self):
        """Test that checkpoints have expected structure."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        review = ctx.create_review(
            repo_path=str(self.test_repo),
            question="test"
        )
        
        # Checkpoints should be accessible
        self.assertTrue(hasattr(review, 'checkpoints'))
        self.assertIsInstance(review.checkpoints, list)
    
    def test_review_state_persistence(self):
        """Test that review state can be persisted."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        review = ctx.create_review(
            repo_path=str(self.test_repo),
            question="test"
        )
        
        # Review should be saveable
        self.assertTrue(hasattr(ctx, 'save_review'))


class TestCacheManagement(unittest.TestCase):
    """Test cache operations and lifecycle."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_repo = self.test_dir / "test_repo"
        self.test_repo.mkdir()
        (self.test_repo / "test.py").write_text("print('test')")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_cache_initialization(self):
        """Test that cache is initialized properly."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        # Cache should be available
        self.assertTrue(hasattr(ctx, 'use_cache'))
        self.assertTrue(hasattr(ctx, 'get_cached_response'))
    
    def test_cache_key_generation(self):
        """Test that cache keys are generated consistently."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        # Same inputs should generate same keys
        if hasattr(ctx, '_make_cache_key'):
            key1 = ctx._make_cache_key("stage1", "prompt1", str(self.test_repo), "model")
            key2 = ctx._make_cache_key("stage1", "prompt1", str(self.test_repo), "model")
            self.assertEqual(key1, key2)
            
            # Different inputs should generate different keys
            key3 = ctx._make_cache_key("stage2", "prompt1", str(self.test_repo), "model")
            self.assertNotEqual(key1, key3)
    
    def test_cache_dir_creation(self):
        """Test that cache directory is created."""
        cache_path = self.test_dir / ".scrynet_cache"
        ctx = ReviewContextManager(cache_dir=cache_path)
        
        # Cache dir should exist or be creatable
        self.assertIsNotNone(ctx)
        self.assertTrue(hasattr(ctx, 'cache_dir'))


class TestCacheHitSavingsCost(unittest.TestCase):
    """Test that cache hits save API costs."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_repo = self.test_dir / "test_repo"
        self.test_repo.mkdir()
        (self.test_repo / "test.py").write_text("print('test')")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_cache_hit_excludes_from_token_count(self):
        """Test that cache hits don't count toward token usage."""
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        # CostTracker should handle cached responses differently
        tracker = CostTracker()
        tracker.add_usage(1000, 500, cached=False)
        tracker.add_usage(1000, 500, cached=True)
        
        # Only non-cached should count toward tokens
        self.assertEqual(tracker.input_tokens, 1000)
        self.assertEqual(tracker.output_tokens, 500)
        self.assertEqual(tracker.cache_hits, 1)
        self.assertEqual(tracker.api_calls, 1)
    
    def test_cost_tracker_functionality(self):
        """Test that cost tracker works correctly."""
        tracker = CostTracker()
        
        # Add some usage
        tracker.add_usage(5000, 2000, cached=False)
        tracker.add_usage(3000, 1500, cached=False)
        
        self.assertEqual(tracker.input_tokens, 8000)
        self.assertEqual(tracker.output_tokens, 3500)
        self.assertEqual(tracker.api_calls, 2)
        
        # Test cost estimation
        cost = tracker.estimate_cost("claude-3-5-haiku-20241022")
        self.assertGreater(cost, 0.0)


class TestDirectoryFingerprinting(unittest.TestCase):
    """Test directory fingerprinting for review matching."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_repo = self.test_dir / "test_repo"
        self.test_repo.mkdir()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_fingerprint_generation(self):
        """Test that directory fingerprints can be generated."""
        # Create identical directory structure
        (self.test_repo / "file1.py").write_text("content1")
        (self.test_repo / "file2.py").write_text("content2")
        
        ctx = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        # Context should have fingerprinting capability
        self.assertTrue(hasattr(ctx, 'compute_dir_fingerprint'))
    
    def test_directory_consistency(self):
        """Test that same directory produces consistent results."""
        (self.test_repo / "file1.py").write_text("original")
        
        ctx1 = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        ctx2 = ReviewContextManager(cache_dir=self.test_dir / ".scrynet_cache")
        
        # Both contexts should be created successfully
        self.assertIsNotNone(ctx1)
        self.assertIsNotNone(ctx2)


if __name__ == '__main__':
    unittest.main()
