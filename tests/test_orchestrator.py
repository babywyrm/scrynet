#!/usr/bin/env python3
"""
Test suite for orchestrator functionality.

Tests orchestrator profile loading, file processing, and basic operations.
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from orchestrator import Orchestrator, Severity


class TestOrchestratorInit(unittest.TestCase):
    """Test orchestrator initialization."""
    
    def test_severity_enum(self):
        """Test severity enum values."""
        self.assertEqual(Severity.CRITICAL.value, 1)
        self.assertEqual(Severity.HIGH.value, 2)
        self.assertEqual(Severity.MEDIUM.value, 3)
        self.assertEqual(Severity.LOW.value, 4)
    
    def test_severity_ordering(self):
        """Test that severity ordering is correct."""
        self.assertLess(Severity.CRITICAL.value, Severity.HIGH.value)
        self.assertLess(Severity.HIGH.value, Severity.MEDIUM.value)
        self.assertLess(Severity.MEDIUM.value, Severity.LOW.value)


class TestProfileLoading(unittest.TestCase):
    """Test profile template loading."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.prompts_dir = Path(__file__).parent.parent / "prompts"
    
    def test_profile_files_exist(self):
        """Test that profile files can be loaded."""
        profiles = ["owasp", "ctf", "code_review", "modern", "soc2", "pci", "compliance"]
        
        for profile in profiles:
            profile_file = self.prompts_dir / f"{profile}_profile.txt"
            self.assertTrue(profile_file.exists(), f"{profile} profile not found")
            
            content = profile_file.read_text(encoding="utf-8")
            self.assertGreater(len(content), 100, f"{profile} profile too short")
    
    def test_profile_placeholders(self):
        """Test that profiles have correct placeholders."""
        profiles = ["owasp", "ctf", "code_review", "modern", "soc2", "pci", "compliance"]
        
        for profile in profiles:
            profile_file = self.prompts_dir / f"{profile}_profile.txt"
            content = profile_file.read_text(encoding="utf-8")
            
            # File-based profiles need these placeholders
            self.assertIn("{file_path}", content)
            self.assertIn("{language}", content)
            self.assertIn("{code}", content)


class TestSeverityFiltering(unittest.TestCase):
    """Test severity filtering logic."""
    
    def test_severity_threshold(self):
        """Test that severity filtering works correctly."""
        # This would require instantiating Orchestrator
        # For now, just test the enum
        self.assertTrue(Severity.CRITICAL.value < Severity.HIGH.value)
        self.assertTrue(Severity.HIGH.value < Severity.MEDIUM.value)


if __name__ == "__main__":
    unittest.main()

