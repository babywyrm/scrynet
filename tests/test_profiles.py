#!/usr/bin/env python3
"""
Test suite for Agent Smith profile system.

Tests profile loading, validation, and basic functionality.
"""

import unittest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from orchestrator import Orchestrator


class TestProfiles(unittest.TestCase):
    """Test profile loading and validation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.prompts_dir = Path(__file__).parent.parent / "prompts"
        self.expected_profiles = [
            "owasp", "ctf", "code_review", "modern",
            "soc2", "pci", "compliance", "performance", "attacker",
            "springboot", "cpp_conan", "flask",  # framework profiles
        ]
    
    def test_all_profile_files_exist(self):
        """Test that all expected profile files exist."""
        for profile in self.expected_profiles:
            profile_file = self.prompts_dir / f"{profile}_profile.txt"
            self.assertTrue(
                profile_file.exists(),
                f"Profile file not found: {profile_file}"
            )
    
    def test_profile_files_have_required_placeholders(self):
        """Test that profile files have required placeholders."""
        # Note: attacker profile is different (repo-level, not file-level)
        file_based_profiles = [p for p in self.expected_profiles if p != "attacker"]
        
        for profile in file_based_profiles:
            profile_file = self.prompts_dir / f"{profile}_profile.txt"
            content = profile_file.read_text(encoding="utf-8")
            
            # Check for required placeholders
            self.assertIn("{file_path}", content, 
                         f"{profile} missing {{file_path}} placeholder")
            self.assertIn("{language}", content,
                         f"{profile} missing {{language}} placeholder")
            self.assertIn("{code}", content,
                         f"{profile} missing {{code}} placeholder")
    
    def test_profile_files_have_json_structure(self):
        """Test that profile files mention JSON structure."""
        file_based_profiles = [p for p in self.expected_profiles if p != "attacker"]
        
        for profile in file_based_profiles:
            profile_file = self.prompts_dir / f"{profile}_profile.txt"
            content = profile_file.read_text(encoding="utf-8")
            
            # Should mention JSON
            self.assertTrue(
                "JSON" in content or "json" in content,
                f"{profile} should mention JSON response format"
            )
    
    def test_profile_files_not_empty(self):
        """Test that profile files are not empty."""
        for profile in self.expected_profiles:
            profile_file = self.prompts_dir / f"{profile}_profile.txt"
            content = profile_file.read_text(encoding="utf-8")
            self.assertGreater(len(content), 100,
                             f"{profile} file seems too short")


class TestProfileLoading(unittest.TestCase):
    """Test profile loading in orchestrator."""
    
    def test_profile_loading_logic(self):
        """Test that profile loading logic works."""
        # This is a basic test - full integration tests would require
        # actual API calls and test repos
        prompts_dir = Path(__file__).parent.parent / "prompts"
        
        # Test that we can read profile files
        test_profile = "owasp"
        profile_file = prompts_dir / f"{test_profile}_profile.txt"
        
        self.assertTrue(profile_file.exists())
        content = profile_file.read_text(encoding="utf-8")
        self.assertGreater(len(content), 0)


if __name__ == "__main__":
    unittest.main()



