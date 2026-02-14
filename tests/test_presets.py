#!/usr/bin/env python3
"""
Test suite for preset system and smart defaults.

Tests the new preset configuration system and smart defaults logic.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.config import get_preset, list_presets, SmartDefaults, TechStackDetector, PRESETS


class TestPresetSystem(unittest.TestCase):
    """Test preset configuration system."""
    
    def test_all_presets_exist(self):
        """Test that all expected presets are defined."""
        expected_presets = ['mcp', 'quick', 'ctf', 'ctf-fast', 'security-audit', 'pentest', 'compliance']
        for preset_name in expected_presets:
            preset = get_preset(preset_name)
            self.assertIsNotNone(preset, f"Preset '{preset_name}' not found")
    
    def test_ctf_preset_configuration(self):
        """Test CTF preset has correct configuration."""
        preset = get_preset('ctf')
        self.assertIsNotNone(preset)
        self.assertEqual(preset.name, 'ctf')
        self.assertIn('ctf', preset.profiles)
        self.assertTrue(preset.prioritize)
        self.assertTrue(preset.generate_payloads)
        self.assertTrue(preset.annotate_code)
        self.assertTrue(preset.deduplicate)
    
    def test_mcp_preset_configuration(self):
        """Test mcp preset is optimized for MCP (2 files, no payloads/annotations)."""
        preset = get_preset('mcp')
        self.assertIsNotNone(preset)
        self.assertEqual(preset.name, 'mcp')
        self.assertTrue(preset.prioritize)
        self.assertEqual(preset.prioritize_top, 2)
        self.assertFalse(preset.generate_payloads)
        self.assertFalse(preset.annotate_code)
        self.assertEqual(preset.export_formats, ['json'])
        self.assertTrue(preset.parallel)

    def test_quick_preset_configuration(self):
        """Test quick preset is optimized for speed."""
        preset = get_preset('quick')
        self.assertIsNotNone(preset)
        self.assertEqual(preset.name, 'quick')
        self.assertTrue(preset.prioritize)
        self.assertFalse(preset.generate_payloads)
        self.assertFalse(preset.annotate_code)
        self.assertEqual(preset.export_formats, ['json'])
        self.assertTrue(preset.parallel)  # Fast execution
    
    def test_pentest_preset_has_attacker_profile(self):
        """Test pentest preset includes attacker profile."""
        preset = get_preset('pentest')
        self.assertIsNotNone(preset)
        self.assertIn('attacker', preset.profiles)
        self.assertTrue(preset.threat_model)
    
    def test_preset_to_dict(self):
        """Test preset conversion to dictionary."""
        preset = get_preset('ctf')
        preset_dict = preset.to_dict()
        
        self.assertIn('profiles', preset_dict)
        self.assertIn('prioritize', preset_dict)
        self.assertIn('generate_payloads', preset_dict)
        self.assertEqual(preset_dict['profiles'], 'ctf,owasp')
    
    def test_list_presets(self):
        """Test listing all presets."""
        presets = list_presets()
        self.assertGreaterEqual(len(presets), 7)
        
        # Check each preset has required attributes
        for preset in presets:
            self.assertTrue(hasattr(preset, 'name'))
            self.assertTrue(hasattr(preset, 'description'))
            self.assertTrue(hasattr(preset, 'profiles'))


class TestSmartDefaults(unittest.TestCase):
    """Test smart defaults logic."""
    
    def test_auto_prioritize_threshold(self):
        """Test auto-prioritization threshold."""
        # Should prioritize for large repos
        self.assertTrue(SmartDefaults.should_auto_prioritize(100))
        self.assertTrue(SmartDefaults.should_auto_prioritize(51))
        
        # Should NOT prioritize for small repos
        self.assertFalse(SmartDefaults.should_auto_prioritize(50))
        self.assertFalse(SmartDefaults.should_auto_prioritize(10))
    
    def test_auto_deduplicate_logic(self):
        """Test auto-deduplication logic."""
        # Should deduplicate with multiple profiles
        self.assertTrue(SmartDefaults.should_auto_deduplicate(['owasp', 'ctf']))
        self.assertTrue(SmartDefaults.should_auto_deduplicate(['owasp', 'ctf', 'code_review']))
        
        # Should NOT deduplicate with single profile
        self.assertFalse(SmartDefaults.should_auto_deduplicate(['owasp']))
        self.assertFalse(SmartDefaults.should_auto_deduplicate([]))
    
    def test_calculate_smart_top_n(self):
        """Test smart top-n calculation."""
        # Minimum 3
        self.assertEqual(SmartDefaults.calculate_smart_top_n(5), 3)
        
        # ~20% of findings
        self.assertEqual(SmartDefaults.calculate_smart_top_n(50), 10)
        
        # Maximum 15
        self.assertEqual(SmartDefaults.calculate_smart_top_n(100), 15)
    
    def test_calculate_smart_prioritize_top(self):
        """Test smart prioritization limit calculation."""
        # Small repos - analyze all
        self.assertEqual(SmartDefaults.calculate_smart_prioritize_top(10), 10)
        
        # Medium repos
        self.assertEqual(SmartDefaults.calculate_smart_prioritize_top(30), 15)
        self.assertEqual(SmartDefaults.calculate_smart_prioritize_top(100), 25)
        
        # Large repos - cap at 30
        self.assertEqual(SmartDefaults.calculate_smart_prioritize_top(200), 30)
    
    def test_should_add_html_export(self):
        """Test HTML export auto-add logic."""
        # Should add HTML if payloads enabled
        self.assertTrue(SmartDefaults.should_add_html_export(True, False))
        
        # Should add HTML if annotations enabled
        self.assertTrue(SmartDefaults.should_add_html_export(False, True))
        
        # Should add HTML if both enabled
        self.assertTrue(SmartDefaults.should_add_html_export(True, True))
        
        # Should NOT add HTML if neither enabled
        self.assertFalse(SmartDefaults.should_add_html_export(False, False))


class TestTechStackDetector(unittest.TestCase):
    """Test tech stack detection."""
    
    def test_detect_test_targets(self):
        """Test detection on real test targets."""
        test_dir = Path(__file__).parent / "test_targets"
        
        # Test DVWA (PHP)
        dvwa_path = test_dir / "DVWA"
        if dvwa_path.exists():
            result = TechStackDetector.detect(dvwa_path)
            self.assertIn('frameworks', result)
            self.assertIn('languages', result)
            self.assertIn('app_type', result)
    
    def test_detect_returns_required_fields(self):
        """Test that detection returns all required fields."""
        test_dir = Path(__file__).parent / "test_targets" / "DVWA"
        if not test_dir.exists():
            self.skipTest("Test target not found")
        
        result = TechStackDetector.detect(test_dir)
        
        self.assertIn('frameworks', result)
        self.assertIn('languages', result)
        self.assertIn('app_type', result)
        self.assertIn('has_docker', result)
        self.assertIn('has_tests', result)
        
        # Should return lists/strings, not None
        self.assertIsInstance(result['frameworks'], list)
        self.assertIsInstance(result['languages'], list)
        self.assertIsInstance(result['app_type'], str)


if __name__ == "__main__":
    unittest.main()

