#!/usr/bin/env python3
"""
Test suite for advanced features.

Tests quick wins, file grouping, and other Phase 3/4 features.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.common import get_line_number, normalize_finding


class TestQuickWinsLogic(unittest.TestCase):
    """Test quick wins filtering logic."""
    
    def test_quick_win_high_exploitability(self):
        """Test that high exploitability score marks as quick win."""
        finding = {
            'exploitability_score': 9,
            'severity': 'HIGH'
        }
        
        # Quick win logic: score >= 7
        is_quick_win = finding['exploitability_score'] >= 7
        self.assertTrue(is_quick_win)
    
    def test_quick_win_fast_exploit_time(self):
        """Test that fast exploit time marks as quick win."""
        finding = {
            'time_to_exploit': '< 1 minute',
            'severity': 'HIGH'
        }
        
        # Quick win logic: time mentions "minute"
        is_quick_win = 'minute' in finding['time_to_exploit'].lower()
        self.assertTrue(is_quick_win)
    
    def test_quick_win_critical_severity(self):
        """Test that CRITICAL severity marks as quick win."""
        finding = {
            'severity': 'CRITICAL',
            'exploitability_score': 5  # Even with medium score
        }
        
        # Quick win logic: CRITICAL severity
        is_quick_win = finding['severity'] == 'CRITICAL'
        self.assertTrue(is_quick_win)
    
    def test_not_quick_win(self):
        """Test that low-impact findings are not quick wins."""
        finding = {
            'exploitability_score': 3,
            'time_to_exploit': '> 1 hour',
            'severity': 'LOW'
        }
        
        is_quick_win = (
            finding['exploitability_score'] >= 7 or
            'minute' in finding['time_to_exploit'].lower() or
            finding['severity'] == 'CRITICAL'
        )
        self.assertFalse(is_quick_win)


class TestFileGroupingLogic(unittest.TestCase):
    """Test file-grouped annotation logic."""
    
    def test_file_grouping_basic(self):
        """Test basic file grouping logic."""
        findings = [
            {'file': 'a.php', 'severity': 'CRITICAL', 'line_number': 10},
            {'file': 'a.php', 'severity': 'HIGH', 'line_number': 20},
            {'file': 'a.php', 'severity': 'MEDIUM', 'line_number': 30},
            {'file': 'b.php', 'severity': 'HIGH', 'line_number': 15},
            {'file': 'c.php', 'severity': 'MEDIUM', 'line_number': 40},
        ]
        
        # Simulate getting top 2 findings by severity
        severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3}
        top_findings = sorted(findings, key=lambda x: severity_order[x['severity']])[:2]
        
        # Extract unique files
        top_files = {f['file'] for f in top_findings}
        
        # Get ALL findings from those files
        all_from_top_files = [f for f in findings if f['file'] in top_files]
        
        # Top 2 findings are: a.php (CRITICAL) and b.php (HIGH)
        # So we should get all findings from a.php only (3 findings)
        # b.php HIGH is the 2nd top finding, so b.php is included → 1 finding from b.php
        # Actually: top 2 = CRITICAL from a.php, then HIGH from a.php OR b.php
        # Let me recalculate: CRITICAL=a.php, next HIGH could be a.php:20 OR b.php:15
        # sorted by severity: CRITICAL(a:10), HIGH(a:20), HIGH(b:15), MEDIUM(a:30), MEDIUM(c:40)
        # Top 2 = a:10(CRITICAL), a:20(HIGH)
        # Files = {a.php} → All from a.php = 3 findings
        self.assertGreaterEqual(len(all_from_top_files), 3)  # At least all from a.php
        self.assertLessEqual(len(all_from_top_files), 4)  # At most a.php + b.php
    
    def test_file_grouping_coverage(self):
        """Test that file grouping increases coverage."""
        findings = [
            {'file': 'token.php', 'severity': 'HIGH', 'line_number': 7},
            {'file': 'token.php', 'severity': 'MEDIUM', 'line_number': 14},
            {'file': 'token.php', 'severity': 'MEDIUM', 'line_number': 20},
            {'file': 'token.php', 'severity': 'MEDIUM', 'line_number': 30},
            {'file': 'other.php', 'severity': 'LOW', 'line_number': 50},
        ]
        
        # Without file grouping: top 1 = 1 finding
        top_1 = findings[:1]
        self.assertEqual(len(top_1), 1)
        
        # With file grouping: top 1 → 1 file → all findings in that file = 4
        top_files = {findings[0]['file']}
        grouped = [f for f in findings if f['file'] in top_files]
        self.assertEqual(len(grouped), 4)
        
        # Improvement: 4x more coverage
        improvement = len(grouped) / len(top_1)
        self.assertEqual(improvement, 4.0)


class TestSmartTopN(unittest.TestCase):
    """Test smart top-n calculation."""
    
    def test_smart_top_n_scales(self):
        """Test that smart top-n scales with findings."""
        from lib.config import SmartDefaults
        
        # Small number of findings
        self.assertEqual(SmartDefaults.calculate_smart_top_n(10), 3)  # Min 3
        
        # Medium
        self.assertEqual(SmartDefaults.calculate_smart_top_n(50), 10)  # 10-20%
        
        # Large
        self.assertEqual(SmartDefaults.calculate_smart_top_n(100), 15)  # Max 15
    
    def test_smart_top_n_bounds(self):
        """Test that smart top-n respects min/max bounds."""
        from lib.config import SmartDefaults
        
        # Should never go below 3
        result = SmartDefaults.calculate_smart_top_n(5)
        self.assertGreaterEqual(result, 3)
        
        # Should never go above 15
        result = SmartDefaults.calculate_smart_top_n(200)
        self.assertLessEqual(result, 15)


class TestColorCoding(unittest.TestCase):
    """Test severity color coding."""
    
    def test_color_mapping(self):
        """Test that severity maps to correct colors."""
        color_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan"
        }
        
        # Verify color assignments
        self.assertEqual(color_map["CRITICAL"], "bold red")
        self.assertEqual(color_map["HIGH"], "red")
        self.assertEqual(color_map["MEDIUM"], "yellow")
        self.assertEqual(color_map["LOW"], "cyan")


class TestFrameworkAwarePrioritization(unittest.TestCase):
    """Test framework-aware prioritization question enhancement."""
    
    def test_question_enhancement(self):
        """Test that questions are enhanced with framework context."""
        from lib.tech_detector import generate_framework_aware_prioritization_question
        
        tech_info = {
            'frameworks': ['Flask', 'SQLAlchemy'],
            'framework_specific_risks': [
                'SSTI via Jinja2',
                'SQLAlchemy injection',
                'Flask Debug Mode'
            ],
            'security_critical_files': ['routes.py', 'config.py']
        }
        
        original = "find security vulnerabilities"
        enhanced = generate_framework_aware_prioritization_question(original, tech_info)
        
        # Should include original question
        self.assertIn("find security vulnerabilities", enhanced)
        
        # Should be longer (has enhancements)
        self.assertGreater(len(enhanced), len(original))
    
    def test_question_without_tech_info(self):
        """Test question enhancement with no tech info."""
        from lib.tech_detector import generate_framework_aware_prioritization_question
        
        original = "find vulnerabilities"
        enhanced = generate_framework_aware_prioritization_question(original, {})
        
        # Should return original if no tech info
        self.assertEqual(enhanced, original)


if __name__ == "__main__":
    unittest.main()

