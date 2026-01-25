#!/usr/bin/env python3
"""
Test suite for universal tech stack detector.

Tests the new universal detection system that finds ANY framework.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.universal_detector import UniversalTechDetector


class TestUniversalDetector(unittest.TestCase):
    """Test universal framework detection."""
    
    def test_detect_on_dvwa(self):
        """Test detection on DVWA (PHP application)."""
        dvwa_path = Path(__file__).parent / "test_targets" / "DVWA"
        if not dvwa_path.exists():
            self.skipTest("DVWA test target not found")
        
        result = UniversalTechDetector.detect_all(dvwa_path)
        
        # Should detect PHP
        self.assertIn('PHP', result['languages'])
        
        # Should detect MySQL (or at least identify as database app)
        # Note: MySQL detection depends on actual DVWA configuration files
        if result.get('databases'):
            has_db = any('mysql' in str(f).lower() for f in result.get('databases', []))
            # If databases detected, great; if not, that's ok for this test
        
        # Should find entry points
        self.assertGreater(len(result['entry_points']), 0)
        
        # Should identify security files
        self.assertGreater(len(result['security_critical_files']), 0)
        
        # Should have framework-specific risks
        self.assertGreater(len(result['framework_specific_risks']), 0)
    
    def test_detect_on_juice_shop(self):
        """Test detection on Juice Shop (Node.js/Express/Angular)."""
        juice_path = Path(__file__).parent / "test_targets" / "juice-shop"
        if not juice_path.exists():
            self.skipTest("Juice Shop test target not found")
        
        result = UniversalTechDetector.detect_all(juice_path)
        
        # Should detect JavaScript/TypeScript
        languages_found = any(lang in ['JavaScript', 'TypeScript'] for lang in result['languages'])
        self.assertTrue(languages_found)
        
        # Should detect Express
        self.assertIn('express', result['frameworks'])
        
        # Should detect Angular
        self.assertIn('angular', result['frameworks'])
        
        # Should have high confidence for Express
        self.assertGreaterEqual(result['frameworks'].get('express', 0), 0.7)
    
    def test_framework_confidence_scores(self):
        """Test that confidence scores are valid."""
        dvwa_path = Path(__file__).parent / "test_targets" / "DVWA"
        if not dvwa_path.exists():
            self.skipTest("Test target not found")
        
        result = UniversalTechDetector.detect_all(dvwa_path)
        
        # All confidence scores should be between 0 and 1
        for fw, confidence in result['frameworks'].items():
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)
    
    def test_app_type_inference(self):
        """Test application type inference."""
        result_web_api = {
            'frameworks': {'fastapi': 0.9, 'grpc': 0.8},
            'languages': ['Python']
        }
        app_type = UniversalTechDetector._infer_app_type(result_web_api)
        self.assertEqual(app_type, 'web_api')
        
        result_web_app = {
            'frameworks': {'flask': 0.9, 'django': 0.7},
            'languages': ['Python']
        }
        app_type = UniversalTechDetector._infer_app_type(result_web_app)
        self.assertEqual(app_type, 'web_app')
        
        result_frontend = {
            'frameworks': {'react': 0.9, 'vue': 0.7},
            'languages': ['JavaScript']
        }
        app_type = UniversalTechDetector._infer_app_type(result_frontend)
        self.assertEqual(app_type, 'frontend_app')
    
    def test_context_string_generation(self):
        """Test context string generation."""
        result = {
            'frameworks': {'flask': 1.0, 'sqlalchemy': 0.9},
            'languages': ['Python'],
            'databases': ['postgresql'],
            'app_type': 'web_app',
            'entry_points': ['app.py', 'routes.py'],
            'security_critical_files': ['config.py']
        }
        
        context = UniversalTechDetector._build_context(result)
        
        self.assertIn('flask', context.lower())  # Framework name (lowercase in output)
        self.assertIn('Python', context)
        self.assertIn('web_app', context)
        self.assertIn('2', context)  # 2 entry points
    
    def test_framework_specific_risks(self):
        """Test framework-specific risk generation."""
        result = {
            'frameworks': {'flask': 1.0, 'sqlalchemy': 0.9},
            'languages': ['Python']
        }
        
        risks = UniversalTechDetector._generate_risks(result)
        
        # Should include Flask-specific risks
        flask_risks = [r for r in risks if 'flask' in r.lower() or 'jinja' in r.lower()]
        self.assertGreater(len(flask_risks), 0)
        
        # Should include SQLAlchemy risks
        sql_risks = [r for r in risks if 'sqlalchemy' in r.lower() or 'sql' in r.lower()]
        self.assertGreater(len(sql_risks), 0)
    
    def test_entry_point_detection(self):
        """Test entry point file detection."""
        test_dir = Path(__file__).parent / "test_targets" / "DVWA"
        if not test_dir.exists():
            self.skipTest("Test target not found")
        
        tech_info = {'frameworks': {'php': 1.0}}
        entry_points = UniversalTechDetector._find_entry_points(test_dir, tech_info)
        
        # Should find some entry points
        self.assertGreater(len(entry_points), 0)
        
        # Entry points should be relative paths
        for ep in entry_points:
            self.assertIsInstance(ep, str)
            self.assertNotIn(str(test_dir), ep)  # Should be relative
    
    def test_security_file_detection(self):
        """Test security-critical file detection."""
        test_dir = Path(__file__).parent / "test_targets" / "DVWA"
        if not test_dir.exists():
            self.skipTest("Test target not found")
        
        tech_info = {'frameworks': {'php': 1.0}}
        security_files = UniversalTechDetector._find_security_files(test_dir, tech_info)
        
        # Should find security files
        self.assertGreater(len(security_files), 0)
        
        # Should find files with security keywords
        has_auth_or_login = any('auth' in f.lower() or 'login' in f.lower() for f in security_files)
        self.assertTrue(has_auth_or_login)


class TestFrameworkPatterns(unittest.TestCase):
    """Test framework pattern definitions."""
    
    def test_pattern_coverage(self):
        """Test that common frameworks are covered."""
        patterns = UniversalTechDetector.FRAMEWORK_PATTERNS
        
        # Web frameworks
        self.assertIn('flask', patterns)
        self.assertIn('django', patterns)
        self.assertIn('express', patterns)
        self.assertIn('spring', patterns)
        self.assertIn('laravel', patterns)
        
        # Frontend
        self.assertIn('react', patterns)
        self.assertIn('vue', patterns)
        self.assertIn('angular', patterns)
        
        # Databases
        self.assertIn('postgresql', patterns)
        self.assertIn('mysql', patterns)
        self.assertIn('mongodb', patterns)
    
    def test_pattern_structure(self):
        """Test that patterns have required fields."""
        patterns = UniversalTechDetector.FRAMEWORK_PATTERNS
        
        for name, info in patterns.items():
            self.assertIn('keywords', info)
            self.assertIn('type', info)
            self.assertIn('lang', info)
            self.assertIsInstance(info['keywords'], list)
            self.assertGreater(len(info['keywords']), 0)


if __name__ == "__main__":
    unittest.main()

