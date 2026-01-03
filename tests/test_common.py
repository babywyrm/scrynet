#!/usr/bin/env python3
"""
Test suite for common utilities.

Tests shared functions in lib/common.py.
"""

import unittest
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.common import (
    parse_json_response,
    get_api_key,
    scan_repo_files,
    retry_with_backoff,
    CODE_EXTS,
    SKIP_DIRS,
)


class TestParseJsonResponse(unittest.TestCase):
    """Test JSON parsing from API responses."""
    
    def test_parse_valid_json(self):
        """Test parsing valid JSON."""
        valid_json = '{"key": "value", "number": 42}'
        result = parse_json_response(valid_json)
        self.assertIsNotNone(result)
        self.assertEqual(result["key"], "value")
        self.assertEqual(result["number"], 42)
    
    def test_parse_json_with_code_fences(self):
        """Test parsing JSON wrapped in code fences."""
        json_with_fences = "```json\n{\"key\": \"value\"}\n```"
        result = parse_json_response(json_with_fences)
        self.assertIsNotNone(result)
        self.assertEqual(result["key"], "value")
    
    def test_parse_json_in_text(self):
        """Test extracting JSON from mixed text."""
        mixed_text = "Some text before\n{\"key\": \"value\"}\nSome text after"
        result = parse_json_response(mixed_text)
        self.assertIsNotNone(result)
        self.assertEqual(result["key"], "value")
    
    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns None."""
        invalid_json = "This is not JSON {invalid}"
        result = parse_json_response(invalid_json)
        self.assertIsNone(result)
    
    def test_parse_empty_string(self):
        """Test parsing empty string returns None."""
        result = parse_json_response("")
        self.assertIsNone(result)


class TestScanRepoFiles(unittest.TestCase):
    """Test file scanning utilities."""
    
    def test_code_extensions(self):
        """Test that CODE_EXTS contains expected extensions."""
        expected = {".py", ".go", ".java", ".js", ".ts", ".php"}
        self.assertTrue(expected.issubset(CODE_EXTS))
    
    def test_skip_dirs(self):
        """Test that SKIP_DIRS contains expected directories."""
        expected = {".git", "node_modules", "__pycache__"}
        self.assertTrue(expected.issubset(SKIP_DIRS))


class TestRetryWithBackoff(unittest.TestCase):
    """Test retry decorator."""
    
    def test_successful_call_no_retry(self):
        """Test that successful calls don't retry."""
        call_count = [0]
        
        @retry_with_backoff(max_retries=3)
        def successful_func():
            call_count[0] += 1
            return "success"
        
        result = successful_func()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 1)
    
    def test_retry_on_exception(self):
        """Test that retries happen on exceptions."""
        call_count = [0]
        
        @retry_with_backoff(max_retries=3, base_delay=0.01)
        def failing_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise Exception("Temporary failure")
            return "success"
        
        result = failing_func()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 2)


if __name__ == "__main__":
    unittest.main()

