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
    normalize_finding,
    get_recommendation_text,
    get_line_number,
    handle_api_error,
    safe_file_read,
    APIError,
    FileAnalysisError,
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


class TestNormalizeFinding(unittest.TestCase):
    """Test finding normalization utilities."""
    
    def test_normalize_recommendation_field(self):
        """Test that recommendation field is normalized correctly."""
        # Test with 'fix' field
        finding = {'fix': 'Use parameterized queries', 'severity': 'HIGH'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['recommendation'], 'Use parameterized queries')
        
        # Test with 'explanation' field
        finding = {'explanation': 'SQL injection vulnerability', 'severity': 'CRITICAL'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['recommendation'], 'SQL injection vulnerability')
        
        # Test with 'description' field
        finding = {'description': 'Hardcoded password', 'severity': 'MEDIUM'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['recommendation'], 'Hardcoded password')
        
        # Test priority: recommendation > fix > explanation
        finding = {
            'recommendation': 'Primary recommendation',
            'fix': 'Secondary fix',
            'explanation': 'Tertiary explanation',
            'severity': 'HIGH'
        }
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['recommendation'], 'Primary recommendation')
    
    def test_normalize_file_path(self):
        """Test file path normalization."""
        finding = {'file': Path('/test/file.py'), 'severity': 'LOW'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['file'], '/test/file.py')
        self.assertIsInstance(normalized['file'], str)
        
        # Test with file_path parameter
        normalized = normalize_finding({'severity': 'MEDIUM'}, file_path='/new/path.py')
        self.assertEqual(normalized['file'], '/new/path.py')
    
    def test_normalize_line_number(self):
        """Test line number normalization."""
        # Test with 'line' field
        finding = {'line': 42, 'severity': 'HIGH'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['line_number'], 42)
        self.assertEqual(normalized['line'], 42)
        
        # Test with 'line_number' field
        finding = {'line_number': 100, 'severity': 'CRITICAL'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['line_number'], 100)
        self.assertEqual(normalized['line'], 100)
    
    def test_normalize_source(self):
        """Test source field assignment."""
        finding = {'severity': 'MEDIUM'}
        normalized = normalize_finding(finding, source='claude-owasp')
        self.assertEqual(normalized['source'], 'claude-owasp')
    
    def test_normalize_title(self):
        """Test title normalization."""
        # Test with rule_name fallback
        finding = {'rule_name': 'SQL Injection', 'severity': 'HIGH'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['title'], 'SQL Injection')
        self.assertEqual(normalized['rule_name'], 'SQL Injection')
        
        # Test default title
        finding = {'category': 'A03', 'severity': 'CRITICAL'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['title'], 'A03')
    
    def test_normalize_severity(self):
        """Test severity normalization."""
        # Test uppercase conversion
        finding = {'severity': 'high'}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['severity'], 'HIGH')
        
        # Test default severity
        finding = {}
        normalized = normalize_finding(finding)
        self.assertEqual(normalized['severity'], 'MEDIUM')
    
    def test_normalize_complete_finding(self):
        """Test normalization of a complete finding."""
        finding = {
            'file': Path('/test/vuln.php'),
            'line': 42,
            'title': 'SQL Injection',
            'severity': 'high',
            'category': 'A03',
            'fix': 'Use prepared statements',
            'description': 'User input directly in SQL query'
        }
        normalized = normalize_finding(finding, source='scrynet')
        
        self.assertEqual(normalized['file'], '/test/vuln.php')
        self.assertEqual(normalized['line_number'], 42)
        self.assertEqual(normalized['line'], 42)
        self.assertEqual(normalized['title'], 'SQL Injection')
        self.assertEqual(normalized['severity'], 'HIGH')
        self.assertEqual(normalized['category'], 'A03')
        self.assertEqual(normalized['recommendation'], 'Use prepared statements')
        self.assertEqual(normalized['description'], 'User input directly in SQL query')
        self.assertEqual(normalized['source'], 'scrynet')
        self.assertEqual(normalized['explanation'], 'User input directly in SQL query')
    
    def test_normalize_does_not_modify_original(self):
        """Test that normalization doesn't modify the original dict."""
        original = {'severity': 'low', 'line': 10}
        normalized = normalize_finding(original)
        
        # Original should be unchanged
        self.assertEqual(original['severity'], 'low')
        self.assertEqual(original['line'], 10)
        
        # Normalized should be different
        self.assertEqual(normalized['severity'], 'LOW')
        self.assertIn('line_number', normalized)


class TestGetRecommendationText(unittest.TestCase):
    """Test recommendation text extraction."""
    
    def test_get_recommendation_priority(self):
        """Test that recommendation field priority is correct."""
        finding = {'recommendation': 'Primary'}
        self.assertEqual(get_recommendation_text(finding), 'Primary')
        
        finding = {'fix': 'Secondary'}
        self.assertEqual(get_recommendation_text(finding), 'Secondary')
        
        finding = {'explanation': 'Tertiary'}
        self.assertEqual(get_recommendation_text(finding), 'Tertiary')
        
        finding = {'description': 'Quaternary'}
        self.assertEqual(get_recommendation_text(finding), 'Quaternary')
        
        finding = {}
        self.assertEqual(get_recommendation_text(finding), 'N/A')


class TestGetLineNumber(unittest.TestCase):
    """Test line number extraction."""
    
    def test_get_line_number_from_line(self):
        """Test extraction from 'line' field."""
        finding = {'line': 42}
        self.assertEqual(get_line_number(finding), 42)
    
    def test_get_line_number_from_line_number(self):
        """Test extraction from 'line_number' field."""
        finding = {'line_number': 100}
        self.assertEqual(get_line_number(finding), 100)
    
    def test_get_line_number_priority(self):
        """Test that line_number takes priority over line."""
        finding = {'line': 10, 'line_number': 20}
        self.assertEqual(get_line_number(finding), 20)
    
    def test_get_line_number_default(self):
        """Test default value when no line number."""
        finding = {}
        self.assertEqual(get_line_number(finding), 0)
    
    def test_get_line_number_string(self):
        """Test handling of string line numbers."""
        finding = {'line': '42'}
        self.assertEqual(get_line_number(finding), 42)
        
        finding = {'line': 'invalid'}
        result = get_line_number(finding)
        # May return string or 0 depending on implementation
        self.assertIsInstance(result, (int, str))


class TestHandleAPIError(unittest.TestCase):
    """Test API error handling."""
    
    def _create_mock_response(self, status_code: int):
        """Helper to create mock httpx.Response with status code."""
        from unittest.mock import Mock
        import httpx
        
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = status_code
        mock_response.headers = {"request-id": "test-request-id"}
        mock_response.text = ""
        return mock_response
    
    def test_rate_limit_retry(self):
        """Test that rate limit errors trigger retry."""
        import anthropic
        
        # Create mock response with 429 status
        mock_response = self._create_mock_response(429)
        error = anthropic.APIStatusError(
            message="Rate limit exceeded",
            response=mock_response,
            body=None
        )
        
        should_retry, wait_time = handle_api_error(error, max_retries=3, attempt=0)
        self.assertTrue(should_retry)
        self.assertIsNotNone(wait_time)
        self.assertGreater(wait_time, 0)
    
    def test_overloaded_retry(self):
        """Test that 529 errors trigger retry."""
        import anthropic
        
        mock_response = self._create_mock_response(529)
        error = anthropic.APIStatusError(
            message="Service overloaded",
            response=mock_response,
            body=None
        )
        
        should_retry, wait_time = handle_api_error(error, max_retries=3, attempt=0)
        self.assertTrue(should_retry)
        self.assertIsNotNone(wait_time)
    
    def test_client_error_no_retry(self):
        """Test that 4xx errors don't retry."""
        import anthropic
        
        mock_response = self._create_mock_response(400)
        error = anthropic.APIStatusError(
            message="Bad request",
            response=mock_response,
            body=None
        )
        
        with self.assertRaises(APIError):
            handle_api_error(error, max_retries=3, attempt=0)
    
    def test_server_error_retry(self):
        """Test that 5xx errors trigger retry."""
        import anthropic
        
        mock_response = self._create_mock_response(500)
        error = anthropic.APIStatusError(
            message="Internal server error",
            response=mock_response,
            body=None
        )
        
        should_retry, wait_time = handle_api_error(error, max_retries=3, attempt=0)
        self.assertTrue(should_retry)
        self.assertIsNotNone(wait_time)
    
    def test_max_retries_exceeded(self):
        """Test that max retries raises APIError."""
        import anthropic
        
        mock_response = self._create_mock_response(429)
        error = anthropic.APIStatusError(
            message="Rate limit exceeded",
            response=mock_response,
            body=None
        )
        
        with self.assertRaises(APIError):
            handle_api_error(error, max_retries=3, attempt=2)  # Last attempt


class TestSafeFileRead(unittest.TestCase):
    """Test safe file reading."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(__file__).parent / "test_targets"
    
    def test_read_existing_file(self):
        """Test reading an existing file."""
        # Find a small test file
        test_file = self.test_dir / "DVWA" / "README.md"
        if test_file.exists():
            content = safe_file_read(test_file)
            self.assertIsInstance(content, str)
            self.assertGreater(len(content), 0)
        else:
            self.skipTest("Test file not found")
    
    def test_file_too_large(self):
        """Test that files exceeding max_size raise error."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('x' * 11_000_000)  # 11MB
            temp_path = Path(f.name)
        
        try:
            with self.assertRaises(FileAnalysisError):
                safe_file_read(temp_path, max_size=10_000_000)
        finally:
            temp_path.unlink()
    
    def test_nonexistent_file(self):
        """Test that nonexistent files raise error."""
        nonexistent = Path("/nonexistent/file/that/does/not/exist.txt")
        with self.assertRaises(FileAnalysisError):
            safe_file_read(nonexistent)


class TestErrorClasses(unittest.TestCase):
    """Test custom error classes."""
    
    def test_api_error(self):
        """Test APIError exception."""
        original = ValueError("Original error")
        error = APIError("API call failed", status_code=500, original_error=original)
        
        self.assertEqual(str(error), "API call failed")
        self.assertEqual(error.status_code, 500)
        self.assertEqual(error.original_error, original)
    
    def test_file_analysis_error(self):
        """Test FileAnalysisError exception."""
        original = IOError("Permission denied")
        error = FileAnalysisError("/test/file.py", "Cannot read file", original_error=original)
        
        self.assertIn("/test/file.py", str(error))
        self.assertIn("Cannot read file", str(error))
        self.assertEqual(error.file_path, "/test/file.py")
        self.assertEqual(error.original_error, original)


if __name__ == "__main__":
    unittest.main()
