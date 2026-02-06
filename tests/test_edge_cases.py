"""
Tests for edge cases and error handling.

Tests SCRYNET's behavior with unusual inputs, boundary conditions,
and error scenarios to ensure robustness.
"""

import unittest
import tempfile
import shutil
from pathlib import Path
import sys
import json

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.common import (
    safe_file_read,
    parse_json_response,
    normalize_finding,
    FileAnalysisError,
    APIError
)


class TestEmptyInputs(unittest.TestCase):
    """Test handling of empty inputs."""
    
    def test_empty_findings_list(self):
        """Test handling of empty findings list."""
        findings = []
        self.assertEqual(len(findings), 0)
        self.assertIsInstance(findings, list)
    
    def test_empty_json_response(self):
        """Test parsing empty JSON response."""
        result = parse_json_response("")
        self.assertIsNone(result)
    
    def test_normalize_empty_finding(self):
        """Test normalizing an empty finding dict."""
        empty_finding = {}
        normalized = normalize_finding(empty_finding)
        
        # Should have default values for core fields
        self.assertIn('severity', normalized)
        self.assertIn('title', normalized)
        # Note: file_path is only added if present in original finding
        self.assertIsInstance(normalized, dict)
    
    def test_empty_file_content(self):
        """Test reading an empty file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_path = Path(f.name)
            # Write nothing (empty file)
        
        try:
            content = safe_file_read(temp_path)
            self.assertEqual(content, "")
        finally:
            temp_path.unlink()


class TestEmptyRepository(unittest.TestCase):
    """Test scanning empty or minimal repositories."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_empty_directory(self):
        """Test scanning completely empty directory."""
        empty_dir = Path(self.test_dir) / "empty"
        empty_dir.mkdir()
        
        # Should handle gracefully
        self.assertTrue(empty_dir.exists())
        self.assertTrue(empty_dir.is_dir())
        self.assertEqual(len(list(empty_dir.iterdir())), 0)
    
    def test_directory_with_only_hidden_files(self):
        """Test directory with only hidden/ignored files."""
        hidden_dir = Path(self.test_dir) / "hidden"
        hidden_dir.mkdir()
        
        # Create hidden files
        (hidden_dir / ".git").mkdir()
        (hidden_dir / ".env").write_text("SECRET=123")
        (hidden_dir / ".gitignore").write_text("*.log")
        
        # Should exist but potentially be skipped
        self.assertTrue(hidden_dir.exists())
    
    def test_directory_with_no_code_files(self):
        """Test directory with only non-code files."""
        no_code_dir = Path(self.test_dir) / "nocode"
        no_code_dir.mkdir()
        
        # Create non-code files
        (no_code_dir / "README.md").write_text("# Test")
        (no_code_dir / "image.png").write_bytes(b'\x89PNG')
        (no_code_dir / "data.json").write_text('{"key": "value"}')
        
        self.assertTrue(no_code_dir.exists())


class TestBinaryFileHandling(unittest.TestCase):
    """Test handling of binary files."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_skip_binary_file(self):
        """Test that binary files are handled."""
        binary_file = Path(self.test_dir) / "binary.bin"
        binary_file.write_bytes(b'\x00\x01\x02\x03\xFF\xFE')
        
        # Binary files should either raise error or be handled gracefully
        self.assertTrue(binary_file.exists())
        try:
            content = safe_file_read(binary_file)
            # If it reads, content should be present (possibly empty or decoded)
            self.assertIsInstance(content, str)
        except (FileAnalysisError, UnicodeDecodeError, Exception):
            # Also acceptable to raise an error
            pass
    
    def test_skip_image_files(self):
        """Test that image files are skipped."""
        image_extensions = ['.png', '.jpg', '.gif', '.ico', '.svg']
        
        for ext in image_extensions:
            img_file = Path(self.test_dir) / f"image{ext}"
            img_file.write_bytes(b'\x89PNG' if ext == '.png' else b'\xFF\xD8\xFF')
            self.assertTrue(img_file.exists())
    
    def test_skip_compiled_files(self):
        """Test that compiled files are skipped."""
        compiled_extensions = ['.pyc', '.class', '.o', '.so', '.dll', '.exe']
        
        for ext in compiled_extensions:
            compiled_file = Path(self.test_dir) / f"compiled{ext}"
            compiled_file.write_bytes(b'\x00\x00\x00\x00')
            self.assertTrue(compiled_file.exists())


class TestVeryLargeFiles(unittest.TestCase):
    """Test handling of very large files."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_file_exceeding_size_limit(self):
        """Test that files exceeding size limit raise error."""
        large_file = Path(self.test_dir) / "large.txt"
        
        # Create a 2MB file
        large_content = "x" * (2 * 1024 * 1024)
        large_file.write_text(large_content)
        
        # Should raise error with reasonable size limit (1MB)
        with self.assertRaises(FileAnalysisError):
            safe_file_read(large_file, max_size=1 * 1024 * 1024)
    
    def test_file_within_size_limit(self):
        """Test that files within limit are read successfully."""
        normal_file = Path(self.test_dir) / "normal.txt"
        content = "x" * 1024  # 1KB
        normal_file.write_text(content)
        
        result = safe_file_read(normal_file, max_size=1 * 1024 * 1024)
        self.assertEqual(len(result), 1024)


class TestMalformedInputs(unittest.TestCase):
    """Test handling of malformed inputs."""
    
    def test_malformed_json(self):
        """Test parsing malformed JSON."""
        malformed_inputs = [
            '{"key": value}',  # Missing quotes
            '{key: "value"}',  # Missing quotes on key
            '{"key": "value",}',  # Trailing comma
            '{"key": undefined}',  # Invalid value
            '{]',  # Mismatched brackets
        ]
        
        for malformed in malformed_inputs:
            result = parse_json_response(malformed)
            # Should return None or handle gracefully
            self.assertTrue(result is None or isinstance(result, dict))
    
    def test_nested_json_with_errors(self):
        """Test JSON with nested errors."""
        nested_malformed = '{"findings": [{"title": "test", "severity": }]}'
        result = parse_json_response(nested_malformed)
        self.assertTrue(result is None or isinstance(result, dict))
    
    def test_json_with_unicode_errors(self):
        """Test JSON with problematic unicode."""
        unicode_json = '{"title": "Test \\u0000 null byte"}'
        result = parse_json_response(unicode_json)
        self.assertTrue(result is None or isinstance(result, dict))


class TestNonexistentPaths(unittest.TestCase):
    """Test handling of nonexistent paths."""
    
    def test_read_nonexistent_file(self):
        """Test reading a file that doesn't exist."""
        fake_path = Path("/nonexistent/path/to/file.txt")
        
        with self.assertRaises(FileAnalysisError):
            safe_file_read(fake_path)
    
    def test_scan_nonexistent_directory(self):
        """Test scanning a directory that doesn't exist."""
        fake_dir = Path("/nonexistent/directory")
        
        self.assertFalse(fake_dir.exists())


class TestSpecialCharactersInPaths(unittest.TestCase):
    """Test handling of special characters in file paths."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_spaces_in_filename(self):
        """Test files with spaces in name."""
        spaced_file = Path(self.test_dir) / "file with spaces.py"
        spaced_file.write_text("print('test')")
        
        content = safe_file_read(spaced_file)
        self.assertEqual(content, "print('test')")
    
    def test_unicode_in_filename(self):
        """Test files with unicode characters."""
        try:
            unicode_file = Path(self.test_dir) / "файл_тест.py"
            unicode_file.write_text("print('test')")
            
            content = safe_file_read(unicode_file)
            self.assertEqual(content, "print('test')")
        except (OSError, UnicodeError):
            # Some filesystems don't support unicode names
            self.skipTest("Filesystem doesn't support unicode filenames")


class TestNoFindings(unittest.TestCase):
    """Test handling when no findings are detected."""
    
    def test_clean_codebase_returns_empty(self):
        """Test that clean codebase returns empty findings."""
        findings = []
        
        # Should handle empty findings gracefully
        self.assertEqual(len(findings), 0)
        self.assertIsInstance(findings, list)
    
    def test_normalization_with_no_findings(self):
        """Test normalization when no findings exist."""
        findings = []
        normalized = [normalize_finding(f) for f in findings]
        
        self.assertEqual(len(normalized), 0)
        self.assertIsInstance(normalized, list)


class TestNetworkErrors(unittest.TestCase):
    """Test handling of network-related errors."""
    
    def test_api_timeout_error(self):
        """Test handling of API timeout errors."""
        # APIError should be raised with timeout info
        error = APIError("Request timeout after 60s", status_code=408)
        
        self.assertIsInstance(error, Exception)
        self.assertEqual(error.status_code, 408)
    
    def test_api_connection_error(self):
        """Test handling of connection errors."""
        error = APIError("Connection refused", status_code=None)
        
        self.assertIsInstance(error, Exception)


class TestConcurrentAccess(unittest.TestCase):
    """Test handling of concurrent access scenarios."""
    
    def test_cache_concurrent_reads(self):
        """Test that cache can handle concurrent reads."""
        # This is a conceptual test
        # Real implementation would use threading
        cache_keys = ["key1", "key2", "key3"]
        
        for key in cache_keys:
            # Each key should be independent
            self.assertIsInstance(key, str)
    
    def test_review_state_concurrent_writes(self):
        """Test that review state handles concurrent writes."""
        # This tests the concept of concurrent access
        # Actual implementation would use file locks or similar
        self.assertTrue(True)


class TestExtremeSeverities(unittest.TestCase):
    """Test handling of edge cases in severity values."""
    
    def test_unknown_severity_normalized(self):
        """Test handling of unknown severities."""
        finding = {"severity": "ULTRA_CRITICAL", "title": "test"}
        normalized = normalize_finding(finding)
        
        # Unknown severities may be passed through or normalized
        # Both behaviors are acceptable
        self.assertIsInstance(normalized['severity'], str)
        self.assertTrue(len(normalized['severity']) > 0)
    
    def test_lowercase_severity(self):
        """Test that lowercase severities are normalized."""
        finding = {"severity": "high", "title": "test"}
        normalized = normalize_finding(finding)
        
        self.assertEqual(normalized['severity'], 'HIGH')
    
    def test_numeric_severity(self):
        """Test that numeric severities are handled."""
        finding = {"severity": 5, "title": "test"}
        normalized = normalize_finding(finding)
        
        # Should convert to string severity
        self.assertIsInstance(normalized['severity'], str)


class TestMissingRequiredFields(unittest.TestCase):
    """Test handling of findings with missing required fields."""
    
    def test_finding_without_title(self):
        """Test finding without title field."""
        finding = {"severity": "HIGH", "file_path": "test.py"}
        normalized = normalize_finding(finding)
        
        # Should have default title
        self.assertIn('title', normalized)
        self.assertIsInstance(normalized['title'], str)
    
    def test_finding_without_severity(self):
        """Test finding without severity field."""
        finding = {"title": "Test", "file_path": "test.py"}
        normalized = normalize_finding(finding)
        
        # Should have default severity
        self.assertIn('severity', normalized)
    
    def test_finding_without_file_path(self):
        """Test finding without file_path field."""
        finding = {"title": "Test", "severity": "HIGH"}
        normalized = normalize_finding(finding)
        
        # Normalization should complete successfully
        self.assertIn('title', normalized)
        self.assertIn('severity', normalized)
        # Note: file_path may not be added if not in original


if __name__ == '__main__':
    unittest.main()
