"""
Tests for MCP Server tools — input validation, path security, and tool logic.

These are unit tests that do NOT require a running MCP server.
They test the tool handlers and validation functions directly.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from mcp_server.tools import (
    _validate_path,
    _validate_severity,
    _find_output_dir,
    _count_by_key,
    TOOL_DEFINITIONS,
    TOOL_HANDLERS,
    handle_list_presets,
    handle_summarize_results,
    handle_list_findings,
    handle_scan_static,
    handle_detect_tech_stack,
)


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------

class TestValidatePath(unittest.TestCase):
    """Test path validation and traversal prevention."""

    def test_valid_path_accepted(self):
        """Valid existing directory should be accepted."""
        # Use the project root as a known valid path
        with patch("mcp_server.tools.ALLOWED_PATHS", [PROJECT_ROOT]):
            result = _validate_path(str(PROJECT_ROOT))
            self.assertEqual(result, PROJECT_ROOT)

    def test_subdirectory_accepted(self):
        """Subdirectory within allowed paths should be accepted."""
        with patch("mcp_server.tools.ALLOWED_PATHS", [PROJECT_ROOT]):
            tests_dir = PROJECT_ROOT / "tests"
            if tests_dir.is_dir():
                result = _validate_path(str(tests_dir))
                self.assertEqual(result, tests_dir)

    def test_empty_path_rejected(self):
        """Empty string should be rejected."""
        with self.assertRaises(ValueError):
            _validate_path("")

    def test_nonexistent_path_rejected(self):
        """Non-existent path should be rejected."""
        with self.assertRaises(ValueError):
            _validate_path("/nonexistent/totally/fake/path")

    def test_file_path_rejected(self):
        """File (not directory) should be rejected."""
        with self.assertRaises(ValueError):
            _validate_path(str(PROJECT_ROOT / "requirements.txt"))

    def test_path_outside_allowed_rejected(self):
        """Path outside allowed directories should be rejected."""
        with patch("mcp_server.tools.ALLOWED_PATHS", [PROJECT_ROOT / "tests"]):
            with self.assertRaises(ValueError) as ctx:
                _validate_path("/tmp")
            self.assertIn("outside allowed", str(ctx.exception))

    def test_traversal_attack_rejected(self):
        """Path traversal via .. should be rejected if it escapes allowed paths."""
        with patch("mcp_server.tools.ALLOWED_PATHS", [PROJECT_ROOT / "tests"]):
            with self.assertRaises(ValueError):
                _validate_path(str(PROJECT_ROOT / "tests" / ".." / ".."))

    def test_very_long_path_rejected(self):
        """Excessively long path should be rejected."""
        with self.assertRaises(ValueError):
            _validate_path("a" * 5000)


class TestValidateSeverity(unittest.TestCase):
    """Test severity parameter validation."""

    def test_valid_severities(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            self.assertEqual(_validate_severity(sev), sev)

    def test_case_insensitive(self):
        self.assertEqual(_validate_severity("critical"), "CRITICAL")
        self.assertEqual(_validate_severity("High"), "HIGH")

    def test_none_returns_none(self):
        self.assertIsNone(_validate_severity(None))

    def test_invalid_rejected(self):
        with self.assertRaises(ValueError):
            _validate_severity("EXTREME")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            _validate_severity("")

    def test_whitespace_handled(self):
        self.assertEqual(_validate_severity("  HIGH  "), "HIGH")


class TestCountByKey(unittest.TestCase):
    """Test the counting utility."""

    def test_basic_count(self):
        items = [{"s": "A"}, {"s": "B"}, {"s": "A"}, {"s": "A"}]
        result = _count_by_key(items, "s")
        self.assertEqual(result, {"A": 3, "B": 1})

    def test_missing_key_counted_as_unknown(self):
        items = [{"x": 1}, {"s": "A"}]
        result = _count_by_key(items, "s")
        self.assertEqual(result, {"unknown": 1, "A": 1})

    def test_top_n(self):
        items = [{"s": "A"}] * 10 + [{"s": "B"}] * 5 + [{"s": "C"}] * 1
        result = _count_by_key(items, "s", top_n=2)
        self.assertEqual(len(result), 2)
        self.assertIn("A", result)
        self.assertIn("B", result)

    def test_empty_list(self):
        result = _count_by_key([], "s")
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# Tool definition tests
# ---------------------------------------------------------------------------

class TestToolDefinitions(unittest.TestCase):
    """Validate tool schemas are well-formed."""

    def test_all_tools_have_definitions(self):
        """Every handler should have a matching definition."""
        def_names = {t["name"] for t in TOOL_DEFINITIONS}
        handler_names = set(TOOL_HANDLERS.keys())
        self.assertEqual(def_names, handler_names)

    def test_definitions_have_required_fields(self):
        for td in TOOL_DEFINITIONS:
            self.assertIn("name", td)
            self.assertIn("description", td)
            self.assertIn("input_schema", td)
            self.assertIsInstance(td["name"], str)
            self.assertIsInstance(td["description"], str)
            self.assertTrue(len(td["description"]) > 10)

    def test_schemas_are_valid_json_schema(self):
        for td in TOOL_DEFINITIONS:
            schema = td["input_schema"]
            self.assertEqual(schema.get("type"), "object")
            self.assertIn("properties", schema)

    def test_tool_count(self):
        self.assertEqual(len(TOOL_DEFINITIONS), 10)
        self.assertEqual(len(TOOL_HANDLERS), 10)

    def test_handler_names(self):
        expected = {
            "scan_static", "scan_hybrid", "detect_tech_stack",
            "summarize_results", "list_findings", "list_presets",
            "scan_file", "explain_finding", "get_fix", "scan_mcp",
        }
        self.assertEqual(set(TOOL_HANDLERS.keys()), expected)


# ---------------------------------------------------------------------------
# Tool handler tests (async)
# ---------------------------------------------------------------------------

class TestHandleListPresets(unittest.TestCase):
    """Test list_presets handler."""

    def test_returns_presets(self):
        result = _run_async(handle_list_presets({}))
        data = json.loads(result)
        self.assertIn("presets", data)
        self.assertIn("count", data)
        self.assertGreaterEqual(data["count"], 7)
        names = [p["name"] for p in data["presets"]]
        self.assertIn("mcp", names)
        self.assertIn("quick", names)
        self.assertIn("ctf", names)
        self.assertIn("pentest", names)

    def test_preset_structure(self):
        result = _run_async(handle_list_presets({}))
        data = json.loads(result)
        for preset in data["presets"]:
            self.assertIn("name", preset)
            self.assertIn("description", preset)


class TestHandleListFindings(unittest.TestCase):
    """Test list_findings handler."""

    def test_missing_output_dir(self):
        """Should raise ValueError when no output exists."""
        with patch("mcp_server.tools.OUTPUT_DIR", Path("/nonexistent")):
            with self.assertRaises(ValueError) as ctx:
                _run_async(handle_list_findings({}))
            self.assertIn("No output", str(ctx.exception))

    def test_severity_filter(self):
        """Test that severity filtering works on mock data."""
        findings = [
            {"severity": "CRITICAL", "title": "crit1", "file": "a.py", "source": "x"},
            {"severity": "HIGH", "title": "high1", "file": "b.py", "source": "x"},
            {"severity": "MEDIUM", "title": "med1", "file": "c.py", "source": "x"},
            {"severity": "LOW", "title": "low1", "file": "d.py", "source": "x"},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)
            (outdir / "combined_findings.json").write_text(json.dumps(findings))

            result = _run_async(handle_list_findings({
                "output_dir": str(outdir), "severity": "HIGH"
            }))
            data = json.loads(result)
            self.assertEqual(data["total_matched"], 2)  # CRITICAL + HIGH
            for f in data["findings"]:
                self.assertIn(f["severity"], ("CRITICAL", "HIGH"))

    def test_source_filter(self):
        """Test source filtering."""
        findings = [
            {"severity": "HIGH", "title": "f1", "file": "a.py", "source": "agentsmith"},
            {"severity": "HIGH", "title": "f2", "file": "b.py", "source": "claude-owasp"},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)
            (outdir / "combined_findings.json").write_text(json.dumps(findings))

            result = _run_async(handle_list_findings({
                "output_dir": str(outdir), "source": "agentsmith"
            }))
            data = json.loads(result)
            self.assertEqual(data["total_matched"], 1)
            self.assertEqual(data["findings"][0]["source"], "agentsmith")

    def test_limit(self):
        """Test limit parameter."""
        findings = [
            {"severity": "HIGH", "title": f"f{i}", "file": "a.py", "source": "x"}
            for i in range(100)
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)
            (outdir / "combined_findings.json").write_text(json.dumps(findings))

            result = _run_async(handle_list_findings({
                "output_dir": str(outdir), "limit": 5
            }))
            data = json.loads(result)
            self.assertEqual(data["returned"], 5)
            self.assertEqual(data["total_matched"], 100)


class TestHandleSummarizeResults(unittest.TestCase):
    """Test summarize_results handler."""

    def test_summarize_with_all_files(self):
        """Test summary with a complete output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)

            # Create mock output files
            static = [{"severity": "HIGH", "rule_name": "XSS"}] * 5
            (outdir / "static_findings.json").write_text(json.dumps(static))

            ai = [{"severity": "CRITICAL", "title": "SQLi", "file_path": "a.py", "line": 10}]
            (outdir / "ai_findings.json").write_text(json.dumps(ai))

            combined = static + ai
            (outdir / "combined_findings.json").write_text(json.dumps(combined))

            cost = {"summary": {"total_calls": 5, "total_tokens": 1000, "total_cost": 0.05}}
            (outdir / "cost_tracking.json").write_text(json.dumps(cost))

            tech = {"languages": ["Python"], "frameworks": {"flask": 0.9}}
            (outdir / "tech_stack.json").write_text(json.dumps(tech))

            result = _run_async(handle_summarize_results({"output_dir": str(outdir)}))
            data = json.loads(result)

            self.assertEqual(data["static"]["count"], 5)
            self.assertEqual(data["ai"]["count"], 1)
            self.assertEqual(data["combined"]["count"], 6)
            self.assertAlmostEqual(data["cost"]["cost_usd"], 0.05)
            self.assertIn("Python", data["tech_stack"]["languages"])


class TestHandleScanStatic(unittest.TestCase):
    """Test scan_static handler."""

    def test_missing_scanner_binary(self):
        """Should return error when scanner binary is missing."""
        with patch("mcp_server.tools.SCANNER_BIN", Path("/nonexistent/scanner")):
            with patch("mcp_server.tools.ALLOWED_PATHS", [Path("/")]):
                result = _run_async(handle_scan_static({"repo_path": "/tmp"}))
                data = json.loads(result)
                self.assertIn("error", data)
                self.assertIn("Scanner binary not found", data["error"])

    def test_invalid_path_rejected(self):
        """Should raise ValueError for invalid paths."""
        with self.assertRaises(ValueError):
            _run_async(handle_scan_static({"repo_path": "/nonexistent/path"}))


class TestHandleDetectTechStack(unittest.TestCase):
    """Test detect_tech_stack handler."""

    def test_detects_project_root(self):
        """Should detect tech stack of our own project."""
        with patch("mcp_server.tools.ALLOWED_PATHS", [PROJECT_ROOT]):
            result = _run_async(handle_detect_tech_stack({"repo_path": str(PROJECT_ROOT)}))
            data = json.loads(result)
            # Should detect Python at minimum
            langs = data.get("languages", [])
            if isinstance(langs, dict):
                langs = list(langs.keys())
            self.assertTrue(
                any("python" in l.lower() for l in langs) or
                any("go" in l.lower() for l in langs),
                f"Expected Python or Go in languages, got {langs}"
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_async(coro):
    """Run an async function synchronously for testing."""
    import asyncio
    return asyncio.run(coro)


if __name__ == "__main__":
    unittest.main()
