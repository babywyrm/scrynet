"""
MCP Tool Definitions and Handlers

Six core tools that call into Agent Smith's scanning and analysis pipeline.
"""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Ensure project root is on the Python path so we can import lib/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp_server.config import (
    ALLOWED_PATHS,
    MAX_OUTPUT_FINDINGS,
    MAX_PATH_LENGTH,
    MAX_QUESTION_LENGTH,
    OUTPUT_DIR,
    RULES_DIR,
    SCANNER_BIN,
)


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def _validate_path(repo_path: str) -> Path:
    """Validate and resolve a repo path, preventing traversal attacks."""
    if not repo_path or len(repo_path) > MAX_PATH_LENGTH:
        raise ValueError(f"repo_path must be 1-{MAX_PATH_LENGTH} characters")

    resolved = Path(repo_path).resolve()

    if not resolved.is_dir():
        raise ValueError(f"Path does not exist or is not a directory: {resolved}")

    # Check against allowed base paths
    allowed = any(
        resolved == base or resolved.is_relative_to(base)
        for base in ALLOWED_PATHS
    )
    if not allowed:
        raise ValueError(
            f"Path '{resolved}' is outside allowed directories. "
            f"Set AGENTSMITH_ALLOWED_PATHS to expand access."
        )

    return resolved


def _validate_severity(severity: str | None) -> str | None:
    """Validate severity parameter."""
    if severity is None:
        return None
    severity = severity.upper().strip()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        raise ValueError(f"Invalid severity: {severity}. Must be CRITICAL, HIGH, MEDIUM, or LOW.")
    return severity


def _find_output_dir(output_dir: str | None = None) -> Path:
    """Find the output directory, defaulting to the most recent one."""
    if output_dir:
        p = Path(output_dir).resolve()
        if not p.is_dir():
            raise ValueError(f"Output directory not found: {p}")
        return p

    if not OUTPUT_DIR.is_dir():
        raise ValueError("No output/ directory found. Run a scan first.")

    dirs = sorted(
        [d for d in OUTPUT_DIR.iterdir() if d.is_dir()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    if not dirs:
        raise ValueError("No scan results found in output/. Run a scan first.")

    return dirs[0]


def _count_by_key(items: list[dict], key: str, top_n: int | None = None) -> dict[str, int]:
    """Count occurrences of a field value across a list of dicts."""
    counts: dict[str, int] = {}
    for item in items:
        val = item.get(key, "unknown")
        counts[val] = counts.get(val, 0) + 1
    if top_n:
        counts = dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n])
    return counts


# ---------------------------------------------------------------------------
# Tool definitions (MCP schema)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS = [
    {
        "name": "scan_static",
        "description": (
            "Run Agent Smith's static security scanner on a repository. "
            "Uses 70+ OWASP rules to find vulnerabilities without AI. "
            "Fast, free, and requires no API key."
        ),
        "input_schema": {
            "type": "object",
            "required": ["repo_path"],
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Absolute path to the repository to scan",
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "Minimum severity to report (default: all)",
                },
            },
        },
    },
    {
        "name": "scan_hybrid",
        "description": (
            "Run a full hybrid scan combining static analysis with AI-powered "
            "vulnerability detection. Requires CLAUDE_API_KEY or Bedrock credentials. "
            "Generates findings, payloads, annotations, and cost tracking."
        ),
        "input_schema": {
            "type": "object",
            "required": ["repo_path"],
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Absolute path to the repository to scan",
                },
                "profile": {
                    "type": "string",
                    "description": "AI analysis profile (default: owasp). Options: owasp, ctf, code_review, modern, attacker, soc2, pci, compliance, performance",
                    "default": "owasp",
                },
                "preset": {
                    "type": "string",
                    "enum": ["quick", "ctf", "ctf-fast", "security-audit", "pentest", "compliance"],
                    "description": "Use a preset configuration (overrides other options)",
                },
                "prioritize_top": {
                    "type": "integer",
                    "description": "Number of top files for AI to prioritize (default: 15)",
                    "default": 15,
                    "minimum": 1,
                    "maximum": 100,
                },
                "question": {
                    "type": "string",
                    "description": "Focus question for AI prioritization (e.g., 'find SQL injection vulnerabilities')",
                },
            },
        },
    },
    {
        "name": "detect_tech_stack",
        "description": (
            "Detect the technology stack of a repository: languages, frameworks, "
            "entry points, security-critical files, and framework-specific risks."
        ),
        "input_schema": {
            "type": "object",
            "required": ["repo_path"],
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Absolute path to the repository to analyze",
                },
            },
        },
    },
    {
        "name": "summarize_results",
        "description": (
            "Get a summary of existing scan results: finding counts by severity, "
            "top rules, AI findings, cost breakdown, and tech stack info."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "output_dir": {
                    "type": "string",
                    "description": "Path to scan output directory (default: most recent in output/)",
                },
            },
        },
    },
    {
        "name": "list_findings",
        "description": (
            "List individual findings from a scan, optionally filtered by severity "
            "or source. Returns structured finding data."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "output_dir": {
                    "type": "string",
                    "description": "Path to scan output directory (default: most recent in output/)",
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "Filter by minimum severity",
                },
                "source": {
                    "type": "string",
                    "description": "Filter by source (e.g., 'agentsmith', 'claude-owasp')",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of findings to return (default: 50)",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 500,
                },
            },
        },
    },
    {
        "name": "list_presets",
        "description": (
            "List all available scan preset configurations with their descriptions "
            "and settings. Presets are one-command configurations for common workflows."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

async def handle_scan_static(arguments: dict[str, Any]) -> str:
    """Run static analysis with the Go scanner binary."""
    repo_path = _validate_path(arguments["repo_path"])
    severity = _validate_severity(arguments.get("severity"))

    if not SCANNER_BIN.is_file():
        return json.dumps({"error": "Scanner binary not found. Run ./setup.sh to build it."})

    # Build command - auto-load rules from rules/ directory
    cmd = [str(SCANNER_BIN), "--dir", str(repo_path), "--output", "json"]
    if severity:
        cmd.extend(["--severity", severity])

    rule_files = sorted(RULES_DIR.glob("*.json")) if RULES_DIR.is_dir() else []
    if rule_files:
        cmd.extend(["--rules", ",".join(str(f) for f in rule_files)])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = proc.stdout
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Static scan timed out after 5 minutes"})
    except Exception as e:
        return json.dumps({"error": f"Scanner failed: {e}"})

    # Parse JSON from output
    start = output.find("[")
    end = output.rfind("]") + 1
    if start < 0 or end <= start:
        return json.dumps({"findings": [], "count": 0})

    try:
        findings = json.loads(output[start:end])
    except json.JSONDecodeError:
        return json.dumps({"error": "Failed to parse scanner output"})

    return json.dumps({
        "findings": findings[:MAX_OUTPUT_FINDINGS],
        "count": len(findings),
        "truncated": len(findings) > MAX_OUTPUT_FINDINGS,
        "rules_loaded": len(rule_files),
    })


async def handle_scan_hybrid(arguments: dict[str, Any]) -> str:
    """Run a full hybrid scan via the orchestrator."""
    repo_path = _validate_path(arguments["repo_path"])
    profile = arguments.get("profile", "owasp")
    preset = arguments.get("preset")
    prioritize_top = arguments.get("prioritize_top", 15)
    question = arguments.get("question", "find security vulnerabilities")

    if question and len(question) > MAX_QUESTION_LENGTH:
        question = question[:MAX_QUESTION_LENGTH]

    if not SCANNER_BIN.is_file():
        return json.dumps({"error": "Scanner binary not found. Run ./setup.sh to build it."})

    # Build orchestrator command
    cmd = [
        sys.executable, str(PROJECT_ROOT / "orchestrator.py"),
        str(repo_path), str(SCANNER_BIN),
        "--profile", profile,
        "--prioritize",
        "--prioritize-top", str(prioritize_top),
        "--question", question,
        "--generate-payloads",
        "--annotate-code",
        "--export-format", "json", "csv", "markdown", "html",
        "--verbose",
    ]

    if preset:
        cmd.extend(["--preset", preset])

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            cwd=str(PROJECT_ROOT),
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Hybrid scan timed out after 10 minutes"})
    except Exception as e:
        return json.dumps({"error": f"Orchestrator failed: {e}"})

    if proc.returncode != 0:
        return json.dumps({
            "error": "Scan failed",
            "stderr": proc.stderr[-2000:] if proc.stderr else "",
        })

    # Find the output directory (most recent)
    try:
        out_dir = _find_output_dir()
        combined = out_dir / "combined_findings.json"
        if combined.is_file():
            findings = json.loads(combined.read_text())
            return json.dumps({
                "status": "completed",
                "output_dir": str(out_dir),
                "total_findings": len(findings),
                "by_severity": _count_by_key(findings, "severity"),
                "by_source": _count_by_key(findings, "source"),
            })
    except Exception:
        pass

    return json.dumps({
        "status": "completed",
        "message": "Scan finished. Check output/ directory for results.",
    })


async def handle_detect_tech_stack(arguments: dict[str, Any]) -> str:
    """Detect technology stack of a repository."""
    repo_path = _validate_path(arguments["repo_path"])

    from lib.universal_detector import UniversalTechDetector

    try:
        result = UniversalTechDetector.detect_all(repo_path)
    except Exception as e:
        return json.dumps({"error": f"Tech stack detection failed: {e}"})

    return json.dumps(result, default=str)


async def handle_summarize_results(arguments: dict[str, Any]) -> str:
    """Summarize existing scan results."""
    out_dir = _find_output_dir(arguments.get("output_dir"))

    summary: dict[str, Any] = {"output_dir": str(out_dir)}

    # Static findings
    static_file = out_dir / "static_findings.json"
    if static_file.is_file():
        static = json.loads(static_file.read_text())
        summary["static"] = {
            "count": len(static),
            "by_severity": _count_by_key(static, "severity"),
            "top_rules": _count_by_key(static, "rule_name", top_n=10),
        }

    # AI findings
    ai_file = out_dir / "ai_findings.json"
    if ai_file.is_file():
        ai = json.loads(ai_file.read_text())
        summary["ai"] = {
            "count": len(ai),
            "by_severity": _count_by_key(ai, "severity"),
            "findings": [
                {
                    "severity": f.get("severity"),
                    "title": f.get("title", f.get("rule_name", "unknown")),
                    "file": Path(f.get("file_path", f.get("file", "?"))).name,
                    "line": f.get("line", f.get("line_number")),
                }
                for f in ai[:20]
            ],
        }

    # Combined
    combined_file = out_dir / "combined_findings.json"
    if combined_file.is_file():
        combined = json.loads(combined_file.read_text())
        summary["combined"] = {
            "count": len(combined),
            "by_severity": _count_by_key(combined, "severity"),
            "by_source": _count_by_key(combined, "source"),
        }

    # Cost
    cost_file = out_dir / "cost_tracking.json"
    if cost_file.is_file():
        cost = json.loads(cost_file.read_text())
        s = cost.get("summary", {})
        summary["cost"] = {
            "api_calls": s.get("total_calls", 0),
            "total_tokens": s.get("total_tokens", 0),
            "cost_usd": s.get("total_cost", 0),
        }

    # Tech stack
    tech_file = out_dir / "tech_stack.json"
    if tech_file.is_file():
        summary["tech_stack"] = json.loads(tech_file.read_text())

    # Artifacts
    payloads_dir = out_dir / "payloads"
    annotations_dir = out_dir / "annotations"
    summary["artifacts"] = {
        "payloads": len(list(payloads_dir.glob("*.json"))) if payloads_dir.is_dir() else 0,
        "annotations": len(list(annotations_dir.glob("*.md"))) if annotations_dir.is_dir() else 0,
    }

    return json.dumps(summary, default=str)


async def handle_list_findings(arguments: dict[str, Any]) -> str:
    """List findings with optional filtering."""
    out_dir = _find_output_dir(arguments.get("output_dir"))
    severity = _validate_severity(arguments.get("severity"))
    source_filter = arguments.get("source")
    limit = min(arguments.get("limit", 50), MAX_OUTPUT_FINDINGS)

    combined_file = out_dir / "combined_findings.json"
    if not combined_file.is_file():
        return json.dumps({"error": "No combined_findings.json found. Run a scan first."})

    findings = json.loads(combined_file.read_text())

    # Apply filters
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if severity:
        threshold = sev_order.get(severity, 3)
        findings = [
            f for f in findings
            if sev_order.get(f.get("severity", "LOW"), 3) <= threshold
        ]

    if source_filter:
        findings = [f for f in findings if f.get("source") == source_filter]

    # Sort by severity
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 3))

    total_matched = len(findings)
    findings = findings[:limit]

    # Slim down for transport
    slim = []
    for f in findings:
        slim.append({
            "severity": f.get("severity"),
            "title": f.get("title", f.get("rule_name", "unknown")),
            "file": f.get("file_path", f.get("file", "?")),
            "line": f.get("line", f.get("line_number")),
            "category": f.get("category", ""),
            "source": f.get("source", ""),
            "recommendation": (
                f.get("recommendation", f.get("fix", f.get("remediation", "")))[:200]
            ),
        })

    return json.dumps({
        "findings": slim,
        "returned": len(slim),
        "total_matched": total_matched,
        "filters": {"severity": severity, "source": source_filter},
    })


async def handle_list_presets(arguments: dict[str, Any]) -> str:
    """List available scan presets."""
    from lib.config import list_presets

    presets = list_presets()
    result = []
    for p in presets:
        result.append({
            "name": p.name,
            "description": p.description,
            "profiles": p.profiles if hasattr(p, "profiles") else [],
            "severity": getattr(p, "severity", None),
            "prioritize": getattr(p, "prioritize", False),
            "prioritize_top": getattr(p, "prioritize_top", None),
        })

    return json.dumps({"presets": result, "count": len(result)})


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

TOOL_HANDLERS = {
    "scan_static": handle_scan_static,
    "scan_hybrid": handle_scan_hybrid,
    "detect_tech_stack": handle_detect_tech_stack,
    "summarize_results": handle_summarize_results,
    "list_findings": handle_list_findings,
    "list_presets": handle_list_presets,
}
