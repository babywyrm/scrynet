"""
MCP Tool Definitions and Handlers

Ten core tools that call into Agent Smith's scanning and analysis pipeline.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import threading
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

# Maximum file size for single-file operations (1 MB)
MAX_FILE_SIZE = 1_000_000
# Maximum code context to send to AI (100 KB)
MAX_CODE_CONTEXT = 100_000


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


def _get_tech_stack_aware_rules(rules_dir: Path, repo_path: Path) -> list[Path]:
    """Load rules with tech-stack awareness: add framework-specific rules only when detected."""
    all_files = sorted(rules_dir.glob("*.json"))
    has_node = (repo_path / "package.json").exists() or bool(list(repo_path.rglob("package.json")))
    has_python = bool(list(repo_path.rglob("requirements.txt")))
    rule_files = []
    for f in all_files:
        if f.name == "rules_node.json" and not has_node:
            continue
        if f.name == "rules_python.json" and not has_python:
            continue
        rule_files.append(f)
    return rule_files


def _find_output_dir(output_dir: str | None = None, prefer_has: str | None = None) -> Path:
    """Find the output directory, defaulting to the most recent one.
    If prefer_has is 'payloads' or 'annotations', pick the most recent dir that has that subdir with content.
    """
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

    if prefer_has == "payloads":
        for d in dirs:
            pay = d / "payloads"
            if pay.is_dir() and any(pay.glob("*.json")):
                return d
    elif prefer_has == "annotations":
        for d in dirs:
            ann = d / "annotations"
            if ann.is_dir() and any(ann.glob("*.md")):
                return d

    return dirs[0]


def _validate_file_path(file_path: str) -> Path:
    """Validate and resolve a single file path, preventing traversal attacks."""
    if not file_path or len(file_path) > MAX_PATH_LENGTH:
        raise ValueError(f"file_path must be 1-{MAX_PATH_LENGTH} characters")

    resolved = Path(file_path).resolve()

    if not resolved.is_file():
        raise ValueError(f"Path does not exist or is not a file: {resolved}")

    if resolved.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large ({resolved.stat().st_size} bytes). "
            f"Maximum is {MAX_FILE_SIZE} bytes."
        )

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


def _get_ai_client():
    """Get an AI client, raising a clear error if credentials are missing."""
    api_key = os.environ.get("CLAUDE_API_KEY")
    bedrock = os.environ.get("AGENTSMITH_PROVIDER", "").lower() == "bedrock"

    if not api_key and not bedrock:
        raise ValueError(
            "AI tools require CLAUDE_API_KEY or AGENTSMITH_PROVIDER=bedrock. "
            "Set the appropriate environment variable."
        )

    from lib.ai_provider import create_client
    return create_client()


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
                    "enum": ["mcp", "quick", "ctf", "ctf-fast", "security-audit", "pentest", "compliance"],
                    "description": "Use a preset. 'mcp' = 2 files, ~1 min; 'quick' = 10 files",
                },
                "prioritize_top": {
                    "type": "integer",
                    "description": "Number of top files for AI to prioritize (default: 2 for MCP)",
                    "default": 2,
                    "minimum": 1,
                    "maximum": 100,
                },
                "question": {
                    "type": "string",
                    "description": "Focus question for AI prioritization (e.g., 'find SQL injection vulnerabilities')",
                },
                "top_n": {
                    "type": "integer",
                    "description": "Number of top findings to generate payloads/annotations for (default: 5, max: 20)",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 20,
                },
                "generate_payloads": {
                    "type": "boolean",
                    "description": "Generate exploit payloads for top findings (overrides preset default)",
                    "default": False,
                },
                "annotate_code": {
                    "type": "boolean",
                    "description": "Generate code annotations with fixes (overrides preset default)",
                    "default": False,
                },
                "verbose": {
                    "type": "boolean",
                    "description": "Include orchestrator output in response (progress, API calls, cost table — same as CLI --verbose)",
                    "default": True,
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
                "prefer_has": {
                    "type": "string",
                    "enum": ["payloads", "annotations"],
                    "description": "Prefer most recent run that has payloads or annotations",
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
    {
        "name": "scan_file",
        "description": (
            "Scan a single file for security vulnerabilities using Agent Smith's "
            "static analysis rules. Fast and focused — ideal for checking the file "
            "you're currently editing. No API key required."
        ),
        "input_schema": {
            "type": "object",
            "required": ["file_path"],
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to scan",
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
        "name": "explain_finding",
        "description": (
            "Get a detailed AI-powered explanation of a security finding. "
            "Provides attack scenarios, real-world impact, CWE details, and "
            "educational context. Requires CLAUDE_API_KEY."
        ),
        "input_schema": {
            "type": "object",
            "required": ["file_path", "description"],
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file containing the vulnerability",
                },
                "line_number": {
                    "type": "integer",
                    "description": "Line number of the vulnerability (optional but improves accuracy)",
                    "minimum": 1,
                },
                "description": {
                    "type": "string",
                    "description": "Description of the finding to explain (e.g., 'SQL injection in login query')",
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "Severity of the finding",
                },
                "cwe": {
                    "type": "string",
                    "description": "CWE identifier if known (e.g., 'CWE-89')",
                },
            },
        },
    },
    {
        "name": "get_fix",
        "description": (
            "Get an AI-generated code fix for a specific security vulnerability. "
            "Returns before/after code, explanation, and a ready-to-apply patch. "
            "Requires CLAUDE_API_KEY."
        ),
        "input_schema": {
            "type": "object",
            "required": ["file_path", "description"],
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file containing the vulnerability",
                },
                "line_number": {
                    "type": "integer",
                    "description": "Line number of the vulnerability (optional but improves accuracy)",
                    "minimum": 1,
                },
                "description": {
                    "type": "string",
                    "description": "Description of the vulnerability to fix (e.g., 'SQL injection in user lookup')",
                },
                "recommendation": {
                    "type": "string",
                    "description": "Existing recommendation or fix guidance, if available",
                },
            },
        },
    },
    {
        "name": "scan_mcp",
        "description": (
            "Security-scan a remote MCP server. Connects to the target, enumerates "
            "tools/resources/prompts, and analyzes them for security risks: missing "
            "auth, dangerous capabilities, weak input validation, injection vectors, "
            "and transport security issues. No API key required."
        ),
        "input_schema": {
            "type": "object",
            "required": ["target_url"],
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": (
                        "URL of the MCP server to scan. "
                        "SSE: http://host:port/sse  "
                        "Streamable HTTP: http://host:port/mcp/"
                    ),
                },
                "transport": {
                    "type": "string",
                    "enum": ["sse", "http"],
                    "description": "Transport type (default: auto-detect from URL)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Connection timeout in seconds (default: 10)",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 60,
                },
                "auth_token": {
                    "type": "string",
                    "description": "Bearer token for authenticated servers (optional)",
                },
            },
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
        return json.dumps({"error": "Scanner binary not found. Run ./scripts/setup.sh to build it."})

    # Build command - auto-load rules from rules/ directory
    cmd = [str(SCANNER_BIN), "--dir", str(repo_path), "--output", "json"]
    if severity:
        cmd.extend(["--severity", severity])

    rule_files = _get_tech_stack_aware_rules(RULES_DIR, repo_path) if RULES_DIR.is_dir() else []
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

    # Persist to output/ so list_findings/summary work (tied to this repo)
    sanitized = str(repo_path).strip("/").replace("/", "_").replace("\\", "_")
    out_dir = OUTPUT_DIR / sanitized
    out_dir.mkdir(parents=True, exist_ok=True)
    for f in findings:
        f.setdefault("source", "agentsmith")
        f.setdefault("file_path", f.get("file", ""))
        f.setdefault("title", f.get("rule_name", "unknown"))
    static_file = out_dir / "static_findings.json"
    combined_file = out_dir / "combined_findings.json"
    with open(static_file, "w", encoding="utf-8") as fp:
        json.dump(findings, fp, indent=2)
    with open(combined_file, "w", encoding="utf-8") as fp:
        json.dump(findings, fp, indent=2)

    return json.dumps({
        "findings": findings[:MAX_OUTPUT_FINDINGS],
        "count": len(findings),
        "truncated": len(findings) > MAX_OUTPUT_FINDINGS,
        "rules_loaded": len(rule_files),
        "output_dir": str(out_dir),
    })


async def handle_scan_hybrid(arguments: dict[str, Any]) -> str:
    """Run a full hybrid scan via the orchestrator."""
    repo_path = _validate_path(arguments["repo_path"])
    profile = arguments.get("profile", "owasp")
    preset = arguments.get("preset")
    prioritize_top = min(arguments.get("prioritize_top", 2), 50)  # default 2 for MCP, cap 50
    top_n = min(arguments.get("top_n", 5), 20)  # cap payloads/annotations
    question = arguments.get("question", "find the most critical security vulnerabilities")

    if question and len(question) > MAX_QUESTION_LENGTH:
        question = question[:MAX_QUESTION_LENGTH]

    if not SCANNER_BIN.is_file():
        return json.dumps({"error": "Scanner binary not found. Run ./scripts/setup.sh to build it."})

    # Build orchestrator command
    # When a preset is specified, let the preset control all settings.
    # Only add extra flags when running without a preset.
    mcp_debug = os.environ.get("AGENTSMITH_MCP_DEBUG", "").strip().lower() in ("1", "true", "yes")
    cmd = [
        sys.executable, str(PROJECT_ROOT / "orchestrator.py"),
        str(repo_path), str(SCANNER_BIN),
        "--verbose",
    ]
    if mcp_debug:
        cmd.append("--debug")

    if preset:
        # Preset controls everything — always pass prioritize_top (default 4 for fast MCP runs)
        cmd.extend(["--preset", preset])
        cmd.extend(["--prioritize-top", str(prioritize_top)])
        if arguments.get("question"):
            cmd.extend(["--question", question])
        if arguments.get("generate_payloads") is True:
            cmd.append("--generate-payloads")
        if arguments.get("annotate_code") is True:
            cmd.append("--annotate-code")
        if arguments.get("top_n") is not None:
            cmd.extend(["--top-n", str(min(arguments["top_n"], 20))])
    else:
        # No preset — use explicit flags
        cmd.extend([
            "--profile", profile,
            "--prioritize",
            "--prioritize-top", str(prioritize_top),
            "--question", question,
            "--generate-payloads",
            "--annotate-code",
            "--top-n", str(top_n),
            "--export-format", "json", "csv", "markdown", "html",
        ])

    hybrid_timeout = int(os.environ.get("AGENTSMITH_HYBRID_TIMEOUT", "600"))  # default 10 min
    run_env = os.environ.copy()
    if run_env.get("AWS_REGION") and not run_env.get("AWS_DEFAULT_REGION"):
        run_env["AWS_DEFAULT_REGION"] = run_env["AWS_REGION"]

    # Stream orchestrator output to server log in real-time (tail -f .mcp_server.log to watch)
    out_buf: list[str] = []
    err_buf: list[str] = []

    def _stream_reader(pipe, buf: list[str]):
        for line in iter(pipe.readline, ""):
            buf.append(line)
            line = line.rstrip()
            if line:
                logger.info(f"[scan_hybrid] {line}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(PROJECT_ROOT),
            env=run_env,
        )
        t_out = threading.Thread(target=_stream_reader, args=(proc.stdout, out_buf))
        t_err = threading.Thread(target=_stream_reader, args=(proc.stderr, err_buf))
        t_out.daemon = True
        t_err.daemon = True
        t_out.start()
        t_err.start()
        proc.wait(timeout=hybrid_timeout)
        t_out.join(timeout=1)
        t_err.join(timeout=1)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return json.dumps({
            "error": f"Hybrid scan timed out after {hybrid_timeout}s. "
            "Use --preset quick for a faster run, or set AGENTSMITH_HYBRID_TIMEOUT (seconds) and restart the server."
        })
    except Exception as e:
        return json.dumps({"error": f"Orchestrator failed: {e}"})

    if proc.returncode != 0:
        stderr_text = "".join(err_buf)[-2000:]
        return json.dumps({
            "error": "Scan failed",
            "stderr": stderr_text,
        })

    # Include orchestrator output when verbose requested or AGENTSMITH_MCP_DEBUG
    # (progress bars, API calls, cost table — same as CLI --verbose)
    debug_log = None
    want_output = arguments.get("verbose", True) or mcp_debug  # default True for MCP
    combined = f"{''.join(out_buf)}\n{''.join(err_buf)}".strip()
    if want_output and combined:
        cap = 32_000 if arguments.get("verbose") else 4_000
        debug_log = combined[-cap:] if len(combined) > cap else combined

    # Use output dir for the repo we just scanned (orchestrator writes to output/sanitized_repo)
    sanitized = str(repo_path).strip("/").replace("/", "_").replace("\\", "_")
    out_dir = OUTPUT_DIR / sanitized
    try:
        combined = out_dir / "combined_findings.json"
        if combined.is_file():
            findings = json.loads(combined.read_text())
            by_source = _count_by_key(findings, "source")
            out = {
                "status": "completed",
                "output_dir": str(out_dir),
                "total_findings": len(findings),
                "by_severity": _count_by_key(findings, "severity"),
                "by_source": by_source,
            }
            ai_sources = [k for k in by_source if k and k != "agentsmith"]
            if not ai_sources and by_source.get("agentsmith", 0) > 0:
                out["notice"] = (
                    "Hybrid run completed but AI reported 0 findings. "
                    "Check debug log for 404/400 (often = wrong AWS credentials in subprocess). "
                    "Start the MCP server from a shell where you run: export AGENTSMITH_PROVIDER=bedrock AWS_REGION=us-west-2 AWS_PROFILE=your-profile (same as when CLI works). "
                    "Then restart the server and try again."
                )
            if debug_log is not None:
                out["debug_log"] = debug_log
            return json.dumps(out)
    except Exception:
        pass

    fallback = {
        "status": "completed",
        "output_dir": str(out_dir),
        "message": "Scan finished. Check output/ directory for results.",
    }
    if debug_log is not None:
        fallback["debug_log"] = debug_log
    return json.dumps(fallback)


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
    out_dir = _find_output_dir(arguments.get("output_dir"), arguments.get("prefer_has"))

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
        "output_dir": str(out_dir),
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


async def handle_scan_file(arguments: dict[str, Any]) -> str:
    """Scan a single file with the Go static scanner."""
    file_path = _validate_file_path(arguments["file_path"])
    severity = _validate_severity(arguments.get("severity"))

    if not SCANNER_BIN.is_file():
        return json.dumps({"error": "Scanner binary not found. Run ./scripts/setup.sh to build it."})

    # The scanner works on directories, so we scan the parent and filter
    cmd = [str(SCANNER_BIN), "--dir", str(file_path.parent), "--output", "json"]
    if severity:
        cmd.extend(["--severity", severity])

    rule_files = _get_tech_stack_aware_rules(RULES_DIR, file_path.parent) if RULES_DIR.is_dir() else []
    if rule_files:
        cmd.extend(["--rules", ",".join(str(f) for f in rule_files)])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Scan timed out after 2 minutes"})
    except Exception as e:
        return json.dumps({"error": f"Scanner failed: {e}"})

    # Parse and filter to just our file
    start = output.find("[")
    end = output.rfind("]") + 1
    if start < 0 or end <= start:
        return json.dumps({"findings": [], "count": 0, "file": str(file_path)})

    try:
        all_findings = json.loads(output[start:end])
    except json.JSONDecodeError:
        return json.dumps({"error": "Failed to parse scanner output"})

    # Filter findings to just the target file
    file_name = file_path.name
    file_str = str(file_path)
    findings = [
        f for f in all_findings
        if f.get("file", "").endswith(file_name)
        or file_str.endswith(f.get("file", "\x00"))
    ]

    return json.dumps({
        "file": str(file_path),
        "findings": findings[:MAX_OUTPUT_FINDINGS],
        "count": len(findings),
        "rules_loaded": len(rule_files),
    })


async def handle_explain_finding(arguments: dict[str, Any]) -> str:
    """Get a detailed AI explanation of a security finding."""
    file_path = _validate_file_path(arguments["file_path"])
    description = arguments["description"].strip()
    line_number = arguments.get("line_number")
    severity = arguments.get("severity", "MEDIUM")
    cwe = arguments.get("cwe", "")

    if not description or len(description) > MAX_QUESTION_LENGTH:
        raise ValueError(f"description must be 1-{MAX_QUESTION_LENGTH} characters")

    # Read the file for context
    content = file_path.read_text(encoding="utf-8", errors="replace")
    if len(content) > MAX_CODE_CONTEXT:
        # If file is too large, extract context around the line
        if line_number:
            lines = content.splitlines()
            start = max(0, line_number - 30)
            end = min(len(lines), line_number + 30)
            content = "\n".join(lines[start:end])
        else:
            content = content[:MAX_CODE_CONTEXT]

    # Build focused prompt
    line_ctx = f"\n- Line: {line_number}" if line_number else ""
    cwe_ctx = f"\n- CWE: {cwe}" if cwe else ""

    prompt = f"""You are a Principal Application Security Engineer providing a detailed explanation of a security finding to a development team.

FINDING:
- File: {file_path.name}
- Severity: {severity}{line_ctx}{cwe_ctx}
- Description: {description}

CODE CONTEXT:
```
{content}
```

Provide a thorough, educational explanation. Your entire response must be ONLY a JSON object:
{{
  "title": "Clear, specific title for this vulnerability",
  "explanation": "2-3 paragraph explanation of what this vulnerability is and why it matters",
  "attack_scenario": "Step-by-step description of how an attacker could exploit this",
  "impact": "What damage could result from successful exploitation",
  "cwe": "The most applicable CWE ID (e.g., CWE-89) with its name",
  "owasp_category": "Relevant OWASP Top 10 category (e.g., A03:2021 Injection)",
  "references": ["URL or reference 1", "URL or reference 2"],
  "severity_justification": "Why this severity rating is appropriate"
}}"""

    client = _get_ai_client()
    from lib.model_registry import get_default_model
    model = get_default_model()

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        raw = response.content[0].text
    except Exception as e:
        return json.dumps({"error": f"AI analysis failed: {type(e).__name__}: {e}"})

    from lib.common import parse_json_response
    parsed = parse_json_response(raw)

    if not parsed:
        return json.dumps({
            "error": "Failed to parse AI response",
            "raw_response": raw[:2000],
        })

    # Include metadata
    parsed["file"] = str(file_path)
    parsed["line_number"] = line_number
    parsed["model_used"] = model

    return json.dumps(parsed, default=str)


async def handle_get_fix(arguments: dict[str, Any]) -> str:
    """Get an AI-generated code fix for a vulnerability."""
    file_path = _validate_file_path(arguments["file_path"])
    description = arguments["description"].strip()
    line_number = arguments.get("line_number")
    recommendation = arguments.get("recommendation", "")

    if not description or len(description) > MAX_QUESTION_LENGTH:
        raise ValueError(f"description must be 1-{MAX_QUESTION_LENGTH} characters")

    # Read the file
    content = file_path.read_text(encoding="utf-8", errors="replace")
    if len(content) > MAX_CODE_CONTEXT:
        if line_number:
            lines = content.splitlines()
            start = max(0, line_number - 40)
            end = min(len(lines), line_number + 40)
            content = "\n".join(lines[start:end])
        else:
            content = content[:MAX_CODE_CONTEXT]

    line_ctx = f"\n- Vulnerable Line: {line_number}" if line_number else ""
    rec_ctx = f"\n- Existing Recommendation: {recommendation}" if recommendation else ""

    prompt = f"""You are a secure coding expert. Provide a precise, production-ready fix for this security vulnerability.

VULNERABILITY:
- File: {file_path.name}
- Description: {description}{line_ctx}{rec_ctx}

CODE:
```
{content}
```

INSTRUCTIONS:
1. Identify the vulnerable code precisely
2. Provide a corrected version that eliminates the vulnerability
3. Ensure the fix maintains existing functionality
4. Use secure coding best practices for this language/framework

Your entire response must be ONLY a JSON object:
{{
  "vulnerable_code": "The exact vulnerable code snippet (5-15 lines)",
  "fixed_code": "The corrected code snippet that replaces the vulnerable code",
  "explanation": "Why this fix eliminates the vulnerability and how it works",
  "changes_summary": "One-line summary of what changed",
  "additional_recommendations": ["Any other hardening steps to consider"],
  "test_suggestion": "How to verify the fix works and the vulnerability is gone"
}}"""

    client = _get_ai_client()
    from lib.model_registry import get_default_model
    model = get_default_model()

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,  # Low temp for precise code
        )
        raw = response.content[0].text
    except Exception as e:
        return json.dumps({"error": f"AI fix generation failed: {type(e).__name__}: {e}"})

    from lib.common import parse_json_response
    parsed = parse_json_response(raw)

    if not parsed:
        return json.dumps({
            "error": "Failed to parse AI response",
            "raw_response": raw[:2000],
        })

    # Include metadata
    parsed["file"] = str(file_path)
    parsed["line_number"] = line_number
    parsed["model_used"] = model

    return json.dumps(parsed, default=str)


# ---------------------------------------------------------------------------
# MCP Server Security Scanner
# ---------------------------------------------------------------------------

# Patterns that indicate dangerous tool capabilities
_DANGEROUS_TOOL_PATTERNS = {
    "CRITICAL": {
        "names": re.compile(
            r"(exec|execute|shell|system|run_command|eval|spawn|popen|subprocess)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"(execut\w+ (command|shell|code|script)|run (shell|bash|system)|"
            r"arbitrary code|system command|shell access)",
            re.IGNORECASE,
        ),
        "label": "Command/Code Execution",
        "cwe": "CWE-78",
    },
    "HIGH_file": {
        "names": re.compile(
            r"(write_file|delete_file|remove|unlink|rmdir|create_file|"
            r"upload|write_to|overwrite|modify_file)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"(write|delete|remove|create|modify|overwrite)\s+(file|director|path)|"
            r"file\s+system\s+write|upload\s+file",
            re.IGNORECASE,
        ),
        "label": "File System Write/Delete",
        "cwe": "CWE-73",
    },
    "HIGH_network": {
        "names": re.compile(
            r"(fetch|http_request|curl|wget|request_url|proxy|forward|"
            r"send_request|make_request|ssrf)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"(fetch|request|call|connect to)\s+(url|endpoint|api|external|remote)|"
            r"(http|network)\s+(request|call|access)|proxy|forward\s+request",
            re.IGNORECASE,
        ),
        "label": "Network/SSRF Risk",
        "cwe": "CWE-918",
    },
    "HIGH_data": {
        "names": re.compile(
            r"(query|sql|database|db_exec|mongo|redis_exec|raw_query)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"(raw|direct|arbitrary)\s+(sql|query|database)|execute\s+query|"
            r"database\s+(command|operation|query)",
            re.IGNORECASE,
        ),
        "label": "Direct Database Access",
        "cwe": "CWE-89",
    },
    "MEDIUM_read": {
        "names": re.compile(
            r"(read_file|get_file|cat_file|file_content|read_dir|list_dir|"
            r"list_files|browse|glob|find_files)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"read\s+(file|director|path|content)|file\s+system\s+read|"
            r"list\s+(director|file|content)|browse\s+(director|file)",
            re.IGNORECASE,
        ),
        "label": "File System Read",
        "cwe": "CWE-22",
    },
    "MEDIUM_env": {
        "names": re.compile(
            r"(get_env|environment|set_env|env_var|config|secret)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"environment\s+variable|system\s+(config|setting|environment)|"
            r"(read|get|set)\s+(env|config|secret)",
            re.IGNORECASE,
        ),
        "label": "Environment/Config Access",
        "cwe": "CWE-200",
    },
    "HIGH_auth": {
        "names": re.compile(
            r"(authenticate|login|auth|verify_token|session|manage_permissions|"
            r"grant_access|revoke|set_role|change_password)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"authenticat\w+|session\s+token|verify\s+(token|session|credential)|"
            r"manage\s+(permission|access|role)|grant|revoke",
            re.IGNORECASE,
        ),
        "label": "Authentication/Authorization Control",
        "cwe": "CWE-287",
    },
    "HIGH_excessive_perms": {
        "names": re.compile(
            r"(file_manager|admin|manage_system|root|sudo|escalat)",
            re.IGNORECASE,
        ),
        "descriptions": re.compile(
            r"(read|write|delete)\s+(and|,)\s+(read|write|delete)|"
            r"full\s+access|all\s+(permission|operation)|unrestrict",
            re.IGNORECASE,
        ),
        "label": "Excessive Permissions (multi-action tool)",
        "cwe": "CWE-250",
    },
}

# Patterns in tool descriptions that suggest hidden/poisoned instructions
_TOOL_POISONING_PATTERNS = re.compile(
    r"(ignore\s+(previous|all|above)\s+(instruction|rule|prompt)|"
    r"do\s+not\s+(tell|reveal|mention|show)|"
    r"secretly|covertly|hidden\s+instruction|"
    r"override\s+(previous|safety|system)|"
    r"disregard\s+(previous|safety|all)|"
    r"you\s+must\s+(always|never)|"
    r"system\s+prompt|"
    r"<\s*(system|hidden|secret)\s*>)",
    re.IGNORECASE,
)

# Parameters that suggest credential/token handling
_CREDENTIAL_PARAM_PATTERNS = re.compile(
    r"(password|passwd|pwd|secret|token|api_key|apikey|auth_token|"
    r"session_id|session_token|bearer|credential|access_key|private_key)",
    re.IGNORECASE,
)

# Parameters that suggest path traversal or injection risks
_PARAM_RISK_PATTERNS = {
    "path_traversal": {
        "names": re.compile(r"(path|file|dir|folder|filename|filepath|location)", re.I),
        "risk": "Path traversal — accepts file/directory paths",
        "cwe": "CWE-22",
    },
    "injection": {
        "names": re.compile(r"(query|sql|command|cmd|code|script|expression|regex|pattern)", re.I),
        "risk": "Injection vector — accepts query/command/code input",
        "cwe": "CWE-74",
    },
    "url_ssrf": {
        "names": re.compile(r"(url|uri|endpoint|host|address|target|destination)", re.I),
        "risk": "SSRF vector — accepts URL/endpoint input",
        "cwe": "CWE-918",
    },
}

# OWASP MCP Top 10 mapping (Phase 1: taxonomy alignment)
# MCP01=Token/Secret, MCP02=Privilege, MCP03=Tool Poisoning, MCP05=Command/Injection,
# MCP06=Prompt Injection, MCP07=Auth, MCP08=Audit
_OWASP_MCP_MAP = {
    "transport_security": ("MCP01", "Alert on: cleartext HTTP to MCP endpoints"),
    "authentication": ("MCP07", "401: no_auth_header or jwt.aud mismatch"),
    "experimental_features": ("MCP03", "version < min_approved in registry"),
    "dangerous_capability": ("MCP05", "shell_metachar_detected or exec_syscall"),  # default
    "injection_vector": ("MCP05", "unconstrained_injection_parameter"),
    "weak_validation": ("MCP05", "missing_maxLength_or_enum"),
    "tool_poisoning": ("MCP03", "instruction_in_tool_output"),
    "credential_exposure": ("MCP01", "secrets_pattern_in_logs"),
    "excessive_permissions": ("MCP02", "audience_mismatch_attempt"),
    "excessive_permissions_tool": ("MCP02", "scope_inflation_detected"),
    "poor_documentation": ("MCP03", "unsigned_tool_registration"),
    "sensitive_resource": ("MCP01", "sensitive_resource_uri"),
    "file_system_resource": ("MCP05", "path_contains_../"),
}


def _add_owasp_mcp_tags(finding: dict) -> None:
    """Add OWASP MCP Top 10 ID and blue-team detection signal to a finding (in-place)."""
    cat = finding.get("category", "")
    title = finding.get("title", "")

    # Special cases for dangerous_capability (map by title content)
    if cat == "dangerous_capability":
        if "Command" in title or "Execution" in title or "Database" in title:
            finding["owasp_mcp_id"] = "MCP05"
            finding["blue_team_signal"] = "shell_metachar_detected"
        elif "File" in title and ("Write" in title or "Delete" in title):
            finding["owasp_mcp_id"] = "MCP05"
            finding["blue_team_signal"] = "path_contains_../"
        elif "Network" in title or "SSRF" in title:
            finding["owasp_mcp_id"] = "MCP05"
            finding["blue_team_signal"] = "unexpected_egress_domain"
        elif "Auth" in title or "Permission" in title or "Excessive" in title:
            finding["owasp_mcp_id"] = "MCP02"
            finding["blue_team_signal"] = "audience_mismatch_attempt"
        elif "Environment" in title or "Config" in title:
            finding["owasp_mcp_id"] = "MCP01"
            finding["blue_team_signal"] = "secrets_pattern_in_logs"
        else:
            finding["owasp_mcp_id"] = "MCP05"
            finding["blue_team_signal"] = "dangerous_capability_detected"
    elif cat == "excessive_permissions":
        # Distinguish tool-level vs param-level
        finding["owasp_mcp_id"] = "MCP02"
        finding["blue_team_signal"] = "scope_inflation_detected"
    else:
        owasp, signal = _OWASP_MCP_MAP.get(cat, ("MCP05", "static_analysis_finding"))
        finding["owasp_mcp_id"] = owasp
        finding["blue_team_signal"] = signal

    # Positive auth finding (server requires auth)
    if cat == "authentication" and finding.get("severity") == "INFO":
        finding["owasp_mcp_id"] = "MCP07"
        finding["blue_team_signal"] = "auth_enforced"


def _analyze_tool_security(tool) -> list[dict]:
    """Run security heuristics on a single MCP tool definition."""
    findings = []
    name = tool.name
    desc = tool.description or ""
    schema = tool.inputSchema or {}
    props = schema.get("properties", {})
    required = set(schema.get("required", []))

    # 1. Check tool name + description against dangerous patterns
    for key, pattern in _DANGEROUS_TOOL_PATTERNS.items():
        severity = key.split("_")[0]
        if pattern["names"].search(name) or pattern["descriptions"].search(desc):
            findings.append({
                "severity": severity,
                "category": "dangerous_capability",
                "title": f"Dangerous capability: {pattern['label']}",
                "detail": (
                    f"Tool '{name}' appears to provide {pattern['label'].lower()}. "
                    f"This capability can be abused if the server lacks proper access controls."
                ),
                "tool": name,
                "cwe": pattern["cwe"],
                "recommendation": (
                    f"Ensure '{name}' has strict access controls, input validation, "
                    f"and audit logging. Consider requiring user confirmation for destructive actions."
                ),
            })

    # 2. Check individual parameters
    for param_name, param_schema in props.items():
        ptype = param_schema.get("type", "string")
        pdesc = param_schema.get("description", "")
        has_enum = "enum" in param_schema
        has_max_length = "maxLength" in param_schema
        has_pattern = "pattern" in param_schema
        has_min = "minimum" in param_schema
        has_max = "maximum" in param_schema

        # Check for risky parameter patterns
        for risk_key, risk_pattern in _PARAM_RISK_PATTERNS.items():
            if risk_pattern["names"].search(param_name) or risk_pattern["names"].search(pdesc):
                # Only flag if there are no constraints
                if not has_enum and not has_pattern:
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "injection_vector",
                        "title": f"Unconstrained {risk_key.replace('_', ' ')} parameter",
                        "detail": (
                            f"Tool '{name}' parameter '{param_name}' ({ptype}) "
                            f"accepts {risk_pattern['risk'].lower()} without "
                            f"enum or pattern constraints."
                        ),
                        "tool": name,
                        "parameter": param_name,
                        "cwe": risk_pattern["cwe"],
                        "recommendation": (
                            f"Add validation: enum for allowed values, pattern regex, "
                            f"or maxLength/allowlist to constrain '{param_name}'."
                        ),
                    })

        # Check for strings without any length limits
        if ptype == "string" and not has_enum and not has_max_length and not has_pattern:
            if param_name in required:
                findings.append({
                    "severity": "LOW",
                    "category": "weak_validation",
                    "title": f"No length limit on required string parameter",
                    "detail": (
                        f"Tool '{name}' required parameter '{param_name}' has no "
                        f"maxLength, enum, or pattern constraint."
                    ),
                    "tool": name,
                    "parameter": param_name,
                    "cwe": "CWE-20",
                    "recommendation": "Add maxLength to prevent abuse via oversized input.",
                })

        # Check for integers without bounds
        if ptype == "integer" and not has_min and not has_max:
            findings.append({
                "severity": "LOW",
                "category": "weak_validation",
                "title": f"Unbounded integer parameter",
                "detail": (
                    f"Tool '{name}' parameter '{param_name}' has no min/max bounds."
                ),
                "tool": name,
                "parameter": param_name,
                "cwe": "CWE-20",
                "recommendation": "Add minimum and maximum to prevent abuse.",
            })

    # 3. Check for tool poisoning (hidden instructions in descriptions)
    if _TOOL_POISONING_PATTERNS.search(desc):
        findings.append({
            "severity": "CRITICAL",
            "category": "tool_poisoning",
            "title": "Possible tool poisoning — hidden instructions in description",
            "detail": (
                f"Tool '{name}' description contains language patterns commonly "
                f"used for prompt injection or tool poisoning attacks. The description "
                f"may contain hidden instructions designed to manipulate LLM behavior."
            ),
            "tool": name,
            "cwe": "CWE-94",
            "recommendation": (
                "Review the tool description carefully for hidden instructions. "
                "Strip non-functional text. Tool descriptions should only describe "
                "what the tool does, not instruct the LLM."
            ),
        })

    # 4. Check for credential parameters (password, token, secret in param names)
    for param_name, param_schema in props.items():
        if _CREDENTIAL_PARAM_PATTERNS.search(param_name):
            pdesc = param_schema.get("description", "")
            findings.append({
                "severity": "HIGH",
                "category": "credential_exposure",
                "title": f"Tool accepts credentials via parameter '{param_name}'",
                "detail": (
                    f"Tool '{name}' accepts sensitive credential data through "
                    f"parameter '{param_name}'. Credentials passed as tool arguments "
                    f"may be logged, cached, or exposed in MCP transport."
                ),
                "tool": name,
                "parameter": param_name,
                "cwe": "CWE-522",
                "recommendation": (
                    "Avoid passing credentials as tool parameters. Use server-side "
                    "credential management, environment variables, or a secure vault instead."
                ),
            })

    # 5. Check for excessive permissions (tool can do read + write + delete)
    action_verbs_in_desc = set()
    for verb in ["read", "write", "delete", "create", "execute", "modify", "remove"]:
        if verb in desc.lower():
            action_verbs_in_desc.add(verb)
    if len(action_verbs_in_desc) >= 3:
        findings.append({
            "severity": "HIGH",
            "category": "excessive_permissions",
            "title": f"Tool has excessive permissions ({', '.join(sorted(action_verbs_in_desc))})",
            "detail": (
                f"Tool '{name}' combines {len(action_verbs_in_desc)} different actions "
                f"({', '.join(sorted(action_verbs_in_desc))}). Multi-action tools increase "
                f"the blast radius if compromised or misused."
            ),
            "tool": name,
            "cwe": "CWE-250",
            "recommendation": (
                "Split into separate tools with minimal permissions each (principle of least privilege). "
                "E.g., separate read_file, write_file, delete_file tools."
            ),
        })

    # 6. Check for missing description (makes tools harder to audit)
    if not desc or len(desc) < 10:
        findings.append({
            "severity": "LOW",
            "category": "poor_documentation",
            "title": "Tool has missing or very short description",
            "detail": (
                f"Tool '{name}' has a description of only {len(desc)} characters. "
                f"Poor documentation makes security auditing difficult."
            ),
            "tool": name,
            "cwe": "CWE-1059",
            "recommendation": "Add a clear description explaining what the tool does and its security implications.",
        })

    return findings


def _analyze_resource_security(resource) -> list[dict]:
    """Run security heuristics on an MCP resource."""
    findings = []
    uri = str(resource.uri) if resource.uri else ""
    name = resource.name or ""
    desc = resource.description or ""

    sensitive_patterns = re.compile(
        r"(password|secret|key|token|credential|private|auth|session|cookie|"
        r"\.env|config|database|backup|dump|log|shadow|passwd|id_rsa|\.pem)",
        re.IGNORECASE,
    )

    file_patterns = re.compile(r"^file://|^/|\\\\", re.IGNORECASE)

    if sensitive_patterns.search(uri) or sensitive_patterns.search(name):
        findings.append({
            "severity": "HIGH",
            "category": "sensitive_resource",
            "title": "Resource with sensitive name or URI",
            "detail": f"Resource '{name}' (URI: {uri}) may expose sensitive data.",
            "resource": name,
            "uri": uri,
            "cwe": "CWE-200",
            "recommendation": "Restrict access to sensitive resources with RBAC or authentication.",
        })

    if file_patterns.search(uri):
        findings.append({
            "severity": "MEDIUM",
            "category": "file_system_resource",
            "title": "File system resource exposed",
            "detail": f"Resource '{name}' exposes file system access via URI: {uri}",
            "resource": name,
            "uri": uri,
            "cwe": "CWE-22",
            "recommendation": "Ensure file system resources are scoped to safe directories with no traversal.",
        })

    return findings


_SCAN_MCP_SCRIPT = '''
import asyncio, json, sys

async def scan(target_url, transport, timeout, auth_token):
    """Connect to target MCP server and enumerate everything."""
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    if transport == "sse":
        from mcp.client.sse import sse_client
        client_ctx = sse_client(target_url, headers=headers, timeout=float(timeout))
    else:
        from mcp.client.streamable_http import streamablehttp_client
        client_ctx = streamablehttp_client(target_url, headers=headers, timeout=float(timeout))

    from mcp import ClientSession

    result = {"tools": [], "resources": [], "prompts": [], "capabilities": {}}

    async with client_ctx as streams:
        read_stream, write_stream = streams[0], streams[1]
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            # Capabilities
            caps = session.get_server_capabilities()
            if caps:
                if caps.tools:
                    result["capabilities"]["tools"] = True
                if caps.resources:
                    result["capabilities"]["resources"] = True
                if caps.prompts:
                    result["capabilities"]["prompts"] = True
                if caps.experimental:
                    result["capabilities"]["experimental"] = True

            # Tools
            try:
                tools_result = await session.list_tools()
                for t in tools_result.tools:
                    result["tools"].append({
                        "name": t.name,
                        "description": t.description or "",
                        "inputSchema": t.inputSchema or {},
                    })
            except Exception as e:
                result["tools_error"] = str(e)

            # Resources
            try:
                resources_result = await session.list_resources()
                for r in resources_result.resources:
                    result["resources"].append({
                        "name": r.name,
                        "uri": str(r.uri) if r.uri else "",
                        "description": r.description or "",
                    })
            except Exception:
                pass

            # Prompts
            try:
                prompts_result = await session.list_prompts()
                for p in prompts_result.prompts:
                    result["prompts"].append({
                        "name": p.name,
                        "description": p.description or "",
                    })
            except Exception:
                pass

    return result

args = json.loads(sys.argv[1])
try:
    data = asyncio.run(scan(args["url"], args["transport"], args["timeout"], args.get("auth_token")))
    print(json.dumps(data))
except Exception as e:
    print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
'''


async def _connect_and_scan(target_url: str, transport: str, timeout: int,
                            auth_token: str | None) -> dict:
    """Connect to a target MCP server and run security analysis.

    Runs the MCP client in a subprocess to avoid async context conflicts
    with the server's own event loop.
    """
    results: dict[str, Any] = {
        "target": target_url,
        "transport": transport,
        "findings": [],
        "server_info": {},
        "tools": [],
        "resources": [],
        "prompts": [],
    }
    findings = results["findings"]

    # --- Transport security check ---
    is_https = target_url.startswith("https://")
    if not is_https:
        findings.append({
            "severity": "MEDIUM",
            "category": "transport_security",
            "title": "Unencrypted transport (HTTP)",
            "detail": f"Server at {target_url} uses plain HTTP. All MCP traffic including tool arguments and results is transmitted in cleartext.",
            "cwe": "CWE-319",
            "recommendation": "Use HTTPS with a valid TLS certificate for production deployments.",
        })

    # --- Health check ---
    import httpx
    if not auth_token:
        try:
            health_url = target_url.rsplit("/", 1)[0] + "/health"
            async with httpx.AsyncClient() as http:
                resp = await http.get(health_url, timeout=float(timeout))
                if resp.status_code == 200:
                    results["server_info"]["health"] = resp.json()
        except Exception:
            pass

    # --- Connect via subprocess (avoids async context conflicts) ---
    scan_args = json.dumps({
        "url": target_url,
        "transport": transport,
        "timeout": timeout,
        "auth_token": auth_token,
    })

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", _SCAN_MCP_SCRIPT, scan_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(PROJECT_ROOT),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 15)
    except asyncio.TimeoutError:
        return {"error": "Connection timed out", "target": target_url}
    except Exception as e:
        return {"error": f"Subprocess failed: {type(e).__name__}: {e}", "target": target_url}

    def _friendly_connection_error(detail: str, url: str) -> str:
        """Turn cryptic subprocess errors into user-friendly messages."""
        if "ExceptionGroup" in detail or "TaskGroup" in detail or "unhandled errors" in detail:
            return f"No server at {url} (connection refused or port not in use?)"
        if "Connection refused" in detail or "ECONNREFUSED" in detail:
            return f"No server at {url} (connection refused)"
        if "timed out" in detail.lower() or "Timeout" in detail:
            return f"Connection to {url} timed out"
        return detail[:200] if len(detail) > 200 else detail

    if not stdout or not stdout.strip():
        err_detail = stderr.decode(errors="replace")[:500] if stderr else "no output"
        # Check for auth rejection
        if "401" in err_detail or "403" in err_detail:
            findings.append({
                "severity": "INFO",
                "category": "authentication",
                "title": "Server requires authentication",
                "detail": "Connection was rejected — server enforces authentication. This is good.",
                "cwe": "N/A",
                "recommendation": "N/A — authentication is enforced.",
            })
            results["auth_required"] = True
            results["summary"] = {
                "total_tools": 0, "total_resources": 0, "total_prompts": 0,
                "total_findings": len(findings), "by_severity": {"INFO": 1},
                "risk_score": "CLEAN",
            }
            return results
        friendly = _friendly_connection_error(err_detail, target_url)
        return {"error": f"Connection failed: {friendly}", "target": target_url}

    try:
        enumerated = json.loads(stdout.decode())
    except json.JSONDecodeError:
        return {"error": f"Invalid response from scanner subprocess", "target": target_url}

    if "error" in enumerated:
        err_msg = enumerated["error"]
        if "401" in err_msg or "403" in err_msg:
            findings.append({
                "severity": "INFO",
                "category": "authentication",
                "title": "Server requires authentication",
                "detail": "Connection was rejected — server enforces authentication. This is good.",
                "cwe": "N/A",
                "recommendation": "N/A — authentication is enforced.",
            })
            results["auth_required"] = True
        else:
            friendly = _friendly_connection_error(err_msg, target_url)
            return {"error": f"Connection failed: {friendly}", "target": target_url}
    else:
        # --- Auth check ---
        if not auth_token:
            findings.append({
                "severity": "HIGH",
                "category": "authentication",
                "title": "No authentication required",
                "detail": (
                    "Successfully connected to MCP server without any authentication. "
                    "Any client on the network can access all tools and resources."
                ),
                "cwe": "CWE-306",
                "recommendation": "Enable bearer token authentication or mutual TLS.",
            })

        # --- Capabilities ---
        results["server_info"]["capabilities"] = enumerated.get("capabilities", {})
        if enumerated.get("capabilities", {}).get("experimental"):
            findings.append({
                "severity": "LOW",
                "category": "experimental_features",
                "title": "Experimental capabilities enabled",
                "detail": "Server exposes experimental MCP capabilities which may be unstable or insecure.",
                "cwe": "CWE-1104",
                "recommendation": "Disable experimental features in production.",
            })

        # --- Analyze tools ---
        for t_data in enumerated.get("tools", []):
            tool_info = {
                "name": t_data["name"],
                "description": t_data.get("description", "")[:200],
                "parameters": list(t_data.get("inputSchema", {}).get("properties", {}).keys()),
            }
            results["tools"].append(tool_info)

            # Create a lightweight tool object for the heuristics engine
            class _ToolProxy:
                pass
            proxy = _ToolProxy()
            proxy.name = t_data["name"]
            proxy.description = t_data.get("description", "")
            proxy.inputSchema = t_data.get("inputSchema", {})
            findings.extend(_analyze_tool_security(proxy))

        # --- Analyze resources ---
        for r_data in enumerated.get("resources", []):
            results["resources"].append({
                "name": r_data["name"],
                "uri": r_data.get("uri", ""),
                "description": r_data.get("description", "")[:200],
            })
            class _ResProxy:
                pass
            rproxy = _ResProxy()
            rproxy.name = r_data["name"]
            rproxy.uri = r_data.get("uri", "")
            rproxy.description = r_data.get("description", "")
            findings.extend(_analyze_resource_security(rproxy))

        # --- Prompts ---
        for p_data in enumerated.get("prompts", []):
            results["prompts"].append({
                "name": p_data["name"],
                "description": p_data.get("description", "")[:200],
            })

        if "tools_error" in enumerated:
            results["tools_error"] = enumerated["tools_error"]

    # --- OWASP MCP Top 10 tags (Phase 1: taxonomy alignment) ---
    for f in findings:
        _add_owasp_mcp_tags(f)

    # --- Summary ---
    sev_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "INFO")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        oid = f.get("owasp_mcp_id", "")
        if oid:
            owasp_counts[oid] = owasp_counts.get(oid, 0) + 1

    results["summary"] = {
        "total_tools": len(results["tools"]),
        "total_resources": len(results["resources"]),
        "total_prompts": len(results["prompts"]),
        "total_findings": len(findings),
        "by_severity": sev_counts,
        "by_owasp_mcp": owasp_counts,
        "risk_score": _calculate_risk_score(findings),
    }

    return results


def _calculate_risk_score(findings: list[dict]) -> str:
    """Calculate an overall risk score from findings."""
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    score = sum(weights.get(f.get("severity", "INFO"), 0) for f in findings)
    if score >= 20:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "CLEAN"


async def handle_scan_mcp(arguments: dict[str, Any]) -> str:
    """Security-scan a remote MCP server."""
    target_url = arguments["target_url"].strip()
    if not target_url or len(target_url) > MAX_PATH_LENGTH:
        raise ValueError(f"target_url must be 1-{MAX_PATH_LENGTH} characters")

    # Basic URL validation
    if not target_url.startswith(("http://", "https://")):
        raise ValueError("target_url must start with http:// or https://")

    timeout = min(arguments.get("timeout", 10), 60)
    auth_token = arguments.get("auth_token")

    # Auto-detect transport from URL
    transport = arguments.get("transport")
    if not transport:
        if "/sse" in target_url:
            transport = "sse"
        else:
            transport = "http"

    try:
        results = await _connect_and_scan(target_url, transport, timeout, auth_token)
    except Exception as e:
        return json.dumps({
            "error": f"Scan failed: {type(e).__name__}: {e}",
            "target": target_url,
        })

    return json.dumps(results, default=str)


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
    "scan_file": handle_scan_file,
    "explain_finding": handle_explain_finding,
    "get_fix": handle_get_fix,
    "scan_mcp": handle_scan_mcp,
}
