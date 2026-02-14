#!/usr/bin/env python3
"""
Agent Smith MCP Test Client

Full-featured client for testing, interacting with, and validating
the Agent Smith MCP server.

Modes:
    test       Run automated test suite against the server (default)
    interact   Interactive REPL to call tools manually
    list       List available tools with full schemas
    benchmark  Time each tool call and report latency

Usage:
    python3 -m mcp_server.test_client                             # run all tests
    python3 -m mcp_server.test_client test --tool scan_static     # test one tool
    python3 -m mcp_server.test_client interact                    # interactive REPL
    python3 -m mcp_server.test_client list                        # list tools + schemas
    python3 -m mcp_server.test_client benchmark                   # latency benchmarks
    python3 -m mcp_server.test_client test --all                  # include scan_hybrid
    python3 -m mcp_server.test_client test --json                 # JSON output for CI
    python3 -m mcp_server.test_client test --quiet                # minimal output
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import time
from io import StringIO
from pathlib import Path
from typing import Any

# When output exceeds this many lines and stdout is a TTY, use a pager (less -R). Set AGENTSMITH_MCP_NOPAGER=1 to disable.
PAGE_LINES = 28

try:
    import readline
except ImportError:
    readline = None  # Windows may not have readline


def _drain_stdin() -> None:
    """If stdin is a TTY and has pending input, read and discard it so the next input() gets a clean line."""
    if not sys.stdin.isatty():
        return
    try:
        import fcntl
        fd = sys.stdin.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            while True:
                try:
                    ch = sys.stdin.read(1)
                    if not ch:
                        break
                except (BlockingIOError, OSError):
                    break
        finally:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
    except (ImportError, OSError):
        pass


class _paged_output:
    """Context manager: capture print() and send through `less -R` when long (preserves color)."""

    def __init__(self, min_lines: int = PAGE_LINES):
        self.min_lines = min_lines
        self._capture = (
            sys.stdout.isatty()
            and not os.environ.get("AGENTSMITH_MCP_NOPAGER")
        )
        self._buf: StringIO | None = None
        self._old_stdout = None

    def __enter__(self):
        if self._capture:
            self._buf = StringIO()
            self._old_stdout = sys.stdout
            sys.stdout = self._buf
        return self

    def __exit__(self, *args):
        if not self._capture or self._buf is None:
            return
        sys.stdout = self._old_stdout
        content = self._buf.getvalue()
        line_count = len(content.splitlines())
        if line_count > self.min_lines:
            try:
                subprocess.run(
                    ["less", "-R", "-X"],
                    input=content,
                    text=True,
                    check=False,
                )
            except (FileNotFoundError, OSError):
                print(content, end="")
        else:
            print(content, end="")


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[0;33m"
CYAN = "\033[0;36m"
MAGENTA = "\033[0;35m"
WHITE = "\033[1;37m"
RESET = "\033[0m"

_no_color = False


def c(text, color):
    if _no_color:
        return str(text)
    return f"{color}{text}{RESET}"


def _colorize_json_line(line: str) -> str:
    """Colorize a single line of pretty-printed JSON for readable verbose output."""
    m = re.match(r"^(\s*)(.*?)(:\s*)(.*)$", line)
    if not m:
        return c(line, DIM)
    indent, key_part, colon, value = m.groups()
    out = indent
    if key_part.strip().startswith('"'):
        out += c(key_part, CYAN)
    else:
        out += key_part
    out += c(colon, DIM)
    v = value.strip()
    if v.startswith('"') and v.endswith('"'):
        out += c(value, GREEN)
    elif v in ("true", "false", "null"):
        out += c(value, DIM)
    elif v and (v[0].isdigit() or (v.startswith("-") and len(v) > 1 and v[1].isdigit())):
        out += c(value, YELLOW)
    elif v in ("{", "}", "[", "]"):
        out += c(value, MAGENTA)
    else:
        out += value
    return out


def _colorize_annotation_line(line: str, in_code_block: bool) -> tuple[str, bool]:
    """Colorize one line of annotation markdown; returns (colored_line, next_in_code_block)."""
    s = line.strip()
    if s.startswith("```"):
        return (c(line, DIM), not in_code_block)
    if in_code_block:
        if "// FLAW" in line:
            idx = line.find("// FLAW")
            rest = line[idx:]
            colon = rest.find(":")
            if colon != -1:
                prefix = line[:idx]
                flaw_label = rest[: colon + 1]
                after = rest[colon + 1 :]
                return (prefix + c(flaw_label, RED) + c(after, DIM), True)
            return (line[:idx] + c(rest, RED), True)
        if "// FIX" in line:
            idx = line.find("// FIX")
            rest = line[idx:]
            colon = rest.find(":")
            if colon != -1:
                prefix = line[:idx]
                fix_label = rest[: colon + 1]
                after = rest[colon + 1 :]
                return (prefix + c(fix_label, GREEN) + c(after, DIM), True)
            return (line[:idx] + c(rest, GREEN), True)
        if "//" in line:
            i = line.index("//")
            return (line[:i] + c(line[i:], DIM), True)
        return (c(line, DIM), True)
    if s.startswith("##") or s.startswith("#"):
        return (c(line, BOLD), False)
    m = re.match(r"^(\s*)(\*\*[^*]+\*\*:\s*)(.*)$", line)
    if m:
        indent, label_part, value = m.groups()
        return (indent + c(label_part, BOLD) + c(value, CYAN), False)
    if s.startswith("- ") or s.startswith("* "):
        lead = line[: len(line) - len(s)]
        return (lead + c(s[:2], CYAN) + s[2:], False)
    return (line, False)


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class Spinner:
    """Animated spinner for long-running operations."""
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = ""):
        self._message = message
        self._stop = threading.Event()
        self._thread = None
        self._start_time = 0.0

    def start(self, message: str = ""):
        if message:
            self._message = message
        self._start_time = time.monotonic()
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            elapsed = time.monotonic() - self._start_time
            frame = self.FRAMES[i % len(self.FRAMES)]
            msg = f"\r    {c(frame, CYAN)} {self._message} {c(f'({elapsed:.0f}s)', DIM)}"
            sys.stdout.write(msg)
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.1)

    def stop(self, clear: bool = True):
        self._stop.set()
        if self._thread:
            self._thread.join()
        if clear:
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

async def connect(url: str, retries: int = 2, delay: float = 1.0):
    """Connect to MCP server with retry logic and fast failure."""
    import httpx

    # Quick pre-check: is the server even reachable?
    health_url = url.rsplit("/", 1)[0] + "/health"
    try:
        async with httpx.AsyncClient() as http:
            resp = await http.get(health_url, timeout=3.0)
            if resp.status_code != 200:
                raise ConnectionError(
                    f"Server at {health_url} returned status {resp.status_code}"
                )
    except httpx.ConnectError:
        raise ConnectionError(
            f"Server not reachable at {health_url}\n"
            f"  Start it with: python3 -m mcp_server --no-auth"
        )
    except httpx.TimeoutException:
        raise ConnectionError(
            f"Server at {health_url} timed out\n"
            f"  Start it with: python3 -m mcp_server --no-auth"
        )

    from mcp.client.sse import sse_client
    from mcp import ClientSession

    sse_read_timeout = float(os.environ.get("AGENTSMITH_MCP_READ_TIMEOUT", "660"))  # 11 min for long scans
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            ctx = sse_client(url, timeout=10.0, sse_read_timeout=sse_read_timeout)
            streams = await ctx.__aenter__()
            read_stream, write_stream = streams[0], streams[1]
            session = ClientSession(read_stream, write_stream)
            await session.__aenter__()
            await session.initialize()
            return ctx, session
        except (ConnectionRefusedError, OSError) as e:
            last_err = e
            if attempt < retries:
                await asyncio.sleep(delay * attempt)
        except Exception as e:
            last_err = e
            break

    raise ConnectionError(
        f"Cannot connect to {url} after {retries} attempts: {last_err}\n"
        f"  Make sure the server is running: python3 -m mcp_server --no-auth"
    )


def _detect_repo_path() -> str | None:
    """Auto-detect a test target repo path."""
    project_root = Path(__file__).resolve().parent.parent
    candidates = [
        project_root / "tests" / "test_targets" / "DVWA",
        project_root / "tests" / "test_targets" / "WebGoat",
        project_root / "tests" / "test_targets" / "juice-shop",
        project_root,
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return str(candidate)
    return None


# ---------------------------------------------------------------------------
# Mode: test
# ---------------------------------------------------------------------------

async def mode_test(url: str, tool_filter: str | None = None,
                    include_all: bool = False, repo_path: str | None = None,
                    json_output: bool = False, quiet: bool = False, verbose: bool = False):
    """Run automated test suite against the MCP server."""
    results = []
    repo_path = repo_path or _detect_repo_path()

    if not json_output:
        print(f"\n{c('Agent Smith MCP Test Suite', BOLD)}")
        print(f"{'=' * 60}")
        print(f"  Server:    {c(url, CYAN)}")
        print(f"  Repo:      {c(repo_path or 'none', DIM)}")
        print()

    try:
        ctx, session = await connect(url)
    except ConnectionError as e:
        if json_output:
            print(json.dumps({"error": str(e), "passed": 0, "failed": 1}))
        else:
            print(f"{c('ERROR', RED)}: {e}")
        return False

    spinner = Spinner()

    try:
        tools_result = await session.list_tools()
        tools = tools_result.tools
        tool_names = [t.name for t in tools]

        if not json_output:
            print(f"{c('Connected', GREEN)} - {len(tools)} tools available")
            print()

        # Build test cases
        test_cases = _build_test_cases(repo_path, tool_filter, include_all, tool_names)

        for tc in test_cases:
            name = tc["name"]
            tool = tc["tool"]
            args = tc["args"]
            checks = tc.get("checks", [])
            is_slow = tool in ("scan_static", "scan_hybrid", "detect_tech_stack")

            if not json_output:
                print(f"  {c('TEST', BOLD)}: {c(name, WHITE)}")
                if not quiet:
                    print(f"    {c('tool', DIM)}: {tool}")
                    if args:
                        _print_args(args)

            # Start spinner for slow operations with time estimates
            if is_slow and not json_output and not quiet:
                if tool == "scan_hybrid":
                    spinner.start(f"Running {tool} (expect 30-90s for AI calls)...")
                else:
                    spinner.start(f"Running {tool}...")

            t0 = time.monotonic()
            try:
                result = await session.call_tool(tool, args)
                elapsed_ms = (time.monotonic() - t0) * 1000

                if is_slow:
                    spinner.stop()

                text = result.content[0].text
                data = json.loads(text)

                # Run assertion checks
                ok = True
                messages = []
                has_error = "error" in data
                skipped_ai = False

                if has_error and not tc.get("expect_error"):
                    err = data.get("error", "")
                    stderr = (data.get("stderr") or "").lower()
                    if tool in ("explain_finding", "get_fix") and "AI tools require" in err and "CLAUDE_API_KEY" in err:
                        skipped_ai = True
                        messages.append("AI not configured (set CLAUDE_API_KEY or use Bedrock)")
                    elif tool == "scan_hybrid" and err.strip() == "Scan failed":
                        if any(x in stderr for x in ("claude_api_key", "api key", "api_key", "environment variable not set", "not set")):
                            skipped_ai = True
                            messages.append("AI not configured (set CLAUDE_API_KEY or use Bedrock)")
                    if not skipped_ai:
                        ok = False
                        messages.append(f"unexpected error: {err}")
                elif has_error and tc.get("expect_error"):
                    ok = True
                    messages.append(f"got expected error")
                else:
                    for check in checks:
                        check_ok, msg = check(data)
                        if not check_ok:
                            ok = False
                        messages.append(msg)

                status = "SKIP" if skipped_ai else ("PASS" if ok else "FAIL")
                results.append({
                    "name": name, "tool": tool, "status": status,
                    "elapsed_ms": round(elapsed_ms, 1),
                    "messages": messages,
                    "data": data,
                })

                if not json_output:
                    if status == "SKIP":
                        icon = c("SKIP", YELLOW)
                    else:
                        icon = c("PASS", GREEN) if ok else c("FAIL", RED)
                    check_summary = "; ".join(messages)
                    print(f"    {icon} {c(f'({elapsed_ms:.0f}ms)', DIM)} {check_summary}")

                    # Always show rich detail (unless quiet)
                    if not quiet:
                        if status == "SKIP":
                            print(f"    {c('(set CLAUDE_API_KEY or AGENTSMITH_PROVIDER=bedrock to run)', DIM)}")
                        elif has_error and tc.get("expect_error"):
                            print(f"    {c('blocked', DIM)}: {data['error'][:70]}")
                        elif not has_error:
                            _print_result_detail(tool, data, verbose=verbose)

            except Exception as e:
                spinner.stop()
                elapsed_ms = (time.monotonic() - t0) * 1000
                results.append({
                    "name": name, "tool": tool, "status": "ERROR",
                    "elapsed_ms": round(elapsed_ms, 1),
                    "messages": [f"{type(e).__name__}: {e}"],
                })
                if not json_output:
                    print(f"    {c('ERROR', RED)} {c(f'({elapsed_ms:.0f}ms)', DIM)} "
                          f"{type(e).__name__}: {e}")

            if not json_output:
                print()

    finally:
        await session.__aexit__(None, None, None)
        await ctx.__aexit__(None, None, None)

    # Summary
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] in ("FAIL", "ERROR"))
    skipped = sum(1 for r in results if r["status"] == "SKIP")
    total = len(results)
    total_ms = sum(r["elapsed_ms"] for r in results)

    if json_output:
        print(json.dumps({
            "passed": passed, "failed": failed, "skipped": skipped, "total": total,
            "total_ms": round(total_ms, 1),
            "results": results,
        }, indent=2, default=str))
    else:
        print(f"{c('Results', BOLD)}")
        print(f"{'=' * 60}")
        print(f"  Passed:     {c(str(passed), GREEN)}")
        if skipped:
            print(f"  Skipped:   {c(str(skipped), YELLOW)} (AI not configured)")
        if failed:
            print(f"  Failed:     {c(str(failed), RED)}")
        print(f"  Total:      {total}")
        print(f"  Total time: {_format_duration(total_ms)}")
        print()

    return failed == 0


def _print_args(args: dict):
    """Print tool arguments in a readable format."""
    for k, v in args.items():
        val = str(v)
        if len(val) > 60:
            val = val[:60] + "..."
        print(f"      {c(k, CYAN)}: {val}")


def _format_duration(ms: float) -> str:
    """Format milliseconds into a human-readable duration."""
    if ms < 1000:
        return f"{ms:.0f}ms"
    elif ms < 60_000:
        return f"{ms / 1000:.1f}s"
    else:
        mins = int(ms / 60_000)
        secs = (ms % 60_000) / 1000
        return f"{mins}m {secs:.0f}s"


def _build_test_cases(repo_path, tool_filter, include_all, available_tools):
    """Build the list of test cases to run."""
    cases = []

    def add(name, tool, args, checks=None, expect_error=False):
        if tool_filter and tool != tool_filter:
            return
        if tool not in available_tools:
            return
        cases.append({
            "name": name, "tool": tool, "args": args,
            "checks": checks or [], "expect_error": expect_error,
        })

    # --- list_presets ---
    add("list all presets", "list_presets", {}, [
        lambda d: (d.get("count", 0) >= 4, f"{d.get('count', 0)} presets found"),
        lambda d: (
            any(p["name"] == "ctf" for p in d.get("presets", [])),
            "ctf preset present" if any(p["name"] == "ctf" for p in d.get("presets", []))
            else "ctf preset missing"
        ),
    ])

    # --- summarize_results ---
    add("summarize latest results", "summarize_results", {}, [
        lambda d: ("combined" in d or "static" in d, "has findings data"),
    ])

    # --- list_findings ---
    add("list critical findings", "list_findings", {"severity": "CRITICAL", "limit": 5}, [
        lambda d: (isinstance(d.get("findings"), list), "findings is a list"),
        lambda d: (d.get("returned", 0) <= 5, f"limit respected: {d.get('returned', 0)} <= 5"),
        lambda d: (
            all(f.get("severity") == "CRITICAL" for f in d.get("findings", [])),
            "all findings are CRITICAL"
        ),
    ])

    add("list high+ findings with limit", "list_findings", {"severity": "HIGH", "limit": 10}, [
        lambda d: (d.get("returned", 0) <= 10, f"limit respected: {d.get('returned', 0)} <= 10"),
        lambda d: (
            all(f.get("severity") in ("CRITICAL", "HIGH") for f in d.get("findings", [])),
            "severity filter correct"
        ),
    ])

    add("list findings by source", "list_findings",
        {"source": "agentsmith", "limit": 3}, [
        lambda d: (
            all(f.get("source") == "agentsmith" for f in d.get("findings", [])),
            "source filter correct"
        ),
    ])

    # --- detect_tech_stack ---
    if repo_path:
        add("detect tech stack", "detect_tech_stack", {"repo_path": repo_path}, [
            lambda d: ("languages" in d, "languages detected"),
            lambda d: ("frameworks" in d, "frameworks detected"),
        ])

    # --- scan_static ---
    if repo_path:
        add("static scan (HIGH+)", "scan_static",
            {"repo_path": repo_path, "severity": "HIGH"}, [
            lambda d: (d.get("count", 0) > 0, f"{d.get('count', 0)} findings"),
            lambda d: (d.get("rules_loaded", 0) > 0, f"{d.get('rules_loaded', 0)} rule files loaded"),
        ])

        add("static scan (CRITICAL only)", "scan_static",
            {"repo_path": repo_path, "severity": "CRITICAL"}, [
            lambda d: (isinstance(d.get("findings"), list), "findings returned"),
        ])

    # --- scan_file ---
    if repo_path:
        # Find a PHP file in the test target for single-file scanning
        test_files = list(Path(repo_path).rglob("*.php"))
        if test_files:
            test_file = str(test_files[0])
            add("scan single file", "scan_file",
                {"file_path": test_file}, [
                lambda d: (isinstance(d.get("findings"), list), "findings returned"),
                lambda d: (d.get("file", "").endswith(".php"), "correct file in response"),
            ])

            add("scan single file (CRITICAL)", "scan_file",
                {"file_path": test_file, "severity": "CRITICAL"}, [
                lambda d: (isinstance(d.get("findings"), list), "findings returned"),
            ])

    # --- explain_finding (only if --all, requires API key) ---
    if include_all and repo_path:
        test_files = list(Path(repo_path).rglob("*.php"))
        if test_files:
            add("explain a finding", "explain_finding",
                {"file_path": str(test_files[0]),
                 "description": "potential SQL injection in database query",
                 "severity": "HIGH"}, [
                lambda d: ("explanation" in d, "has explanation"),
                lambda d: ("attack_scenario" in d, "has attack scenario"),
            ])

            add("get fix for finding", "get_fix",
                {"file_path": str(test_files[0]),
                 "description": "potential SQL injection in database query"}, [
                lambda d: ("fixed_code" in d, "has fixed code"),
                lambda d: ("explanation" in d, "has explanation"),
            ])

    # --- Input validation / security tests ---
    add("reject invalid path", "scan_static",
        {"repo_path": "/nonexistent/fakepath"}, expect_error=True)

    add("reject traversal attack", "scan_static",
        {"repo_path": "/etc/passwd/../../../tmp"}, expect_error=True)

    add("reject missing repo_path", "detect_tech_stack",
        {"repo_path": ""}, expect_error=True)

    add("reject invalid file path", "scan_file",
        {"file_path": "/nonexistent/fakefile.py"}, expect_error=True)

    add("reject file traversal attack", "scan_file",
        {"file_path": "/etc/passwd"}, expect_error=True)

    # --- scan_mcp (optional: set AGENTSMITH_MCP_TEST_TARGET to a running MCP server URL, e.g. DVMCP) ---
    mcp_target = os.environ.get("AGENTSMITH_MCP_TEST_TARGET", "").strip()
    if mcp_target and "scan_mcp" in available_tools:
        add("scan MCP server (security)", "scan_mcp",
            {"target_url": mcp_target}, [
            lambda d: ("summary" in d or "findings" in d, "has summary or findings"),
            lambda d: ("error" not in d, "no error"),
        ])

    # --- scan_hybrid (only if --all) ---
    # Uses tight defaults: prioritize top 5 files, quick preset to keep it fast
    if include_all and repo_path:
        add("hybrid scan (quick preset, top 5)", "scan_hybrid",
            {"repo_path": repo_path, "preset": "quick", "prioritize_top": 5,
             "question": "find the top 5 most critical vulnerabilities"}, [
            lambda d: (d.get("status") == "completed", f"status: {d.get('status')}"),
        ])

    return cases


# ---------------------------------------------------------------------------
# Result detail printing (always shown unless --quiet)
# ---------------------------------------------------------------------------

def _print_result_detail(tool_name: str, data: dict, *, verbose: bool = False):
    """Print detailed, informative result for each tool."""
    if data.get("debug_log"):
        n_lines = 60 if verbose else 25
        lines = data["debug_log"].splitlines()[-n_lines:]
        print(f"    {c('Debug log (orchestrator stderr):', BOLD)}")
        for line in lines:
            print(f"      {c(line[:120], DIM)}")
        if not verbose and len(data["debug_log"].splitlines()) > n_lines:
            print(f"      {c('(... run client with -v for more)', DIM)}")
    if tool_name == "list_presets":
        for p in data.get("presets", []):
            profiles = ", ".join(p.get("profiles", [])) or "default"
            print(f"      {c(p['name'], CYAN):>20}: {p.get('description', '')[:55]}")

    elif tool_name == "summarize_results":
        combined = data.get("combined", {})
        cost = data.get("cost", {})
        static = data.get("static", {})
        ai = data.get("ai", {})
        artifacts = data.get("artifacts", {})

        print(f"    {c('Findings:', BOLD)}")
        print(f"      Static:     {static.get('count', 0)}")
        print(f"      AI:         {ai.get('count', 0)}")
        print(f"      Combined:   {combined.get('count', 0)}")

        by_sev = combined.get("by_severity", {})
        if by_sev:
            parts = []
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in by_sev:
                    color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}.get(sev, DIM)
                    parts.append(f"{c(sev, color)}: {by_sev[sev]}")
            print(f"      Severity:   {', '.join(parts)}")

        by_source = combined.get("by_source", {})
        if by_source:
            print(f"      Sources:    {', '.join(f'{k} ({v})' for k, v in by_source.items())}")

        if cost or verbose:
            print(f"    {c('Cost:', BOLD)}")
            if cost:
                cost_usd = cost.get('cost_usd', 0)
                print(f"      API calls:  {cost.get('api_calls', 0)}")
                print(f"      Tokens:     {cost.get('total_tokens', 0):,}")
                print(f"      Cost:       {c(f'${cost_usd:.3f}', GREEN)}")
            else:
                print(f"      {c('(no cost tracking — run scan_hybrid for AI/Claude/Bedrock costs)', DIM)}")

        if artifacts.get("payloads") or artifacts.get("annotations"):
            print(f"    {c('Artifacts:', BOLD)}")
            print(f"      Payloads:   {artifacts.get('payloads', 0)}")
            print(f"      Annotations: {artifacts.get('annotations', 0)}")

        # Top rules from static
        top_rules = static.get("top_rules", {})
        if top_rules:
            print(f"    {c('Top static rules:', BOLD)}")
            for rule, cnt in list(top_rules.items())[:5]:
                print(f"      {cnt:>5}x  {rule}")

        # AI findings summary
        ai_findings = ai.get("findings", [])
        if ai_findings:
            print(f"    {c('AI findings:', BOLD)}")
            for f in ai_findings[:5]:
                sev = f.get("severity", "?")
                color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW}.get(sev, DIM)
                title = f.get("title", "?")[:50]
                loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
                print(f"      {c(f'[{sev}]', color):>22} {title} {c(loc, DIM)}")

    elif tool_name == "list_findings":
        returned = data.get("returned", 0)
        total = data.get("total_matched", 0)
        filters = data.get("filters", {})
        findings_list = data.get("findings", [])
        cap = len(findings_list) if verbose else 8
        print(f"    {c(f'{returned} of {total} matched', DIM)} "
              f"(severity>={filters.get('severity', 'any')}, "
              f"source={filters.get('source', 'any')})")
        for f in findings_list[:cap]:
            sev = f.get("severity", "?")
            color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}.get(sev, DIM)
            title = f.get("title", "?")[:50]
            fname = Path(f.get("file", "?")).name
            line = f.get("line", "")
            loc = f"{fname}:{line}" if line else fname
            rec = f.get("recommendation", "")
            print(f"      {c(f'[{sev}]', color):>22} {title}")
            print(f"      {'':>14} {c(loc, DIM)}")
            if rec:
                print(f"      {'':>14} {c(rec[:65], GREEN)}")
        if returned > cap:
            print(f"      {c(f'... and {returned - cap} more', DIM)}")

    elif tool_name == "detect_tech_stack":
        langs = data.get("languages", [])
        if isinstance(langs, dict):
            langs = list(langs.keys())
        fws = data.get("frameworks", {})
        entries = data.get("entry_points", [])
        sec_files = data.get("security_critical_files", data.get("security_files", []))
        risks = data.get("framework_specific_risks", data.get("risks", []))

        print(f"    {c('Languages:', BOLD)}  {', '.join(langs)}")

        if isinstance(fws, dict):
            fw_items = sorted(fws.items(), key=lambda x: x[1], reverse=True)
            confirmed = [(n, s) for n, s in fw_items if s >= 0.8]
            possible = [(n, s) for n, s in fw_items if s < 0.8]

            if confirmed:
                print(f"    {c('Confirmed:', BOLD)}")
                for name, conf in confirmed[:6]:
                    bar_len = int(conf * 20)
                    bar = c("█" * bar_len, GREEN) + c("░" * (20 - bar_len), DIM)
                    print(f"      {name:>15} {bar} {int(conf * 100)}%")
            if possible:
                names = ", ".join(n for n, _ in possible[:8])
                print(f"    {c('Possible:', DIM)}   {names}")
        elif isinstance(fws, list):
            print(f"    {c('Frameworks:', BOLD)} {', '.join(str(f) for f in fws[:6])}")

        if entries:
            print(f"    {c('Entry points:', BOLD)} ({len(entries)})")
            for ep in entries[:5]:
                ep_name = ep if isinstance(ep, str) else ep.get("file", str(ep))
                print(f"      {c('>', CYAN)} {Path(ep_name).name}")
            if len(entries) > 5:
                print(f"      {c(f'... and {len(entries) - 5} more', DIM)}")

        if sec_files:
            print(f"    {c('Security files:', BOLD)} ({len(sec_files)})")
            for sf in sec_files[:5]:
                sf_name = sf if isinstance(sf, str) else sf.get("file", str(sf))
                print(f"      {c('!', YELLOW)} {Path(sf_name).name}")

        if risks:
            print(f"    {c('Risks:', BOLD)} ({len(risks)})")
            for r in risks[:4]:
                print(f"      {c('⚠', YELLOW)} {r}")

    elif tool_name == "scan_static":
        count = data.get("count", 0)
        rules = data.get("rules_loaded", 0)
        truncated = data.get("truncated", False)
        print(f"    {c(f'{count} findings from {rules} rule files', DIM)}"
              f"{'  (truncated to 500)' if truncated else ''}")

        # Show severity breakdown from findings
        findings = data.get("findings", [])
        if findings:
            sevs: dict[str, int] = {}
            rule_counts: dict[str, int] = {}
            for f in findings:
                s = f.get("severity", "?")
                sevs[s] = sevs.get(s, 0) + 1
                rn = f.get("rule_name", "?")
                rule_counts[rn] = rule_counts.get(rn, 0) + 1

            parts = []
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in sevs:
                    color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}.get(sev, DIM)
                    parts.append(f"{c(sev, color)}: {sevs[sev]}")
            print(f"    {c('Severity:', BOLD)}  {', '.join(parts)}")

            print(f"    {c('Top rules:', BOLD)}")
            top = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:6]
            for rule, cnt in top:
                print(f"      {cnt:>5}x  {rule}")

    elif tool_name == "scan_file":
        count = data.get("count", 0)
        fname = Path(data.get("file", "?")).name
        print(f"    {c(f'{count} findings in {fname}', DIM)}")
        findings = data.get("findings", [])
        if findings:
            sevs: dict[str, int] = {}
            for f in findings:
                s = f.get("severity", "?")
                sevs[s] = sevs.get(s, 0) + 1
            parts = []
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in sevs:
                    clr = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}.get(sev, DIM)
                    parts.append(f"{c(sev, clr)}: {sevs[sev]}")
            if parts:
                print(f"    {c('Severity:', BOLD)}  {', '.join(parts)}")

    elif tool_name == "explain_finding":
        title = data.get("title", "?")
        cwe = data.get("cwe", "")
        owasp = data.get("owasp_category", "")
        explanation = data.get("explanation", "")[:120]
        print(f"    {c('Title:', BOLD)}       {title}")
        if cwe:
            print(f"    {c('CWE:', BOLD)}         {cwe}")
        if owasp:
            print(f"    {c('OWASP:', BOLD)}       {owasp}")
        if explanation:
            print(f"    {c('Explanation:', BOLD)}  {explanation}...")

    elif tool_name == "get_fix":
        summary = data.get("changes_summary", "?")
        has_fix = bool(data.get("fixed_code"))
        has_vuln = bool(data.get("vulnerable_code"))
        test = data.get("test_suggestion", "")[:80]
        print(f"    {c('Summary:', BOLD)}    {summary}")
        print(f"    {c('Has fix:', BOLD)}    {'yes' if has_fix else 'no'}")
        print(f"    {c('Has vuln:', BOLD)}   {'yes' if has_vuln else 'no'}")
        if test:
            print(f"    {c('Test:', BOLD)}       {test}...")

    elif tool_name == "scan_mcp":
        summary = data.get("summary", {})
        risk = summary.get("risk_score", "?")
        risk_color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "CLEAN": GREEN}.get(risk, DIM)
        total = summary.get("total_findings", 0)
        by_sev = summary.get("by_severity", {})

        print(f"    {c('Risk Score:', BOLD)}  {c(risk, risk_color)}")
        print(f"    {c('Findings:', BOLD)}    {total}")
        if by_sev:
            parts = []
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in by_sev:
                    clr = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": DIM}.get(sev, DIM)
                    parts.append(f"{c(sev, clr)}: {by_sev[sev]}")
            print(f"    {c('Severity:', BOLD)}    {', '.join(parts)}")

        print(f"    {c('Tools:', BOLD)}       {summary.get('total_tools', 0)}")
        print(f"    {c('Resources:', BOLD)}   {summary.get('total_resources', 0)}")
        print(f"    {c('Prompts:', BOLD)}     {summary.get('total_prompts', 0)}")

        # Show top findings
        findings = data.get("findings", [])
        if findings:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))
            print(f"    {c('Top findings:', BOLD)}")
            for f in findings[:8]:
                sev = f.get("severity", "?")
                clr = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}.get(sev, DIM)
                title = f.get("title", "?")[:60]
                tool = f.get("tool", f.get("resource", ""))
                loc = f" ({tool})" if tool else ""
                print(f"      {c(f'[{sev}]', clr):>22} {title}{c(loc, DIM)}")
            if len(findings) > 8:
                print(f"      {c(f'... and {len(findings) - 8} more', DIM)}")

        # Show enumerated tools
        tools_list = data.get("tools", [])
        if tools_list:
            print(f"    {c('Exposed tools:', BOLD)}")
            for t in tools_list[:6]:
                params = ", ".join(t.get("parameters", []))
                print(f"      {c('>', CYAN)} {t['name']}({c(params, DIM)})")
            if len(tools_list) > 6:
                print(f"      {c(f'... and {len(tools_list) - 6} more', DIM)}")

    elif tool_name == "scan_hybrid":
        status = data.get("status", "?")
        total = data.get("total_findings", "?")
        by_sev = data.get("by_severity", {})
        by_source = data.get("by_source", {})
        outdir = data.get("output_dir", "")
        print(f"    {c('Status:', BOLD)}    {c(status, GREEN)}")
        print(f"    {c('Findings:', BOLD)}  {total}")
        if by_sev:
            parts = []
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in by_sev:
                    color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}.get(sev, DIM)
                    parts.append(f"{c(sev, color)}: {by_sev[sev]}")
            print(f"    {c('Severity:', BOLD)}  {', '.join(parts)}")
        if by_source:
            print(f"    {c('Sources:', BOLD)}   {', '.join(f'{k} ({v})' for k, v in by_source.items())}")
        if outdir:
            print(f"    {c('Output:', BOLD)}    {outdir}")
            print(f"    {c('To see cost & full summary:', DIM)} summarize_results {{\"output_dir\": \"{outdir}\"}}")
            print(f"    {c('To list findings from this run:', DIM)} list_findings {{\"output_dir\": \"{outdir}\", \"severity\": \"CRITICAL\", \"limit\": 10}}")
        if data.get("notice"):
            print(f"    {c('Note:', YELLOW)} {data['notice']}")

    else:
        keys = list(data.keys())
        print(f"    {c('Response keys:', DIM)} {keys}")


# ---------------------------------------------------------------------------
# Mode: interact
# ---------------------------------------------------------------------------

async def _run_full_scan(session, tools: dict, repo_path: str, spinner: Spinner) -> dict | None:
    """Run a complete scan: detect_tech_stack → static or hybrid → summarize → list_findings."""
    print(f"  {c('Complete scan', BOLD)} using repo: {c(repo_path, DIM)}")
    try:
        choice = input(f"  Static only (s) or Hybrid with AI (h)? {c('[h]', DIM)} ").strip().lower() or "h"
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    use_hybrid = choice == "h"

    steps = [
        ("detect_tech_stack", {"repo_path": repo_path}),
        (
            "scan_hybrid" if use_hybrid else "scan_static",
            {"repo_path": repo_path, "preset": "quick", "prioritize_top": 5,
             "question": "find the most critical vulnerabilities"} if use_hybrid
            else {"repo_path": repo_path, "severity": "HIGH"},
        ),
        ("summarize_results", {}),
        ("list_findings", {"severity": "CRITICAL", "limit": 10}),
    ]

    last = None
    for i, (tool_name, args) in enumerate(steps, 1):
        if tool_name not in tools:
            continue
        print(f"  {c(f'Step {i}/{len(steps)}', BOLD)}: {tool_name}")
        spinner.start(f"Running {tool_name}...")
        t0 = time.monotonic()
        try:
            result = await session.call_tool(tool_name, args)
            elapsed_ms = (time.monotonic() - t0) * 1000
            spinner.stop()
            data = json.loads(result.content[0].text)
            last = data
            if "error" in data:
                print(f"    {c('Error', YELLOW)}: {data['error']}")
            else:
                _print_result_detail(tool_name, data, verbose=True)
            print(f"    {c(f'({elapsed_ms:.0f}ms)', DIM)}")
        except Exception as e:
            spinner.stop()
            print(f"    {c('FAIL', RED)}: {type(e).__name__}: {e}")
        print()
    return last


async def mode_interact(url: str, repo_path: str | None = None):
    """Interactive REPL for calling MCP tools."""
    repo_path = repo_path or _detect_repo_path()

    print(f"\n{c('Agent Smith MCP Interactive Client', BOLD)}")
    print(f"{'=' * 60}")
    print(f"  Server:        {c(url, CYAN)}")
    if repo_path:
        print(f"  Default repo:  {c(repo_path, DIM)}")

    # Show allowed paths so users know what they can scan
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from mcp_server.config import ALLOWED_PATHS
        paths = [str(p) for p in ALLOWED_PATHS]
        print(f"  Allowed paths: {c(', '.join(paths), DIM)}")
        print(f"  {c('(set AGENTSMITH_ALLOWED_PATHS to expand)', DIM)}")
    except Exception:
        pass
    print()

    try:
        ctx, session = await connect(url)
    except ConnectionError as e:
        print(f"{c('ERROR', RED)}: {e}")
        return False

    spinner = Spinner()

    try:
        tools_result = await session.list_tools()
        tools = {t.name: t for t in tools_result.tools}

        print(f"{c('Connected', GREEN)} - {len(tools)} tools available")
        print(f"Type {c('tools', CYAN)} to list them, {c('help', CYAN)} for commands, {c('scan', CYAN)} for full scan, {c('status', CYAN)} for session config, {c('quit', CYAN)} to exit. {c('Tab', DIM)} to autocomplete.")
        print()

        last_result = None
        last_output_dir = None
        verbose = False

        _BUILTINS = (
            "help", "quit", "exit", "q", "scan", "summary", "findings",
            "annotations", "payloads", "everything", "verbose", "repo",
            "tools", "list_presets", "last", "status", "state",
        )
        _completion_list = sorted(set(_BUILTINS) | set(tools.keys()))

        def _complete(text: str, state: int):
            if not text:
                return None
            matches = [m for m in _completion_list if m.startswith(text)]
            return matches[state] if state < len(matches) else None

        if readline is not None:
            readline.set_completer(_complete)
            readline.set_completer_delims(" \t\n")
            readline.parse_and_bind("tab: complete")
            try:
                readline.parse_and_bind(r"\C-i: complete")
            except Exception:
                pass

        while True:
            try:
                _drain_stdin()
                line = input(f"{c('mcp', MAGENTA)}> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            if line in ("quit", "exit", "q"):
                break

            if line == "help":
                print(f"  {c('Commands:', BOLD)}")
                print(f"    {c('scan', CYAN)}                  Run a complete scan (tech stack → static/hybrid → summary → findings)")
                print(f"    {c('summary', CYAN)}               Summary + cost for last scan")
                print(f"    {c('findings', CYAN)} [N|all]     Findings from last scan (default 20); verbose = show all returned")
                print(f"    {c('annotations', CYAN)}           Annotation files; verbose = full content of every file")
                print(f"    {c('payloads', CYAN)}              Payload files; verbose = full JSON of every file")
                print(f"    {c('everything', CYAN)}            Dump full run: summary + all findings + all annotations + all payloads)")
                print(f"    {c('verbose', CYAN)}              Toggle verbose (no truncation; full content for annotations/payloads/findings)")
                print(f"    {c('repo', CYAN)} [path]           Show or set default repo (e.g. repo /path/to/repo)")
                print(f"    {c('tools', CYAN)}                 List available tools")
                print(f"    {c('<tool_name>', CYAN)}           Call a tool (prompts for args)")
                print(f"    {c('<tool_name> {json}', CYAN)}    Call with inline JSON args")
                print(f"    {c('last', CYAN)}                  Show last result (full JSON)")
                print(f"    {c('status', CYAN)} / {c('state', CYAN)}        Show session config (server, repo, verbose, last output)")
                print(f"    {c('help', CYAN)}                  Show this help")
                print(f"    {c('quit', CYAN)}                  Exit (or Ctrl+C)")
                print(f"  {c('Long output', DIM)} is paged (less); set AGENTSMITH_MCP_NOPAGER=1 to disable.")
                print(f"  {c('Progress', DIM)}: tail -f .mcp_server.log in another terminal to see API calls live.")
                print()
                print(f"  {c('Examples:', BOLD)}")
                print(f'    scan_static {{"severity": "HIGH"}}   # repo_path auto-filled')
                print(f'    scan_hybrid {{"preset": "mcp"}}              # 2 files, ~1 min')
                print(f'    scan_hybrid {{"preset": "quick"}}             # 10 files')
                print(f'    scan_mcp {{"target_url": "http://localhost:9001/sse"}}')
                print(f'    summary')
                print(f'    findings 50')
                print()
                continue

            if line == "verbose":
                verbose = not verbose
                print(f"  Verbose: {c('on', GREEN) if verbose else c('off', DIM)}")
                print()
                continue

            if line == "repo" or line.startswith("repo "):
                rest = line[4:].strip()
                if not rest:
                    if repo_path:
                        print(f"  Default repo: {c(repo_path, CYAN)}")
                    else:
                        print(f"  {c('No default repo set', DIM)}. Use: repo /path/to/repo")
                else:
                    new_path = str(Path(rest).expanduser().resolve())
                    if not Path(new_path).is_dir():
                        print(f"  {c('Not a directory (or missing)', RED)}: {new_path}")
                    else:
                        repo_path = new_path
                        print(f"  Default repo set to: {c(repo_path, CYAN)}")
                print()
                continue

            if line in ("status", "state"):
                print(f"  {c('Session', BOLD)}")
                print(f"    Server:        {c(url, CYAN)}")
                print(f"    Default repo:  {c(repo_path or '(none)', DIM)}")
                print(f"    Verbose:       {c('on' if verbose else 'off', DIM)}")
                print(f"    Last output:   {c(last_output_dir or '(none)', DIM)}")
                print(f"    Tools:         {len(tools)}")
                print()
                continue

            if line == "summary":
                args = {"output_dir": last_output_dir} if last_output_dir else {}
                if not last_output_dir:
                    print(f"  {c('No last scan output dir', DIM)} — using most recent output/ dir")
                print(f"  {c('Calling', DIM)}: summarize_results")
                spinner.start("Running summarize_results...")
                t0 = time.monotonic()
                try:
                    result = await session.call_tool("summarize_results", args)
                    spinner.stop()
                    data = json.loads(result.content[0].text)
                    with _paged_output():
                        _print_result_detail("summarize_results", data, verbose=True)
                    print(f"  {c(f'({(time.monotonic()-t0)*1000:.0f}ms)', DIM)}")
                except Exception as e:
                    spinner.stop()
                    print(f"  {c('FAIL', RED)}: {e}")
                print()
                continue

            if line.startswith("findings"):
                rest = line[8:].strip()
                limit = 20
                if rest == "all":
                    limit = 500
                elif rest.isdigit():
                    limit = min(int(rest), 500)
                args = {"severity": "CRITICAL", "limit": limit}
                if last_output_dir:
                    args["output_dir"] = last_output_dir
                else:
                    print(f"  {c('No last scan output dir', DIM)} — using most recent output/ dir")
                print(f"  {c('Calling', DIM)}: list_findings (limit={limit})")
                spinner.start("Running list_findings...")
                t0 = time.monotonic()
                try:
                    result = await session.call_tool("list_findings", args)
                    spinner.stop()
                    data = json.loads(result.content[0].text)
                    with _paged_output():
                        _print_result_detail("list_findings", data, verbose=verbose)
                    print(f"  {c(f'({(time.monotonic()-t0)*1000:.0f}ms)', DIM)}")
                except Exception as e:
                    spinner.stop()
                    print(f"  {c('FAIL', RED)}: {e}")
                print()
                continue

            if line == "scan":
                if not repo_path:
                    print(f"  {c('No default repo', YELLOW)}. Set --repo or run detect_tech_stack with a repo_path first.")
                    print()
                    continue
                last_result = await _run_full_scan(session, tools, repo_path, spinner)
                print()
                continue

            if line == "annotations":
                if not last_output_dir:
                    try:
                        result = await session.call_tool("summarize_results", {"prefer_has": "annotations"})
                        data = json.loads(result.content[0].text)
                        if data.get("output_dir") and "error" not in data:
                            last_output_dir = data["output_dir"]
                            print(f"  {c('Using latest run with annotations', DIM)}: {last_output_dir[:60]}...")
                        else:
                            print(f"  {c('No run with annotations found', DIM)} — run a hybrid scan with annotate_code first.")
                            print()
                            continue
                    except Exception as e:
                        print(f"  {c('Could not get output dir', DIM)}: {e}")
                        print()
                        continue
                ann_dir = Path(last_output_dir) / "annotations"
                if not ann_dir.is_dir():
                    print(f"  {c('No annotations dir', DIM)} at {ann_dir}")
                    print()
                    continue
                files = sorted(ann_dir.glob("*.md"))
                with _paged_output():
                    print(f"  {c('Annotations', BOLD)} ({len(files)} files) from last run")
                    for f in files:
                        print(f"  {c('---', DIM)} {f.name}")
                        if verbose:
                            try:
                                body = f.read_text(encoding="utf-8", errors="replace")
                                in_code = False
                                for ln in body.splitlines():
                                    colored, in_code = _colorize_annotation_line(ln, in_code)
                                    print(f"    {colored}")
                            except Exception as e:
                                print(f"    {c(str(e), RED)}")
                        else:
                            print(f"    {c('(use verbose to show full content)', DIM)}")
                print()
                continue

            if line == "payloads":
                if not last_output_dir:
                    try:
                        result = await session.call_tool("summarize_results", {"prefer_has": "payloads"})
                        data = json.loads(result.content[0].text)
                        if data.get("output_dir") and "error" not in data:
                            last_output_dir = data["output_dir"]
                            print(f"  {c('Using latest run with payloads', DIM)}: {last_output_dir[:60]}...")
                        else:
                            print(f"  {c('No run with payloads found', DIM)} — run a hybrid scan with generate_payloads first.")
                            print()
                            continue
                    except Exception as e:
                        print(f"  {c('Could not get output dir', DIM)}: {e}")
                        print()
                        continue
                pay_dir = Path(last_output_dir) / "payloads"
                if not pay_dir.is_dir():
                    print(f"  {c('No payloads dir', DIM)} at {pay_dir}")
                    print()
                    continue
                files = sorted(pay_dir.glob("*.json"))
                with _paged_output():
                    print(f"  {c('Payloads', BOLD)} ({len(files)} files) from last run")
                    for f in files:
                        print(f"  {c('---', DIM)} {f.name}")
                        if verbose:
                            try:
                                data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                                for ln in json.dumps(data, indent=2).splitlines():
                                    print(f"    {_colorize_json_line(ln)}")
                            except Exception as e:
                                print(f"    {c(str(e), RED)}")
                        else:
                            print(f"    {c('(use verbose to show full content)', DIM)}")
                print()
                continue

            if line == "everything":
                if not last_output_dir:
                    try:
                        result = await session.call_tool("summarize_results", {"prefer_has": "payloads"})
                        data = json.loads(result.content[0].text)
                        if data.get("output_dir") and "error" not in data:
                            last_output_dir = data["output_dir"]
                        else:
                            result = await session.call_tool("summarize_results", {})
                            data = json.loads(result.content[0].text)
                            if data.get("output_dir") and "error" not in data:
                                last_output_dir = data["output_dir"]
                            else:
                                print(f"  {c('No scan output found', DIM)} — run a hybrid scan first.")
                                print()
                                continue
                    except Exception as e:
                        print(f"  {c('Could not get output dir', DIM)}: {e}")
                        print()
                        continue
                print(f"  {c('Full output from last run', BOLD)} (no truncation)")
                print()
                try:
                    result = await session.call_tool("summarize_results", {"output_dir": last_output_dir})
                    data = json.loads(result.content[0].text)
                    with _paged_output():
                        _print_result_detail("summarize_results", data, verbose=True)
                except Exception as e:
                    print(f"    {c('FAIL', RED)}: {e}")
                print()
                try:
                    result = await session.call_tool("list_findings", {"output_dir": last_output_dir, "limit": 500})
                    data = json.loads(result.content[0].text)
                    with _paged_output():
                        _print_result_detail("list_findings", data, verbose=True)
                except Exception as e:
                    print(f"    {c('FAIL', RED)}: {e}")
                print()
                ann_dir = Path(last_output_dir) / "annotations"
                if ann_dir.is_dir():
                    with _paged_output():
                        print(f"  {c('Annotations (full)', BOLD)}")
                        for f in sorted(ann_dir.glob("*.md")):
                            print(f"  {c('---', DIM)} {f.name}")
                            try:
                                in_code = False
                                for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
                                    colored, in_code = _colorize_annotation_line(ln, in_code)
                                    print(f"    {colored}")
                            except Exception as e:
                                print(f"    {c(str(e), RED)}")
                pay_dir = Path(last_output_dir) / "payloads"
                if pay_dir.is_dir():
                    with _paged_output():
                        print(f"  {c('Payloads (full)', BOLD)}")
                        for f in sorted(pay_dir.glob("*.json")):
                            print(f"  {c('---', DIM)} {f.name}")
                            try:
                                pay_data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                                for ln in json.dumps(pay_data, indent=2).splitlines():
                                    print(f"    {_colorize_json_line(ln)}")
                            except Exception as e:
                                print(f"    {c(str(e), RED)}")
                print()
                continue

            if line == "tools":
                # Group tools by category for clarity
                ai_tools = {"scan_hybrid", "explain_finding", "get_fix"}
                for name, t in tools.items():
                    tag = c("[AI]", YELLOW) if name in ai_tools else c("    ", DIM)
                    print(f"  {tag} {c(name, CYAN)}")
                    print(f"         {c(t.description, DIM)}")
                print()
                print(f"  {c('[AI]', YELLOW)} = requires CLAUDE_API_KEY or Bedrock credentials")
                print()
                continue

            if line == "last":
                if last_result is not None:
                    print(json.dumps(last_result, indent=2, default=str))
                else:
                    print(f"  {c('No previous result', DIM)}")
                print()
                continue

            # Parse tool name and optional inline JSON args
            parts = line.split(None, 1)
            tool_name = parts[0]
            inline_args = parts[1] if len(parts) > 1 else None

            if tool_name not in tools:
                print(f"  {c('Unknown tool', RED)}: {tool_name}")
                print(f"  Type 'tools' to see available tools")
                print()
                continue

            # Build arguments
            tool = tools[tool_name]
            if inline_args:
                try:
                    args = json.loads(inline_args)
                except json.JSONDecodeError:
                    print(f"  {c('Invalid JSON', RED)}: {inline_args}")
                    continue
                if "repo_path" not in args and repo_path and tool_name in ("scan_hybrid", "scan_static", "detect_tech_stack"):
                    args["repo_path"] = repo_path
                    print(f"  {c('(using default repo_path)', DIM)}")
            else:
                args = _prompt_for_args(tool, repo_path)

            print(f"  {c('Calling', DIM)}: {tool_name}")
            spinner.start(f"Running {tool_name}...")
            t0 = time.monotonic()
            try:
                result = await session.call_tool(tool_name, args)
                elapsed_ms = (time.monotonic() - t0) * 1000
                spinner.stop()
                text = result.content[0].text
                data = json.loads(text)
                last_result = data
                if data.get("output_dir"):
                    last_output_dir = data["output_dir"]

                if "error" in data:
                    print(f"  {c('Error', YELLOW)}: {data['error']}")
                    stderr = (data.get("stderr") or "").strip()
                    if stderr:
                        lines = stderr.splitlines()[-15:]
                        print(f"  {c('Details (orchestrator stderr):', DIM)}")
                        for ln in lines:
                            print(f"    {c(ln[:120], DIM)}")
                        if "api" in stderr.lower() or "key" in stderr.lower() or "bedrock" in stderr.lower():
                            print(f"  {c('Tip: set env in the shell where you START the MCP server (CLAUDE_API_KEY or AGENTSMITH_PROVIDER=bedrock + AWS_REGION).', DIM)}")
                else:
                    with _paged_output():
                        _print_result_detail(tool_name, data, verbose=verbose)
                    if tool_name == "scan_hybrid" and data.get("output_dir") and "error" not in data:
                        if data.get("notice"):
                            print(f"  {c('⚠ ', YELLOW)}{c(data['notice'], YELLOW)}")
                        print(f"  {c('---', DIM)}")
                        print(f"  {c('Summary for this run:', BOLD)}")
                        try:
                            sum_result = await session.call_tool("summarize_results", {"output_dir": data["output_dir"]})
                            sum_data = json.loads(sum_result.content[0].text)
                            with _paged_output():
                                _print_result_detail("summarize_results", sum_data, verbose=True)
                        except Exception:
                            pass
                print(f"  {c(f'({elapsed_ms:.0f}ms)', DIM)}")

            except Exception as e:
                spinner.stop()
                print(f"  {c('FAIL', RED)}: {type(e).__name__}: {e}")

            print()

    finally:
        await session.__aexit__(None, None, None)
        await ctx.__aexit__(None, None, None)

    return True


def _prompt_for_args(tool, default_repo: str | None) -> dict:
    """Prompt user for tool arguments based on the schema."""
    schema = tool.inputSchema or {}
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    args = {}

    for name, prop in props.items():
        ptype = prop.get("type", "string")
        desc = prop.get("description", "")
        enum_vals = prop.get("enum")
        default = prop.get("default")

        # Smart defaults for path arguments
        if name == "repo_path" and default_repo:
            default = default_repo
        elif name == "file_path" and default_repo:
            # Suggest a likely file from the repo
            repo = Path(default_repo)
            candidates = (
                list(repo.glob("*.py"))[:1]
                or list(repo.glob("*.php"))[:1]
                or list(repo.glob("*.js"))[:1]
            )
            if candidates:
                default = str(candidates[0])

        hint = f" [{default}]" if default else ""
        req_mark = c("*", RED) if name in required else " "
        if enum_vals:
            hint = f" ({'/'.join(enum_vals)}){hint}"
        # Show description for required args to help the user
        if name in required and desc and not default:
            print(f"      {c(desc, DIM)}")

        try:
            val = input(f"    {req_mark}{c(name, CYAN)}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return args

        if not val and default is not None:
            val = str(default)
        if not val:
            continue

        if ptype == "integer":
            try:
                val = int(val)
            except ValueError:
                print(f"      {c('must be an integer, skipping', YELLOW)}")
                continue
        elif ptype == "boolean":
            val = val.lower() in ("true", "1", "yes")

        args[name] = val

    return args


# ---------------------------------------------------------------------------
# Mode: list
# ---------------------------------------------------------------------------

async def mode_list(url: str):
    """List all tools with full schemas."""
    print(f"\n{c('Agent Smith MCP Tools', BOLD)}")
    print(f"{'=' * 60}")

    try:
        ctx, session = await connect(url)
    except ConnectionError as e:
        print(f"{c('ERROR', RED)}: {e}")
        return False

    try:
        tools_result = await session.list_tools()
        ai_tools = {"scan_hybrid", "explain_finding", "get_fix"}

        for t in tools_result.tools:
            tag = f" {c('[AI]', YELLOW)}" if t.name in ai_tools else ""
            print(f"\n{c(t.name, CYAN)}{tag}")
            print(f"  {t.description}")
            schema = t.inputSchema or {}
            props = schema.get("properties", {})
            required = set(schema.get("required", []))
            if props:
                print(f"  {c('Parameters:', BOLD)}")
                for name, prop in props.items():
                    req = c("required", RED) if name in required else c("optional", DIM)
                    ptype = prop.get("type", "string")
                    desc = prop.get("description", "")
                    enum_vals = prop.get("enum")
                    default = prop.get("default")
                    parts = [f"{ptype}", req]
                    if enum_vals:
                        parts.append(f"enum: {enum_vals}")
                    if default is not None:
                        parts.append(f"default: {default}")
                    print(f"    {c(name, WHITE)}: {', '.join(parts)}")
                    if desc:
                        print(f"      {c(desc, DIM)}")
            else:
                print(f"  {c('No parameters', DIM)}")

        print()
        print(f"  {c('[AI]', YELLOW)} = requires CLAUDE_API_KEY or Bedrock credentials")
        print()

    finally:
        await session.__aexit__(None, None, None)
        await ctx.__aexit__(None, None, None)

    return True


# ---------------------------------------------------------------------------
# Mode: benchmark
# ---------------------------------------------------------------------------

async def mode_benchmark(url: str, repo_path: str | None = None, iterations: int = 3):
    """Benchmark tool latency."""
    repo_path = repo_path or _detect_repo_path()

    print(f"\n{c('Agent Smith MCP Benchmark', BOLD)}")
    print(f"{'=' * 60}")
    print(f"  Server:     {c(url, CYAN)}")
    print(f"  Iterations: {iterations}")
    print()

    try:
        ctx, session = await connect(url)
    except ConnectionError as e:
        print(f"{c('ERROR', RED)}: {e}")
        return False

    try:
        bench_tools = [
            ("list_presets", {}),
            ("summarize_results", {}),
            ("list_findings", {"severity": "CRITICAL", "limit": 10}),
        ]
        if repo_path:
            bench_tools.extend([
                ("detect_tech_stack", {"repo_path": repo_path}),
                ("scan_static", {"repo_path": repo_path, "severity": "HIGH"}),
            ])

        print(f"  {'Tool':<25} {'Min':>8} {'Avg':>8} {'Max':>8} {'Status':>8}")
        print(f"  {'-' * 25} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8}")

        for tool_name, args in bench_tools:
            times = []
            errors = 0
            for _ in range(iterations):
                t0 = time.monotonic()
                try:
                    result = await session.call_tool(tool_name, args)
                    elapsed = (time.monotonic() - t0) * 1000
                    text = result.content[0].text
                    data = json.loads(text)
                    if "error" in data:
                        errors += 1
                    times.append(elapsed)
                except Exception:
                    errors += 1
                    times.append((time.monotonic() - t0) * 1000)

            if times:
                min_t = min(times)
                avg_t = sum(times) / len(times)
                max_t = max(times)
                status = c("OK", GREEN) if errors == 0 else c(f"{errors}err", YELLOW)
                print(f"  {tool_name:<25} {min_t:>7.0f}ms {avg_t:>7.0f}ms {max_t:>7.0f}ms {status:>8}")

        print()

    finally:
        await session.__aexit__(None, None, None)
        await ctx.__aexit__(None, None, None)

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Agent Smith MCP Test Client",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "mode", nargs="?", default="test",
        choices=["test", "interact", "list", "benchmark"],
        help="Client mode (default: test)",
    )
    parser.add_argument("--url", default="http://localhost:2266/sse",
                        help="MCP server SSE URL (default: http://localhost:2266/sse)")
    parser.add_argument("--tool", type=str, help="Test a specific tool only")
    parser.add_argument("--repo", type=str, help="Repository path for scanning tools")
    parser.add_argument("--all", action="store_true", help="Include slow tools (scan_hybrid)")
    parser.add_argument("--json", action="store_true", help="JSON output (for CI/CD)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output (pass/fail only)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show cost block, orchestrator debug log (when present), and extra detail")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--iterations", type=int, default=3, help="Benchmark iterations (default: 3)")
    args = parser.parse_args()

    global _no_color
    _no_color = args.no_color or args.json

    if args.mode == "test":
        ok = asyncio.run(mode_test(
            args.url, args.tool, args.all, args.repo, args.json, args.quiet, args.verbose
        ))
    elif args.mode == "interact":
        ok = asyncio.run(mode_interact(args.url, args.repo))
    elif args.mode == "list":
        ok = asyncio.run(mode_list(args.url))
    elif args.mode == "benchmark":
        ok = asyncio.run(mode_benchmark(args.url, args.repo, args.iterations))
    else:
        ok = False

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
