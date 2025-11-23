#!/usr/bin/env python3
"""
Smart Code Analyzer (full features + caching)

Stages:
  1. Prioritization
  2. Deep Dive
  3. Synthesis
  4. (Optional) Annotation & Payload Generation
  5. (Optional with --optimize) Code Quality Improvement
"""

from __future__ import annotations

import argparse
import sys

# Check for --help-examples before importing heavy dependencies
if "--help-examples" in sys.argv:
    from help_examples import print_help_examples, print_quick_reference
    print_help_examples()
    print_quick_reference()
    sys.exit(0)

import html
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Final, List, Optional, Sequence, Union

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.syntax import Syntax
from rich.table import Table

# Add beta directory to path for imports
_BETA_DIR = Path(__file__).parent
if str(_BETA_DIR) not in sys.path:
    sys.path.insert(0, str(_BETA_DIR))

from common import (
    get_api_key,
    parse_json_response,
    scan_repo_files,
    retry_with_backoff,
    CODE_EXTS,
    YAML_EXTS,
    HELM_EXTS,
    SKIP_DIRS,
)
from models import AnalysisReport, Finding
from output_manager import OutputManager
from prompts import PromptFactory

# Unified context management library
try:
    from scrynet_context import ReviewContextManager
    CONTEXT_AVAILABLE = True
except ImportError:
    CONTEXT_AVAILABLE = False


# ---------- Constants ----------
CLAUDE_MODEL: Final = "claude-3-5-haiku-20241022"
DEFAULT_MAX_FILE_BYTES: Final = 500_000
DEFAULT_MAX_FILES: Final = 400


# Data models are now in models.py
# CostTracker is now in scrynet_context.py
# Deprecated CacheManager, ConversationLog, and helper functions removed
# All utilities are now in common.py


class SmartAnalyzer:
    def __init__(self, console: Console, client: anthropic.Anthropic, context: Optional[ReviewContextManager], *, model: str, default_max_tokens: int, temperature: float, repo_root: Optional[Path] = None, max_retries: int = 3):
        self.console = console
        self.client = client
        self.context = context  # ReviewContextManager handles both cache and review state
        self.model = model
        self.default_max_tokens = default_max_tokens
        self.temperature = temperature
        self.repo_root = repo_root
        self.max_retries = max_retries

    def _call_claude_api(self, prompt: str, max_tokens: int) -> anthropic.types.Message:
        """Make API call with retry logic."""
        @retry_with_backoff(max_retries=self.max_retries, base_delay=1.0, max_delay=60.0)
        def _make_call():
            # Log that we're about to make the call (for debugging)
            import sys
            print(f"[DEBUG] Calling API: model={self.model}, max_tokens={max_tokens}, prompt_len={len(prompt)}", file=sys.stderr, flush=True)
            try:
                result = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.temperature,
                )
                print(f"[DEBUG] API call completed successfully", file=sys.stderr, flush=True)
                return result
            except Exception as e:
                print(f"[DEBUG] API call failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
                raise
        return _make_call()

    def _call_claude(
        self, stage: str, file: Optional[str], prompt: str, max_tokens: int = 4000,
        repo_path: Optional[str] = None
    ) -> Optional[str]:
        import sys
        print(f"[DEBUG] _call_claude called: stage={stage}, file={file}, prompt_len={len(prompt)}", file=sys.stderr, flush=True)
        
        # Input validation to prevent memory exhaustion
        if not prompt or len(prompt) > 100_000:
            self.console.print(f"[red]Invalid prompt length: {len(prompt)} bytes (max 100,000)[/red]")
            return None

        # Check cache using context manager
        print(f"[DEBUG] Checking cache...", file=sys.stderr, flush=True)
        cached = None
        if self.context:
            try:
                cached = self.context.get_cached_response(
                    stage, prompt, file=file, repo_path=repo_path, model=self.model
                )
                print(f"[DEBUG] Cache check complete, cached={cached is not None}", file=sys.stderr, flush=True)
            except Exception as e:
                print(f"[DEBUG] Cache check failed: {e}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc(file=sys.stderr)
        
        if cached:
            self.console.print(f"[dim]Cache hit for {stage} ({file or 'n/a'})[/dim]")
            if self.context:
                self.context.track_cost(0, 0, cached=True)
            return cached.raw_response
        
        try:
            # Make API call - this may take 30-60+ seconds for complex analysis
            print(f"[DEBUG] About to call _call_claude_api...", file=sys.stderr, flush=True)
            response = self._call_claude_api(prompt, max_tokens)
            print(f"[DEBUG] _call_claude_api returned", file=sys.stderr, flush=True)
            if not response or not hasattr(response, 'content'):
                self.console.print(f"[red]Invalid API response structure[/red]")
                return None
            raw = response.content[0].text if response.content else ""
            
            # Track token usage from API response
            if hasattr(response, 'usage') and response.usage:
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens
            else:
                # Fallback: estimate tokens (rough approximation: 1 token ≈ 4 chars)
                input_tokens = len(prompt) // 4
                output_tokens = len(raw) // 4
            
            # Track costs and save to cache
            if self.context:
                parsed = parse_json_response(raw)
                self.context.save_response(
                    stage, prompt, raw, parsed=parsed,
                    file=file, repo_path=repo_path, model=self.model,
                    input_tokens=input_tokens, output_tokens=output_tokens
                )
                self.context.track_cost(input_tokens, output_tokens, cached=False)
            
            return raw
        except anthropic.APIStatusError as e:
            if e.status_code == 429:
                self.console.print(f"[yellow]Rate limit hit. Retrying with backoff...[/yellow]")
            self.console.print(f"[red]API Error ({e.status_code}): {e}[/red]")
            return None
        except TimeoutError as e:
            self.console.print(f"[red]API call timed out after 5 minutes: {e}[/red]")
            return None
        except Exception as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                self.console.print(f"[red]API call timed out: {error_msg}[/red]")
            else:
                self.console.print(f"[red]API Error: {error_msg}[/red]")
            return None

    def run_prioritization_stage(
        self, all_files: List[Path], question: str, debug: bool, limit: int
    ) -> Optional[List[Dict[str, str]]]:
        self.console.print("[bold]Stage 1: Prioritization[/bold]")
        if not all_files:
            return None
        prompt = PromptFactory.prioritization(all_files, question, limit)
        raw = self._call_claude("prioritization", None, prompt, repo_path=str(Path.cwd()))
        if not raw:
            return None
        if debug:
            self.console.print(Panel(raw, title="RAW API RESPONSE (Prioritization)"))
        parsed = parse_json_response(raw)
        if parsed and isinstance(parsed.get("prioritized_files"), list):
            prioritized_info = parsed["prioritized_files"]
            self.console.print(
                f"[green]✓ AI has suggested {len(prioritized_info)} files for analysis.[/green]\n"
            )
            return prioritized_info
        self.console.print(
            "[yellow]Could not parse prioritization response. Continuing with all files.[/yellow]"
        )
        return None

    def run_deep_dive_stage(
        self,
        files: List[Path],
        question: str,
        verbose: bool,
        debug: bool,
        threshold: Optional[str],
    ) -> List[Finding]:
        self.console.print("\n[bold]Stage 2: Deep Dive[/bold]")
        findings: List[Finding] = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task(f"[cyan]Analyzing {len(files)} files...", total=len(files))
            
            for i, file_path in enumerate(files, 1):
                # Update progress bar with current file name and progress
                file_display = file_path.name if len(file_path.name) <= 40 else file_path.name[:37] + "..."
                progress.update(
                    task,
                    description=f"[cyan]Processing {i}/{len(files)}: {file_display}...",
                    refresh=True
                )
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                except OSError as e:
                    self.console.print(f"  [red]Error reading {file_path}: {e}[/red]")
                    progress.advance(task)
                    continue

                if file_path.suffix.lower() in YAML_EXTS:
                    prompt = PromptFactory.deep_dive_yaml(file_path, content, question)
                elif file_path.suffix.lower() in HELM_EXTS or "templates" in file_path.parts:
                    prompt = PromptFactory.deep_dive_helm(file_path, content, question)
                else:
                    prompt = PromptFactory.deep_dive(file_path, content, question)

                # Update progress bar before API call - show we're calling API
                progress.update(
                    task,
                    description=f"[yellow]Calling API ({i}/{len(files)}): {file_display}...[/yellow]",
                    refresh=True
                )
                # Print to console so user knows API call is starting (progress bar might not update during blocking call)
                self.console.print(f"[dim]  [{i}/{len(files)}] Calling API for {file_display}... (this may take 30-60 seconds)[/dim]")
                # Flush to ensure message is visible
                import sys
                sys.stdout.flush()
                sys.stderr.flush()
                
                start_time = time.time()
                try:
                    # Debug: show we're about to call _call_claude
                    print(f"[DEBUG] About to call _call_claude for {file_display}, prompt_len={len(prompt)}", file=sys.stderr, flush=True)
                    raw = self._call_claude("deep_dive", str(file_path), prompt, repo_path=str(Path(file_path).anchor or Path.cwd()))
                    print(f"[DEBUG] _call_claude returned for {file_display}, raw_len={len(raw) if raw else 0}", file=sys.stderr, flush=True)
                    elapsed = time.time() - start_time
                    if elapsed > 30:
                        self.console.print(f"[dim]  [{i}/{len(files)}] API call completed for {file_display} in {elapsed:.1f}s[/dim]")
                except Exception as e:
                    elapsed = time.time() - start_time
                    self.console.print(f"  [red]Error analyzing {file_display} after {elapsed:.1f}s: {e}[/red]")
                    progress.advance(task)
                    continue
                
                if not raw:
                    self.console.print(f"  [yellow]No response for {file_display}, skipping...[/yellow]")
                    progress.advance(task)
                    continue
                
                # Update progress bar after API call, before console output
                progress.update(
                    task,
                    description=f"[green]Processing results ({i}/{len(files)}): {file_display}...[/green]",
                    refresh=True
                )
                
                if debug:
                    self.console.print(Panel(raw, title=f"RAW API RESPONSE ({file_path.name})"))

                parsed = parse_json_response(raw)
                if parsed and isinstance(parsed.get("insights"), list):
                    relevance = str(parsed.get("relevance", "N/A"))
                    if threshold and relevance not in ("HIGH", threshold):
                        progress.advance(task)
                        continue

                    file_insights: Sequence[dict] = parsed["insights"]
                    # Update progress bar before printing results
                    progress.update(
                        task,
                        description=f"[cyan]Found {len(file_insights)} insights ({i}/{len(files)}): {file_display}[/cyan]",
                        refresh=True
                    )
                    self.console.print(f"   Relevance: {relevance}, Found: {len(file_insights)} insights")
                    for ins in file_insights:
                        findings.append(Finding.from_dict(ins, str(file_path), relevance))

                        if verbose:
                            line_num_val = ins.get("line_number")
                            code_line_printed = False
                            try:
                                # Attempt to parse line number, forgiving str/int mismatch from AI
                                if line_num_val is not None:
                                    line_num_int = int(line_num_val)
                                    if 0 < line_num_int <= len(lines):
                                        code_line = lines[line_num_int - 1]

                                        # Only print the code line if it contains non-whitespace chars
                                        if code_line.strip():
                                            lexer = "java" if file_path.suffix == ".java" else "python"
                                            self.console.print(
                                                Syntax(
                                                    code_line,
                                                    lexer,
                                                    theme="monokai",
                                                    line_numbers=True,
                                                    start_line=line_num_int,
                                                )
                                            )
                                        else:
                                            self.console.print(
                                                f"[dim]   (Line {line_num_int} is empty)[/dim]"
                                            )
                                        code_line_printed = True
                            except (ValueError, TypeError):
                                # Fail gracefully if line number is not a valid int
                                pass

                            finding_text = f"     Finding: {ins.get('finding')} (Impact: {ins.get('impact')}, CWE: {ins.get('cwe')})"
                            # Adjust indentation if no code line was printed
                            if not code_line_printed:
                                finding_text = finding_text.lstrip()

                            self.console.print(finding_text)
                            self.console.print("")  # Add vertical space for readability
                    
                    progress.advance(task)
                    time.sleep(0.5)  # Reduced delay since we have progress bar
        
        self.console.print(f"\n[green]✓ Deep dive complete. Found {len(findings)} total insights.[/green]")
        return findings

    def run_synthesis_stage(self, findings: List[Finding], question: str) -> str:
        self.console.print("\n[bold]Stage 3: Synthesis[/bold]")
        if not findings:
            return "No insights were found to synthesize."
        prompt = PromptFactory.synthesis(findings, question)
        raw = self._call_claude("synthesis", None, prompt, repo_path=str(Path.cwd()))
        self.console.print("[green]✓ Synthesis complete.[/green]\n")
        return raw or "Synthesis failed."

    def run_annotation_stage(self, top_findings: List[Finding], debug: bool) -> None:
        self.console.print("\n[bold]Stage: Code Annotation[/bold]")
        for finding in top_findings:
            try:
                content = Path(finding.file_path).read_text(encoding="utf-8", errors="ignore")
                prompt = PromptFactory.annotation(finding, content)
                raw = self._call_claude("annotation", finding.file_path, prompt, repo_path=str(Path(finding.file_path).anchor or Path.cwd()))
                if not raw:
                    continue
                if debug:
                    self.console.print(
                        Panel(
                            raw, title=f"RAW API RESPONSE (Annotation for {Path(finding.file_path).name})"
                        )
                    )

                parsed = parse_json_response(raw)
                if parsed and "annotated_snippet" in parsed:
                    finding.annotated_snippet = parsed["annotated_snippet"]
                    self.console.print(f"✓ Annotated snippet for [yellow]'{finding.finding}'[/yellow]")
                time.sleep(1)
            except Exception as e:
                self.console.print(f"[red]Error annotating {finding.file_path}: {e}[/red]")

    def run_payload_generation_stage(self, top_findings: List[Finding], debug: bool) -> None:
        self.console.print("\n[bold]Stage 4: Payload Generation[/bold]")
        for f in top_findings:
            try:
                snippet = Path(f.file_path).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                snippet = "Could not read snippet."
            prompt = PromptFactory.payload_generation(f, snippet[:500])
            raw = self._call_claude("payload", f.file_path, prompt, repo_path=str(Path(f.file_path).anchor or Path.cwd()))
            if not raw:
                continue
            if debug:
                self.console.print(
                    Panel(raw, title=f"RAW API RESPONSE (Payloads for {Path(f.file_path).name})")
                )
            parsed = parse_json_response(raw)
            if parsed:
                rt, bt = parsed.get("red_team_payload", {}), parsed.get("blue_team_payload", {})
                self.console.print(
                    Panel(
                        f"[bold red]Red Team[/bold red]\nPayload: `{rt.get('payload','')}`\n{rt.get('explanation','')}\n\n"
                        f"[bold green]Blue Team[/bold green]\nPayload: `{bt.get('payload','')}`\n{bt.get('explanation','')}",
                        title=f"Payloads for '{f.finding}'",
                        border_style="magenta",
                    )
                )
            time.sleep(1)

    def run_code_improvement_stage(
        self, files: List[Path], focus_areas: List[str], debug: bool
    ) -> Dict[str, List[dict]]:
        """Analyze Python files for code quality improvements (ONLY when --optimize flag is used)."""
        self.console.print("\n[bold cyan]Stage: Code Quality Optimization[/bold cyan]")
        improvements_by_file: Dict[str, List[dict]] = {}
        
        python_files = [f for f in files if f.suffix == ".py"]
        if not python_files:
            self.console.print("[yellow]No Python files found to optimize.[/yellow]")
            return improvements_by_file
        
        for i, file_path in enumerate(python_files, 1):
            self.console.print(
                f"[[bold]{i}/{len(python_files)}[/bold]] Optimizing {file_path.name}..."
            )
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.console.print(f"  [red]Error reading {file_path}: {e}[/red]")
                continue
            
            prompt = PromptFactory.code_improvement(
                file_path, content, focus_areas
            )
            raw = self._call_claude(
                "code_improvement", str(file_path), prompt, max_tokens=6000
            )
            
            if not raw:
                continue
                
            if debug:
                self.console.print(
                    Panel(raw, title=f"RAW API RESPONSE ({file_path.name})")
                )
            
            parsed = parse_json_response(raw)
            if parsed and isinstance(parsed.get("improvements"), list):
                quality = parsed.get("overall_quality", "N/A")
                improvements = parsed["improvements"]
                improvements_by_file[str(file_path)] = improvements
                
                self.console.print(
                    f"   Quality: [{'green' if quality == 'EXCELLENT' else 'yellow'}]{quality}[/], "
                    f"Improvements: {len(improvements)}"
                )
                
                # Display high-impact improvements
                high_impact = [
                    imp for imp in improvements if imp.get("impact") == "HIGH"
                ]
                if high_impact:
                    self.console.print(
                        f"   [bold red]⚠ {len(high_impact)} HIGH impact "
                        f"improvement(s) found[/bold red]"
                    )
            
            time.sleep(1)
        
        self.console.print(
            f"\n[green]✓ Code optimization complete. "
            f"Analyzed {len(python_files)} Python files.[/green]"
        )
        return improvements_by_file

    def generate_optimized_files(
        self,
        improvements_by_file: Dict[str, List[dict]],
        original_files: List[Path],
        debug: bool
    ) -> Dict[str, str]:
        """Generate full optimized versions of files with improvements."""
        self.console.print(
            "\n[bold cyan]Generating Optimized Code Files...[/bold cyan]"
        )
        optimized_code: Dict[str, str] = {}
        
        for file_path, improvements in improvements_by_file.items():
            if not improvements:
                continue
            
            # Only generate for HIGH impact improvements
            high_impact = [
                imp for imp in improvements if imp.get("impact") == "HIGH"
            ]
            if not high_impact:
                self.console.print(
                    f"[dim]Skipping {Path(file_path).name} "
                    f"(no HIGH impact changes)[/dim]"
                )
                continue
            
            self.console.print(
                f"Generating optimized version of {Path(file_path).name}..."
            )
            
            try:
                content = Path(file_path).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError as e:
                self.console.print(f"  [red]Error reading {file_path}: {e}[/red]")
                continue
            
            prompt = PromptFactory.full_code_optimization(
                Path(file_path), content, improvements
            )
            raw = self._call_claude(
                "full_optimization", str(file_path), prompt, max_tokens=8000
            )
            
            if not raw:
                continue
            
            if debug:
                self.console.print(
                    Panel(
                        raw[:500] + "...",
                        title=f"RAW API RESPONSE (Optimized {Path(file_path).name})"
                    )
                )
            
            # Extract code from markdown fences if present
            code = raw
            if "```python" in raw:
                start = raw.find("```python") + 9
                end = raw.rfind("```")
                if start > 8 and end > start:
                    code = raw[start:end].strip()
            elif "```" in raw:
                start = raw.find("```") + 3
                end = raw.rfind("```")
                if start > 2 and end > start:
                    code = raw[start:end].strip()
            
            optimized_code[file_path] = code
            self.console.print(
                f"  [green]✓ Generated optimized {Path(file_path).name}[/green]"
            )
            time.sleep(1)
        
        return optimized_code


# OutputManager is now in output_manager.py


# ---------- Interactivity ----------
def clarify_question_interactively(question: str, console: Console) -> str:
    if "security" in question.lower():
        console.print(
            "\n[bold cyan]?[/] Your question is about [bold]security[/bold]. To focus the analysis, what aspect are you most interested in?"
        )
        options = [
            "Injection Vulnerabilities (SQLi, XSS)",
            "Authentication & Authorization",
            "Insecure Data Handling (Secrets, PII)",
            "Dependency & Configuration Issues",
        ]
        for i, opt in enumerate(options, 1):
            console.print(f"  ({i}) {opt}")
        choice = input("Enter number (or press Enter to skip): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            clarification = options[int(choice) - 1]
            console.print(f"[dim]Focusing on: {clarification}[/dim]")
            return f"{question}, focusing specifically on {clarification}."
    return question


# ---------- CLI & Main ----------
def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Smart Code Analyzer with caching + full features")
    p.add_argument("repo_path", help="Path to the repository to analyze")
    p.add_argument("question", nargs="?", help="Analysis question")
    p.add_argument("--cache-dir", default=".scrynet_cache", help="Directory for conversation cache")
    p.add_argument("--no-cache", action="store_true", help="Disable cache (always hit API)")
    p.add_argument(
        "--save-conversations", action="store_true", help="Save full session log as JSON"
    )
    p.add_argument("--include-yaml", action="store_true", help="Include .yaml/.yml files")
    p.add_argument("--include-helm", action="store_true", help="Include Helm templates")
    p.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    p.add_argument("--prioritize-top", type=int, default=15, help="Ask AI to prioritize top N files.")
    p.add_argument(
        "--format",
        nargs="*",
        default=["console"],
        choices=["console", "html", "markdown", "json"],
    )
    # Model and generation controls
    p.add_argument("--model", default=CLAUDE_MODEL, help="Override Claude model identifier")
    p.add_argument("--max-tokens", type=int, default=4000, help="Max tokens per response")
    p.add_argument("--temperature", type=float, default=0.0, help="Sampling temperature (0.0 determinism)")
    p.add_argument("--max-retries", type=int, default=3, help="Max retries for API calls with exponential backoff")
    p.add_argument(
        "--top-n", type=int, default=5, help="Number of items for payload/annotation generation"
    )
    p.add_argument(
        "--threshold", choices=["HIGH", "MEDIUM"], help="Filter findings below this relevance"
    )
    p.add_argument("--generate-payloads", action="store_true", help="Generate Red/Blue payloads")
    p.add_argument(
        "--annotate-code", action="store_true", help="Generate annotated code snippets for top findings"
    )
    p.add_argument(
        "-v", "--verbose", action="store_true", help="Print findings inline with code context"
    )
    p.add_argument("--debug", action="store_true", help="Print raw API responses")
    
    # Code optimization flags
    p.add_argument(
        "--optimize",
        action="store_true",
        help="Run code quality optimization analysis on Python files"
    )
    p.add_argument(
        "--focus",
        nargs="*",
        choices=["typing", "readability", "security", "performance", "pythonic"],
        help="Focus areas for code optimization (default: all). Only used with --optimize"
    )
    p.add_argument(
        "--optimize-output",
        metavar="DIR",
        help="Write optimized Python files to this directory (requires --optimize)"
    )
    p.add_argument(
        "--diff",
        action="store_true",
        help="Show unified diff of changes when writing optimized files (requires --optimize-output)"
    )

    # Scan filters
    p.add_argument("--include-exts", nargs="*", help="Only include these file extensions (e.g., .py .go)")
    p.add_argument("--ignore-dirs", nargs="*", help="Additional directories to skip during scan")

    # Cache management (optional, non-breaking)
    p.add_argument("--cache-info", action="store_true", help="Show cache statistics and exit")
    p.add_argument("--cache-list", action="store_true", help="List recent cache entries and exit")
    p.add_argument("--cache-prune", type=int, metavar="DAYS", help="Prune cache entries older than DAYS and exit")
    p.add_argument("--cache-clear", action="store_true", help="Clear all cache entries and exit")
    p.add_argument("--cache-export", metavar="FILE", help="Export cache manifest to FILE and exit")
    
    # Review state management flags (optional, non-breaking)
    if CONTEXT_AVAILABLE:
        p.add_argument(
            "--enable-review-state",
            action="store_true",
            help="Enable review state tracking for resuming reviews"
        )
        p.add_argument(
            "--resume-last",
            action="store_true",
            help="Resume the most recent review matching the current repo (auto-detect)"
        )
        p.add_argument(
            "--resume-review",
            metavar="REVIEW_ID",
            help="Resume an existing review by review ID"
        )
        p.add_argument(
            "--list-reviews",
            action="store_true",
            help="List all available reviews and exit"
        )
        p.add_argument(
            "--review-status",
            metavar="REVIEW_ID",
            help="Show status of a specific review and exit"
        )
        p.add_argument(
            "--print-review",
            metavar="REVIEW_ID",
            help="Print full report of a specific review and exit"
        )
        p.add_argument(
            "--verbose-review",
            action="store_true",
            help="Show all findings with code snippets and detailed recommendations (use with --print-review)"
        )
    
    p.add_argument(
        "--help-examples",
        action="store_true",
        help="Show comprehensive usage examples and scenarios"
    )
    
    return p


def main() -> None:
    args = create_parser().parse_args()
    console = Console()
    
    # Handle help examples (already handled at top of file, but keep as fallback)
    if args.help_examples:
        try:
            from help_examples import print_help_examples, print_quick_reference
            print_help_examples()
            print_quick_reference()
        except ImportError:
            console.print("[yellow]Help examples module not available[/yellow]")
            console.print("Run: python3 help_examples.py")
        return

    # Handle review state management commands (if available)
    if CONTEXT_AVAILABLE:
        context = ReviewContextManager(args.cache_dir, use_cache=not args.no_cache, enable_cost_tracking=True)
        
        if args.list_reviews:
            reviews = context.list_reviews()
            if not reviews:
                console.print("[yellow]No reviews found.[/yellow]")
                return
            
            table = Table(title="Available Reviews", show_header=True, header_style="bold magenta")
            table.add_column("Review ID", style="cyan", width=12)
            table.add_column("Repository Path", style="magenta", width=40, overflow="fold")
            table.add_column("Question", style="green", width=50, overflow="fold")
            table.add_column("Status", style="yellow", width=10)
            table.add_column("Last Updated", style="dim", width=20)
            
            for review in reviews[:20]:  # Limit to 20 most recent
                # Format repository path - show full path, but truncate if too long
                repo_display = review.repo_path
                if len(repo_display) > 40:
                    # Show last 40 chars if path is too long
                    repo_display = "..." + repo_display[-37:]
                
                # Format timestamp - show full datetime
                try:
                    # Try to parse and format the timestamp nicely
                    if "T" in review.updated_at:
                        # ISO format with T
                        dt = datetime.fromisoformat(review.updated_at.replace("Z", "+00:00"))
                    else:
                        # Try parsing as space-separated format
                        dt = datetime.strptime(review.updated_at, "%Y-%m-%d %H:%M:%S")
                    timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, AttributeError):
                    # Fallback to original if parsing fails
                    timestamp_str = review.updated_at[:19] if len(review.updated_at) >= 19 else review.updated_at
                
                # Truncate question if too long
                question_display = review.question[:47] + "..." if len(review.question) > 50 else review.question
                
                table.add_row(
                    review.review_id,
                    repo_display,
                    question_display,
                    review.status,
                    timestamp_str
                )
            console.print(table)
            if len(reviews) > 20:
                console.print(f"\n[dim]... and {len(reviews) - 20} more reviews[/dim]")
            return
        
        if args.review_status:
            try:
                review = context.load_review(args.review_status)
                console.print(Panel(
                    f"[bold]Review ID:[/bold] {review.review_id}\n"
                    f"[bold]Repository:[/bold] {review.repo_path}\n"
                    f"[bold]Question:[/bold] {review.question}\n"
                    f"[bold]Status:[/bold] {review.status}\n"
                    f"[bold]Created:[/bold] {review.created_at}\n"
                    f"[bold]Updated:[/bold] {review.updated_at}\n"
                    f"[bold]Files Analyzed:[/bold] {len(review.files_analyzed)}\n"
                    f"[bold]Findings:[/bold] {len(review.findings)}\n"
                    f"[bold]Checkpoints:[/bold] {len(review.checkpoints)}",
                    title="Review Status",
                    border_style="blue"
                ))
                if review.checkpoints:
                    console.print("\n[bold]Checkpoints:[/bold]")
                    for cp in review.checkpoints:
                        console.print(f"  - {cp.stage} ({cp.timestamp[:19]})")
            except FileNotFoundError:
                console.print(f"[red]Review '{args.review_status}' not found.[/red]")
            return
        
        if args.print_review:
            try:
                review = context.load_review(args.print_review)
                
                # Convert findings from dicts to Finding objects
                findings = [
                    Finding.from_dict(
                        f,
                        f.get("file_path", ""),
                        f.get("relevance", "MEDIUM")
                    ) for f in review.findings
                ]
                
                # Restore optional fields
                for i, f in enumerate(findings):
                    if i < len(review.findings):
                        stored = review.findings[i]
                        if "line_number" in stored:
                            f.line_number = stored.get("line_number")
                        if "annotated_snippet" in stored:
                            f.annotated_snippet = stored.get("annotated_snippet")
                
                # Create a report
                report = AnalysisReport(
                    repo_path=review.repo_path,
                    question=review.question,
                    timestamp=review.updated_at or review.created_at,
                    file_count=len(review.files_analyzed),
                    insights=findings,
                    synthesis=review.synthesis or "No synthesis available."
                )
                
                # Print the report using OutputManager
                output_mgr = OutputManager(console)
                output_mgr.display_console_summary(report)
                
                # If verbose-review flag is set, show all findings with detailed info
                if args.verbose_review:
                    console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
                    console.print("[bold cyan]Detailed Findings Report (Verbose Mode)[/bold cyan]")
                    console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
                    
                    # Group findings by file
                    from collections import defaultdict
                    findings_by_file = defaultdict(list)
                    for finding in findings:
                        findings_by_file[finding.file_path].append(finding)
                    
                    # Sort by impact level
                    impact_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    
                    for file_path, file_findings in sorted(findings_by_file.items()):
                        file_findings.sort(key=lambda f: impact_order.get(f.impact, 0), reverse=True)
                        file_name = Path(file_path).name
                        console.print(f"\n[bold yellow]📄 {file_name}[/bold yellow]")
                        console.print(f"[dim]{file_path}[/dim]\n")
                        
                        # Try to read the file to show code context
                        try:
                            file_content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                            lines = file_content.splitlines()
                        except Exception:
                            lines = []
                            file_content = ""
                        
                        for finding in file_findings:
                            # Show finding details
                            impact_color = {
                                "CRITICAL": "red",
                                "HIGH": "yellow",
                                "MEDIUM": "cyan",
                                "LOW": "dim"
                            }.get(finding.impact, "white")
                            
                            console.print(f"  [{impact_color}]● {finding.finding}[/{impact_color}]")
                            console.print(f"    [dim]Impact: {finding.impact} | Confidence: {finding.confidence} | CWE: {finding.cwe}[/dim]")
                            if finding.line_number:
                                console.print(f"    [dim]Line: {finding.line_number}[/dim]")
                            console.print(f"    [green]Recommendation:[/green] {finding.recommendation}")
                            
                            # Show annotated snippet if available
                            if finding.annotated_snippet:
                                lexer_name = "java" if ".java" in finding.file_path else "python"
                                syntax = Syntax(
                                    finding.annotated_snippet,
                                    lexer_name,
                                    theme="monokai",
                                    line_numbers=True
                                )
                                console.print(Panel(
                                    syntax,
                                    title=f"[cyan]Code with Fix Suggestion[/cyan]",
                                    border_style="magenta"
                                ))
                            # Otherwise, show code context around the line
                            elif finding.line_number and lines:
                                try:
                                    line_num = int(finding.line_number)
                                    if 0 < line_num <= len(lines):
                                        # Show 5 lines before and after
                                        start = max(0, line_num - 6)
                                        end = min(len(lines), line_num + 5)
                                        context_lines = lines[start:end]
                                        context_code = "\n".join(context_lines)
                                        lexer_name = "java" if ".java" in finding.file_path else "python"
                                        syntax = Syntax(
                                            context_code,
                                            lexer_name,
                                            theme="monokai",
                                            line_numbers=True,
                                            start_line=start + 1
                                        )
                                        console.print(Panel(
                                            syntax,
                                            title=f"[yellow]Code Context (Line {line_num} highlighted)[/yellow]",
                                            border_style="yellow"
                                        ))
                                except (ValueError, TypeError):
                                    pass
                            
                            console.print()  # Blank line between findings
                
                # Also show checkpoints and metadata
                console.print(f"\n[bold]Review Metadata[/bold]")
                console.print(f"Review ID: {review.review_id}")
                console.print(f"Status: {review.status}")
                console.print(f"Created: {review.created_at}")
                console.print(f"Updated: {review.updated_at}")
                if review.checkpoints:
                    console.print(f"\n[bold]Checkpoints:[/bold]")
                    for cp in review.checkpoints:
                        console.print(f"  - {cp.stage} ({cp.timestamp[:19]})")
                
                # Show context file location
                context_file = context.reviews_dir / f"_{review.review_id}_context.md"
                if context_file.exists():
                    console.print(f"\n[dim]Full context file: {context_file}[/dim]")
                
            except FileNotFoundError:
                console.print(f"[red]Review '{args.print_review}' not found.[/red]")
            except Exception as e:
                console.print(f"[red]Error loading review: {e}[/red]")
                import traceback
                if args.debug:
                    console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return

    api_key = get_api_key()
    # Initialize client with timeout for all API calls
    # Note: timeout may need to be set via httpx_client if Anthropic SDK doesn't support it directly
    client = anthropic.Anthropic(api_key=api_key)
    
    # Initialize context manager (handles both cache and review state)
    context = None
    if CONTEXT_AVAILABLE:
        context = ReviewContextManager(args.cache_dir, use_cache=not args.no_cache, enable_cost_tracking=True)
    else:
        # Fallback: create a minimal context for backward compatibility
        console.print("[yellow]Warning: scrynet_context not available, some features disabled[/yellow]")
    
    analyzer = SmartAnalyzer(
        console, client, context, 
        model=args.model, 
        default_max_tokens=args.max_tokens, 
        temperature=args.temperature, 
        repo_root=None,
        max_retries=args.max_retries
    )

    # Handle cache management requests
    if args.cache_info:
        if not context:
            console.print("[red]Context manager not available[/red]")
            return
        stats = context.cache_stats()
        console.print(Panel(f"Dir: {stats['dir']}\nFiles: {stats['files']}\nBytes: {stats['bytes']} ({stats.get('bytes_mb', 0)} MB)", title="Cache Info", border_style="blue"))
        return
    if args.cache_list:
        if not context:
            console.print("[red]Context manager not available[/red]")
            return
        items = context.list_cache_entries()
        if not items:
            console.print("[yellow]No cache entries found.[/yellow]")
        else:
            table = Table(title="Recent Cache Entries")
            table.add_column("Path", style="cyan")
            for it in items:
                table.add_row(it)
            console.print(table)
        return
    if args.cache_prune is not None:
        if not context:
            console.print("[red]Context manager not available[/red]")
            return
        deleted = context.prune_cache(args.cache_prune)
        console.print(f"[green]Pruned {deleted} cache file(s) older than {args.cache_prune} days[/green]")
        return
    if args.cache_clear:
        if not context:
            console.print("[red]Context manager not available[/red]")
            return
        deleted = context.clear_cache()
        console.print(f"[green]Cleared {deleted} cache file(s)[/green]")
        return
    if args.cache_export:
        if not context:
            console.print("[red]Context manager not available[/red]")
            return
        # Note: export functionality would need to be added to ReviewContextManager
        console.print("[yellow]Cache export not yet implemented in new context manager[/yellow]")
        return

    repo_path = Path(args.repo_path)
    if not repo_path.exists():
        console.print(f"[red]Error: Repository path '{repo_path}' does not exist[/red]")
        sys.exit(1)

    question = args.question or input("Enter analysis question: ").strip()
    if not question:
        console.print("[red]No question provided[/red]")
        sys.exit(1)

    question = clarify_question_interactively(question, console)

    # Initialize review state management (if enabled)
    review_state = None
    if CONTEXT_AVAILABLE and context and (args.enable_review_state or args.resume_review or args.resume_last):
        # Compute fingerprint when needed (for change detection)
        # This can be slow on large repos, so we compute it lazily
        current_fingerprint = None  # Will be computed when needed
        
        if args.resume_review:
            try:
                review_state = context.load_review(args.resume_review)
                console.print(f"[green]✓ Resuming review: {review_state.review_id}[/green]")
                console.print(f"[dim]Previous question: {review_state.question}[/dim]")
                
                # Compute current fingerprint for comparison
                if current_fingerprint is None:
                    current_fingerprint = context.compute_dir_fingerprint(repo_path)
                
                # Check if codebase has changed
                if review_state.dir_fingerprint != current_fingerprint:
                    console.print(f"\n[yellow]⚠ Codebase has changed since this review was created![/yellow]")
                    console.print(f"[dim]Original fingerprint: {review_state.dir_fingerprint[:8]}...[/dim]")
                    console.print(f"[dim]Current fingerprint:  {current_fingerprint[:8]}...[/dim]")
                    choice = input("\nHow would you like to proceed?\n  [1] Re-analyze changed files (recommended)\n  [2] Continue with old analysis (may be outdated)\n  [3] Start fresh review\nEnter choice [1-3] (default: 1): ").strip()
                    if choice == "3":
                        if current_fingerprint is None:
                            current_fingerprint = context.compute_dir_fingerprint(repo_path)
                        review_state = context.create_review(repo_path, question, current_fingerprint)
                        console.print("[green]Starting fresh review...[/green]")
                    elif choice == "2":
                        console.print("[yellow]Continuing with old analysis (codebase may have changed)[/yellow]")
                    else:  # default or "1"
                        # Update fingerprint but keep review ID for continuity
                        review_state.dir_fingerprint = current_fingerprint
                        review_state.status = "in_progress"
                        # Clear checkpoints to force re-analysis
                        review_state.checkpoints = []
                        review_state.findings = []
                        review_state.synthesis = None
                        context.save_review(review_state)
                        console.print("[green]Re-analyzing with updated codebase...[/green]")
                
                # Optionally use previous question if not provided
                if not args.question:
                    use_previous = input("Use previous question? [Y/n]: ").strip().lower()
                    if use_previous in ("", "y", "yes"):
                        question = review_state.question
            except FileNotFoundError:
                console.print(f"[yellow]Review '{args.resume_review}' not found. Starting new review.[/yellow]")
                if current_fingerprint is None:
                    current_fingerprint = context.compute_dir_fingerprint(repo_path)
                review_state = context.create_review(repo_path, question, current_fingerprint)
        else:
            # Compute current fingerprint for matching
            if current_fingerprint is None:
                current_fingerprint = context.compute_dir_fingerprint(repo_path)
            
            # Check for matching review by directory fingerprint
            matching_id = context.find_matching_review(repo_path, current_fingerprint)
            if args.resume_last and matching_id:
                review_state = context.load_review(matching_id)
                console.print(f"[green]✓ Auto-resumed latest matching review: {matching_id}[/green]")
                # Check if codebase has changed (even if fingerprint matched, files might have changed)
                if review_state.dir_fingerprint != current_fingerprint:
                    console.print(f"\n[yellow]⚠ Codebase has changed since this review was created![/yellow]")
                    console.print(f"[dim]Original fingerprint: {review_state.dir_fingerprint[:8]}...[/dim]")
                    console.print(f"[dim]Current fingerprint:  {current_fingerprint[:8]}...[/dim]")
                    console.print("[yellow]Clearing checkpoints to force re-analysis...[/yellow]")
                    review_state.dir_fingerprint = current_fingerprint
                    review_state.status = "in_progress"
                    review_state.checkpoints = []
                    review_state.findings = []
                    review_state.synthesis = None
                    context.save_review(review_state)
            else:
                # Not using --resume-last, or no matching review found
                if matching_id:
                    console.print(f"[yellow]Found matching review: {matching_id}[/yellow]")
                    resume = input("Resume this review? [Y/n]: ").strip().lower()
                    if resume in ("", "y", "yes"):
                        review_state = context.load_review(matching_id)
                        # Compute current fingerprint if not already computed
                        if current_fingerprint is None:
                            current_fingerprint = context.compute_dir_fingerprint(repo_path)
                        # Check if codebase has changed
                        if review_state.dir_fingerprint != current_fingerprint:
                            console.print(f"\n[yellow]⚠ Codebase has changed since this review was created![/yellow]")
                            console.print(f"[dim]Original fingerprint: {review_state.dir_fingerprint[:8]}...[/dim]")
                            console.print(f"[dim]Current fingerprint:  {current_fingerprint[:8]}...[/dim]")
                            choice = input("\nHow would you like to proceed?\n  [1] Re-analyze changed files (recommended)\n  [2] Continue with old analysis (may be outdated)\nEnter choice [1-2] (default: 1): ").strip()
                            if choice == "2":
                                console.print("[yellow]Continuing with old analysis (codebase may have changed)[/yellow]")
                            else:  # default or "1"
                                review_state.dir_fingerprint = current_fingerprint
                                review_state.status = "in_progress"
                                review_state.checkpoints = []
                                review_state.findings = []
                                review_state.synthesis = None
                                context.save_review(review_state)
                                console.print("[green]Re-analyzing with updated codebase...[/green]")
                    else:
                        if current_fingerprint is None:
                            current_fingerprint = context.compute_dir_fingerprint(repo_path)
                        review_state = context.create_review(repo_path, question, current_fingerprint)
                else:
                    if current_fingerprint is None:
                        current_fingerprint = context.compute_dir_fingerprint(repo_path)
                    review_state = context.create_review(repo_path, question, current_fingerprint)
        
        console.print(f"[dim]Review ID: {review_state.review_id}[/dim]")

    # Build scan filters
    extra_skips = set(args.ignore_dirs or [])
    include_exts = set(args.include_exts or [])

    files = scan_repo_files(
        repo_path, args.include_yaml, args.include_helm, args.max_file_bytes, args.max_files
    )
    # Apply include/ignore filters (post-filter to avoid changing core scanner semantics)
    if include_exts:
        include_exts = {e if e.startswith('.') else f'.{e}' for e in include_exts}
        files = [f for f in files if f.suffix.lower() in include_exts]
    if extra_skips:
        files = [f for f in files if not any(skip in f.parts for skip in extra_skips)]

    console.print(f"\nFound [bold]{len(files)}[/bold] files to analyze.")

    # Check if prioritization stage was already completed
    prioritization_checkpoint = None
    if review_state:
        prioritization_checkpoint = next(
            (cp for cp in review_state.checkpoints if cp.stage == "prioritization"), None
        )
    
    if prioritization_checkpoint:
        console.print("[dim]✓ Prioritization stage already completed, loading from checkpoint...[/dim]")
        prioritized_info = prioritization_checkpoint.data.get("prioritized_files", [])
    else:
        prioritized_info = analyzer.run_prioritization_stage(
            files, question, args.debug, args.prioritize_top
        )
        
        # Save checkpoint after prioritization
        if review_state and context:
            context.add_checkpoint(
                review_state.review_id,
                "prioritization",
                {"prioritized_files": prioritized_info or []},
                files_analyzed=[str(f) for f in files[:20]]  # First 20 for checkpoint
            )

    files_to_analyze = files
    if prioritized_info:
        table = Table(title="AI-Prioritized Files for Analysis")
        table.add_column("File Name", style="cyan")
        table.add_column("Reason for Selection", style="magenta")
        for item in prioritized_info:
            table.add_row(item.get("file_name", "N/A"), item.get("reason", "N/A"))
        console.print(table)

        while True:
            prompt = f"[?] Proceed with all {len(prioritized_info)} files? ([Y]es / [N]o / Enter a number to analyze less): "
            choice = input(prompt).strip().lower()

            if choice in ("y", "yes", ""):
                break
            elif choice in ("n", "no"):
                console.print("[yellow]Analysis aborted by user.[/yellow]")
                sys.exit(0)
            elif choice.isdigit():
                num_to_analyze = int(choice)
                if 0 < num_to_analyze <= len(prioritized_info):
                    prioritized_info = prioritized_info[:num_to_analyze]
                    console.print(f"[dim]Proceeding with the top {num_to_analyze} file(s).[/dim]")
                    break
                else:
                    console.print(f"[red]Please enter a number between 1 and {len(prioritized_info)}.[/red]")
            else:
                console.print("[red]Invalid input. Please enter 'y', 'n', or a number.[/red]")

        prioritized_filenames = {item["file_name"] for item in prioritized_info if "file_name" in item}
        files_to_analyze = [p for p in files if p.name in prioritized_filenames]

    # Check if deep dive stage was already completed
    deep_dive_checkpoint = None
    if review_state:
        deep_dive_checkpoint = next(
            (cp for cp in review_state.checkpoints if cp.stage == "deep_dive"), None
        )
    
    if deep_dive_checkpoint and review_state.findings:
        console.print("[dim]✓ Deep dive stage already completed, loading findings from checkpoint...[/dim]")
        # Convert stored findings (dicts) back to Finding objects
        findings = [
            Finding.from_dict(
                f, 
                f.get("file_path", ""), 
                f.get("relevance", "MEDIUM")
            ) for f in review_state.findings
        ]
        # Restore optional fields
        for i, f in enumerate(findings):
            if i < len(review_state.findings):
                stored = review_state.findings[i]
                if "line_number" in stored:
                    f.line_number = stored.get("line_number")
                if "annotated_snippet" in stored:
                    f.annotated_snippet = stored.get("annotated_snippet")
    else:
        findings = analyzer.run_deep_dive_stage(
            files_to_analyze, question, args.verbose, args.debug, args.threshold
        )
        
        # Save checkpoint after deep dive
        if review_state and context:
            context.update_findings(review_state.review_id, findings)
            # Update files_analyzed in review state
            state = context.load_review(review_state.review_id)
            state.files_analyzed = [str(f) for f in files_to_analyze]
            context.save_review(state)
            context.add_checkpoint(
                review_state.review_id,
                "deep_dive",
                {"findings_count": len(findings)},
                files_analyzed=[str(f) for f in files_to_analyze],
                findings_count=len(findings)
            )

    impact_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(key=lambda f: impact_order.get(f.impact, 0), reverse=True)

    # Check if synthesis stage was already completed
    synthesis_checkpoint = None
    if review_state:
        synthesis_checkpoint = next(
            (cp for cp in review_state.checkpoints if cp.stage == "synthesis"), None
        )
    
    if synthesis_checkpoint and review_state.synthesis:
        console.print("[dim]✓ Synthesis stage already completed, loading from checkpoint...[/dim]")
        synthesis = review_state.synthesis
    else:
        synthesis = analyzer.run_synthesis_stage(findings, question)
        
        # Save checkpoint after synthesis
        if review_state and context:
            context.update_synthesis(review_state.review_id, synthesis)
            context.add_checkpoint(
                review_state.review_id,
                "synthesis",
                {"synthesis_length": len(synthesis)},
                findings_count=len(findings)
            )

    report = AnalysisReport(
        repo_path=str(repo_path),
        question=question,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        file_count=len(files_to_analyze),
        insights=findings,
        synthesis=synthesis,
    )

    # Curate top findings for actions
    top_findings_for_action = []
    processed_files = set()
    if findings:
        for finding in findings:
            if len(top_findings_for_action) >= args.top_n:
                break
            if finding.file_path not in processed_files:
                top_findings_for_action.append(finding)
                processed_files.add(finding.file_path)

    if args.annotate_code and top_findings_for_action:
        analyzer.run_annotation_stage(top_findings_for_action, args.debug)

    out = OutputManager(console)
    if "console" in args.format:
        out.display_console_summary(report)

    file_formats = [f for f in args.format if f != "console"]
    if file_formats:
        out.save_reports(report, file_formats, args.output)

    if args.generate_payloads and top_findings_for_action:
        analyzer.run_payload_generation_stage(top_findings_for_action, args.debug)

    # Code optimization stage (ONLY runs if --optimize flag is set)
    improvements = {}
    if args.optimize:
        focus_areas = args.focus or []
        improvements = analyzer.run_code_improvement_stage(
            files_to_analyze, focus_areas, args.debug
        )
        
        # Display improvements in console
        if improvements:
            out.display_code_improvements(improvements)
            
            # Save improvements report
            if args.output:
                improvement_output = Path(args.output).with_suffix(
                    ".optimization.md"
                )
                out.save_improvement_report(improvements, improvement_output)
            
            # Generate and write optimized files
            if args.optimize_output:
                optimized_code = analyzer.generate_optimized_files(
                    improvements, files_to_analyze, args.debug
                )
                if optimized_code:
                    out.write_optimized_files(
                        optimized_code,
                        Path(args.optimize_output),
                        repo_path,
                        args.diff
                    )

    # Note: Session log saving removed - use context manager's built-in tracking
    
    # Mark review as completed if review state was enabled
    if review_state and context:
        context.mark_completed(review_state.review_id)
        console.print(f"\n[green]✓ Review state saved: {review_state.review_id}[/green]")
        console.print(f"[dim]Context file: .scrynet_cache/reviews/_{review_state.review_id}_context.md[/dim]")
    
    # Display cost summary
    # Get cost summary from context manager
    if context:
        cost_summary = context.get_cost_summary(analyzer.model)
    else:
        cost_summary = {"api_calls": 0, "cache_hits": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "estimated_cost_usd": 0.0}
    if cost_summary["api_calls"] > 0 or cost_summary["cache_hits"] > 0:
        cost_table = Table(title="API Usage Summary", show_header=True, header_style="bold magenta")
        cost_table.add_column("Metric", style="cyan")
        cost_table.add_column("Value", style="green")
        cost_table.add_row("API Calls", str(cost_summary["api_calls"]))
        cost_table.add_row("Cache Hits", str(cost_summary["cache_hits"]))
        cost_table.add_row("Input Tokens", f"{cost_summary['input_tokens']:,}")
        cost_table.add_row("Output Tokens", f"{cost_summary['output_tokens']:,}")
        cost_table.add_row("Total Tokens", f"{cost_summary['total_tokens']:,}")
        cost_table.add_row("Estimated Cost", f"${cost_summary['estimated_cost_usd']:.4f}")
        console.print("\n")
        console.print(cost_table)


if __name__ == "__main__":
    main()
