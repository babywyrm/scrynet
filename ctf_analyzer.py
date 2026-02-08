#!/usr/bin/env python3
"""
CTF Code Analyzer - Quick vulnerability discovery for Capture The Flag challenges.

Optimized for finding exploitable vulnerabilities, flags, and quick wins.
Reuses the SmartAnalyzer infrastructure but with CTF-focused prompts.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Final, List, Optional

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from lib.common import (
    get_api_key,
    parse_json_response,
    scan_repo_files,
    retry_with_backoff,
    CODE_EXTS,
    YAML_EXTS,
    HELM_EXTS,
    SKIP_DIRS,
)
from lib.models import AnalysisReport, Finding
from lib.output_manager import OutputManager
from lib.ctf_prompts import CTFPromptFactory

# Unified context management library
try:
    from lib.agentsmith_context import ReviewContextManager
    CONTEXT_AVAILABLE = True
except ImportError:
    CONTEXT_AVAILABLE = False

from lib.model_registry import get_default_model, resolve_model, model_cli_help


# ---------- Constants ----------
CLAUDE_MODEL: Final = get_default_model()
DEFAULT_MAX_FILE_BYTES: Final = 500_000
DEFAULT_MAX_FILES: Final = 400


class CTFAnalyzer:
    """CTF-focused analyzer that reuses SmartAnalyzer infrastructure with CTF prompts."""
    
    def __init__(self, console: Console, client: anthropic.Anthropic, context: Optional[ReviewContextManager], *, model: str, default_max_tokens: int, temperature: float, repo_root: Optional[Path] = None, max_retries: int = 3):
        self.console = console
        self.client = client
        self.context = context
        self.model = model
        self.default_max_tokens = default_max_tokens
        self.temperature = temperature
        self.repo_root = repo_root
        self.max_retries = max_retries

    def _call_claude_api(self, prompt: str, max_tokens: int) -> anthropic.types.Message:
        """Make API call with retry logic."""
        @retry_with_backoff(max_retries=self.max_retries, base_delay=1.0, max_delay=60.0)
        def _make_call():
            return self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
            )
        return _make_call()

    def _call_claude(
        self, stage: str, file: Optional[str], prompt: str, max_tokens: int = 4000,
        repo_path: Optional[str] = None
    ) -> Optional[str]:
        """Call Claude API with caching support."""
        if not prompt or len(prompt) > 100_000:
            self.console.print(f"[red]Invalid prompt length: {len(prompt)} bytes (max 100,000)[/red]")
            return None

        # Check cache
        cached = None
        if self.context:
            try:
                cached = self.context.get_cached_response(
                    stage, prompt, file=file, repo_path=repo_path, model=self.model, mode="ctf"
                )
            except Exception:
                pass
        
        if cached:
            self.console.print(f"[dim]Cache hit for {stage} ({file or 'n/a'})[/dim]")
            if self.context:
                self.context.track_cost(0, 0, cached=True)
            return cached.raw_response
        
        try:
            response = self._call_claude_api(prompt, max_tokens)
            if not response or not hasattr(response, 'content'):
                return None
            raw = response.content[0].text if response.content else ""
            
            # Track token usage
            if hasattr(response, 'usage') and response.usage:
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens
            else:
                input_tokens = len(prompt) // 4
                output_tokens = len(raw) // 4
            
            # Save to cache
            if self.context:
                parsed = parse_json_response(raw)
                self.context.save_response(
                    stage, prompt, raw, parsed=parsed,
                    file=file, repo_path=repo_path, model=self.model,
                    input_tokens=input_tokens, output_tokens=output_tokens,
                    mode="ctf"
                )
                self.context.track_cost(input_tokens, output_tokens, cached=False)
            
            return raw
        except Exception as e:
            self.console.print(f"[red]API Error: {e}[/red]")
            return None

    def run_prioritization_stage(
        self, all_files: List[Path], question: str, debug: bool, limit: int
    ) -> Optional[List[Dict[str, str]]]:
        """Prioritize files for CTF analysis."""
        self.console.print("[bold cyan]🎯 CTF Stage 1: Prioritization[/bold cyan]")
        if not all_files:
            return None
        prompt = CTFPromptFactory.prioritization(all_files, question, limit)
        raw = self._call_claude("prioritization", None, prompt, repo_path=str(Path.cwd()))
        if not raw:
            return None
        if debug:
            self.console.print(Panel(raw, title="RAW API RESPONSE (Prioritization)"))
        parsed = parse_json_response(raw)
        if not parsed or "prioritized_files" not in parsed:
            self.console.print("[red]Failed to parse prioritization response[/red]")
            return None
        prioritized = parsed["prioritized_files"]
        self.console.print(f"[green]✓ Prioritized {len(prioritized)} files for CTF analysis[/green]")
        return prioritized

    def run_deep_dive_stage(
        self,
        files: List[Path],
        question: str,
        verbose: bool,
        debug: bool,
        threshold: Optional[str],
    ) -> List[Finding]:
        """Deep dive analysis with CTF focus."""
        self.console.print("\n[bold cyan]🔍 CTF Stage 2: Deep Dive Analysis[/bold cyan]")
        findings: List[Finding] = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task("[yellow]Analyzing files for vulnerabilities...", total=len(files))
            
            for i, file_path in enumerate(files, 1):
                # Truncate filename for display
                file_display = file_path.name
                if len(file_display) > 50:
                    file_display = file_display[:47] + "..."
                
                progress.update(
                    task,
                    description=f"[yellow]Analyzing ({i}/{len(files)}): {file_display}...[/yellow]",
                    refresh=True
                )
                self.console.print(f"[dim]  [{i}/{len(files)}] Analyzing {file_display} for CTF vulnerabilities...[/dim]")
                
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    self.console.print(f"  [red]Error reading {file_path}: {e}[/red]")
                    progress.advance(task)
                    continue
                
                # Choose prompt based on file type
                if file_path.suffix.lower() in YAML_EXTS:
                    prompt = CTFPromptFactory.deep_dive_yaml(file_path, content, question)
                elif file_path.suffix.lower() in HELM_EXTS:
                    prompt = CTFPromptFactory.deep_dive_helm(file_path, content, question)
                else:
                    prompt = CTFPromptFactory.deep_dive(file_path, content, question)
                
                raw = self._call_claude("deep_dive", str(file_path), prompt, repo_path=str(Path(file_path).anchor or Path.cwd()))
                if not raw:
                    progress.advance(task)
                    continue
                
                if debug:
                    self.console.print(Panel(raw, title=f"RAW API RESPONSE ({file_path.name})"))
                
                parsed = parse_json_response(raw)
                if not parsed:
                    progress.advance(task)
                    continue
                
                relevance = parsed.get("relevance", "NONE")
                if threshold and relevance not in ["HIGH", "MEDIUM"]:
                    progress.advance(task)
                    continue
                
                insights = parsed.get("insights", [])
                for insight in insights:
                    finding = Finding.from_dict(insight, str(file_path), relevance)
                    findings.append(finding)
                
                progress.advance(task)
        
        # Sort by impact (CRITICAL first)
        impact_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: (impact_order.get(f.impact, 99), impact_order.get(f.confidence, 99)))
        
        self.console.print(f"\n[green]✓ Found {len(findings)} CTF-relevant findings[/green]")
        return findings

    def run_synthesis_stage(self, findings: List[Finding], question: str, debug: bool) -> str:
        """Generate CTF-focused synthesis."""
        self.console.print("\n[bold cyan]📊 CTF Stage 3: Synthesis & Exploitation Roadmap[/bold cyan]")
        if not findings:
            return "No findings to synthesize."
        
        prompt = CTFPromptFactory.synthesis(findings, question)
        raw = self._call_claude("synthesis", None, prompt, max_tokens=6000)
        if not raw:
            return "Failed to generate synthesis."
        
        if debug:
            self.console.print(Panel(raw, title="RAW API RESPONSE (Synthesis)"))
        
        # Extract markdown from response (might be wrapped in code fences)
        synthesis = raw.strip()
        if synthesis.startswith("```"):
            lines = synthesis.split("\n")
            if lines[0].startswith("```"):
                synthesis = "\n".join(lines[1:])
            if synthesis.endswith("```"):
                synthesis = synthesis[:-3].strip()
        
        return synthesis

    def run_payload_generation(self, findings: List[Finding], debug: bool, top_n: int = 5):
        """Generate CTF exploitation payloads."""
        self.console.print("\n[bold cyan]💣 CTF Stage 4: Payload Generation[/bold cyan]")
        high_impact = [f for f in findings if f.impact in ["CRITICAL", "HIGH"]][:top_n]
        
        if not high_impact:
            self.console.print("[yellow]No high-impact findings for payload generation[/yellow]")
            return
        
        for f in high_impact:
            self.console.print(f"\n[bold]Payload for: {f.finding}[/bold]")
            try:
                snippet = Path(f.file_path).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                snippet = "Could not read snippet."
            prompt = CTFPromptFactory.payload_generation(f, snippet[:500])
            raw = self._call_claude("payload", f.file_path, prompt, repo_path=str(Path(f.file_path).anchor or Path.cwd()))
            if not raw:
                continue
            if debug:
                self.console.print(Panel(raw, title=f"RAW API RESPONSE (Payloads for {Path(f.file_path).name})"))
            parsed = parse_json_response(raw)
            if parsed:
                exploit = parsed.get("exploitation_payload", {})
                alt_payloads = parsed.get("alternative_payloads", [])
                self.console.print(
                    Panel(
                        f"[bold red]Exploitation Payload[/bold red]\n"
                        f"Payload: `{exploit.get('payload','')}`\n"
                        f"Explanation: {exploit.get('explanation','')}\n"
                        f"Expected Result: {exploit.get('expected_result','')}\n\n"
                        + (f"[bold yellow]Alternatives:[/bold yellow]\n" + "\n".join([
                            f"  • {alt.get('payload','')} - {alt.get('use_case','')}"
                            for alt in alt_payloads
                        ]) if alt_payloads else ""),
                        title=f"💣 Exploitation Payloads for '{f.finding}'",
                        border_style="red",
                    )
                )


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CTF analyzer."""
    p = argparse.ArgumentParser(
        description="CTF Code Analyzer - Quick vulnerability discovery for Capture The Flag challenges",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick CTF scan
  python3 ctf__.py /path/to/ctf-challenge "find all vulnerabilities and flags"
  
  # Focused scan with payloads
  python3 ctf__.py /path/to/ctf-challenge "find SQL injection" --top-n 10 --generate-payloads
  
  # Fast scan (fewer files)
  python3 ctf__.py /path/to/ctf-challenge "find flags" --max-files 20 --prioritize-top 5
        """
    )
    p.add_argument("repo_path", help="Path to the CTF challenge repository")
    p.add_argument("question", nargs="?", default="Find all security vulnerabilities, flags, and exploitable weaknesses", 
                   help="Analysis question (default: find vulnerabilities and flags)")
    p.add_argument("--cache-dir", default=".agentsmith_cache", help="Directory for conversation cache")
    p.add_argument("--no-cache", action="store_true", help="Disable cache")
    p.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    p.add_argument("--prioritize-top", type=int, default=10, help="Prioritize top N files for CTF analysis")
    p.add_argument("--model", default=CLAUDE_MODEL, help=model_cli_help())
    p.add_argument("--max-tokens", type=int, default=4000, help="Max tokens per response")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-retries", type=int, default=3)
    p.add_argument("--top-n", type=int, default=5, help="Number of findings for payload generation")
    p.add_argument("--threshold", choices=["HIGH", "MEDIUM"], help="Filter findings below this relevance")
    p.add_argument("--generate-payloads", action="store_true", help="Generate exploitation payloads for high-impact findings")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--debug", action="store_true", help="Print raw API responses")
    p.add_argument("--include-yaml", action="store_true", help="Include YAML files")
    p.add_argument("--include-helm", action="store_true", help="Include Helm templates")
    p.add_argument("--include-exts", nargs="*", help="Only include these file extensions (e.g., .py .java). Applied after scanning.")
    p.add_argument("--ignore-dirs", nargs="*", help="Additional directories to skip (merged with defaults)")
    
    # Cache management
    p.add_argument("--cache-info", action="store_true", help="Show cache statistics and exit")
    p.add_argument("--cache-clear", action="store_true", help="Clear all cache and exit")
    
    return p


def main() -> None:
    args = create_parser().parse_args()
    console = Console()
    
    # Handle cache management commands
    if CONTEXT_AVAILABLE:
        context = ReviewContextManager(args.cache_dir, use_cache=not args.no_cache, enable_cost_tracking=True)
        
        if args.cache_info:
            stats = context.cache_stats()
            console.print(Panel(
                f"[bold]Cache Statistics[/bold]\n"
                f"Cache directory: {stats.get('dir', 'N/A')}\n"
                f"Total entries: {stats.get('files', 0)}\n"
                f"Total size: {stats.get('bytes_mb', 0):.2f} MB ({stats.get('bytes', 0):,} bytes)",
                title="Cache Info",
                border_style="blue"
            ))
            return
        
        if args.cache_clear:
            context.clear_cache()
            console.print("[green]✓ Cache cleared[/green]")
            return
    else:
        context = None
    
    # Validate repo path
    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        console.print(f"[red]Error: Repository path does not exist: {repo_path}[/red]")
        sys.exit(1)
    
    # Scan files
    console.print(f"[bold]🔍 Scanning CTF challenge: {repo_path}[/bold]")
    
    # Prepare skip_dirs (merge with defaults if provided)
    skip_dirs = None
    if args.ignore_dirs:
        skip_dirs = set(args.ignore_dirs)
    
    all_files = scan_repo_files(
        repo_path,
        max_file_bytes=args.max_file_bytes,
        max_files=args.max_files,
        include_yaml=args.include_yaml,
        include_helm=args.include_helm,
        skip_dirs=skip_dirs,
    )
    
    # Filter by extensions if specified (post-scan filtering)
    if args.include_exts:
        allowed_exts = {ext if ext.startswith('.') else f'.{ext}' for ext in args.include_exts}
        all_files = [f for f in all_files if f.suffix.lower() in allowed_exts]
    
    if not all_files:
        console.print("[red]No files found to analyze[/red]")
        sys.exit(1)
    
    console.print(f"[green]✓ Found {len(all_files)} files[/green]")
    
    # Initialize analyzer
    # Initialize AI client (supports both direct Anthropic API and AWS Bedrock)
    from lib.ai_provider import create_client
    client = create_client()
    resolved_model = resolve_model(args.model)
    analyzer = CTFAnalyzer(
        console=console,
        client=client,
        context=context,
        model=resolved_model,
        default_max_tokens=args.max_tokens,
        temperature=args.temperature,
        repo_root=repo_path,
        max_retries=args.max_retries,
    )
    
    # Run analysis stages
    prioritized = analyzer.run_prioritization_stage(
        all_files, args.question, args.debug, args.prioritize_top
    )
    if not prioritized:
        console.print("[red]Prioritization failed[/red]")
        sys.exit(1)
    
    # Get prioritized file paths
    prioritized_files = []
    for item in prioritized:
        file_name = item.get("file_name")
        if file_name:
            file_path = next((f for f in all_files if f.name == file_name), None)
            if file_path:
                prioritized_files.append(file_path)
    
    if not prioritized_files:
        console.print("[yellow]No prioritized files found[/yellow]")
        sys.exit(1)
    
    # Deep dive
    findings = analyzer.run_deep_dive_stage(
        prioritized_files, args.question, args.verbose, args.debug, args.threshold
    )
    
    # Synthesis
    synthesis = analyzer.run_synthesis_stage(findings, args.question, args.debug)
    
    # Payload generation (if requested)
    if args.generate_payloads:
        analyzer.run_payload_generation(findings, args.debug, args.top_n)
    
    # Display results
    console.print("\n" + "="*80)
    console.print("[bold cyan]🎯 CTF Analysis Results[/bold cyan]")
    console.print("="*80)
    
    # Quick wins table
    if findings:
        table = Table(title="🚨 Quick Wins - High Impact Findings", show_header=True, header_style="bold red")
        table.add_column("File", style="cyan", max_width=30)
        table.add_column("Vulnerability", style="yellow", max_width=40)
        table.add_column("Impact", style="red")
        table.add_column("Line", style="dim")
        
        high_impact = [f for f in findings if f.impact in ["CRITICAL", "HIGH"]][:10]
        for f in high_impact:
            file_display = Path(f.file_path).name
            if len(file_display) > 30:
                file_display = file_display[:27] + "..."
            table.add_row(
                file_display,
                f.finding[:37] + "..." if len(f.finding) > 40 else f.finding,
                f.impact,
                str(f.line_number) if f.line_number else "?"
            )
        console.print(table)
    
    # Synthesis
    console.print("\n[bold cyan]📋 Exploitation Roadmap[/bold cyan]")
    console.print(Panel(synthesis, border_style="cyan"))
    
    # Summary
    console.print(f"\n[green]✓ Analysis complete: {len(findings)} findings, {len([f for f in findings if f.impact in ['CRITICAL', 'HIGH']])} high-impact[/green]")
    
    if context:
        cost_summary = context.get_cost_summary(resolved_model)
        total_cost = cost_summary.get("estimated_cost_usd", 0.0)
        api_calls = cost_summary.get("api_calls", 0)
        cache_hits = cost_summary.get("cache_hits", 0)
        if api_calls > 0 or cache_hits > 0:
            console.print(f"[dim]API calls: {api_calls}, Cache hits: {cache_hits}, Total cost: ${total_cost:.4f}[/dim]")


if __name__ == "__main__":
    main()

