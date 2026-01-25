#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess
import argparse
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import logging
import anthropic
import csv
from enum import Enum
from typing import TypedDict

# Rich console for better UX
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

# Import prioritization support
from lib.common import (
    parse_json_response,
    normalize_finding,
    get_recommendation_text,
    get_line_number,
    handle_api_error,
    APIError,
    FileAnalysisError,
    safe_file_read
)
from lib.prompts import PromptFactory
from lib.deduplication import deduplicate_findings
from lib.cost_tracker import CostTracker
from lib.cost_estimator import estimate_scan_cost
from lib.profile_metadata import list_profiles_by_category, get_all_profiles
from lib.config import get_preset, list_presets, SmartDefaults, TechStackDetector
from lib.tech_detector import EnhancedTechDetector, generate_framework_aware_prioritization_question
from lib.universal_detector import UniversalTechDetector

# --- Constants / Configuration ---
CLAUDE_MODEL = "claude-3-5-haiku-20241022"  # Using Haiku for cost efficiency; can be overridden via --model flag
MAX_WORKERS = 4
MAX_RETRIES = 3
CHUNK_SIZE = 2000  # lines per file chunk
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB per file safeguard

SUPPORTED_EXTENSIONS = {
    '.go': 'go', '.py': 'python', '.java': 'java', '.js': 'javascript',
    '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.php': 'php', '.html': 'html', '.htm': 'html', '.css': 'css', '.sql': 'sql',
}


class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class Finding(TypedDict, total=False):
    severity: str
    file: str
    line_number: int
    category: str
    title: str
    source: str


# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinates scrynet static scan, Claude AI analysis, and threat modeling."""

    def __init__(self, repo_path: Path, scanner_bin: Path, parallel: bool, debug: bool,
                 severity: Optional[str], profiles: str, static_rules: Optional[str],
                 threat_model: bool, verbose: bool, model: Optional[str] = None,
                 prioritize: bool = False, prioritize_top: int = 15, question: Optional[str] = None,
                 generate_payloads: bool = False, annotate_code: bool = False, top_n: int = 5,
                 export_formats: Optional[List[str]] = None, output_dir: Optional[Path] = None,
                 deduplicate: bool = False, dedupe_threshold: float = 0.7, dedupe_strategy: str = "keep_highest_severity",
                 show_quick_wins: bool = False):
        self.repo_path = repo_path.resolve()
        self.scanner_bin = scanner_bin.resolve()
        self.parallel = parallel
        self.debug = debug
        self.severity = severity.upper() if severity else None
        self.profiles = [p.strip() for p in profiles.split(',')]
        self.static_rules = static_rules
        self.threat_model = threat_model
        self.verbose = verbose
        self.model = model or CLAUDE_MODEL
        self.prioritize = prioritize
        self.prioritize_top = prioritize_top
        self.question = question or "find security vulnerabilities"
        self.generate_payloads = generate_payloads
        self.annotate_code = annotate_code
        self.top_n = top_n
        self.export_formats = export_formats or ['json', 'csv', 'markdown']
        self.deduplicate = deduplicate
        self.dedupe_threshold = dedupe_threshold
        self.dedupe_strategy = dedupe_strategy
        self.show_quick_wins = show_quick_wins
        
        # Initialize cost tracker
        self.cost_tracker = CostTracker()
        
        # Rich console for better UX
        self.console = Console()

        self.api_key = os.getenv("CLAUDE_API_KEY")
        if not self.api_key:
            logger.error("CLAUDE_API_KEY environment variable not set.")
            sys.exit(1)

        sanitized_repo_name = str(repo_path).strip('/').replace('/', '_')
        if output_dir:
            self.output_path = Path(output_dir) / sanitized_repo_name
        else:
            self.output_path = Path("output") / sanitized_repo_name
        os.makedirs(self.output_path, exist_ok=True)
        self.console.print(f"[dim]Outputs will be saved in: {self.output_path}[/dim]")
        if self.severity:
            self.console.print(f"[dim]Filtering for minimum severity: {self.severity}[/dim]")
        self.console.print(f"[dim]Using AI analysis profiles: {self.profiles}[/dim]")

        # Detect application context for smarter analysis using universal detector
        self.enhanced_tech_info = UniversalTechDetector.detect_all(self.repo_path)
        self.app_context = self._build_app_context()
        
        if self.verbose and self.enhanced_tech_info['frameworks']:
            fw_names = [f for f in sorted(self.enhanced_tech_info['frameworks'].keys(), key=lambda x: self.enhanced_tech_info['frameworks'][x], reverse=True)]
            self.console.print(f"[dim]🔍 Detected: {', '.join(fw_names)} ({self.enhanced_tech_info['app_type']})[/dim]")
            if self.enhanced_tech_info['framework_specific_risks']:
                self.console.print(f"[dim]   Framework risks: {len(self.enhanced_tech_info['framework_specific_risks'])} identified[/dim]")
            if self.enhanced_tech_info['security_critical_files']:
                self.console.print(f"[dim]   Critical files: {len(self.enhanced_tech_info['security_critical_files'])} security-sensitive files found[/dim]")

        self.prompt_templates = self._load_prompt_templates()
        self.client = anthropic.Anthropic(api_key=self.api_key)

    def _build_app_context(self) -> Dict[str, any]:
        """Build application context for smarter analysis."""
        # Use universal detector (already stored in self.enhanced_tech_info)
        enhanced_info = self.enhanced_tech_info
        
        # Build context string with framework-specific enhancements
        context_str = enhanced_info.get('context_str', '')
        prompt_enhancements = enhanced_info.get('prompt_enhancements', '')
        
        full_context = f"{context_str}\n{prompt_enhancements}".strip()
        
        return {
            **enhanced_info,
            'context_str': full_context
        }

    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load profile-specific AI prompts from prompts/ directory."""
        templates: Dict[str, str] = {}
        profiles_to_load = self.profiles[:]
        if self.threat_model and 'attacker' not in profiles_to_load:
            profiles_to_load.append('attacker')
        
        for profile in profiles_to_load:
            # Try enhanced version first (if it exists)
            enhanced_file = Path("prompts") / f"{profile}_enhanced_profile.txt"
            prompt_file = Path("prompts") / f"{profile}_profile.txt"
            
            # Check from current directory first
            if enhanced_file.is_file():
                prompt_file = enhanced_file
                if self.verbose:
                    self.console.print(f"[dim]   Using enhanced prompt for {profile}[/dim]")
            elif not prompt_file.is_file():
                # Fallback: check if we're in a different directory structure
                script_dir = Path(__file__).parent
                enhanced_file = script_dir / "prompts" / f"{profile}_enhanced_profile.txt"
                prompt_file = script_dir / "prompts" / f"{profile}_profile.txt"
                if enhanced_file.is_file():
                    prompt_file = enhanced_file
            
            if not prompt_file.is_file():
                self.console.print(f"[red]Prompt file not found: {prompt_file}[/red]")
                sys.exit(1)
            
            templates[profile] = prompt_file.read_text(encoding="utf-8")
        
        self.console.print(f"[dim]   (Loaded {len(templates)} prompt templates)[/dim]")
        return templates

    def _meets_severity_threshold(self, finding_severity: str) -> bool:
        """Check if finding meets severity filter threshold."""
        if not self.severity:
            return True
        try:
            finding_level = Severity[finding_severity.upper()].value
            threshold_level = Severity[self.severity].value
            return finding_level <= threshold_level
        except KeyError:
            return False

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON object from model output using regex fallback."""
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {e}")
        return None

    def run_static_scanner(self) -> List[Finding]:
        """Invoke scrynet scanner binary and parse JSON results."""
        self.console.print("\n[bold cyan]⚡ Stage 0: Static Scanner[/bold cyan]")
        self.console.print("[dim]Running fast static analysis...[/dim]")
        
        cmd = [str(self.scanner_bin), "--dir", str(self.repo_path), "--output", "json"]
        if self.severity:
            cmd.extend(["--severity", self.severity])
        if self.static_rules:
            cmd.extend(["--rules", self.static_rules])
        if self.verbose:
            cmd.append("--verbose")
        
        with self.console.status("[bold cyan]🔍 Scanning repository...[/bold cyan]", spinner="dots"):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            except subprocess.TimeoutExpired:
                self.console.print("[red]scrynet scanner timed out after 5 minutes[/red]")
                return []
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]scrynet scanner failed: {e.stderr}[/red]")
                return []
            except Exception as e:
                self.console.print(f"[red]Unexpected error running scanner: {e}[/red]")
                return []
        out = proc.stdout
        start = out.find('[')
        end = out.rfind(']') + 1
        if start < 0 or end <= start:
            return []
        try:
            findings = json.loads(out[start:end])
            self.console.print(f"[green]✓[/green] Static scanner found {len(findings)} issues")
            return findings
        except json.JSONDecodeError:
            return []

    def _get_files_to_scan(self) -> List[Path]:
        """List source files, excluding dependency/build dirs."""
        skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
        files: List[Path] = []
        for p in self.repo_path.rglob('*'):
            if (p.is_file() and
                p.suffix.lower() in SUPPORTED_EXTENSIONS and
                not any(skip_dir in p.parts for skip_dir in skip_dirs)):
                if p.stat().st_size <= MAX_FILE_SIZE:
                    files.append(p)
                else:
                    logger.warning(f"Skipping {p}, file exceeds {MAX_FILE_SIZE} bytes.")
        return sorted(files)

    def _chunk_file(self, file_path: Path) -> List[str]:
        """Split large file into chunks to avoid token limits."""
        with file_path.open(encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if len(lines) <= CHUNK_SIZE:
            return ["".join(lines)]
        return [
            "".join(lines[i:i+CHUNK_SIZE])
            for i in range(0, len(lines), CHUNK_SIZE)
        ]

    def _analyze_file_with_claude(self, file_path: Path, profile: str) -> Optional[Dict[str, Any]]:
        """Send file contents (chunked if needed) to Claude and parse JSON response."""
        client = self.client
        code_chunks = self._chunk_file(file_path)
        language = SUPPORTED_EXTENSIONS.get(file_path.suffix.lower(), "text")
        for chunk in code_chunks:
            if not chunk.strip():
                continue
            try:
                # Try to format with app_context (for enhanced prompts)
                prompt = self.prompt_templates[profile].format(
                    file_path=file_path,
                    language=language,
                    code=chunk,
                    app_context=self.app_context.get('context_str', 'Unknown')
                )
            except KeyError as e:
                # Fallback for legacy prompts without app_context
                try:
                    prompt = self.prompt_templates[profile].format(
                        file_path=file_path,
                        language=language,
                        code=chunk
                    )
                except KeyError as e2:
                    logger.error(f"Prompt template for {profile} missing placeholder: {e2}")
                return None
            for attempt in range(MAX_RETRIES):
                try:
                    resp = client.messages.create(
                        model=self.model,
                        max_tokens=3000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    # Track cost for this API call (including retries - each attempt costs)
                    self.cost_tracker.record_from_response(
                        response=resp,
                        stage="analysis",
                        model=self.model,
                        profile=profile,
                        file=str(file_path)
                    )
                    parsed = self._extract_json(resp.content[0].text.strip())
                    if parsed:
                        return parsed
                except anthropic.APIStatusError as e:
                    # Track failed attempts too (if they consume tokens before failing)
                    # API errors may charge for input tokens before failing
                    if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                        wait_time = 2 ** (attempt + 1)
                        logger.warning(f"Claude API overloaded for {file_path}. Retrying in {wait_time}s... (attempt {attempt + 1}/{MAX_RETRIES})")
                        # Estimate tokens for failed call (prompt was sent)
                        estimated_input = len(prompt.split()) * 1.3  # Rough estimate
                        self.cost_tracker.record_call(
                            stage="analysis",
                            model=self.model,
                            input_tokens=int(estimated_input),
                            output_tokens=0,
                            profile=profile,
                            file=str(file_path)
                        )
                        time.sleep(wait_time)
                    else:
                        raise e
                except Exception as e:
                    logger.error(f"Unexpected error analyzing {file_path}: {e}")
                    return None
        return None

    def _print_live_claude_summary(self, file_path: Path, result: Dict[str, Any], profile: str) -> None:
        """Render inline summary of model findings for a single file with Rich formatting."""
        if not self.verbose:
            return
        
        risk = result.get("overall_risk", "N/A")
        findings_key = next((key for key in result if key.endswith("_findings")), None)
        findings = result.get(findings_key, [])
        
        # Color code risk level by severity
        risk_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan"
        }.get(risk.upper(), "white")
        
        self.console.print(f"\n[bold cyan]📄 {file_path.name}[/bold cyan] [dim]({profile})[/dim]")
        self.console.print(f"  Risk: [{risk_color}]{risk}[/{risk_color}] | Findings: {len(findings)}")
        
        if findings:
            for f in findings[:5]:  # Show top 5
                sev = f.get('severity', 'UNK')
                title = f.get('title', 'Unknown Issue')
                line = f.get('line_number', '?')
                
                # Display exploitability score if available
                exploit_score = f.get('exploitability_score', '')
                exploit_str = f" [dim]⚡{exploit_score}/10[/dim]" if exploit_score else ""
                
                # Color code by severity
                sev_color = {
                    "CRITICAL": "bold red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "cyan"
                }.get(sev.upper(), "white")
                
                self.console.print(f"    [{sev_color}]●[/{sev_color}] {title}{exploit_str} [dim](Line {line})[/dim]")
            if len(findings) > 5:
                self.console.print(f"    [dim]... and {len(findings) - 5} more[/dim]")
    
    def run_prioritization_stage(self, all_files: List[Path]) -> Optional[List[Path]]:
        """Prioritize files using AI - returns list of prioritized file paths."""
        if not self.prioritize or not all_files:
            return None
        
        self.console.print("\n[bold cyan]🎯 Stage 1: Prioritization[/bold cyan]")
        self.console.print(f"[dim]Analyzing {len(all_files)} files to identify top {self.prioritize_top} most relevant...[/dim]")
        
        # Enhance question with framework-specific context
        enhanced_question = generate_framework_aware_prioritization_question(
            self.question,
            self.enhanced_tech_info
        )
        
        if self.verbose and enhanced_question != self.question:
            self.console.print(f"[dim]💡 Enhanced question with framework context[/dim]")
        
        try:
            prompt = PromptFactory.prioritization(all_files, enhanced_question, self.prioritize_top)
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            # Track cost for prioritization
            self.cost_tracker.record_from_response(
                response=response,
                stage="prioritization",
                model=self.model
            )
            raw = response.content[0].text.strip()
            
            if self.debug:
                self.console.print(Panel(raw, title="[dim]RAW API RESPONSE (Prioritization)[/dim]", border_style="dim"))
            
            parsed = parse_json_response(raw)
            if parsed and isinstance(parsed.get("prioritized_files"), list):
                prioritized_info = parsed["prioritized_files"]
                
                # Create table showing prioritized files
                table = Table(title="[bold green]AI-Prioritized Files[/bold green]", show_header=True, header_style="bold magenta")
                table.add_column("File Name", style="cyan", width=40)
                table.add_column("Reason for Selection", style="magenta")
                
                for item in prioritized_info:
                    table.add_row(
                        item.get("file_name", "N/A"),
                        item.get("reason", "N/A")
                    )
                
                self.console.print(table)
                
                # Interactive prompt
                while True:
                    prompt_text = f"\n[?] Proceed with all {len(prioritized_info)} files? ([Y]es / [N]o / Enter a number to analyze less): "
                    choice = input(prompt_text).strip().lower()
                    
                    if choice in ("y", "yes", ""):
                        break
                    elif choice in ("n", "no"):
                        self.console.print("[yellow]Analysis aborted by user.[/yellow]")
                        sys.exit(0)
                    elif choice.isdigit():
                        num_to_analyze = int(choice)
                        if 0 < num_to_analyze <= len(prioritized_info):
                            prioritized_info = prioritized_info[:num_to_analyze]
                            self.console.print(f"[dim]Proceeding with the top {num_to_analyze} file(s).[/dim]")
                            break
                        else:
                            self.console.print(f"[red]Please enter a number between 1 and {len(prioritized_info)}.[/red]")
                    else:
                        self.console.print("[red]Invalid input. Please enter 'y', 'n', or a number.[/red]")
                
                # Map file names back to Path objects
                # Use a smarter matching strategy: prefer unique matches, handle duplicates
                prioritized_filenames = {item["file_name"] for item in prioritized_info if "file_name" in item}
                prioritized_paths = []
                matched_names = set()
                
                for filename in prioritized_filenames:
                    matches = [p for p in all_files if p.name == filename]
                    if len(matches) == 1:
                        # Unique match - use it
                        prioritized_paths.append(matches[0])
                        matched_names.add(filename)
                    elif len(matches) > 1:
                        # Multiple matches - prefer the one closest to repo root (shallowest path)
                        # This is a heuristic: usually the most important file is near the root
                        best_match = min(matches, key=lambda p: len(p.parts))
                        prioritized_paths.append(best_match)
                        matched_names.add(filename)
                        if self.verbose:
                            self.console.print(f"[dim]  Note: '{filename}' found in {len(matches)} locations, selected: {best_match.relative_to(self.repo_path)}[/dim]")
                
                # Warn if we couldn't match some files
                unmatched = prioritized_filenames - matched_names
                if unmatched:
                    self.console.print(f"[yellow]Warning: Could not find {len(unmatched)} prioritized file(s): {', '.join(list(unmatched)[:5])}[/yellow]")
                
                self.console.print(f"[green]✓[/green] Selected {len(prioritized_paths)} files for analysis\n")
                return prioritized_paths
            else:
                self.console.print("[yellow]Could not parse prioritization response. Continuing with all files.[/yellow]")
                return None
        except Exception as e:
            self.console.print(f"[red]Error during prioritization: {e}[/red]")
            self.console.print("[yellow]Continuing with all files...[/yellow]")
            return None

    def run_ai_scanner(self) -> List[Finding]:
        """Iterate over files, run AI analysis per profile, collect findings with Rich UI."""
        all_files = self._get_files_to_scan()
        
        # Prioritization stage
        if self.debug:
            logger.debug(f"Prioritization enabled: {self.prioritize}, files: {len(all_files)}")
        files = self.run_prioritization_stage(all_files)
        if files is None:
            if self.prioritize:
                logger.warning(f"Prioritization was enabled but returned None (files: {len(all_files)})")
            files = all_files
        else:
            if self.verbose:
                self.console.print(f"[dim]Using {len(files)} prioritized files (from {len(all_files)} total)[/dim]")
        
        all_ai_findings: List[Finding] = []
        run_mode = "parallel" if self.parallel else "sequential"
        
        self.console.print(f"\n[bold cyan]🔍 Stage 2: Deep Dive Analysis[/bold cyan]")
        self.console.print(f"[dim]Running Claude File-by-File Analysis ({run_mode} mode) on {len(files)} files[/dim]")
        
        file_profiles = [p for p in self.profiles if p != 'attacker']
        for profile in file_profiles:
            self.console.print(f"\n[bold yellow]--- Starting AI Profile: {profile} ---[/bold yellow]")
            profile_findings: List[Finding] = []
            
            def process_and_log(full_result: Optional[Dict[str, Any]], fpath: Path) -> List[Finding]:
                if not full_result:
                    return []
                if self.debug or self.verbose:
                    self._print_live_claude_summary(fpath, full_result, profile)
                findings_key = next((key for key in full_result if key.endswith("_findings")), None)
                original_findings = full_result.get(findings_key, [])
                processed: List[Finding] = []
                for item in original_findings:
                    if self._meets_severity_threshold(item.get("severity", "")):
                        # Normalize finding fields for consistency
                        normalized = normalize_finding(item, file_path=fpath, source=f'claude-{profile}')
                        processed.append(normalized)
                return processed
            
            # Use Rich progress bar with enhanced colors and spinners
            with Progress(
                SpinnerColumn(spinner_name="dots", style="cyan"),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(bar_width=None, style="cyan", complete_style="bold cyan", finished_style="bold green"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=self.console,
                transient=False,
            ) as progress:
                task = progress.add_task(f"[bold cyan]🔍 Analyzing {len(files)} files ({profile})...[/bold cyan]", total=len(files))
                
                for i, fpath in enumerate(files, 1):
                    file_display = fpath.name if len(fpath.name) <= 40 else fpath.name[:37] + "..."
                    progress.update(
                        task,
                        description=f"[bold cyan]⚡ Processing {i}/{len(files)}: [yellow]{file_display}[/yellow]...",
                        refresh=True
                    )
                    
                    if self.verbose:
                        self.console.print(f"[dim]  [{i}/{len(files)}] Analyzing {file_display}...[/dim]")
                    
                    try:
                        full_result = self._analyze_file_with_claude(fpath, profile)
                        profile_findings.extend(process_and_log(full_result, fpath))
                        if not self.parallel:
                            time.sleep(0.3)  # Small delay to avoid rate limits
                    except KeyboardInterrupt:
                        self.console.print("\n[yellow]Analysis interrupted by user[/yellow]")
                        raise
                    except Exception as e:
                        self.console.print(f"[red]Error analyzing {fpath}: {e}[/red]")
                        if self.debug:
                            import traceback
                            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
                    
                    progress.advance(task)
            
            all_ai_findings.extend(profile_findings)
            self.console.print(f"[green]✓[/green] Completed {profile} profile: Found {len(profile_findings)} issues (after filtering)")
        
        return all_ai_findings

    def run_threat_model(self) -> None:
        """Aggregate full repo context, run attacker-perspective threat model via Claude."""
        self.console.print("\n[bold cyan]🎯 Stage 4: Threat Modeling[/bold cyan]")
        self.console.print("[dim]Running attacker-perspective threat model...[/dim]")
        files = self._get_files_to_scan()
        full_context = "".join(
            f"--- FILE: {fpath} ---\n{fpath.read_text(encoding='utf-8', errors='replace')}\n\n"
            for fpath in files
        )
        if not full_context:
            self.console.print("[yellow]No files found for threat model.[/yellow]")
            return
        try:
            prompt = self.prompt_templates['attacker'].format(code=full_context)
        except KeyError as e:
            self.console.print(f"[red]Attacker template missing placeholder: {e}[/red]")
            return
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.client.messages.create(
                    model=self.model,
                    max_tokens=4000,
                    messages=[{"role": "user", "content": prompt}]
                )
                # Track cost for threat modeling
                self.cost_tracker.record_from_response(
                    response=resp,
                    stage="threat_modeling",
                    model=self.model
                )
                parsed = self._extract_json(resp.content[0].text.strip())
                if parsed:
                    report_file = self.output_path / "threat_model_report.json"
                    with open(report_file, "w", encoding="utf-8") as f:
                        json.dump(parsed, f, indent=2)
                    self.console.print(f"[green]✓[/green] Threat model report written to {report_file}")
                    return
                else:
                    self.console.print("[red]Claude did not return valid JSON for threat model[/red]")
                    return
            except anthropic.APIStatusError as e:
                if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                    wait_time = 20
                    self.console.print(f"[yellow]Claude API overloaded for threat model. Retrying in {wait_time}s...[/yellow]")
                    time.sleep(wait_time)
                else:
                    self.console.print(f"[red]Threat model generation failed: {e}[/red]")
                    return
            except Exception as e:
                self.console.print(f"[red]Threat model error: {e}[/red]")
                return
        self.console.print("[red]All retries failed for threat model generation[/red]")
    
    def _generate_html_report(self, findings: List[Dict[str, Any]], output_file: Path) -> None:
        """Generate an HTML report with detailed findings."""
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCRYNET Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }}
        .stat-card.critical {{ border-left-color: #f44336; }}
        .stat-card.high {{ border-left-color: #ff9800; }}
        .stat-card.medium {{ border-left-color: #ffc107; }}
        .stat-card.low {{ border-left-color: #2196F3; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .severity {{ padding: 4px 8px; border-radius: 3px; font-weight: 600; font-size: 0.85em; }}
        .severity.CRITICAL {{ background: #ffebee; color: #c62828; }}
        .severity.HIGH {{ background: #fff3e0; color: #e65100; }}
        .severity.MEDIUM {{ background: #fffde7; color: #f57f17; }}
        .severity.LOW {{ background: #e3f2fd; color: #1565c0; }}
        .file-path {{ font-family: 'Monaco', 'Courier New', monospace; font-size: 0.9em; color: #666; }}
        .line-num {{ color: #4CAF50; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SCRYNET Security Report</h1>
        <p><strong>Repository:</strong> {self.repo_path}</p>
        <p><strong>Generated:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
"""
        
        # Calculate severity counts
        severity_counts = {}
        for item in findings:
            sev = item.get('severity', 'UNKNOWN').upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(sev, 0)
            html_content += f"""
            <div class="stat-card {sev.lower()}">
                <div style="font-size: 2em; font-weight: bold;">{count}</div>
                <div>{sev} Findings</div>
            </div>
"""
        
        html_content += """
        </div>
        
        <h2>Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Category</th>
                    <th>Title</th>
                    <th>Source</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for item in findings:
            sev = item.get('severity', 'UNKNOWN')
            file_path = item.get('file', '')
            line_num = get_line_number(item)
            category = item.get('category', '')
            title = item.get('title', item.get('rule_name', ''))
            source = item.get('source', '')
            recommendation = get_recommendation_text(item)
            # Truncate for table display
            rec_display = recommendation[:150] + "..." if len(recommendation) > 150 else recommendation
            
            html_content += f"""
                <tr>
                    <td><span class="severity {sev}">{sev}</span></td>
                    <td class="file-path">{file_path}</td>
                    <td class="line-num">{line_num}</td>
                    <td>{category}</td>
                    <td>{title}</td>
                    <td>{source}</td>
                    <td>{rec_display}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    def run_payload_generation_stage(self, top_findings: List[Dict[str, Any]]) -> None:
        """Generate Red/Blue team payloads for top findings."""
        if not self.generate_payloads or not top_findings:
            return
        
        self.console.print("\n[bold magenta]💣 Stage 4: Payload Generation[/bold magenta]")
        self.console.print(f"[dim]Generating payloads for top {len(top_findings)} findings...[/dim]")
        
        with Progress(
            SpinnerColumn(spinner_name="dots", style="magenta"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None, style="magenta", complete_style="bold magenta"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task("[magenta]Generating payloads...", total=len(top_findings))
            
            for i, finding in enumerate(top_findings, 1):
                file_path = Path(finding.get('file', ''))
                if not file_path.exists():
                    progress.advance(task)
                    continue
                
                try:
                    snippet = file_path.read_text(encoding="utf-8", errors="ignore")[:500]
                except Exception:
                    snippet = "Could not read snippet."
                
                # Create a simple finding-like object for the prompt
                class FindingObj:
                    def __init__(self, d):
                        self.file_path = str(d.get('file', ''))
                        self.line_number = get_line_number(d)
                        self.finding = d.get('title', d.get('rule_name', 'Unknown'))
                
                finding_obj = FindingObj(finding)
                prompt = PromptFactory.payload_generation(finding_obj, snippet)
                
                # Show finding details in progress
                finding_title = finding.get('title', finding.get('rule_name', 'Unknown'))
                line_num = get_line_number(finding)
                severity = finding.get('severity', 'UNKNOWN')
                progress.update(
                    task,
                    description=f"[magenta]Generating payload {i}/{len(top_findings)}: {finding_title} ({file_path.name}:L{line_num}) [{severity}]...",
                    refresh=True
                )
                
                try:
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=2000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    # Track cost for payload generation
                    finding_id = f"{file_path.name}:L{line_num}"
                    self.cost_tracker.record_from_response(
                        response=response,
                        stage="payload_generation",
                        model=self.model,
                        file=str(file_path),
                        finding_id=finding_id
                    )
                    raw = response.content[0].text.strip()
                    
                    if self.debug:
                        self.console.print(Panel(raw, title=f"[dim]RAW API RESPONSE (Payloads for {file_path.name})[/dim]", border_style="dim"))
                    
                    parsed = parse_json_response(raw)
                    if parsed:
                        rt = parsed.get("red_team_payload", {})
                        bt = parsed.get("blue_team_payload", {})
                        
                        # Extract file and line info
                        file_path = finding.get('file', 'Unknown')
                        line_num = get_line_number(finding)
                        finding_title = finding.get('title', finding.get('rule_name', 'Unknown'))
                        severity = finding.get('severity', 'UNKNOWN')
                        # Get recommendation using utility
                        recommendation = get_recommendation_text(finding)
                        
                        # Create detailed header with full context
                        # Show which profiles found this (if deduplicated)
                        profile_info = ""
                        if finding.get('profiles') and len(finding.get('profiles', [])) > 1:
                            profiles_list = [p.replace('claude-', '') for p in finding.get('profiles', [])]
                            profile_info = f" [dim](Found by: {', '.join(profiles_list)})[/dim]"
                        
                        location_info = f"[bold cyan]📍 Location:[/bold cyan] {file_path} [dim](Line {line_num})[/dim]"
                        finding_info = f"[bold yellow]🔍 Finding:[/bold yellow] {finding_title} [dim][{severity}][/dim]{profile_info}"
                        recommendation_info = f"[bold green]💡 Fix/Recommendation:[/bold green] {recommendation}"
                        
                        self.console.print(
                            Panel(
                                f"{location_info}\n"
                                f"{finding_info}\n"
                                f"{recommendation_info}\n\n"
                                f"[bold red]🔴 Red Team Payload[/bold red]\n"
                                f"Payload: [bold]`{rt.get('payload', 'N/A')}`[/bold]\n"
                                f"Explanation: {rt.get('explanation', 'N/A')}\n\n"
                                f"[bold green]🔵 Blue Team Payload[/bold green]\n"
                                f"Payload: [bold]`{bt.get('payload', 'N/A')}`[/bold]\n"
                                f"Explanation: {bt.get('explanation', 'N/A')}",
                                title=f"💣 Payloads for '{finding_title}'",
                                border_style="magenta",
                            )
                        )
                        
                        # Save to file for later reference
                        payload_file = self.output_path / "payloads" / f"payload_{Path(file_path).stem}_L{line_num}.json"
                        payload_file.parent.mkdir(parents=True, exist_ok=True)
                        # Get recommendation using utility
                        recommendation = get_recommendation_text(finding)
                        payload_data = {
                            "file": file_path,
                            "line": line_num,
                            "finding": finding_title,
                            "severity": severity,
                            "recommendation": recommendation,
                            "red_team_payload": rt,
                            "blue_team_payload": bt,
                            "category": finding.get('category', 'N/A'),
                            "impact": finding.get('impact', 'N/A')
                        }
                        with open(payload_file, "w", encoding="utf-8") as f:
                            json.dump(payload_data, f, indent=2)
                        # Show relative path if possible, otherwise absolute
                        try:
                            abs_payload_file = payload_file.resolve()
                            rel_path = abs_payload_file.relative_to(Path.cwd().resolve())
                            self.console.print(f"[dim]  💾 Saved to: {rel_path}[/dim]")
                        except (ValueError, OSError):
                            self.console.print(f"[dim]  💾 Saved to: {payload_file}[/dim]")
                except Exception as e:
                    self.console.print(f"[red]Error generating payloads for {file_path}: {e}[/red]")
                
                progress.advance(task)
                time.sleep(0.5)  # Small delay
    
    def run_annotation_stage(self, top_findings: List[Dict[str, Any]]) -> None:
        """Generate annotated code snippets for top findings."""
        if not self.annotate_code or not top_findings:
            return
        
        self.console.print("\n[bold yellow]📝 Stage 5: Code Annotation[/bold yellow]")
        self.console.print(f"[dim]Generating annotated code snippets for top {len(top_findings)} findings...[/dim]")
        
        with Progress(
            SpinnerColumn(spinner_name="dots", style="yellow"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None, style="yellow", complete_style="bold yellow"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task("[yellow]Annotating code...", total=len(top_findings))
            
            for i, finding in enumerate(top_findings, 1):
                file_path = Path(finding.get('file', ''))
                if not file_path.exists():
                    progress.advance(task)
                    continue
                
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception as e:
                    self.console.print(f"[red]Error reading {file_path}: {e}[/red]")
                    progress.advance(task)
                    continue
                
                # Create a simple finding-like object for the prompt
                class FindingObj:
                    def __init__(self, d):
                        self.file_path = str(d.get('file', ''))
                        self.line_number = get_line_number(d)
                        self.finding = d.get('title', d.get('rule_name', 'Unknown'))
                        self.recommendation = get_recommendation_text(d)
                
                finding_obj = FindingObj(finding)
                prompt = PromptFactory.annotation(finding_obj, content)
                
                # Show finding details in progress
                finding_title = finding.get('title', finding.get('rule_name', 'Unknown'))
                line_num = get_line_number(finding)
                severity = finding.get('severity', 'UNKNOWN')
                progress.update(
                    task,
                    description=f"[cyan]Annotating {i}/{len(top_findings)}: {finding_title} ({file_path.name}:L{line_num}) [{severity}]...",
                    refresh=True
                )
                
                try:
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=2000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    # Track cost for annotation
                    finding_id = f"{file_path.name}:L{line_num}"
                    self.cost_tracker.record_from_response(
                        response=response,
                        stage="annotation",
                        model=self.model,
                        file=str(file_path),
                        finding_id=finding_id
                    )
                    raw = response.content[0].text.strip()
                    
                    if self.debug:
                        self.console.print(Panel(raw, title=f"[dim]RAW API RESPONSE (Annotation for {file_path.name})[/dim]", border_style="dim"))
                    
                    parsed = parse_json_response(raw)
                    if parsed and "annotated_snippet" in parsed:
                        snippet = parsed["annotated_snippet"]
                        
                        # Extract file and line info
                        file_path = finding.get('file', 'Unknown')
                        line_num = get_line_number(finding)
                        finding_title = finding.get('title', finding.get('rule_name', 'Unknown'))
                        severity = finding.get('severity', 'UNKNOWN')
                        recommendation = get_recommendation_text(finding)
                        
                        # Detect language from file extension
                        file_ext = Path(file_path).suffix.lower()
                        language = SUPPORTED_EXTENSIONS.get(file_ext, 'text')
                        
                        # Create detailed header
                        # Show which profiles found this (if deduplicated)
                        profile_info = ""
                        if finding.get('profiles') and len(finding.get('profiles', [])) > 1:
                            profiles_list = [p.replace('claude-', '') for p in finding.get('profiles', [])]
                            profile_info = f" [dim](Found by: {', '.join(profiles_list)})[/dim]"
                        
                        location_info = f"[bold cyan]📍 File:[/bold cyan] {file_path} [dim]| Line: {line_num} | Severity: [{severity}][/dim]"
                        finding_info = f"[bold yellow]🔍 Issue:[/bold yellow] {finding_title}{profile_info}"
                        recommendation_info = f"[bold green]💡 Recommendation:[/bold green] {recommendation}"
                        
                        self.console.print(f"\n{location_info}")
                        self.console.print(f"{finding_info}")
                        self.console.print(f"{recommendation_info}\n")
                        
                        self.console.print(
                            Panel(
                                Syntax(snippet, language, theme="monokai", line_numbers=True, start_line=max(1, int(line_num) - 5) if str(line_num).isdigit() else 1),
                                title=f"📝 Annotated Code Snippet",
                                border_style="yellow",
                            )
                        )
                        self.console.print(f"[green]✓[/green] Annotated code for [yellow]{Path(file_path).name}[/yellow] [dim](Line {line_num})[/dim]\n")
                        
                        # Save to file for later reference
                        annotation_file = self.output_path / "annotations" / f"annotation_{Path(file_path).stem}_L{line_num}.md"
                        annotation_file.parent.mkdir(parents=True, exist_ok=True)
                        annotation_content = f"""# Code Annotation: {finding_title}

**File:** `{file_path}`  
**Line:** {line_num}  
**Severity:** {severity}  
**Category:** {finding.get('category', 'N/A')}  
**Finding:** {finding_title}  
**Impact:** {finding.get('impact', 'N/A')}  
**Recommendation/Fix:** {recommendation}

## Vulnerable Code Context

```{language}
{snippet}
```

## Additional Context

- **Explanation:** {finding.get('explanation', 'N/A')}
- **Vulnerable Code:** `{finding.get('vulnerable_code', 'N/A')}`
"""
                        with open(annotation_file, "w", encoding="utf-8") as f:
                            f.write(annotation_content)
                        # Show relative path if possible, otherwise absolute
                        try:
                            abs_annotation_file = annotation_file.resolve()
                            rel_path = abs_annotation_file.relative_to(Path.cwd().resolve())
                            self.console.print(f"[dim]  💾 Saved to: {rel_path}[/dim]")
                        except (ValueError, OSError):
                            self.console.print(f"[dim]  💾 Saved to: {annotation_file}[/dim]")
                except Exception as e:
                    self.console.print(f"[red]Error annotating {file_path}: {e}[/red]")
                
                progress.advance(task)
                time.sleep(0.5)  # Small delay

    def _display_tech_stack_summary(self) -> None:
        """Display tech stack detection summary in final report."""
        tech = self.enhanced_tech_info
        
        if not tech.get('frameworks'):
            return  # Skip if nothing detected
        
        self.console.print(f"\n[bold cyan]🔍 Tech Stack Analysis[/bold cyan]")
        
        # Sort frameworks by confidence
        frameworks_sorted = sorted(
            tech['frameworks'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        fw_display = ", ".join([f"{name} ({score:.0%})" for name, score in frameworks_sorted[:5]])
        self.console.print(f"  Frameworks: {fw_display}")
        
        if tech.get('languages'):
            self.console.print(f"  Languages: {', '.join(tech['languages'])}")
        
        if tech.get('databases'):
            self.console.print(f"  Databases: {', '.join(tech['databases'])}")
        
        self.console.print(f"  App Type: {tech['app_type']}")
        
        if tech.get('entry_points'):
            self.console.print(f"  Entry Points: {len(tech['entry_points'])} detected")
        
        if tech.get('security_critical_files'):
            self.console.print(f"  Security Files: {len(tech['security_critical_files'])} detected")
        
        if tech.get('framework_specific_risks'):
            top_risks = tech['framework_specific_risks'][:3]
            self.console.print(f"  Top Risks: {', '.join(top_risks)}")
        
        self.console.print(f"  [dim]Full details: {self.output_path / 'tech_stack.json'}[/dim]")
    
    def _display_quick_wins(self, findings: List[Dict[str, Any]]) -> None:
        """Display quick win summary highlighting most exploitable findings."""
        # Filter for high exploitability findings
        exploitable = []
        for f in findings:
            exploit_score = f.get('exploitability_score', 0)
            time_to_exploit = f.get('time_to_exploit', '')
            
            # Consider it a quick win if:
            # - Exploitability score >= 7, OR
            # - Time to exploit mentions "minute" or "instant", OR
            # - Severity is CRITICAL
            is_quick_win = (
                (exploit_score and exploit_score >= 7) or
                (time_to_exploit and ('minute' in time_to_exploit.lower() or 'instant' in time_to_exploit.lower())) or
                (f.get('severity', '').upper() == 'CRITICAL')
            )
            
            if is_quick_win:
                exploitable.append(f)
        
        if not exploitable:
            return
        
        # Sort by exploitability score (highest first)
        exploitable.sort(key=lambda x: x.get('exploitability_score', 0), reverse=True)
        
        # Display quick wins
        self.console.print(f"\n[bold magenta]🎯 Quick Wins[/bold magenta] [dim]({len(exploitable)} highly exploitable findings)[/dim]")
        self.console.print("[dim]These findings have high exploitability scores or fast time-to-exploit:[/dim]\n")
        
        for i, f in enumerate(exploitable[:10], 1):  # Show top 10
            file_name = Path(f.get('file', '')).name
            line_num = get_line_number(f)
            title = f.get('title', 'Unknown')
            severity = f.get('severity', 'UNKNOWN')
            exploit_score = f.get('exploitability_score', '?')
            time_to_exploit = f.get('time_to_exploit', 'Unknown')
            
            # Color by severity
            sev_color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan"
            }.get(severity.upper(), "white")
            
            # Format exploit info
            exploit_info = f"⚡{exploit_score}/10" if exploit_score != '?' else ""
            time_info = f"🕐{time_to_exploit}" if time_to_exploit != 'Unknown' else ""
            meta = " ".join([exploit_info, time_info]).strip()
            
            self.console.print(
                f"  [{sev_color}]{i}.[/{sev_color}] [{sev_color}]{title}[/{sev_color}] "
                f"[dim]({file_name}:L{line_num})[/dim] "
                f"[dim]{meta}[/dim]"
            )
            
            # Show attack scenario if available
            attack_scenario = f.get('attack_scenario', '')
            if attack_scenario and isinstance(attack_scenario, str):
                # Truncate long scenarios
                scenario_display = attack_scenario[:100] + "..." if len(attack_scenario) > 100 else attack_scenario
                self.console.print(f"     [dim]→ {scenario_display}[/dim]")
        
        if len(exploitable) > 10:
            self.console.print(f"\n[dim]... and {len(exploitable) - 10} more exploitable findings[/dim]")

    def estimate_cost(self) -> Dict[str, Any]:
        """Estimate cost before running the scan."""
        all_files = self._get_files_to_scan()
        return estimate_scan_cost(
            files=all_files,
            model=self.model,
            profiles=self.profiles,
            prioritize=self.prioritize,
            prioritize_top=self.prioritize_top,
            generate_payloads=self.generate_payloads,
            annotate_code=self.annotate_code,
            top_n=self.top_n,
            threat_model=self.threat_model
        )

    def run(self) -> None:
        """Execute static scan, AI analysis, merge, and export findings."""
        # Save tech stack detection results
        tech_stack_file = self.output_path / "tech_stack.json"
        with open(tech_stack_file, "w", encoding="utf-8") as f:
            # Convert sets to lists for JSON serialization
            tech_data = {k: list(v) if isinstance(v, set) else v for k, v in self.enhanced_tech_info.items()}
            json.dump(tech_data, f, indent=2)
        if self.verbose:
            self.console.print(f"[dim]Tech stack detection saved to {tech_stack_file}[/dim]")
        
        static_findings = self.run_static_scanner()
        for finding in static_findings:
            finding['source'] = 'scrynet'
        static_output_file = self.output_path / "static_findings.json"
        with open(static_output_file, "w", encoding="utf-8") as f:
            json.dump(static_findings, f, indent=2)
        self.console.print(f"[dim]{len(static_findings)} static findings written to {static_output_file}[/dim]")

        ai_findings = self.run_ai_scanner()
        ai_output_file = self.output_path / "ai_findings.json"
        with open(ai_output_file, "w", encoding="utf-8") as f:
            json.dump(ai_findings, f, indent=2)
        self.console.print(f"[dim]{len(ai_findings)} AI findings written to {ai_output_file}[/dim]")

        self.console.print("\n[bold cyan]📊 Stage 3: Merging Results[/bold cyan]")
        if self.deduplicate:
            self.console.print(f"[dim]Merging and deduplicating findings (similarity: {self.dedupe_threshold}, strategy: {self.dedupe_strategy})...[/dim]")
        else:
            self.console.print("[dim]Merging findings (basic deduplication)...[/dim]")
        
        # Basic exact-match deduplication first
        combined: List[Finding] = []
        seen: set[Tuple[Any, ...]] = set()
        for f in static_findings + ai_findings:
            key = (
                Path(f.get('file', '')).as_posix(),
                f.get('category', '').lower().strip(),
                f.get('title', f.get('rule_name', '')).lower().strip(),
                str(get_line_number(f))
            )
            if key in seen:
                continue
            seen.add(key)
            combined.append(f)
        
        # Apply intelligent deduplication if enabled
        deduped_count = 0
        deduplicated_findings = []
        if self.deduplicate and len(self.profiles) > 1:
            original_count = len(combined)
            combined = deduplicate_findings(
                combined,
                similarity_threshold=self.dedupe_threshold,
                merge_strategy=self.dedupe_strategy
            )
            deduped_count = original_count - len(combined)
            if deduped_count > 0:
                # Find which findings were deduplicated (have profiles field)
                deduplicated_findings = [f for f in combined if f.get('profiles') and len(f.get('profiles', [])) > 1]
                self.console.print(f"[green]✓[/green] Deduplicated {deduped_count} similar findings from multiple profiles")
                if self.verbose and deduplicated_findings:
                    self.console.print(f"[dim]   Found {len(deduplicated_findings)} findings detected by multiple profiles[/dim]")

        combined.sort(
            key=lambda x: (
                Severity[x.get("severity", "LOW").upper()].value
                if x.get("severity", "").upper() in Severity.__members__ else 99,
                x.get("file", ""),
                str(x.get("line_number", x.get("line", "")))
            )
        )

        combined_output_file = self.output_path / "combined_findings.json"
        with open(combined_output_file, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)
        self.console.print(f"[green]✓[/green] {len(combined)} combined findings written to {combined_output_file}")

        csv_output_file = self.output_path / "combined_findings.csv"
        with open(csv_output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "File", "Line", "Category", "Title", "Source", "Recommendation", "Impact", "Explanation"])
            for item in combined:
                # Extract fields for CSV export
                recommendation = get_recommendation_text(item)
                line_num = get_line_number(item)
                
                writer.writerow([
                    item.get("severity", ""),
                    item.get("file", ""),
                    line_num,
                    item.get("category", ""),
                    item.get("title", item.get("rule_name", "")),
                    item.get("source", ""),
                    recommendation,
                    item.get("impact", ""),
                    item.get("explanation", "")
                ])
        self.console.print(f"[green]✓[/green] CSV report: {csv_output_file}")

        md_output_file = self.output_path / "combined_findings.md"
        with open(md_output_file, "w", encoding="utf-8") as f:
            f.write("| Severity | File | Line | Category | Title | Source | Recommendation |\n")
            f.write("|----------|------|------|----------|-------|--------|----------------|\n")
            for item in combined:
                recommendation = get_recommendation_text(item)
                # Truncate long recommendations for table
                rec_display = recommendation[:100] + "..." if len(recommendation) > 100 else recommendation
                line_num = get_line_number(item)
                
                f.write(
                    f"| {item.get('severity','')} "
                    f"| `{item.get('file','')}` "
                    f"| {line_num} "
                    f"| {item.get('category','')} "
                    f"| {item.get('title', item.get('rule_name',''))} "
                    f"| {item.get('source','')} "
                    f"| {rec_display} |\n"
                )
        self.console.print(f"[green]✓[/green] Markdown report: {md_output_file}")

        # Generate HTML report if requested
        if self.export_formats and 'html' in self.export_formats:
            html_output_file = self.output_path / "combined_findings.html"
            self._generate_html_report(combined, html_output_file)
            self.console.print(f"[green]✓[/green] HTML report: {html_output_file}")

        # Get top findings for payload generation and annotation
        # Strategy: Group by file so we don't miss findings in important files
        # Use smart top-n if not explicitly set (default is 5)
        effective_top_n = self.top_n
        if self.top_n == 5 and len(combined) > 10:  # Default wasn't changed
            effective_top_n = SmartDefaults.calculate_smart_top_n(len(combined))
            if self.verbose:
                self.console.print(f"[dim]💡 Smart default: Analyzing top {effective_top_n} findings (found {len(combined)} total)[/dim]")
        
        # First, get the top N findings by severity
        top_n_globally = sorted(
            combined,
            key=lambda x: (
                Severity[x.get("severity", "LOW").upper()].value
                if x.get("severity", "").upper() in Severity.__members__ else 99,
            ),
            reverse=True
        )[:effective_top_n]
        
        # Extract unique files from those top findings
        top_files = {f.get('file') for f in top_n_globally if f.get('file')}
        
        # Now get ALL findings from those top files (not just the top N)
        top_findings = [f for f in combined if f.get('file') in top_files]
        
        if self.verbose and len(top_findings) != len(top_n_globally):
            self.console.print(
                f"[dim]💡 Analyzing {len(top_files)} files with {len(top_findings)} total findings "
                f"(expanded from top {effective_top_n} to include all findings in those files)[/dim]"
            )
        
        # Run payload generation if requested
        if self.generate_payloads:
            self.run_payload_generation_stage(top_findings)
        
        # Run code annotation if requested
        if self.annotate_code:
            self.run_annotation_stage(top_findings)

        if self.threat_model:
            self.run_threat_model()
        
        # Final summary
        self.console.print("\n[bold green]✨ Analysis Complete![/bold green]")
        
        # Display tech stack summary
        self._display_tech_stack_summary()
        
        # Calculate breakdowns
        severity_counts = {}
        profile_counts = {}
        for f in combined:
            sev = f.get('severity', 'UNKNOWN').upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            source = f.get('source', 'unknown')
            if source:
                profile_counts[source] = profile_counts.get(source, 0) + 1
        
        # Build summary table
        from rich.table import Table as RichTable
        
        summary_table = RichTable(show_header=False, box=None, padding=(0, 1))
        summary_table.add_column(style="bold cyan")
        summary_table.add_column()
        
        # Total findings with deduplication note
        total_note = ""
        if deduped_count > 0:
            total_note = f" (deduplicated {deduped_count} similar findings)"
        summary_table.add_row("Total Findings:", f"[bold]{len(combined)}[/bold]{total_note}")
        
        # Breakdown by source
        summary_table.add_row("", "")  # Spacer
        summary_table.add_row("[bold]By Source:[/bold]", "")
        for source, count in sorted(profile_counts.items()):
            # Format source display nicely
            if ',' in source:
                # Multiple profiles - format as "profile1 + profile2"
                profiles = [p.strip().replace('claude-', '') for p in source.split(',')]
                source_display = ' + '.join(profiles)
            else:
                source_display = source.replace('claude-', '').replace('scrynet', 'Static Scanner')
            summary_table.add_row(f"  • {source_display}:", str(count))
        
        # Breakdown by severity
        summary_table.add_row("", "")  # Spacer
        summary_table.add_row("[bold]By Severity:[/bold]", "")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in severity_counts:
                count = severity_counts[sev]
                # Color code by severity level
                color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
                summary_table.add_row(f"  • {sev}:", f"[{color}]{count}[/{color}]")
        
        # Deduplication summary
        if deduped_count > 0 and deduplicated_findings:
            summary_table.add_row("", "")  # Spacer
            summary_table.add_row("[bold]Deduplication:[/bold]", f"[green]{len(deduplicated_findings)} findings found by multiple profiles[/green]")
        
        self.console.print(summary_table)
        
        # Show original counts for clarity
        if deduped_count > 0:
            self.console.print(f"[dim]Original counts: Static: {len(static_findings)}, AI: {len(ai_findings)} → Combined: {len(combined)} (after deduplication)[/dim]")
        else:
            self.console.print(f"[dim]Breakdown: Static: {len(static_findings)}, AI: {len(ai_findings)}[/dim]")
        
        # Quick Wins Summary (if enabled)
        if self.show_quick_wins:
            self._display_quick_wins(combined)
        
        # Cost summary
        if self.cost_tracker.calls:
            self.console.print("\n[bold yellow]💰 Cost Summary[/bold yellow]")
            cost_table = RichTable(show_header=False, box=None, padding=(0, 1))
            cost_table.add_column(style="bold cyan")
            cost_table.add_column()
            
            cost_table.add_row("Total API Calls:", f"[bold]{len(self.cost_tracker.calls)}[/bold]")
            cost_table.add_row("Total Input Tokens:", f"{self.cost_tracker.total_input_tokens:,}")
            cost_table.add_row("Total Output Tokens:", f"{self.cost_tracker.total_output_tokens:,}")
            cost_table.add_row("Total Tokens:", f"[bold]{self.cost_tracker.total_tokens:,}[/bold]")
            cost_table.add_row("Estimated Cost:", f"[bold green]${self.cost_tracker.total_cost:.4f}[/bold green]")
            
            # Breakdown by stage
            stage_summary = self.cost_tracker.get_stage_summary()
            if stage_summary:
                cost_table.add_row("", "")  # Spacer
                cost_table.add_row("[bold]By Stage:[/bold]", "")
                for stage, stats in sorted(stage_summary.items()):
                    cost_table.add_row(
                        f"  • {stage.replace('_', ' ').title()}:",
                        f"${stats['cost']:.4f} ({stats['calls']} calls, {stats['total_tokens']:,} tokens)"
                    )
            
            # Breakdown by profile
            profile_summary = self.cost_tracker.get_profile_summary()
            if profile_summary and any(p != "unknown" for p in profile_summary):
                cost_table.add_row("", "")  # Spacer
                cost_table.add_row("[bold]By Profile:[/bold]", "")
                for profile, stats in sorted(profile_summary.items()):
                    if profile != "unknown":
                        cost_table.add_row(
                            f"  • {profile}:",
                            f"${stats['cost']:.4f} ({stats['calls']} calls, {stats['total_tokens']:,} tokens)"
                        )
            
            self.console.print(cost_table)
            
            # Export cost data
            cost_output_file = self.output_path / "cost_tracking.json"
            self.cost_tracker.export_to_json(cost_output_file)
            self.console.print(f"[dim]Cost tracking data saved to: {cost_output_file}[/dim]")
            self.console.print(f"[dim]Note: Actual costs may be slightly higher (failed calls, retries, or accumulated costs)[/dim]")


def _print_preset_list(console: Console) -> None:
    """Print a formatted list of all available presets."""
    console.print("\n[bold]Available Scan Presets[/bold]")
    console.print("=" * 70)
    console.print("\nPresets provide optimized configurations for common scanning scenarios.")
    console.print("Use: --preset <name> to apply a preset configuration.\n")
    
    for preset in list_presets():
        console.print(f"\n[bold cyan]{preset.name}[/bold cyan]")
        console.print(f"  {preset.description}")
        console.print(f"  Profiles: {', '.join(preset.profiles)}")
        console.print(f"  Prioritize: {preset.prioritize} (top {preset.prioritize_top if preset.prioritize else 'N/A'})")
        console.print(f"  Payloads: {preset.generate_payloads}, Annotations: {preset.annotate_code}")
        console.print(f"  Deduplicate: {preset.deduplicate}")
        console.print(f"  Export: {', '.join(preset.export_formats)}")
        
        console.print(f"\n  [dim]Example:[/dim]")
        console.print(f"  [dim]python3 orchestrator.py /path/to/repo ./scanner --preset {preset.name}[/dim]")
    
    console.print("\n[bold]Note:[/bold] Preset flags can be overridden by specifying individual options.\n")


def _print_profile_list(console: Console) -> None:
    """Print a formatted list of all available profiles."""
    console.print("\n[bold]Available AI Profiles[/bold]")
    console.print("=" * 70)
    
    profiles_by_category = list_profiles_by_category()
    
    for category_name in ["security", "compliance", "code_quality"]:
        if category_name not in profiles_by_category:
            continue
            
        category_title = category_name.replace("_", " ").title()
        console.print(f"\n[bold cyan]{category_title}[/bold cyan]")
        console.print("-" * 70)
        
        for profile in profiles_by_category[category_name]:
            default_marker = " (default)" if profile.default else ""
            console.print(f"\n[bold]{profile.display_name}[/bold]{default_marker}")
            console.print(f"  Name: [dim]{profile.name}[/dim]")
            console.print(f"  {profile.description}")
            
            console.print(f"\n  [bold]Use Cases:[/bold]")
            for use_case in profile.use_cases:
                console.print(f"    • {use_case}")
            
            console.print(f"\n  [bold]Focus Areas:[/bold]")
            for focus in profile.focus_areas[:5]:  # Show first 5
                console.print(f"    • {focus}")
            if len(profile.focus_areas) > 5:
                console.print(f"    ... and {len(profile.focus_areas) - 5} more")
            
            console.print(f"\n  [bold]Examples:[/bold]")
            for example in profile.examples:
                console.print(f"    [dim]$[/dim] python3 scrynet.py hybrid ./repo ./scanner {example}")
            console.print()
    
    console.print("\n[bold]Usage Tips:[/bold]")
    console.print("  • Combine multiple profiles: --profile owasp,ctf,code_review")
    console.print("  • Use --prioritize with multiple profiles to save time and cost")
    console.print("  • Default profile is 'owasp' if none specified")
    console.print()


def main() -> None:
    """CLI parser and entrypoint."""
    parser = argparse.ArgumentParser(
        description="Orchestrator for scrynet and Claude scanners.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("repo_path", type=Path, nargs='?', help="Path to repo to scan.")
    parser.add_argument("scanner_bin", type=Path, nargs='?', help="Path to scrynet scanner binary.")
    parser.add_argument("--preset", type=str.lower,
                        choices=['quick', 'ctf', 'ctf-fast', 'security-audit', 'pentest', 'compliance'],
                        help="Use a preset configuration (overrides individual flags). Available: quick, ctf, ctf-fast, security-audit, pentest, compliance. Use --list-presets to see details.")
    parser.add_argument("--profile", type=str.lower, default="owasp",
                        help="Comma-separated list of AI profiles. Available: owasp, ctf, code_review, modern, soc2, pci, compliance, performance, attacker (e.g., 'owasp,ctf' or 'soc2,compliance').")
    parser.add_argument("--static-rules", type=str,
                        help="Comma-separated paths to static rule files for scrynet.")
    parser.add_argument("--severity", type=str.upper,
                        choices=[s.name for s in Severity],
                        help="Minimum severity to report.")
    parser.add_argument("--threat-model", action="store_true",
                        help="Perform repo-level attacker-perspective threat model.")
    parser.add_argument("--parallel", action="store_true",
                        help="Run Claude analysis in parallel.")
    parser.add_argument("--verbose", action="store_true",
                        help="Show progress bars + live results.")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug mode for troubleshooting.")
    parser.add_argument("--model", type=str, default=CLAUDE_MODEL,
                        help=f"Claude model to use (default: {CLAUDE_MODEL})")
    parser.add_argument("--prioritize", action="store_true",
                        help="Enable AI prioritization to select top files for analysis (saves time and cost)")
    parser.add_argument("--prioritize-top", type=int, default=15,
                        help="Number of top files to prioritize (default: 15)")
    parser.add_argument("--question", type=str,
                        help="Analysis question for prioritization (default: 'find security vulnerabilities')")
    parser.add_argument("--generate-payloads", action="store_true",
                        help="Generate Red/Blue team payloads for top findings")
    parser.add_argument("--annotate-code", action="store_true",
                        help="Generate annotated code snippets showing flaws and fixes")
    parser.add_argument("--top-n", type=int, default=5,
                        help="Number of top findings for payload/annotation generation (default: 5)")
    parser.add_argument("--export-format", nargs="*", 
                        choices=['json', 'csv', 'markdown', 'html'],
                        default=['json', 'csv', 'markdown'],
                        help='Report export formats (default: json, csv, markdown)')
    parser.add_argument("--output-dir", type=Path,
                        help='Custom output directory for reports (default: ./output)')
    parser.add_argument("--deduplicate", action="store_true",
                        help="Enable intelligent deduplication of similar findings from multiple profiles")
    parser.add_argument("--dedupe-threshold", type=float, default=0.7,
                        help="Similarity threshold for deduplication (0.0-1.0, default: 0.7)")
    parser.add_argument("--dedupe-strategy", type=str, default="keep_highest_severity",
                        choices=["keep_highest_severity", "keep_first", "merge"],
                        help="Deduplication strategy: keep_highest_severity (default), keep_first, or merge")
    parser.add_argument("--estimate-cost", action="store_true",
                        help="Estimate API costs before running (does not execute scan)")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List all available AI profiles with descriptions and use cases")
    parser.add_argument("--list-presets", action="store_true",
                        help="List all available preset configurations")
    parser.add_argument("--smart-defaults", action="store_true", default=True,
                        help="Enable smart defaults (auto-prioritize large repos, auto-deduplicate multiple profiles) (default: enabled)")
    parser.add_argument("--no-smart-defaults", action="store_true",
                        help="Disable smart defaults (use only explicitly specified options)")
    parser.add_argument("--show-quick-wins", action="store_true",
                        help="Display quick win summary with most exploitable findings (auto-enabled for CTF presets)")
    parser.add_argument("--detect-tech-stack", action="store_true",
                        help="Display detailed tech stack detection and exit (shows frameworks, entry points, security files)")
    args = parser.parse_args()

    console = Console()
    
    # Handle preset listing early (no repo required)
    if args.list_presets:
        _print_preset_list(console)
        sys.exit(0)
    
    # Handle profile listing early (no repo required)
    if args.list_profiles:
        _print_profile_list(console)
        sys.exit(0)
    
    # Handle tech stack detection (requires repo only)
    if args.detect_tech_stack:
        if not args.repo_path:
            console.print("[red]Error: repo_path is required for tech stack detection[/red]")
            sys.exit(1)
        if not args.repo_path.is_dir():
            console.print(f"[red]Error: '{args.repo_path}' is not a directory[/red]")
            sys.exit(1)
        
        console.print("\n[bold cyan]🔍 Tech Stack Detection[/bold cyan]")
        console.print("=" * 70)
        
        tech_info = UniversalTechDetector.detect_all(args.repo_path)
        
        console.print(f"\n[bold]Application Information:[/bold]")
        console.print(f"  Type: {tech_info['app_type']}")
        console.print(f"  Languages: {', '.join(tech_info['languages'])}")
        
        # Show frameworks with confidence scores
        if tech_info['frameworks']:
            fw_list = sorted(tech_info['frameworks'].items(), key=lambda x: x[1], reverse=True)
            fw_display = ', '.join([f"{name} ({score:.0%})" for name, score in fw_list])
            console.print(f"  Frameworks: {fw_display}")
        else:
            console.print(f"  Frameworks: None detected")
        
        if tech_info['databases']:
            console.print(f"  Databases/ORMs: {', '.join(tech_info['databases'])}")
        
        console.print(f"  Containerized: {'Yes' if tech_info['has_docker'] else 'No'}")
        console.print(f"  Has Tests: {'Yes' if tech_info['has_tests'] else 'No'}")
        
        if tech_info['entry_points']:
            console.print(f"\n[bold]Entry Points ({len(tech_info['entry_points'])}):[/bold]")
            for ep in tech_info['entry_points'][:10]:
                console.print(f"  • {ep}")
            if len(tech_info['entry_points']) > 10:
                console.print(f"  ... and {len(tech_info['entry_points']) - 10} more")
        
        if tech_info['security_critical_files']:
            console.print(f"\n[bold]Security-Critical Files ({len(tech_info['security_critical_files'])}):[/bold]")
            for sf in tech_info['security_critical_files'][:10]:
                console.print(f"  • {sf}")
            if len(tech_info['security_critical_files']) > 10:
                console.print(f"  ... and {len(tech_info['security_critical_files']) - 10} more")
        
        if tech_info['framework_specific_risks']:
            console.print(f"\n[bold yellow]⚠️  Framework-Specific Security Risks:[/bold yellow]")
            for risk in tech_info['framework_specific_risks']:
                console.print(f"  • {risk}")
        
        console.print(f"\n[dim]Use this information to guide your security analysis.[/dim]")
        console.print(f"[dim]Run with --question to focus on specific risks.[/dim]\n")
        sys.exit(0)
    
    # Now validate required arguments
    if not args.repo_path:
        console.print("[red]Error: repo_path is required[/red]")
        parser.print_help()
        sys.exit(1)
    if not args.scanner_bin:
        console.print("[red]Error: scanner_bin is required[/red]")
        parser.print_help()
        sys.exit(1)
    
    # Apply preset configuration if specified
    if args.preset:
        preset = get_preset(args.preset)
        if not preset:
            console.print(f"[red]Error: Unknown preset '{args.preset}'[/red]")
            console.print("[dim]Use --list-presets to see available presets[/dim]")
            sys.exit(1)
        
        console.print(f"[bold cyan]📦 Using preset: {preset.name}[/bold cyan]")
        console.print(f"[dim]{preset.description}[/dim]")
        
        # Apply preset values (only if not explicitly overridden)
        preset_dict = preset.to_dict()
        for key, value in preset_dict.items():
            arg_key = key.replace('-', '_')
            # Only apply preset value if user didn't explicitly set it
            if arg_key == 'profiles' and args.profile == "owasp":  # Default wasn't changed
                args.profile = value
            elif not hasattr(args, arg_key) or getattr(args, arg_key) in [None, False, []]:
                setattr(args, arg_key, value)
    
    if not args.repo_path.is_dir():
        console.print(f"[red]Error: '{args.repo_path}' is not a directory[/red]")
        sys.exit(1)
    if not args.scanner_bin.is_file() or not os.access(args.scanner_bin, os.X_OK):
        console.print(f"[red]Error: scanner binary '{args.scanner_bin}' not found or not executable[/red]")
        sys.exit(1)

    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Apply smart defaults (unless disabled)
    if not args.no_smart_defaults and args.smart_defaults:
        # Quick file count for smart defaults
        from pathlib import Path as P
        skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
        quick_files = [
            p for p in args.repo_path.rglob('*')
            if (p.is_file() and
                p.suffix.lower() in SUPPORTED_EXTENSIONS and
                not any(skip_dir in p.parts for skip_dir in skip_dirs))
        ]
        num_files = len(quick_files)
        profiles_list = [p.strip() for p in args.profile.split(',')]
        
        # Auto-prioritize for large repos
        if not args.prioritize and SmartDefaults.should_auto_prioritize(num_files):
            args.prioritize = True
            args.prioritize_top = SmartDefaults.calculate_smart_prioritize_top(num_files)
            console.print(f"[dim]💡 Smart default: Auto-enabled prioritization (top {args.prioritize_top} of {num_files} files)[/dim]")
        
        # Auto-deduplicate with multiple profiles
        if not args.deduplicate and SmartDefaults.should_auto_deduplicate(profiles_list):
            args.deduplicate = True
            console.print(f"[dim]💡 Smart default: Auto-enabled deduplication (multiple profiles detected)[/dim]")
        
        # Auto-add HTML export if payloads/annotations enabled
        if SmartDefaults.should_add_html_export(args.generate_payloads, args.annotate_code):
            if 'html' not in args.export_format:
                args.export_format.append('html')
                console.print(f"[dim]💡 Smart default: Added HTML export (visual features enabled)[/dim]")

    # Handle cost estimation
    if args.estimate_cost:
        orchestrator = Orchestrator(
            repo_path=args.repo_path,
            scanner_bin=args.scanner_bin,
            parallel=args.parallel,
            debug=args.debug,
            severity=args.severity,
            profiles=args.profile,
            static_rules=args.static_rules,
            threat_model=args.threat_model,
            verbose=True,  # Force verbose for estimation
            model=args.model,
            prioritize=args.prioritize,
            prioritize_top=args.prioritize_top,
            question=args.question,
            generate_payloads=args.generate_payloads,
            annotate_code=args.annotate_code,
            top_n=args.top_n,
            export_formats=args.export_format,
            output_dir=args.output_dir,
            deduplicate=args.deduplicate,
            dedupe_threshold=args.dedupe_threshold,
            dedupe_strategy=args.dedupe_strategy,
            show_quick_wins=args.show_quick_wins
        )
        
        console.print("\n[bold yellow]💰 Cost Estimation[/bold yellow]")
        console.print("=" * 60)
        
        estimate = orchestrator.estimate_cost()
        all_files = orchestrator._get_files_to_scan()
        
        console.print(f"\n[bold]Configuration:[/bold]")
        console.print(f"  Target: {args.repo_path}")
        console.print(f"  Model: {estimate['model']}")
        console.print(f"  Profiles: {', '.join(args.profile.split(','))}")
        console.print(f"  Total files: {len(all_files)}")
        if args.prioritize:
            console.print(f"  Prioritization: [green]ENABLED[/green] (top {args.prioritize_top} files)")
            console.print(f"  Files to analyze: {min(args.prioritize_top, len(all_files))} (prioritized)")
        else:
            console.print(f"  Prioritization: [dim]DISABLED[/dim]")
            console.print(f"  Files to analyze: {len(all_files)}")
        if args.generate_payloads:
            console.print(f"  Payload generation: [green]ENABLED[/green] (top {args.top_n} findings)")
        if args.annotate_code:
            console.print(f"  Code annotation: [green]ENABLED[/green] (top {args.top_n} findings)")
        if args.threat_model:
            console.print(f"  Threat modeling: [green]ENABLED[/green]")
        
        console.print(f"\n[bold]Estimated Costs:[/bold]")
        from rich.table import Table as RichTable
        cost_table = RichTable(show_header=False, box=None, padding=(0, 1))
        cost_table.add_column(style="bold cyan")
        cost_table.add_column()
        
        cost_table.add_row("Total API Calls:", f"[bold]{estimate['total_calls']:,}[/bold]")
        cost_table.add_row("Total Input Tokens:", f"{estimate['total_input_tokens']:,.0f}")
        cost_table.add_row("Total Output Tokens:", f"{estimate['total_output_tokens']:,.0f}")
        cost_table.add_row("Total Tokens:", f"[bold]{estimate['total_tokens']:,.0f}[/bold]")
        cost_table.add_row("Estimated Cost:", f"[bold green]${estimate['total_estimated_cost']:.4f}[/bold green]")
        
        # Breakdown by stage
        breakdown = estimate['breakdown_by_stage']
        cost_table.add_row("", "")
        cost_table.add_row("[bold]Breakdown by Stage:[/bold]", "")
        
        # Show main stages (not per-profile)
        for stage in ["prioritization", "analysis", "payload_generation", "annotation", "threat_modeling"]:
            if stage in breakdown:
                stats = breakdown[stage]
                cost_table.add_row(
                    f"  • {stage.replace('_', ' ').title()}:",
                    f"${stats['cost']:.4f} ({stats['calls']} calls, ~{stats['total_tokens']:,.0f} tokens)"
                )
        
        # Show per-profile breakdown for analysis
        if args.prioritize or len(args.profile.split(',')) > 1:
            cost_table.add_row("", "")
            cost_table.add_row("[bold]By Profile:[/bold]", "")
            for key in breakdown:
                if key.startswith("analysis_") and key != "analysis":
                    profile = key.replace("analysis_", "")
                    stats = breakdown[key]
                    cost_table.add_row(
                        f"  • {profile}:",
                        f"${stats['cost']:.4f} (~{stats['calls']} calls)"
                    )
        
        console.print(cost_table)
        
        console.print(f"\n[dim]Note: Estimates are approximate based on file sizes and typical usage patterns.[/dim]")
        console.print(f"[dim]Actual costs may vary based on file complexity and AI response lengths.[/dim]")
        console.print(f"\n[bold]Model Pricing:[/bold]")
        pricing = estimate['model_pricing']
        console.print(f"  Input: ${pricing['input_per_1M']:.2f} per 1M tokens")
        console.print(f"  Output: ${pricing['output_per_1M']:.2f} per 1M tokens")
        console.print(f"\n[yellow]Run without --estimate-cost to execute the scan.[/yellow]\n")
        return

    orchestrator = Orchestrator(
        repo_path=args.repo_path,
        scanner_bin=args.scanner_bin,
        parallel=args.parallel,
        debug=args.debug,
        severity=args.severity,
        profiles=args.profile,
        static_rules=args.static_rules,
        threat_model=args.threat_model,
        verbose=args.verbose,
        model=args.model,
        prioritize=args.prioritize,
        prioritize_top=args.prioritize_top,
        question=args.question,
        generate_payloads=args.generate_payloads,
        annotate_code=args.annotate_code,
        top_n=args.top_n,
        export_formats=args.export_format,
        output_dir=args.output_dir,
        deduplicate=args.deduplicate,
        dedupe_threshold=args.dedupe_threshold,
        dedupe_strategy=args.dedupe_strategy,
        show_quick_wins=args.show_quick_wins
    )
    orchestrator.run()


if __name__ == "__main__":
    main()

