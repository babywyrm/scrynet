#!/usr/bin/env python3
"""
SCRYNET - Unified Security Scanner Entry Point

A unified command-line interface for all SCRYNET scanning modes:
- static: Fast Go-based static analysis
- analyze: AI-powered multi-stage analysis
- ctf: CTF-focused vulnerability discovery
- hybrid: Combines static scanner with AI analysis
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="🔍 SCRYNET - Unified Security Scanner\n\n"
        "Combine fast static analysis with AI-powered contextual security review.\n"
        "Perfect for security audits, CTF challenges, and vulnerability discovery.\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
📚 QUICK START EXAMPLES:

  🚀 Fast Static Scan (No AI, Instant Results):
     python3 scrynet.py static ./myapp --severity HIGH

  🧠 AI-Powered Deep Analysis (Smart Prioritization):
     python3 scrynet.py analyze ./myapp "find SQL injection vulnerabilities" \\
       --prioritize --prioritize-top 20 --verbose

  🎯 CTF Mode (Exploitation-Focused):
     python3 scrynet.py ctf ./ctf-challenge "find all vulnerabilities" \\
       --generate-payloads --top-n 10

  ⚡ Hybrid Mode (Best of Both Worlds):
     python3 scrynet.py hybrid ./myapp ./scanner --profile owasp \\
       --prioritize --prioritize-top 15 \\
       --question "find authentication bypass vulnerabilities" \\
       --generate-payloads --annotate-code --top-n 8 --verbose

💡 PRO TIPS:

  • Use --prioritize for large repos (saves time & API costs)
  • Combine --generate-payloads + --annotate-code for comprehensive reports
  • Use --verbose to see real-time progress with colors and spinners
  • Set --top-n to control how many findings get payloads/annotations

📖 For detailed help on each mode:
   python3 scrynet.py <mode> --help
        """
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Scanning mode')
    
    # Static mode (Go scanner)
    static_parser = subparsers.add_parser(
        'static',
        help='⚡ Static scanner only (fast, no AI)',
        description='Lightning-fast static analysis using the Go scanner binary.\n'
                   'Perfect for quick scans, CI/CD pipelines, and when you need instant results.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚡ STATIC MODE EXAMPLES:

  Quick Scan (All Severities):
    python3 scrynet.py static ./myapp ./scanner

  High/Critical Only:
    python3 scrynet.py static ./myapp ./scanner --severity HIGH

  Custom Rules:
    python3 scrynet.py static ./myapp ./scanner \\
      --rules ./custom-rules.json,./more-rules.json

  JSON Output for Automation:
    python3 scrynet.py static ./myapp ./scanner --output json > results.json
        """
    )
    static_parser.add_argument('repo_path', help='Path to repository to scan')
    static_parser.add_argument('scanner_bin', help='Path to scanner binary', nargs='?', default='./scanner')
    static_parser.add_argument('--rules', help='Comma-separated rule files')
    static_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], help='Minimum severity')
    static_parser.add_argument('--output', choices=['text', 'json', 'markdown'], default='text', help='Output format')
    static_parser.add_argument('--verbose', action='store_true', help='Show remediation advice')
    static_parser.add_argument('--git-diff', action='store_true', help='Scan only changed files')
    static_parser.add_argument('--ignore', help='Comma-separated glob patterns to ignore')
    
    # Analyze mode (smart analyzer)
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='🧠 AI-powered multi-stage analysis',
        description='Advanced AI-powered security analysis with prioritization, deep dive, synthesis, and more.\n'
                   'Best for comprehensive security reviews and detailed vulnerability discovery.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🧠 ANALYZE MODE EXAMPLES:

  Basic AI Analysis:
    python3 scrynet.py analyze ./myapp "find security vulnerabilities"

  Prioritized SQL Injection Hunt:
    python3 scrynet.py analyze ./myapp \\
      "find SQL injection vulnerabilities" \\
      --prioritize-top 20 \\
      --verbose

  Comprehensive Security Review:
    python3 scrynet.py analyze ./myapp \\
      "find authentication and authorization vulnerabilities" \\
      --prioritize-top 25 \\
      --generate-payloads \\
      --annotate-code \\
      --top-n 10 \\
      --verbose

💡 TIP: Use specific questions for better results!
        """
    )
    analyze_parser.add_argument('repo_path', help='Path to repository to analyze')
    analyze_parser.add_argument('question', nargs='?', help='Analysis question')
    # Pass through all smart_analyzer arguments
    analyze_parser.add_argument('--cache-dir', default='.scrynet_cache', help='Cache directory')
    analyze_parser.add_argument('--no-cache', action='store_true', help='Disable cache')
    analyze_parser.add_argument('--include-yaml', action='store_true', help='Include YAML files')
    analyze_parser.add_argument('--include-helm', action='store_true', help='Include Helm templates')
    analyze_parser.add_argument('--max-file-bytes', type=int, default=500_000, help='Max file size')
    analyze_parser.add_argument('--max-files', type=int, default=400, help='Max files to analyze')
    analyze_parser.add_argument('--prioritize-top', type=int, default=15, help='Top N files to prioritize')
    analyze_parser.add_argument('--format', nargs='*', default=['console'], choices=['console', 'html', 'markdown', 'json'])
    analyze_parser.add_argument('--model', default='claude-3-5-haiku-20241022', help='Claude model')
    analyze_parser.add_argument('--max-tokens', type=int, default=4000, help='Max tokens per response')
    analyze_parser.add_argument('--temperature', type=float, default=0.0, help='Sampling temperature')
    analyze_parser.add_argument('--top-n', type=int, default=5, help='Top N findings for payloads/annotations')
    analyze_parser.add_argument('--threshold', choices=['HIGH', 'MEDIUM'], help='Filter findings by relevance')
    analyze_parser.add_argument('--generate-payloads', action='store_true', help='Generate payloads')
    analyze_parser.add_argument('--annotate-code', action='store_true', help='Generate code annotations')
    analyze_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    analyze_parser.add_argument('--debug', action='store_true', help='Debug mode')
    analyze_parser.add_argument('--enable-review-state', action='store_true', help='Enable review state tracking')
    analyze_parser.add_argument('--resume-last', action='store_true', help='Resume last review')
    analyze_parser.add_argument('--resume-review', metavar='ID', help='Resume review by ID')
    analyze_parser.add_argument('--list-reviews', action='store_true', help='List all reviews')
    analyze_parser.add_argument('--cache-info', action='store_true', help='Show cache stats')
    analyze_parser.add_argument('--cache-clear', action='store_true', help='Clear cache')
    analyze_parser.add_argument('--help-examples', action='store_true', help='Show usage examples')
    
    # CTF mode
    ctf_parser = subparsers.add_parser(
        'ctf',
        help='🎯 CTF mode (exploitation-focused)',
        description='CTF-focused vulnerability discovery optimized for quick exploitation.\n'
                   'Perfect for Capture The Flag challenges, bug bounties, and penetration testing.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 CTF MODE EXAMPLES:

  Quick CTF Challenge Scan:
    python3 scrynet.py ctf ./ctf-challenge "find all vulnerabilities" \\
      --generate-payloads \\
      --verbose

  Focused SQL Injection CTF:
    python3 scrynet.py ctf ./ctf-challenge \\
      "find SQL injection vulnerabilities" \\
      --prioritize-top 15 \\
      --generate-payloads \\
      --top-n 10 \\
      --verbose

💡 CTF Mode is optimized for quick vulnerability discovery and exploitation.
        """
    )
    ctf_parser.add_argument('repo_path', help='Path to CTF challenge')
    ctf_parser.add_argument('question', nargs='?', help='Analysis question')
    # Similar args to analyze mode
    ctf_parser.add_argument('--cache-dir', default='.scrynet_cache', help='Cache directory')
    ctf_parser.add_argument('--no-cache', action='store_true', help='Disable cache')
    ctf_parser.add_argument('--max-file-bytes', type=int, default=500_000, help='Max file size')
    ctf_parser.add_argument('--max-files', type=int, default=400, help='Max files to analyze')
    ctf_parser.add_argument('--prioritize-top', type=int, default=15, help='Top N files to prioritize')
    ctf_parser.add_argument('--format', nargs='*', default=['console'], choices=['console', 'html', 'markdown', 'json'])
    ctf_parser.add_argument('--top-n', type=int, default=10, help='Top N findings for payloads')
    ctf_parser.add_argument('--generate-payloads', action='store_true', help='Generate exploitation payloads')
    ctf_parser.add_argument('--annotate-code', action='store_true', help='Generate code annotations')
    ctf_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    ctf_parser.add_argument('--debug', action='store_true', help='Debug mode')
    ctf_parser.add_argument('--enable-review-state', action='store_true', help='Enable review state tracking')
    ctf_parser.add_argument('--resume-last', action='store_true', help='Resume last review')
    
    # Hybrid mode (orchestrator)
    hybrid_parser = subparsers.add_parser(
        'hybrid',
        help='⚡ Hybrid analysis: Static scanner + AI (Recommended)',
        description='Combines fast static scanning with AI-powered contextual analysis.\n'
                   'Best for comprehensive security reviews with prioritization and detailed findings.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 HYBRID MODE EXAMPLES:

  Basic Scan (Quick & Effective):
    python3 scrynet.py hybrid ./myapp ./scanner --profile owasp

  Focused SQL Injection Hunt (Prioritized):
    python3 scrynet.py hybrid ./myapp ./scanner \\
      --profile owasp \\
      --prioritize \\
      --prioritize-top 20 \\
      --question "find SQL injection vulnerabilities in database queries" \\
      --verbose

  Comprehensive Security Audit (Full Features):
    python3 scrynet.py hybrid ./myapp ./scanner \\
      --profile owasp \\
      --prioritize \\
      --prioritize-top 25 \\
      --question "find authentication bypass and broken access control" \\
      --generate-payloads \\
      --annotate-code \\
      --top-n 10 \\
      --export-format json html markdown \\
      --output-dir ./reports \\
      --verbose

💡 UNDERSTANDING THE FLAGS:

  --prioritize-top N    → AI selects top N files to analyze (saves time/cost)
                          Example: --prioritize-top 20 analyzes 20 most relevant files

  --top-n N             → Generate payloads/annotations for top N findings
                          Example: --top-n 10 creates payloads for 10 most critical issues

  --question "..."      → Guides AI prioritization (be specific!)
                          Good: "find SQL injection in user input handling"
                          Bad: "find bugs"
        """
    )
    hybrid_parser.add_argument('repo_path', help='Path to repository to scan')
    hybrid_parser.add_argument('scanner_bin', help='Path to scanner binary', nargs='?', default='./scanner')
    hybrid_parser.add_argument('--profile', default='owasp', help='AI analysis profile (comma-separated)')
    hybrid_parser.add_argument('--static-rules', help='Comma-separated static rule files')
    hybrid_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], help='Minimum severity')
    hybrid_parser.add_argument('--threat-model', action='store_true', help='Perform threat modeling')
    hybrid_parser.add_argument('--parallel', action='store_true', help='Run AI analysis in parallel')
    hybrid_parser.add_argument('--verbose', action='store_true', help='Verbose output with colors and details')
    hybrid_parser.add_argument('--debug', action='store_true', help='Debug mode')
    hybrid_parser.add_argument('--model', help='Claude model to use (default: claude-3-5-haiku-20241022)')
    hybrid_parser.add_argument('--prioritize', action='store_true', help='Enable AI prioritization (recommended for large repos)')
    hybrid_parser.add_argument('--prioritize-top', type=int, default=15, help='Number of top files to prioritize (default: 15)')
    hybrid_parser.add_argument('--question', help='Analysis question for prioritization')
    hybrid_parser.add_argument('--generate-payloads', action='store_true', help='Generate Red/Blue team payloads for top findings')
    hybrid_parser.add_argument('--annotate-code', action='store_true', help='Generate annotated code snippets showing flaws and fixes')
    hybrid_parser.add_argument('--top-n', type=int, default=5, help='Number of top findings for payload/annotation generation (default: 5)')
    hybrid_parser.add_argument('--export-format', nargs='*',
                              choices=['json', 'csv', 'markdown', 'html'],
                              default=['json', 'csv', 'markdown'],
                              help='Report export formats (default: json, csv, markdown)')
    hybrid_parser.add_argument('--output-dir', type=Path,
                              help='Custom output directory for reports (default: ./output)')
    hybrid_parser.add_argument('--deduplicate', action='store_true',
                              help='Enable intelligent deduplication of similar findings from multiple profiles')
    hybrid_parser.add_argument('--dedupe-threshold', type=float, default=0.7,
                              help='Similarity threshold for deduplication (0.0-1.0, default: 0.7)')
    hybrid_parser.add_argument('--dedupe-strategy', type=str, default='keep_highest_severity',
                              choices=['keep_highest_severity', 'keep_first', 'merge'],
                              help='Deduplication strategy: keep_highest_severity (default), keep_first, or merge')
    hybrid_parser.add_argument('--estimate-cost', action='store_true',
                              help='Estimate API costs before running (does not execute scan)')
    hybrid_parser.add_argument('--list-profiles', action='store_true',
                              help='List all available AI profiles with descriptions and use cases')
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    
    # Dispatch to appropriate mode
    if args.mode == 'static':
        # Run Go scanner directly
        import subprocess
        cmd = [args.scanner_bin, '--dir', args.repo_path, '--output', args.output]
        if args.rules:
            cmd.extend(['--rules', args.rules])
        if args.severity:
            cmd.extend(['--severity', args.severity])
        if args.verbose:
            cmd.append('--verbose')
        if args.git_diff:
            cmd.append('--git-diff')
        if args.ignore:
            cmd.extend(['--ignore', args.ignore])
        
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            sys.exit(e.returncode)
        except FileNotFoundError:
            print(f"Error: Scanner binary '{args.scanner_bin}' not found", file=sys.stderr)
            sys.exit(1)
    
    elif args.mode == 'analyze':
        # Import and run smart_analyzer
        from smart_analyzer import main as analyze_main
        # Convert argparse namespace to sys.argv for smart_analyzer
        sys.argv = ['smart_analyzer.py', args.repo_path]
        if args.question:
            sys.argv.append(args.question)
        
        # Add all other arguments
        for key, value in vars(args).items():
            if key in ('mode', 'repo_path', 'question') or value is None:
                continue
            if isinstance(value, bool) and value:
                sys.argv.append(f'--{key.replace("_", "-")}')
            elif not isinstance(value, bool):
                sys.argv.append(f'--{key.replace("_", "-")}')
                if isinstance(value, list):
                    sys.argv.extend(str(v) for v in value)
                else:
                    sys.argv.append(str(value))
        
        analyze_main()
    
    elif args.mode == 'ctf':
        # Import and run ctf_analyzer
        from ctf_analyzer import main as ctf_main
        # Similar conversion for CTF mode
        sys.argv = ['ctf_analyzer.py', args.repo_path]
        if args.question:
            sys.argv.append(args.question)
        
        for key, value in vars(args).items():
            if key in ('mode', 'repo_path', 'question') or value is None:
                continue
            if isinstance(value, bool) and value:
                sys.argv.append(f'--{key.replace("_", "-")}')
            elif not isinstance(value, bool):
                sys.argv.append(f'--{key.replace("_", "-")}')
                if isinstance(value, list):
                    sys.argv.extend(str(v) for v in value)
                else:
                    sys.argv.append(str(value))
        
        ctf_main()
    
    elif args.mode == 'hybrid':
        # Import and run orchestrator
        try:
            from orchestrator import main as hybrid_main
        except ImportError as e:
            print(f"Error: Failed to import orchestrator: {e}", file=sys.stderr)
            print("Make sure all dependencies are installed: pip install -r requirements.txt", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error loading orchestrator: {e}", file=sys.stderr)
            sys.exit(1)
        
        # Build sys.argv for orchestrator
        sys.argv = ['orchestrator.py', args.repo_path, args.scanner_bin]
        
        for key, value in vars(args).items():
            if key in ('mode', 'repo_path', 'scanner_bin') or value is None:
                continue
            if isinstance(value, bool) and value:
                sys.argv.append(f'--{key.replace("_", "-")}')
            elif isinstance(value, list):
                # Handle list arguments like --export-format
                sys.argv.append(f'--{key.replace("_", "-")}')
                sys.argv.extend(str(v) for v in value)
            elif not isinstance(value, bool):
                sys.argv.append(f'--{key.replace("_", "-")}')
                sys.argv.append(str(value))
        
        hybrid_main()


if __name__ == '__main__':
    main()

