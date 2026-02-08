#!/usr/bin/env python3
"""
Agent Smith - Scan Results Summary

Quick command-line summary of scan output.

Usage:
    python3 summarize.py                          # Auto-find latest output
    python3 summarize.py output/tests_test_targets_WebGoat
    python3 summarize.py output/tests_test_targets_WebGoat --top 10
    python3 summarize.py output/tests_test_targets_WebGoat --findings
    python3 summarize.py output/tests_test_targets_WebGoat --cost
"""

import json
import sys
import os
from pathlib import Path
from collections import Counter

# ---------------------------------------------------------------------------
# Color helpers (no dependencies)
# ---------------------------------------------------------------------------
COLORS = {
    "CRITICAL": "\033[1;31m", "HIGH": "\033[0;31m",
    "MEDIUM": "\033[0;33m", "LOW": "\033[0;36m",
    "BOLD": "\033[1m", "DIM": "\033[2m", "RESET": "\033[0m",
    "GREEN": "\033[0;32m", "CYAN": "\033[0;36m", "WHITE": "\033[1;37m",
}

def c(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"

# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def find_output_dir():
    """Find the most recent output directory."""
    output = Path("output")
    if not output.is_dir():
        return None
    dirs = sorted(
        [d for d in output.iterdir() if d.is_dir()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    return dirs[0] if dirs else None

# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------
def print_header(output_dir):
    name = output_dir.name.replace("tests_test_targets_", "").replace("_", "/")
    print(f"\n{c('Agent Smith Scan Summary', 'BOLD')}")
    print(f"{'=' * 55}")
    print(f"  Target:  {c(name, 'WHITE')}")
    ts = output_dir.stat().st_mtime
    from datetime import datetime
    print(f"  Date:    {datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')}")
    print()

def summarize_static(output_dir):
    data = load_json(output_dir / "static_findings.json")
    if not data:
        print(f"  {c('No static findings', 'DIM')}")
        return
    sevs = Counter(f.get("severity", "?") for f in data)
    rules = Counter(f.get("rule_name", "?") for f in data)
    print(f"{c('Static Scanner', 'BOLD')}  ({len(data)} findings, {len(rules)} rules)")
    print(f"  {c('CRITICAL', 'CRITICAL')}: {sevs.get('CRITICAL', 0):>4}   "
          f"{c('HIGH', 'HIGH')}: {sevs.get('HIGH', 0):>4}   "
          f"{c('MEDIUM', 'MEDIUM')}: {sevs.get('MEDIUM', 0):>4}   "
          f"{c('LOW', 'LOW')}: {sevs.get('LOW', 0):>4}")
    print()
    print(f"  {c('Top rules:', 'DIM')}")
    for rule, count in rules.most_common(10):
        print(f"    {count:>4}x  {rule}")
    print()

def summarize_ai(output_dir):
    data = load_json(output_dir / "ai_findings.json")
    if not data:
        print(f"  {c('No AI findings', 'DIM')}")
        return
    sevs = Counter(f.get("severity", "?") for f in data)
    print(f"{c('AI Analysis', 'BOLD')}  ({len(data)} findings)")
    print(f"  {c('CRITICAL', 'CRITICAL')}: {sevs.get('CRITICAL', 0):>4}   "
          f"{c('HIGH', 'HIGH')}: {sevs.get('HIGH', 0):>4}   "
          f"{c('MEDIUM', 'MEDIUM')}: {sevs.get('MEDIUM', 0):>4}   "
          f"{c('LOW', 'LOW')}: {sevs.get('LOW', 0):>4}")
    print()
    print(f"  {c('AI findings:', 'DIM')}")
    for f in data[:10]:
        sev = f.get("severity", "?")
        title = f.get("title", f.get("rule_name", "?"))[:60]
        fpath = f.get("file_path", f.get("file", "?"))
        fname = Path(fpath).name if fpath else "?"
        line = f.get("line", f.get("line_number", ""))
        loc = f"{fname}:{line}" if line else fname
        print(f"    {c(f'[{sev}]', sev):>22}  {title}")
        print(f"    {'':>14}  {c(loc, 'DIM')}")
    if len(data) > 10:
        print(f"    {c(f'... and {len(data) - 10} more', 'DIM')}")
    print()

def summarize_combined(output_dir):
    data = load_json(output_dir / "combined_findings.json")
    if not data:
        return
    sources = Counter(f.get("source", "?") for f in data)
    sevs = Counter(f.get("severity", "?") for f in data)
    files = Counter(Path(f.get("file_path", f.get("file", "?"))).name for f in data)
    print(f"{c('Combined', 'BOLD')}  ({len(data)} total)")
    print(f"  {c('CRITICAL', 'CRITICAL')}: {sevs.get('CRITICAL', 0):>4}   "
          f"{c('HIGH', 'HIGH')}: {sevs.get('HIGH', 0):>4}   "
          f"{c('MEDIUM', 'MEDIUM')}: {sevs.get('MEDIUM', 0):>4}   "
          f"{c('LOW', 'LOW')}: {sevs.get('LOW', 0):>4}")
    print(f"  Sources: {', '.join(f'{k} ({v})' for k, v in sources.most_common())}")
    print()
    print(f"  {c('Hottest files:', 'DIM')}")
    for fname, count in files.most_common(8):
        print(f"    {count:>4}x  {fname}")
    print()

def summarize_cost(output_dir):
    data = load_json(output_dir / "cost_tracking.json")
    if not data or "summary" not in data:
        return
    s = data["summary"]
    print(f"{c('Cost', 'BOLD')}")
    print(f"  API calls:    {s['total_calls']}")
    print(f"  Tokens:       {s['total_tokens']:,} "
          f"({s['total_input_tokens']:,} in / {s['total_output_tokens']:,} out)")
    cost_val = s['total_cost']
    print(f"  Cost:         {c(f'${cost_val:.3f}', 'GREEN')}")
    by_stage = s.get("by_stage", {})
    if by_stage:
        print(f"  By stage:")
        for stage, info in by_stage.items():
            print(f"    {stage:<20} {info['calls']:>3} calls  "
                  f"{info['total_tokens']:>7,} tokens  ${info['cost']:.3f}")
    print()

def summarize_tech(output_dir):
    data = load_json(output_dir / "tech_stack.json")
    if not data:
        return
    print(f"{c('Tech Stack', 'BOLD')}")
    langs = data.get("languages", [])
    fws = data.get("frameworks", {})
    if langs:
        if isinstance(langs, list):
            print(f"  Languages:    {', '.join(langs)}")
        elif isinstance(langs, dict):
            print(f"  Languages:    {', '.join(langs.keys())}")
    if fws:
        if isinstance(fws, dict):
            fw_items = sorted(fws.items(), key=lambda x: x[1], reverse=True)[:8]
            fw_names = [f"{name} ({int(conf*100)}%)" for name, conf in fw_items]
        elif isinstance(fws, list):
            fw_names = [f.get("name", str(f)) if isinstance(f, dict) else str(f) for f in fws[:8]]
        else:
            fw_names = []
        if fw_names:
            print(f"  Frameworks:   {', '.join(fw_names)}")
    entries = data.get("entry_points", [])
    if entries:
        print(f"  Entry points: {len(entries)}")
    sec = data.get("security_files", [])
    if sec:
        print(f"  Security files: {len(sec)}")
    print()

def summarize_payloads(output_dir):
    pdir = output_dir / "payloads"
    adir = output_dir / "annotations"
    pcount = len(list(pdir.glob("*.json"))) if pdir.is_dir() else 0
    acount = len(list(adir.glob("*.md"))) if adir.is_dir() else 0
    if pcount or acount:
        print(f"{c('Artifacts', 'BOLD')}")
        if pcount:
            print(f"  Payloads:     {pcount} files in payloads/")
        if acount:
            print(f"  Annotations:  {acount} files in annotations/")
        print()

def show_top_findings(output_dir, n=10):
    data = load_json(output_dir / "combined_findings.json")
    if not data:
        return
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_f = sorted(data, key=lambda f: sev_order.get(f.get("severity", "LOW"), 9))
    print(f"\n{c(f'Top {n} Findings', 'BOLD')}")
    print(f"{'-' * 55}")
    for i, f in enumerate(sorted_f[:n], 1):
        sev = f.get("severity", "?")
        title = f.get("title", f.get("rule_name", "unknown"))[:55]
        fpath = f.get("file_path", f.get("file", "?"))
        fname = Path(fpath).name if fpath else "?"
        line = f.get("line", f.get("line_number", ""))
        loc = f"{fname}:{line}" if line else fname
        rec = f.get("recommendation", f.get("fix", f.get("remediation", "")))
        print(f"  {i:>2}. {c(f'[{sev}]', sev)}  {title}")
        print(f"      {c(loc, 'DIM')}")
        if rec:
            rec_short = rec[:70] + "..." if len(rec) > 70 else rec
            print(f"      {c(rec_short, 'GREEN')}")
    print()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    show_findings = "--findings" in args
    show_cost_only = "--cost" in args
    top_n = 10

    # Parse --top N
    if "--top" in args:
        idx = args.index("--top")
        if idx + 1 < len(args):
            top_n = int(args[idx + 1])
            show_findings = True

    # Find output directory
    clean_args = [a for a in args if not a.startswith("--")]
    if clean_args:
        output_dir = Path(clean_args[0])
    else:
        output_dir = find_output_dir()

    if not output_dir or not output_dir.is_dir():
        print("No output directory found. Run a scan first or specify a path:")
        print("  python3 summarize.py output/tests_test_targets_WebGoat")
        sys.exit(1)

    print_header(output_dir)

    if show_cost_only:
        summarize_cost(output_dir)
        return

    summarize_tech(output_dir)
    summarize_static(output_dir)
    summarize_ai(output_dir)
    summarize_combined(output_dir)
    summarize_payloads(output_dir)
    summarize_cost(output_dir)

    if show_findings:
        show_top_findings(output_dir, top_n)

if __name__ == "__main__":
    main()
