"""CLI argument parsing."""

import argparse
import re
import sys
from pathlib import Path

from mcp_attack import __version__

# Built-in public targets (DVMCP, demo servers — run locally)
PUBLIC_TARGETS_FILE = Path(__file__).parent / "data" / "public_targets.txt"


def expand_port_range(spec: str) -> list[str]:
    m = re.match(r"^(.+):(\d+)-(\d+)$", spec)
    if not m:
        raise ValueError(f"Invalid port range spec: {spec!r}")
    host, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    if end < start:
        raise ValueError(f"End port {end} < start port {start}")
    return [f"http://{host}:{p}" for p in range(start, end + 1)]


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcp-audit — MCP Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--targets",
        nargs="+",
        metavar="URL",
        help="One or more MCP target URLs",
    )
    p.add_argument(
        "--port-range",
        metavar="HOST:START-END",
        help="Scan a port range, e.g. localhost:9001-9010",
    )
    p.add_argument(
        "--targets-file",
        metavar="FILE",
        help="Read target URLs from file (one per line, # comments ignored)",
    )
    p.add_argument(
        "--public-targets",
        action="store_true",
        help="Use built-in public targets list (DVMCP, demo servers)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=25.0,
        metavar="SEC",
        help="Per-target connection timeout (default: 25)",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="Parallel scan workers (default: 4)",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (very noisy)",
    )
    p.add_argument(
        "--json",
        metavar="FILE",
        dest="json_out",
        help="Write JSON report to FILE",
    )
    p.add_argument(
        "--k8s-namespace",
        metavar="NS",
        default="default",
        help="Kubernetes namespace for internal checks (default: default)",
    )
    p.add_argument(
        "--no-k8s",
        action="store_true",
        help="Skip Kubernetes internal checks",
    )
    return p.parse_args(args)


def _load_urls_from_file(path: Path) -> list[str]:
    """Load URLs from file, one per line, skip comments and blanks."""
    if not path.is_file():
        return []
    urls = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def build_url_list(args: argparse.Namespace) -> list[str]:
    urls: list[str] = []

    if args.targets:
        urls.extend(args.targets)

    if args.targets_file:
        p = Path(args.targets_file)
        if not p.is_file():
            print(f"Error: targets file not found: {p}", file=sys.stderr)
            sys.exit(1)
        urls.extend(_load_urls_from_file(p))

    if args.public_targets and PUBLIC_TARGETS_FILE.is_file():
        urls.extend(_load_urls_from_file(PUBLIC_TARGETS_FILE))

    if args.port_range:
        try:
            urls.extend(expand_port_range(args.port_range))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    if not urls:
        print(
            "Error: specify --targets, --port-range, --targets-file, or --public-targets",
            file=sys.stderr,
        )
        sys.exit(1)

    seen: set[str] = set()
    deduped: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped
