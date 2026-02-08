"""
MCP Server Configuration

All settings are read from environment variables with sensible defaults.
"""

import os
from pathlib import Path

# Server
MCP_HOST = os.getenv("AGENTSMITH_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("AGENTSMITH_MCP_PORT", "2266"))

# Auth
MCP_TOKEN = os.getenv("AGENTSMITH_MCP_TOKEN", "")

# CORS
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("AGENTSMITH_CORS_ORIGINS", "http://localhost:*").split(",")
    if o.strip()
]

# Path security - restrict repo_path arguments to these base directories.
# Comma-separated list of allowed base paths. Defaults to cwd.
_allowed_raw = os.getenv("AGENTSMITH_ALLOWED_PATHS", "")
ALLOWED_PATHS: list[Path] = [
    Path(p.strip()).resolve()
    for p in (_allowed_raw.split(",") if _allowed_raw else [os.getcwd()])
    if p.strip()
]

# Agent Smith paths (auto-detected relative to this file)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCANNER_BIN = PROJECT_ROOT / "scanner"
RULES_DIR = PROJECT_ROOT / "rules"
OUTPUT_DIR = PROJECT_ROOT / "output"

# Input limits
MAX_PATH_LENGTH = 4096
MAX_QUESTION_LENGTH = 1000
MAX_OUTPUT_FINDINGS = 500
