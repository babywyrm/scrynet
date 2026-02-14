#!/bin/bash
# Quick activation script for Agent Smith virtual environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    echo "Virtual environment not found. Run ./scripts/setup.sh first."
    exit 1
fi

source "$PROJECT_ROOT/.venv/bin/activate"
cd "$PROJECT_ROOT"

echo "Agent Smith environment activated"
echo ""
echo "Commands:"
echo "  python3 agentsmith.py --help            # All modes"
echo "  python3 orchestrator.py --help          # Hybrid mode (recommended)"
echo "  python3 -m mcp_server --no-auth         # Start MCP server"
echo "  python3 -m mcp_server.test_client interact  # Interactive REPL"
echo ""
echo "One-command flows:"
echo "  ./scripts/run_mcp_shell.sh              # Setup + server + interactive client"
echo "  ./scripts/run_mcp_shell.sh --debug      # Same, with server debug mode"
echo "  ./scripts/run_mcp_tests.sh              # Start server if needed, run test suite"
echo ""
