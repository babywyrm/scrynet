#!/bin/bash
# Clone vulnerable test target applications for Agent Smith scanning
#
# These repos are gitignored and will NOT be committed.
# Run this once after a fresh clone to set up test targets.
#
# Usage:
#   ./setup_test_targets.sh          # Clone all test targets
#   ./setup_test_targets.sh --dvwa   # Clone only DVWA
#   ./setup_test_targets.sh --webgoat # Clone only WebGoat
#   ./setup_test_targets.sh --juice  # Clone only Juice Shop

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR/tests/test_targets"

CLONE_DVWA=false
CLONE_WEBGOAT=false
CLONE_JUICE=false
CLONE_ALL=true

for arg in "$@"; do
    case $arg in
        --dvwa)     CLONE_DVWA=true; CLONE_ALL=false ;;
        --webgoat)  CLONE_WEBGOAT=true; CLONE_ALL=false ;;
        --juice)    CLONE_JUICE=true; CLONE_ALL=false ;;
        --help|-h)
            echo "Usage: ./setup_test_targets.sh [--dvwa|--webgoat|--juice|--help]"
            echo ""
            echo "Clones vulnerable web apps into tests/test_targets/ for scanning."
            echo "These are gitignored and will not be committed."
            echo ""
            echo "Options:"
            echo "  --dvwa      Clone only DVWA"
            echo "  --webgoat   Clone only WebGoat"
            echo "  --juice     Clone only Juice Shop"
            echo "  --help      Show this help"
            echo ""
            echo "With no flags, clones all three targets."
            exit 0
            ;;
    esac
done

if [ "$CLONE_ALL" = true ]; then
    CLONE_DVWA=true
    CLONE_WEBGOAT=true
    CLONE_JUICE=true
fi

echo ""
echo "Agent Smith - Test Target Setup"
echo "================================"
echo ""
echo "Target directory: $TARGET_DIR"
echo ""

mkdir -p "$TARGET_DIR"

# -------------------------------------------------------
# DVWA - Damn Vulnerable Web Application
# -------------------------------------------------------
if [ "$CLONE_DVWA" = true ]; then
    if [ -d "$TARGET_DIR/DVWA" ]; then
        echo "DVWA already exists, skipping."
    else
        echo "Cloning DVWA (Damn Vulnerable Web Application)..."
        git clone --depth 1 https://github.com/digininja/DVWA.git "$TARGET_DIR/DVWA"
        echo "Done."
    fi
    echo ""
fi

# -------------------------------------------------------
# WebGoat - OWASP WebGoat
# -------------------------------------------------------
if [ "$CLONE_WEBGOAT" = true ]; then
    if [ -d "$TARGET_DIR/WebGoat" ]; then
        echo "WebGoat already exists, skipping."
    else
        echo "Cloning WebGoat (OWASP WebGoat)..."
        git clone --depth 1 https://github.com/WebGoat/WebGoat.git "$TARGET_DIR/WebGoat"
        echo "Done."
    fi
    echo ""
fi

# -------------------------------------------------------
# Juice Shop - OWASP Juice Shop
# -------------------------------------------------------
if [ "$CLONE_JUICE" = true ]; then
    if [ -d "$TARGET_DIR/juice-shop" ]; then
        echo "Juice Shop already exists, skipping."
    else
        echo "Cloning Juice Shop (OWASP Juice Shop)..."
        git clone --depth 1 https://github.com/juice-shop/juice-shop.git "$TARGET_DIR/juice-shop"
        echo "Done."
    fi
    echo ""
fi

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo "================================"
echo ""
echo "Test targets installed:"
for d in "$TARGET_DIR"/*/; do
    if [ -d "$d" ]; then
        name=$(basename "$d")
        file_count=$(find "$d" -type f -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.php" -o -name "*.go" -o -name "*.html" 2>/dev/null | wc -l | xargs)
        echo "  $name ($file_count scannable files)"
    fi
done
echo ""
echo "These directories are gitignored and will not be committed."
echo ""
echo "Run a scan:"
echo "  python3 orchestrator.py tests/test_targets/DVWA ./scanner \\"
echo "    --profile owasp --prioritize --verbose"
echo ""
