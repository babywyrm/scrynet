#!/bin/bash
# Quick test script for all new profiles

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Testing All SCRYNET Profiles${NC}"
echo "=================================="
echo ""

# Check if venv is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "⚠️  Virtual environment not activated!"
    echo "Run: source .venv/bin/activate"
    exit 1
fi

# Check API key
if [[ -z "$CLAUDE_API_KEY" ]]; then
    echo "⚠️  CLAUDE_API_KEY not set!"
    echo "Run: export CLAUDE_API_KEY='your_key_here'"
    exit 1
fi

# Test targets
TARGET="../test_targets/DVWA"
SCANNER="../../scanner"

# Profiles to test
PROFILES=("ctf" "code_review" "modern" "soc2" "pci" "compliance")

for profile in "${PROFILES[@]}"; do
    echo -e "${GREEN}Testing $profile profile...${NC}"
    
    python3 ../../scrynet.py hybrid "$TARGET" "$SCANNER" \
        --profile "$profile" \
        --prioritize \
        --prioritize-top 5 \
        --question "test $profile profile with full features" \
        --generate-payloads \
        --annotate-code \
        --top-n 5 \
        --export-format json html markdown \
        --output-dir "../test-reports/${profile}-test" \
        --verbose
    
    echo -e "${GREEN}✓ $profile test complete${NC}"
    echo ""
done

echo -e "${BLUE}✅ All profile tests complete!${NC}"
echo "Check ../test-reports/ directory for results"


