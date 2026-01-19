#!/bin/bash
# Advanced test script for multi-profile scans with deduplication

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🔬 Advanced SCRYNET Testing${NC}"
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

TARGET="../test_targets/DVWA"
SCANNER="../../scanner"

echo -e "${YELLOW}Test 1: Multi-Profile with Deduplication (OWASP + CTF)${NC}"
python3 ../../scrynet.py hybrid "$TARGET" "$SCANNER" \
    --profile owasp,ctf \
    --prioritize \
    --prioritize-top 10 \
    --question "find security vulnerabilities and exploitable issues" \
    --deduplicate \
    --dedupe-threshold 0.7 \
    --dedupe-strategy keep_highest_severity \
    --generate-payloads \
    --annotate-code \
    --top-n 5 \
    --export-format json html \
    --output-dir "../test-reports/advanced-1" \
    --verbose

echo -e "${GREEN}✓ Test 1 complete${NC}"
echo ""

echo -e "${YELLOW}Test 2: Compliance Suite (SOC2 + PCI + Compliance)${NC}"
python3 ../../scrynet.py hybrid "$TARGET" "$SCANNER" \
    --profile soc2,pci,compliance \
    --prioritize \
    --prioritize-top 10 \
    --question "find compliance gaps" \
    --deduplicate \
    --dedupe-threshold 0.75 \
    --dedupe-strategy merge \
    --generate-payloads \
    --top-n 5 \
    --export-format json html \
    --output-dir "./test-reports/advanced-2" \
    --verbose

echo -e "${GREEN}✓ Test 2 complete${NC}"
echo ""

echo -e "${YELLOW}Test 3: All Profiles with Aggressive Deduplication${NC}"
python3 ../../scrynet.py hybrid "$TARGET" "$SCANNER" \
    --profile owasp,ctf,code_review \
    --prioritize \
    --prioritize-top 8 \
    --question "comprehensive security analysis" \
    --deduplicate \
    --dedupe-threshold 0.6 \
    --dedupe-strategy merge \
    --generate-payloads \
    --annotate-code \
    --top-n 5 \
    --export-format json \
    --output-dir "./test-reports/advanced-3" \
    --verbose

echo -e "${GREEN}✓ Test 3 complete${NC}"
echo ""

echo -e "${BLUE}✅ All advanced tests complete!${NC}"
echo ""
echo "Check results:"
echo "  ls -lh ../test-reports/advanced-*/combined_findings.*"
echo "  cat ../test-reports/advanced-*/combined_findings.json | jq '.[] | select(.profiles != null)'"
