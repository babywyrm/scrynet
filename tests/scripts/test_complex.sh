#!/bin/bash
# Complex end-to-end test with multiple profiles and deduplication

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🧪 Complex End-to-End Test${NC}"
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

# Test with SQL injection vulnerability directory (good test case)
TARGET="../test_targets/DVWA/vulnerabilities/sqli"
SCANNER="../../scanner"

if [ ! -d "$TARGET" ]; then
    echo "⚠️  Test target not found: $TARGET"
    echo "Trying alternative: ../test_targets/DVWA/vulnerabilities"
    TARGET="../test_targets/DVWA/vulnerabilities"
fi

echo -e "${YELLOW}Test Configuration:${NC}"
echo "  Target: $TARGET"
echo "  Profiles: owasp,ctf"
echo "  Deduplication: ENABLED"
echo "  Payloads: ENABLED"
echo "  Annotations: ENABLED"
echo "  Prioritization: ENABLED (top 6 files)"
echo ""

echo -e "${BLUE}Running complex test...${NC}"
echo ""

python3 ../../scrynet.py hybrid "$TARGET" "$SCANNER" \
    --profile owasp,ctf \
    --prioritize \
    --prioritize-top 6 \
    --question "find SQL injection vulnerabilities and exploitable security issues" \
    --deduplicate \
    --dedupe-threshold 0.7 \
    --dedupe-strategy keep_highest_severity \
    --generate-payloads \
    --annotate-code \
    --top-n 6 \
    --export-format json html markdown csv \
    --output-dir ../test-reports/complex-test \
    --verbose

echo ""
echo -e "${GREEN}✅ Test complete!${NC}"
echo ""
echo "Check results:"
echo "  ls -lh ../test-reports/complex-test/"
echo "  cat ../test-reports/complex-test/combined_findings.json | jq 'length'"
echo "  cat ../test-reports/complex-test/combined_findings.json | jq '.[] | select(.profiles != null)'"
