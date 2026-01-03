# Profile Testing Guide

Comprehensive test examples for all SCRYNET profiles with full features enabled (annotations, payloads, verbose output).

## Prerequisites

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Set API key
export CLAUDE_API_KEY="your_key_here"

# 3. Make sure scanner is built
go build -o scanner scrynet.go
```

## Test Examples by Profile

### 1. CTF Profile Test

**Full-featured CTF scan with all outputs:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile ctf \
  --prioritize \
  --prioritize-top 10 \
  --question "find exploitable vulnerabilities and potential flags" \
  --generate-payloads \
  --annotate-code \
  --top-n 8 \
  --export-format json html markdown csv \
  --output-dir ./test-reports/ctf-test \
  --verbose
```

**What to check:**
- ✓ CTF-focused findings (SQL injection, file inclusion, hardcoded secrets)
- ✓ Payloads show exploitation hints
- ✓ Annotations include exploit paths
- ✓ Reports in all formats (JSON, HTML, Markdown, CSV)
- ✓ File paths and line numbers in all outputs

---

### 2. Code Review Profile Test

**Code quality analysis with full features:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile code_review \
  --prioritize \
  --prioritize-top 10 \
  --question "find code quality issues, maintainability problems, and technical debt" \
  --generate-payloads \
  --annotate-code \
  --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/code-review-test \
  --verbose
```

**What to check:**
- ✓ Code quality findings (complexity, maintainability, best practices)
- ✓ Recommendations for improvements
- ✓ Annotations show before/after code examples
- ✓ Focus on readability and maintainability

---

### 3. Modern Security Profile Test

**Modern security practices analysis:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile modern \
  --prioritize \
  --prioritize-top 10 \
  --question "find modern security issues: supply chain, cloud-native, zero-trust, DevSecOps" \
  --generate-payloads \
  --annotate-code \
  --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/modern-test \
  --verbose
```

**What to check:**
- ✓ Supply chain security issues
- ✓ Cloud-native security concerns
- ✓ Zero-trust architecture gaps
- ✓ DevSecOps integration issues

---

### 4. SOC 2 Compliance Profile Test

**SOC 2 compliance audit:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile soc2 \
  --prioritize \
  --prioritize-top 10 \
  --question "find SOC 2 compliance gaps: access controls, encryption, monitoring, audit trails" \
  --generate-payloads \
  --annotate-code \
  --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/soc2-test \
  --verbose
```

**What to check:**
- ✓ Access control issues (CC6)
- ✓ Encryption and data protection (CC6)
- ✓ Monitoring and logging (CC7)
- ✓ Change management gaps (CC8)

---

### 5. PCI-DSS Compliance Profile Test

**PCI-DSS compliance audit:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile pci \
  --prioritize \
  --prioritize-top 10 \
  --question "find PCI-DSS compliance issues: cardholder data protection, encryption, access controls" \
  --generate-payloads \
  --annotate-code \
  --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/pci-test \
  --verbose
```

**What to check:**
- ✓ Cardholder data protection (Req 3)
- ✓ Encryption requirements (Req 4)
- ✓ Access controls (Req 7, 8)
- ✓ Logging and monitoring (Req 10)

---

### 6. General Compliance Profile Test

**Multi-framework compliance (HIPAA, GDPR, CCPA):**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile compliance \
  --prioritize \
  --prioritize-top 10 \
  --question "find compliance issues: data privacy, encryption, consent management, audit trails" \
  --generate-payloads \
  --annotate-code \
  --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/compliance-test \
  --verbose
```

**What to check:**
- ✓ Data privacy violations (GDPR, CCPA)
- ✓ PHI protection issues (HIPAA)
- ✓ Consent management gaps
- ✓ Audit trail requirements

---

### 7. Multiple Profiles Combined Test

**Comprehensive security + compliance audit:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf,code_review \
  --prioritize \
  --prioritize-top 15 \
  --question "find security vulnerabilities, exploitable issues, and code quality problems" \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html markdown csv \
  --output-dir ./test-reports/comprehensive-test \
  --verbose
```

**What to check:**
- ✓ Findings from multiple profiles
- ✓ Source tags show which profile found each issue
- ✓ Combined reports with all findings
- ✓ Payloads and annotations for top findings

---

### 8. Compliance Multi-Profile Test

**Full compliance audit:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile soc2,pci,compliance \
  --prioritize \
  --prioritize-top 15 \
  --question "find all compliance gaps across SOC 2, PCI-DSS, and general regulations" \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html markdown \
  --output-dir ./test-reports/compliance-full \
  --verbose
```

**What to check:**
- ✓ SOC 2, PCI, and general compliance findings
- ✓ Cross-framework compliance gaps
- ✓ Comprehensive compliance report

---

## Quick Test (Small Subset)

**Fast test with minimal files:**
```bash
python3 scrynet.py hybrid ./test_targets/DVWA/login.php ./scanner \
  --profile ctf \
  --prioritize \
  --prioritize-top 3 \
  --question "find SQL injection and authentication bypass" \
  --generate-payloads \
  --annotate-code \
  --top-n 3 \
  --export-format json html \
  --output-dir ./test-reports/quick-test \
  --verbose
```

---

## Verification Checklist

After each test, verify:

### 1. Console Output
- [ ] Rich UI with colors and spinners
- [ ] Progress bars showing file analysis
- [ ] Real-time findings displayed
- [ ] Payloads shown in console
- [ ] Annotations previewed

### 2. Generated Files
- [ ] `combined_findings.json` - All findings in JSON
- [ ] `combined_findings.html` - HTML report
- [ ] `combined_findings.md` - Markdown report
- [ ] `combined_findings.csv` - CSV report (if requested)
- [ ] `payloads/` directory with individual payload files
- [ ] `annotations/` directory with individual annotation files

### 3. Payload Files
- [ ] Each payload file has: file path, line number, finding title
- [ ] Red team payloads present
- [ ] Blue team payloads present
- [ ] Recommendations included

### 4. Annotation Files
- [ ] Each annotation has: file path, line number, severity
- [ ] Code snippets with syntax highlighting
- [ ] FLAW comments showing issues
- [ ] FIX comments showing solutions
- [ ] Recommendations included

### 5. Reports
- [ ] JSON has all finding fields
- [ ] HTML has Recommendation column
- [ ] Markdown has Recommendation column
- [ ] CSV has Recommendation column
- [ ] File paths and line numbers in all reports

### 6. Profile-Specific Checks

**CTF Profile:**
- [ ] Focus on exploitable vulnerabilities
- [ ] Exploitation hints in payloads
- [ ] CTF-specific findings

**Code Review Profile:**
- [ ] Code quality focus
- [ ] Maintainability issues
- [ ] Best practices recommendations

**Modern Profile:**
- [ ] Supply chain security
- [ ] Cloud-native issues
- [ ] Zero-trust gaps

**SOC 2 Profile:**
- [ ] Access control issues (CC6)
- [ ] Encryption requirements
- [ ] Monitoring gaps

**PCI Profile:**
- [ ] Cardholder data protection
- [ ] Encryption requirements
- [ ] Access control issues

**Compliance Profile:**
- [ ] Data privacy issues
- [ ] Consent management
- [ ] Audit trail requirements

---

## Quick Verification Commands

```bash
# Check if reports were generated
ls -lh test-reports/*/combined_findings.*

# Check payloads
ls -lh test-reports/*/payloads/
cat test-reports/*/payloads/*.json | jq . | head -20

# Check annotations
ls -lh test-reports/*/annotations/
cat test-reports/*/annotations/*.md | head -30

# Verify recommendations in JSON
cat test-reports/*/combined_findings.json | jq '.[] | select(.recommendation != null and .recommendation != "N/A")' | head -20

# Check HTML for recommendations
grep -i "recommendation" test-reports/*/combined_findings.html | head -5
```

---

## Expected Output Structure

```
test-reports/
└── {profile}-test/
    ├── static_findings.json
    ├── ai_findings.json
    ├── combined_findings.json
    ├── combined_findings.html
    ├── combined_findings.md
    ├── combined_findings.csv (if requested)
    ├── payloads/
    │   ├── payload_File1_L45.json
    │   ├── payload_File2_L123.json
    │   └── ...
    └── annotations/
        ├── annotation_File1_L45.md
        ├── annotation_File2_L123.md
        └── ...
```

---

## Troubleshooting

**If profiles don't load:**
```bash
# Check profile files exist
ls -lh prompts/*_profile.txt

# Test profile loading
python3 -c "from pathlib import Path; print([f.stem.replace('_profile', '') for f in Path('prompts').glob('*_profile.txt')])"
```

**If payloads/annotations missing:**
- Check `--generate-payloads` and `--annotate-code` flags are set
- Verify `--top-n` is set (default is 5)
- Check that findings were actually found

**If recommendations are "N/A":**
- Check AI responses include `fix`, `explanation`, or `recommendation` fields
- Verify JSON parsing is working
- Check verbose output for API responses

---

## Test All Profiles at Once

```bash
# Run all profile tests sequentially
for profile in ctf code_review modern soc2 pci compliance; do
  echo "Testing $profile profile..."
  python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
    --profile $profile \
    --prioritize \
    --prioritize-top 5 \
    --question "test $profile profile" \
    --generate-payloads \
    --annotate-code \
    --top-n 3 \
    --export-format json html \
    --output-dir ./test-reports/$profile-test \
    --verbose
  echo "✓ $profile test complete"
  echo ""
done
```

