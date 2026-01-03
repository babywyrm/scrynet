# Quick Test Commands

## Setup (First Time)
```bash
source .venv/bin/activate
export CLAUDE_API_KEY="your_key_here"
```

## Test Individual Profiles

### CTF Profile (Full Features)
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile ctf \
  --prioritize --prioritize-top 10 \
  --question "find exploitable vulnerabilities and potential flags" \
  --generate-payloads --annotate-code --top-n 8 \
  --export-format json html markdown csv \
  --output-dir ./test-reports/ctf-test --verbose
```

### Code Review Profile
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile code_review \
  --prioritize --prioritize-top 10 \
  --question "find code quality issues and technical debt" \
  --generate-payloads --annotate-code --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/code-review-test --verbose
```

### Modern Security Profile
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile modern \
  --prioritize --prioritize-top 10 \
  --question "find modern security issues: supply chain, cloud-native, zero-trust" \
  --generate-payloads --annotate-code --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/modern-test --verbose
```

### SOC 2 Compliance
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile soc2 \
  --prioritize --prioritize-top 10 \
  --question "find SOC 2 compliance gaps: access controls, encryption, monitoring" \
  --generate-payloads --annotate-code --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/soc2-test --verbose
```

### PCI-DSS Compliance
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile pci \
  --prioritize --prioritize-top 10 \
  --question "find PCI-DSS compliance issues: cardholder data protection, encryption" \
  --generate-payloads --annotate-code --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/pci-test --verbose
```

### General Compliance (HIPAA, GDPR, CCPA)
```bash
python3 scrynet.py hybrid ./test_targets/DVWA ./scanner \
  --profile compliance \
  --prioritize --prioritize-top 10 \
  --question "find compliance issues: data privacy, encryption, consent management" \
  --generate-payloads --annotate-code --top-n 8 \
  --export-format json html markdown \
  --output-dir ./test-reports/compliance-test --verbose
```

## Test All Profiles at Once
```bash
./test_all_profiles.sh
```

## Verify Results
```bash
# Check reports
ls -lh test-reports/*/combined_findings.*

# Check payloads
ls -lh test-reports/*/payloads/

# Check annotations
ls -lh test-reports/*/annotations/

# Verify recommendations
cat test-reports/*/combined_findings.json | jq '.[] | .recommendation' | grep -v "N/A" | head -10
```

For detailed examples, see TEST_PROFILES.md
