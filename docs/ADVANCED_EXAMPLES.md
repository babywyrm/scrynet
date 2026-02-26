# Advanced Agent Smith Examples

Comprehensive examples demonstrating multi-profile scans, deduplication, and advanced workflows.

**See also:** [USE_CASES.md](USE_CASES.md) (simple to complex) · [MCP_SCANNING.md](MCP_SCANNING.md) (scan MCP servers)

**⚠️ Note: Deduplication is OPT-IN only!**

Deduplication only runs if you explicitly enable it with the `--deduplicate` flag. By default, all findings from all profiles are shown separately, giving you full visibility into what each profile discovered.

## Multi-Profile Scans with Deduplication

### Example 1: Security + Compliance Audit

**Scenario**: Comprehensive security audit with compliance checking

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,soc2,compliance \
  --prioritize \
  --prioritize-top 20 \
  --question "find security vulnerabilities and compliance gaps" \
  --deduplicate \
  --dedupe-threshold 0.75 \
  --dedupe-strategy keep_highest_severity \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html markdown csv \
  --output-dir ./security-audit-reports \
  --verbose
```

**What this does**:
- Runs 3 profiles simultaneously (OWASP, SOC2, Compliance)
- Prioritizes top 20 files
- Deduplicates similar findings with 75% similarity threshold
- Keeps highest severity when duplicates found
- Generates payloads and annotations for top 10 findings
- Exports in all formats

**Expected output**:
- Combined findings with deduplication stats
- `source` field shows which profiles found each issue
- `profiles` field lists all profiles that found duplicates

---

### Example 2: CTF + Code Review (Exploitation + Quality)

**Scenario**: CTF challenge analysis with code quality review

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile ctf,code_review \
  --prioritize \
  --prioritize-top 15 \
  --question "find exploitable vulnerabilities and code quality issues" \
  --deduplicate \
  --dedupe-threshold 0.65 \
  --dedupe-strategy merge \
  --generate-payloads \
  --annotate-code \
  --top-n 8 \
  --export-format json html \
  --output-dir ./ctf-quality-report \
  --verbose
```

**What this does**:
- Combines CTF (exploitation-focused) with code review (quality-focused)
- Lower threshold (0.65) catches more similar findings
- `merge` strategy combines recommendations from both profiles
- Focuses on top 8 findings for detailed analysis

**Expected output**:
- Findings show both exploitation potential and code quality issues
- Merged recommendations combine CTF and code review insights
- Payloads include exploitation hints

---

### Example 3: Full Compliance Suite

**Scenario**: Complete compliance audit (SOC2 + PCI + General)

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile soc2,pci,compliance \
  --prioritize \
  --prioritize-top 25 \
  --question "find all compliance gaps across SOC2, PCI-DSS, and general regulations" \
  --deduplicate \
  --dedupe-threshold 0.8 \
  --dedupe-strategy keep_highest_severity \
  --generate-payloads \
  --annotate-code \
  --top-n 12 \
  --export-format json html markdown \
  --output-dir ./compliance-audit \
  --verbose
```

**What this does**:
- Runs all compliance profiles together
- Higher threshold (0.8) for stricter deduplication
- Prioritizes more files (25) for comprehensive coverage
- Top 12 findings get detailed analysis

**Expected output**:
- Compliance findings tagged with specific frameworks
- Cross-framework compliance gaps identified
- Detailed annotations showing compliance violations

---

### Example 4: Modern Security + OWASP (Comprehensive Security)

**Scenario**: Modern security practices + OWASP Top 10

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile modern,owasp \
  --prioritize \
  --prioritize-top 18 \
  --question "find modern security issues and OWASP Top 10 vulnerabilities" \
  --deduplicate \
  --dedupe-threshold 0.7 \
  --dedupe-strategy keep_first \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html markdown csv \
  --output-dir ./modern-security-report \
  --verbose
```

**What this does**:
- Combines modern security (supply chain, cloud-native) with OWASP
- `keep_first` strategy preserves original finding order
- Balanced threshold (0.7) for good deduplication

---

### Example 5: All Profiles (Maximum Coverage)

**Scenario**: Run all profiles for maximum vulnerability coverage

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf,code_review,modern,soc2,pci,compliance \
  --prioritize \
  --prioritize-top 30 \
  --question "comprehensive security and compliance analysis" \
  --deduplicate \
  --dedupe-threshold 0.7 \
  --dedupe-strategy merge \
  --generate-payloads \
  --annotate-code \
  --top-n 15 \
  --export-format json html markdown csv \
  --output-dir ./comprehensive-audit \
  --verbose
```

**What this does**:
- Runs ALL profiles simultaneously
- Maximum file coverage (30 files)
- `merge` strategy combines insights from all profiles
- Top 15 findings get full analysis

**Expected output**:
- Comprehensive findings from all perspectives
- Merged recommendations show multi-profile insights
- Source tracking shows which profiles found what

---

## Deduplication Strategy Comparison

### Test Different Strategies

**1. Keep Highest Severity (Default)**
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --dedupe-strategy keep_highest_severity \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Use case**: When you want the most critical finding preserved

---

**2. Keep First**
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --dedupe-strategy keep_first \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Use case**: When you want to preserve original finding order

---

**3. Merge**
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --dedupe-strategy merge \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Use case**: When you want combined insights from all profiles

---

## Threshold Tuning Examples

### Strict Deduplication (High Threshold)

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --dedupe-threshold 0.9 \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Result**: Only very similar findings (90%+ similarity) are deduplicated

---

### Aggressive Deduplication (Low Threshold)

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --dedupe-threshold 0.5 \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Result**: More findings deduplicated (50%+ similarity)

---

### Balanced Deduplication (Default)

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --dedupe-threshold 0.7 \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Result**: Balanced deduplication (70% similarity)

---

## Advanced Workflows

### Workflow 1: Progressive Analysis

**Step 1**: Quick scan with prioritization
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp \
  --prioritize \
  --prioritize-top 10 \
  --question "find critical security vulnerabilities" \
  --export-format json \
  --output-dir ./quick-scan \
  --verbose
```

**Step 2**: Deep dive on prioritized files with multiple profiles
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf,code_review \
  --deduplicate \
  --dedupe-strategy merge \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html \
  --output-dir ./deep-dive \
  --verbose
```

---

### Workflow 2: Compliance-Focused Audit

**Step 1**: Compliance scan
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile soc2,pci,compliance \
  --prioritize \
  --prioritize-top 20 \
  --question "find compliance gaps" \
  --deduplicate \
  --dedupe-threshold 0.75 \
  --export-format json html \
  --output-dir ./compliance-scan \
  --verbose
```

**Step 2**: Security validation
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,modern \
  --prioritize \
  --prioritize-top 15 \
  --question "validate security controls" \
  --deduplicate \
  --generate-payloads \
  --export-format json html \
  --output-dir ./security-validation \
  --verbose
```

---

### Workflow 3: CTF Challenge Analysis

**Step 1**: Quick exploitation scan
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile ctf \
  --prioritize \
  --prioritize-top 15 \
  --question "find exploitable vulnerabilities and flags" \
  --generate-payloads \
  --top-n 10 \
  --export-format json \
  --output-dir ./ctf-quick \
  --verbose
```

**Step 2**: Comprehensive analysis with deduplication
```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile ctf,owasp \
  --deduplicate \
  --dedupe-strategy merge \
  --generate-payloads \
  --annotate-code \
  --top-n 15 \
  --export-format json html markdown \
  --output-dir ./ctf-comprehensive \
  --verbose
```

---

## Verification Commands

### Check Deduplication Results

```bash
# Count findings before/after deduplication
cat output/*/combined_findings.json | jq 'length'

# Check which profiles found each issue
cat output/*/combined_findings.json | jq '.[] | {title: .title, source: .source, profiles: .profiles}'

# Find deduplicated findings (those with multiple profiles)
cat output/*/combined_findings.json | jq '.[] | select(.profiles != null and (.profiles | length) > 1)'

# Compare findings from different profiles
cat output/*/ai_findings.json | jq 'group_by(.source) | map({profile: .[0].source, count: length})'
```

### Verify Payloads and Annotations

```bash
# Count generated payloads
find output/*/payloads -name "*.json" 2>/dev/null | wc -l

# Count generated annotations
find output/*/annotations -name "*.md" 2>/dev/null | wc -l

# Check payload content
cat output/*/payloads/*.json | jq '.'

# Check annotation content
head -20 output/*/annotations/*.md
```

### Compare Reports

```bash
# Compare JSON vs HTML report counts
echo "JSON findings: $(cat output/*/combined_findings.json | jq 'length')"
echo "HTML findings: $(grep -c '<tr>' output/*/combined_findings.html)"

# Check export formats
ls -lh output/*/combined_findings.*
```

---

## Performance Testing

### Test with Different File Counts

**Small repo (10 files)**:
```bash
python3 agentsmith.py hybrid ./small-repo ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --prioritize-top 5 \
  --verbose
```

**Medium repo (50 files)**:
```bash
python3 agentsmith.py hybrid ./medium-repo ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --prioritize-top 15 \
  --verbose
```

**Large repo (200+ files)**:
```bash
python3 agentsmith.py hybrid ./large-repo ./scanner \
  --profile owasp,ctf \
  --deduplicate \
  --prioritize-top 30 \
  --verbose
```

---

## Edge Cases

### Single Profile (Deduplication Not Needed)

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp \
  --deduplicate \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Note**: Deduplication has minimal effect with single profile, but still runs basic exact-match dedup

---

### No Deduplication (Baseline)

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf \
  --prioritize --prioritize-top 10 \
  --verbose
```
**Result**: All findings from both profiles shown separately

---

### Maximum Profiles

```bash
python3 agentsmith.py hybrid ./test_targets/DVWA ./scanner \
  --profile owasp,ctf,code_review,modern,soc2,pci,compliance \
  --deduplicate \
  --dedupe-threshold 0.6 \
  --dedupe-strategy merge \
  --prioritize --prioritize-top 20 \
  --verbose
```
**Result**: Maximum coverage with aggressive deduplication

---

### Example: Spring Boot Microservice Audit

**Scenario**: Deep security audit of a Spring Boot microservice with profile-driven prioritization

```bash
python3 agentsmith.py hybrid ./spring-microservice ./scanner \
  --profile springboot,owasp,modern \
  --prioritize \
  --prioritize-top 25 \
  --question "find actuator exposure, SpEL injection, mass assignment, and Spring Security misconfigs" \
  --deduplicate \
  --dedupe-threshold 0.75 \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html markdown \
  --output-dir ./spring-audit-reports \
  --verbose
```

**What this does**:
- Runs 3 profiles (Spring Boot, OWASP, Modern) with profile-driven prioritization
- Prioritization automatically favors *Controller.java, SecurityConfig*, application.yml, *Repository.java
- Generates payloads and annotations for top 10 findings
- Exports in all formats

### Example: C++/Conan Native Code Review

**Scenario**: Memory safety audit of a C++ project with Conan dependencies

```bash
python3 agentsmith.py hybrid ./native-lib ./scanner \
  --profile cpp_conan \
  --prioritize \
  --prioritize-top 30 \
  --question "find buffer overflows, use-after-free, format string bugs, and unsafe C functions" \
  --generate-payloads \
  --annotate-code \
  --top-n 15 \
  --export-format json markdown \
  --output-dir ./cpp-security-audit \
  --verbose
```

**What this does**:
- C++/Conan profile prioritizes parser/socket/buffer code, CMakeLists.txt, conanfile.py
- Finds CWE-120 (buffer overflow), CWE-416 (use-after-free), CWE-134 (format string), CWE-190 (integer overflow)
- Checks CMake FetchContent for unpinned dependencies
- Generates exploitation payloads for memory corruption findings

### Example: Flask Application Security Audit

**Scenario**: Security review of a Flask web application

```bash
python3 agentsmith.py hybrid ./flask-webapp ./scanner \
  --profile flask,owasp \
  --prioritize \
  --prioritize-top 20 \
  --question "find SSTI, SQLAlchemy injection, debug mode, weak secret keys" \
  --deduplicate \
  --generate-payloads \
  --annotate-code \
  --top-n 10 \
  --export-format json html \
  --output-dir ./flask-audit \
  --verbose
```

**What this does**:
- Flask profile prioritizes app.py, routes/views, auth/login modules, config.py, templates
- Finds Jinja2 SSTI, app.run(debug=True), hardcoded SECRET_KEY, SQLAlchemy raw SQL
- OWASP profile catches generic issues; deduplication merges overlapping findings

---

## Expected Output Analysis

### With Deduplication Enabled

**Console Output**:
```
📊 Stage 3: Merging Results
Merging and deduplicating findings (similarity: 0.7, strategy: keep_highest_severity)...
   Deduplicated 12 similar findings from multiple profiles
✓ 45 combined findings written to output/.../combined_findings.json
```

**JSON Output**:
```json
{
  "title": "SQL Injection Vulnerability",
  "file": "login.php",
  "line_number": 35,
  "severity": "CRITICAL",
  "source": "owasp, ctf",
  "profiles": ["owasp", "ctf"],
  "recommendation": "Use parameterized queries..."
}
```

### Without Deduplication

**JSON Output**:
```json
[
  {
    "title": "SQL Injection Vulnerability",
    "file": "login.php",
    "line_number": 35,
    "severity": "CRITICAL",
    "source": "owasp"
  },
  {
    "title": "SQL Injection Vulnerability",
    "file": "login.php",
    "line_number": 35,
    "severity": "HIGH",
    "source": "ctf"
  }
]
```

---

## Tips and Best Practices

1. **Start with lower threshold (0.6-0.7)** for initial scans, then adjust
2. **Use `merge` strategy** when you want comprehensive recommendations
3. **Use `keep_highest_severity`** for compliance/audit reports
4. **Combine profiles strategically**: Security + Compliance, or CTF + Code Review
5. **Prioritize files first** to save API costs before running multiple profiles
6. **Check deduplication stats** in console output to tune threshold
7. **Review `profiles` field** in JSON to see which profiles found duplicates

---

## Troubleshooting

### Too Many Duplicates

**Problem**: Many similar findings not being deduplicated
**Solution**: Lower threshold (0.5-0.6) or check if findings are truly similar

### Too Aggressive Deduplication

**Problem**: Different findings being merged incorrectly
**Solution**: Raise threshold (0.8-0.9) for stricter matching

### Missing Profile Information

**Problem**: `profiles` field not showing in merged findings
**Solution**: Ensure `--deduplicate` is enabled and multiple profiles are used

---

## Next Steps

1. Run examples with your test repositories
2. Compare results with/without deduplication
3. Tune threshold based on your findings
4. Choose strategy based on your use case
5. Integrate into your security workflow

