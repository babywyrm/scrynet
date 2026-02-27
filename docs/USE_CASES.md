# Agent Smith Use Cases - Simple to Complex

Detailed workflows for common security analysis scenarios. For copy-paste commands, see **[../QUICKSTART.md](../QUICKSTART.md)**.

**See also:** [examples/README.md](../examples/README.md) (CI, pre-commit) · [ADVANCED_EXAMPLES.md](ADVANCED_EXAMPLES.md) (multi-profile, deduplication) · [MCP_SCANNING.md](MCP_SCANNING.md) (scan MCP servers) · [PROFILES.md](PROFILES.md) (AI profiles)

## 🚀 Simple Use Cases (5 minutes or less)

### Use Case 1: Quick Security Check (No API Key)

**Scenario:** You want to quickly scan code before committing.

```bash
# Static scan (fast, free, no API key needed)
python3 agentsmith.py static ./myapp --severity HIGH

# Takes: ~5 seconds
# Cost: Free
# Finds: Pattern-based vulnerabilities (hardcoded secrets, weak crypto, etc.)
```

**When to use:** CI/CD pipelines, pre-commit checks, quick audits

**Pre-commit:** See [examples/README.md](../examples/README.md) for `pre-commit-hook.sh` and `.pre-commit-config.yaml` — block commits with CRITICAL findings.

---

### Use Case 2: List Available Options

**Scenario:** You're new and want to see what's available.

```bash
# See all presets
python3 orchestrator.py --list-presets

# See all AI profiles
python3 orchestrator.py --list-profiles

# Detect tech stack (understand your codebase)
python3 orchestrator.py ./myapp --detect-tech-stack
```

**When to use:** First time using Agent Smith, exploring a new codebase

---

### Use Case 3: Fast CTF Recon

**Scenario:** You have a CTF challenge and need quick wins.

```bash
export CLAUDE_API_KEY="your-key"

python3 orchestrator.py ./ctf-challenge ./scanner \
  --preset ctf-fast

# Takes: ~1-2 minutes
# Cost: ~$0.02-0.03
# Analyzes: Top 8 files
# Finds: Exploitable vulnerabilities with payloads
# Shows: Quick wins (most exploitable)
```

**When to use:** CTF challenges, bug bounty recon, quick pentest

---

## 🎯 Intermediate Use Cases (10-15 minutes)

### Use Case 4: Full CTF Analysis

**Scenario:** You want comprehensive CTF analysis with attack chains.

```bash
python3 orchestrator.py ./ctf-challenge ./scanner \
  --preset ctf \
  --show-chains

# Takes: ~3-5 minutes
# Cost: ~$0.06-0.10
# Analyzes: Top 15 files
# Features:
#   - CTF + OWASP profiles
#   - Payloads for exploitation
#   - Code annotations
#   - Quick wins display
#   - Attack chains (data flow visualization)
#   - Tech stack detection
```

**Interactive:** After prioritization, you'll see:
```
[?] Proceed with all 15 files? (Y/N/number): 
```
Type `5` to analyze only 5 files (faster, cheaper)

**When to use:** HTB machines, serious CTF challenges, comprehensive analysis

---

### Use Case 5: Targeted Vulnerability Hunt (prioritize_top + top_n)

**Scenario:** You suspect SQL injection in a specific module. Use both options for full control.

- **prioritize_top** = FILES: How many files the AI analyzes (lower=faster).
- **top_n** = FINDINGS: How many findings get payloads/annotations (default 5, max 20).

```bash
python3 agentsmith.py hybrid ./webapp/api ./scanner \
  --profile owasp \
  --prioritize --prioritize-top 10 \
  --question "find SQL injection in database queries and API endpoints" \
  --show-chains \
  --generate-payloads --annotate-code --top-n 8

# prioritize_top=10 → AI analyzes 10 files
# top_n=8 → 8 findings get payloads + annotations
# Takes: ~2-3 minutes
```

**MCP equivalent:**
```
mcp> scan_hybrid profile=owasp prioritize_top=10 top_n=8 question="find SQL injection" generate_payloads=true annotate_code=true
```

**When to use:** Focused security assessment, specific vulnerability types

---

### Use Case 6: Production Code Audit

**Scenario:** Security audit of production application.

```bash
python3 orchestrator.py ./production-app ./scanner \
  --preset security-audit \
  --output-dir ./reports/prod-audit-2026-01

# Takes: ~10-20 minutes (scans ALL files)
# Cost: ~$0.15-0.30
# Profiles: OWASP + Code Review
# Features:
#   - Comprehensive coverage
#   - All export formats
#   - Detailed annotations
#   - Quality analysis
```

**When to use:** Pre-release audits, compliance requirements, thorough review

---

## 🔥 Advanced Use Cases (20+ minutes)

### Use Case 7: Penetration Test Mode

**Scenario:** Full penetration test with all features.

```bash
python3 orchestrator.py ./target-app ./scanner \
  --preset pentest \
  --question "find authentication bypass, broken access control, and RCE" \
  --top 15

# Takes: ~5-10 minutes
# Cost: ~$0.15-0.25
# Features (EVERYTHING):
#   - 3 AI profiles (CTF + OWASP + Attacker)
#   - Tech stack detection
#   - Attack chains (cross-file)
#   - Threat modeling
#   - Quick wins
#   - Payloads (top 15)
#   - Annotations (top 15)
#   - All export formats
```

**Interactive:** Type number at prompt to reduce file count

**When to use:** Professional pentests, red team engagements, comprehensive security

---

### Use Case 8: Framework-Specific Analysis

**Scenario:** You know the framework; use a dedicated profile for deeper findings.

**Spring Boot / Java Microservices:**
```bash
python3 orchestrator.py ./spring-app ./scanner \
  --profile springboot,owasp \
  --prioritize --prioritize-top 25 \
  --question "find actuator exposure, SpEL injection, and Spring Security misconfigs"
```

Focuses on: @RestController entry points, SecurityConfig, application.yml credentials, JPA injection, OAuth2/JWT flaws

**C++ / Conan Native Code:**
```bash
python3 orchestrator.py ./cpp-project ./scanner \
  --profile cpp_conan \
  --prioritize --prioritize-top 30 \
  --question "find buffer overflows, use-after-free, and format string bugs"
```

Focuses on: Memory safety (CWE-120/416/415), unsafe C functions, CMake FetchContent without hash pinning, Conan supply chain

**Flask / Python Web App:**
```bash
python3 orchestrator.py ./flask-app ./scanner \
  --profile flask,owasp \
  --prioritize --prioritize-top 20 \
  --question "find SSTI, SQLAlchemy injection, and debug mode exposure"
```

Focuses on: Jinja2 SSTI, app.run(debug=True), weak SECRET_KEY, SQLAlchemy raw SQL, unsafe file uploads, pickle deserialization

**When to use:** Framework-specific audits. Profile-driven prioritization automatically surfaces the most relevant files for the selected framework.

---

### Use Case 9: Multi-Profile Comparison

**Scenario:** Want different perspectives on the same code.

```bash
python3 orchestrator.py ./webapp ./scanner \
  --profile ctf,owasp,code_review \
  --prioritize-top 20 \
  --deduplicate \
  --generate-payloads \
  --show-quick-wins

# Takes: ~5-8 minutes
# Profiles:
#   - CTF: Exploitation focus
#   - OWASP: Security best practices
#   - Code Review: Code quality + security
# Features:
#   - Deduplication across profiles
#   - Findings from all 3 perspectives
#   - Quick wins (most exploitable)
```

**When to use:** Comprehensive analysis, multiple viewpoints needed

---

## 💼 Real-World Scenarios

### Scenario A: HTB Machine

```bash
# Step 1: Understand the tech stack
python3 orchestrator.py ~/htb/machine/src --detect-tech-stack

# Step 2: Run comprehensive analysis
python3 orchestrator.py ~/htb/machine/src ./scanner \
  --preset ctf \
  --show-chains \
  --question "find path traversal, command injection, auth bypass, and flag locations" \
  --top 10

# Step 3: At prompt, type 8 to analyze top 8 files only

# Results:
#   - Quick wins: Instant exploitation paths
#   - Attack chains: Source → Sink visualization
#   - Payloads: Ready-to-use exploits
#   - Annotations: Code with fixes
```

**Expected time:** 3-5 minutes  
**Expected cost:** $0.06-0.10  
**Expected result:** Flag locations and exploitation paths

---

### Scenario B: Bug Bounty Program

```bash
# Quick recon
python3 orchestrator.py ./target-app ./scanner \
  --preset ctf-fast \
  --prioritize-top 10 \
  --question "find authentication bypass, IDOR, and injection vulnerabilities"

# Takes: ~2 minutes
# Cost: ~$0.03
# Perfect for: Initial reconnaissance

# If you find something, deep dive:
python3 orchestrator.py ./target-app/suspicious-module ./scanner \
  --preset ctf \
  --show-chains \
  --question "analyze specific vulnerability type" \
  --top 15
```

**When to use:** Bug bounty hunting, time-limited testing

---

### Scenario C: CI/CD Integration

```bash
# In your CI pipeline (.github/workflows/security.yml)
python3 orchestrator.py ./src ./scanner \
  --preset quick \
  --severity HIGH \
  --output-dir ./security-reports

# Takes: ~30-60 seconds
# Cost: ~$0.01-0.02
# Returns: JSON for automation
# Fails: If CRITICAL/HIGH vulnerabilities found
```

**When to use:** Automated security checks, continuous security

---

### Scenario D: Compliance Audit (SOC2, PCI-DSS)

```bash
python3 orchestrator.py ./production-app ./scanner \
  --preset compliance \
  --question "verify SOC2 security controls and PCI-DSS compliance" \
  --output-dir ./compliance-reports-2026

# Takes: ~8-12 minutes
# Profiles: OWASP + SOC2 + Compliance
# Output: JSON, CSV, HTML (for auditors)
# Focuses on: Compliance requirements, security controls
```

**When to use:** Compliance audits, regulatory requirements

---

## 🎓 Learning Examples

### Example 1: Compare Security Levels

**Scenario:** Learn how DVWA implements different security levels.

```bash
# Scan low.php
python3 orchestrator.py tests/test_targets/DVWA/vulnerabilities/sqli/source/low.php ./scanner \
  --profile owasp \
  --annotate-code

# Scan impossible.php
python3 orchestrator.py tests/test_targets/DVWA/vulnerabilities/sqli/source/impossible.php ./scanner \
  --profile owasp \
  --annotate-code

# Compare annotations to see secure vs insecure implementations
```

---

### Example 2: Estimate Cost Before Running

**Scenario:** You want to know API costs before running expensive scan.

```bash
python3 orchestrator.py ./large-repo ./scanner \
  --preset security-audit \
  --estimate-cost

# Shows:
#   - Total files to scan
#   - Estimated API calls
#   - Estimated tokens
#   - Estimated cost
# Exits without running (no charges)
```

---

## 🔧 Power User Examples

### Custom Scan with All Features

```bash
python3 orchestrator.py ./target ./scanner \
  --profile ctf,owasp \
  --prioritize --prioritize-top 20 \
  --question "find RCE, SQLi, and auth bypass" \
  --generate-payloads \
  --annotate-code \
  --show-chains \
  --show-quick-wins \
  --deduplicate \
  --export-format json html markdown \
  --output-dir ./detailed-report \
  --top 10 \
  --verbose

# Everything enabled!
# Takes: ~5-8 minutes
# Cost: ~$0.12-0.18
```

---

### Iterative Analysis (Resume)

```bash
# First run (use review state)
python3 agentsmith.py analyze ./app "find vulnerabilities" --enable-review-state

# Later, resume
python3 agentsmith.py analyze ./app --resume-last

# Or resume specific review
python3 agentsmith.py analyze ./app --resume-review abc123
```

**When to use:** Large codebases, interrupted scans, iterative analysis

---

## 📋 Preset Quick Reference

| Preset | Files | Time | Cost | Use For |
|--------|-------|------|------|---------|
| `quick` | 10 | ~1min | $0.02 | CI/CD, quick checks |
| `ctf-fast` | 8 | ~2min | $0.03 | Fast CTF recon |
| `ctf` | 15 | ~3-5min | $0.06-0.10 | Full CTF analysis |
| `security-audit` | ALL | ~10-20min | $0.15-0.30 | Comprehensive audit |
| `pentest` | 20 | ~5-10min | $0.15-0.25 | Professional pentest |
| `compliance` | 25 | ~8-12min | $0.12-0.20 | SOC2, PCI-DSS compliance |

---

## 💡 Tips & Tricks

### Reduce Costs

```bash
# Use --prioritize-top to analyze fewer files
--prioritize-top 10  # Instead of 15

# Skip expensive features
--preset ctf-fast  # Instead of ctf (no annotations)

# Use --estimate-cost first
--estimate-cost  # See cost before running
```

### Better Results

```bash
# Be specific in --question
--question "find SQL injection in user authentication"  # Good
--question "find bugs"  # Bad (too vague)

# Use --show-chains for complex vulnerabilities
--show-chains  # See data flow across files

# Enable --show-quick-wins for CTF
--show-quick-wins  # Highlights easy wins
```

### Speed Up Scans

```bash
# Use --parallel for large repos
--parallel  # Analyze files in parallel

# Reduce --top-n
--top 5  # Instead of 15 (fewer payloads)

# Use smaller targets
./specific-module  # Instead of entire repo
```

---

## 🎯 Common Workflows

### Daily Developer Workflow
```bash
# Morning: Quick check before standup
python3 agentsmith.py static . --severity HIGH

# Found issue: Deep dive
python3 orchestrator.py ./problematic-module ./scanner --preset ctf-fast
```

### Security Researcher Workflow
```bash
# 1. Reconnaissance
python3 orchestrator.py ./target --detect-tech-stack

# 2. Initial scan
python3 orchestrator.py ./target ./scanner --preset ctf --top 10

# 3. Deep dive on findings
python3 orchestrator.py ./target/vulnerable-file.php ./scanner \
  --profile owasp --annotate-code --show-chains
```

### CTF Player Workflow
```bash
# 1. Fast scan to find obvious issues
python3 orchestrator.py ./challenge ./scanner --preset ctf-fast

# 2. If no obvious wins, full analysis
python3 orchestrator.py ./challenge ./scanner \
  --preset ctf \
  --show-chains \
  --question "find flag locations and RCE vectors"

# 3. Check attack chains for exploitation paths
cat output/*/attack_chains.json | jq '.[] | select(.exploitability_score >= 9)'
```

---

## 🏆 Pro Tips

1. **Always detect tech stack first** on unknown codebases
2. **Use --question** to focus AI on specific vulnerabilities
3. **Start with ctf-fast**, upgrade to `ctf` if needed
4. **Use interactive prompt** to reduce file count (save money)
5. **Check quick wins first** - easiest exploitation paths
6. **Review attack_chains.json** for complex multi-file vulnerabilities
7. **Use --estimate-cost** for large repos before running
8. **Keep --top small** (5-10) for faster results

---

## 📚 More Examples

See:
- [README.md](README.md) - Complete feature documentation
- [ADVANCED_EXAMPLES.md](docs/ADVANCED_EXAMPLES.md) - Complex multi-profile workflows
- [PROFILES.md](PROFILES.md) - AI profile descriptions
- [MCP_SCANNING.md](MCP_SCANNING.md) - Security-scan MCP servers

### MCP Shell (Interactive)

**Scenario:** You use Cursor or want to scan from an interactive shell.

```bash
./scripts/run_mcp_shell.sh
# At mcp> prompt:
scan_hybrid {"preset": "mcp"}                    # 2 files, ~1 min
scan_mcp {"target_url": "http://localhost:9001/sse"}  # Scan DVMCP
summary
findings 20
```

See [mcp_server/README.md](../mcp_server/README.md) and [MCP_SCANNING.md](MCP_SCANNING.md).

## 🚀 Quick Start

**Your first scan:**
```bash
export CLAUDE_API_KEY="your-key"
python3 orchestrator.py ./target ./scanner --preset ctf --verbose
```

**Wait for interactive prompt, type a number (like 5) to analyze fewer files.**

Happy hunting! 🏴‍☠️

