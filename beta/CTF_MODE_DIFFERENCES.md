# CTF Mode vs Regular Mode - Behavioral Differences

This document explains exactly what changes when you use `--ctf-mode` in `smart__.py`.

## Summary

**Regular Mode**: General-purpose security analysis focused on comprehensive security review, remediation, and industry best practices.

**CTF Mode**: Exploitation-focused analysis optimized for finding exploitable vulnerabilities quickly, with emphasis on attack paths and quick wins.

---

## 1. File Prioritization Stage

### Regular Mode
- **Role**: "Lead software architect"
- **Focus**: Files most relevant to answering the user's question
- **Approach**: General relevance based on the question
- **Example reasoning**: "This file likely handles user creation and authentication, which is central to the user's security question."

### CTF Mode
- **Role**: "CTF security expert"
- **Focus**: Files most likely to contain **vulnerabilities or flags**
- **Approach**: Explicit CTF priority checklist:
  - Entry points (index.php, main.py, routes, controllers)
  - Authentication files (login, auth, session, token)
  - Configuration files (.env, secrets, credentials)
  - Database files (SQL, models with user input)
  - File operations (upload, download, file inclusion)
  - API endpoints
  - Admin panels
  - Crypto/encoding functions
- **Example reasoning**: "Authentication entry point - likely contains SQL injection, weak password checks, or session vulnerabilities"

**Result**: CTF mode prioritizes files that are common attack vectors, while regular mode prioritizes files relevant to the question.

---

## 2. Deep Dive Analysis Stage

### Regular Mode
- **Role**: "Principal Application Security Engineer"
- **Focus**: "Meticulous, pragmatic analysis mapping to industry standards"
- **Finding description**: "A concise description of the specific security weakness"
- **Recommendation**: "A specific, actionable recommendation with a brief 'why'"
- **Approach**: General security analysis

### CTF Mode
- **Role**: "CTF security expert"
- **Focus**: "Exploitable vulnerabilities that could lead to flags or unauthorized access"
- **Explicit CTF Vulnerability Checklist**:
  - ✓ SQL Injection (unparameterized queries, string concatenation)
  - ✓ Command Injection (system(), exec(), shell_exec(), backticks)
  - ✓ File Inclusion (include, require, file_get_contents with user input)
  - ✓ Path Traversal (../, directory traversal, file operations)
  - ✓ Hardcoded Secrets (passwords, API keys, flags, tokens in code)
  - ✓ Weak Authentication (bypassable login, default creds, weak checks)
  - ✓ Insecure Deserialization (unpickle, unserialize, eval with user data)
  - ✓ XSS (reflected/stored, unescaped output)
  - ✓ SSRF (server-side requests with user-controlled URLs)
  - ✓ Crypto Weaknesses (weak algorithms, hardcoded keys, predictable IVs)
  - ✓ Race Conditions (file operations, TOCTOU)
  - ✓ Logic Flaws (price manipulation, privilege escalation, bypasses)
- **Finding description**: "A concise description of the specific **exploitable** vulnerability. If you find a potential flag or secret, mention it explicitly."
- **Recommendation**: "Specific **exploitation path** or remediation. For CTF, focus on **how to exploit this**."

**Result**: CTF mode actively looks for exploitable vulnerabilities and flags, while regular mode looks for security weaknesses in general.

---

## 3. Synthesis/Report Stage

### Regular Mode
- **Role**: "Principal software architect"
- **Report Structure**:
  1. **Executive Summary**: High-level overview for non-technical manager, business risk focus
  2. **Key Patterns & Root Causes**: Groups findings into patterns (e.g., "Systemic Lack of Input Validation")
  3. **Prioritized Action Plan**: Steps for development team, highest-impact/lowest-effort first
- **Focus**: Strategic remediation and business impact

### CTF Mode
- **Role**: "CTF security expert creating an exploitation roadmap"
- **Report Structure**:
  1. **Quick Wins (Exploitable Now)**: Highest-impact, easiest-to-exploit vulnerabilities first
     - Vulnerability type
     - File and line number
     - Brief exploitation path (how to trigger it)
     - Expected outcome (what you can achieve)
  2. **Potential Flags/Secrets**: Hardcoded credentials, API keys, tokens, flag locations
  3. **Exploitation Priority**: Ranked by exploitability, impact, and confidence
  4. **Next Steps**: Concrete actions - which files to examine next, what payloads to try
- **Focus**: Exploitation roadmap and attack paths

**Result**: CTF mode produces an exploitation guide, while regular mode produces a remediation plan.

---

## 4. Payload Generation

### Regular Mode
- **Role**: "Security testing expert"
- **Payloads Generated**:
  - `red_team_payload`: Simple, non-destructive payload to verify flaw existence
  - `blue_team_payload`: Payload for unit test or WAF rule to test the fix
- **Focus**: Verification and defensive testing

### CTF Mode
- **Role**: "CTF exploitation expert"
- **Payloads Generated**:
  - `exploitation_payload`: Working payload for CTF exploitation
    - Payload text
    - How it works and what it achieves
    - **Expected result** (e.g., flag output, RCE, file read)
  - `alternative_payloads`: Alternative variants with use cases
- **Focus**: Practical exploitation with expected outcomes

**Result**: CTF mode generates exploitation payloads with expected results, while regular mode generates verification/testing payloads.

---

## 5. Code Annotation

### Regular Mode
- **Comments Added**:
  - `// FLAW: [Brief summary of the flaw]`
  - `// FIX: [Corrected code line(s)]`
- **Focus**: Showing the flaw and the fix

### CTF Mode
- **Comments Added**:
  - `// VULN: [Brief description]`
  - `// EXPLOIT: [How to exploit this]`
  - `// PAYLOAD: [Example payload]`
- **Focus**: Showing the vulnerability and how to exploit it

**Result**: CTF annotations focus on exploitation, while regular annotations focus on remediation.

---

## 6. Cache Separation

### Regular Mode
- **Cache namespace**: `smart/<repo_hash>/<model>/`
- **Shared with**: Other regular analyses

### CTF Mode
- **Cache namespace**: `ctf/<repo_hash>/<model>/`
- **Shared with**: Other CTF analyses only

**Result**: CTF and regular analyses don't share cache entries, preventing cross-contamination.

---

## 7. Stage Titles

### Regular Mode
- Stage 1: "Stage 1: Prioritization"
- Stage 2: "Stage 2: Deep Dive"
- Stage 3: "Stage 3: Synthesis"

### CTF Mode
- Stage 1: "🎯 CTF Stage 1: Prioritization"
- Stage 2: "🔍 CTF Stage 2: Deep Dive Analysis"
- Stage 3: "📊 CTF Stage 3: Synthesis & Exploitation Roadmap"

**Result**: Visual distinction in console output.

---

## When to Use Each Mode

### Use Regular Mode When:
- Performing comprehensive security audits
- Creating remediation plans for production code
- Need business-focused risk assessment
- Want industry-standard security analysis
- Building security into development workflow

### Use CTF Mode When:
- Participating in CTF competitions
- Penetration testing exercises
- Need quick vulnerability discovery
- Want exploitation-focused analysis
- Security training scenarios
- Need to find flags or secrets quickly

---

## Example Output Differences

### Regular Mode Finding:
```
Finding: SQL query uses string concatenation, creating injection risk
Recommendation: Use parameterized queries with prepared statements to prevent SQL injection attacks.
```

### CTF Mode Finding:
```
Finding: SQL Injection via unparameterized query - exploitable to bypass authentication
Recommendation: Exploit by injecting ' OR '1'='1' -- to bypass login, or UNION SELECT to extract data
```

### Regular Mode Synthesis:
```
Executive Summary: The codebase shows systemic issues with input validation...

Key Patterns:
1. Systemic Lack of Input Validation
2. Inconsistent Error Handling

Prioritized Action Plan:
1. Implement input validation framework...
```

### CTF Mode Synthesis:
```
Quick Wins (Exploitable Now):
1. SQL Injection in login.php:line 45
   - Exploitation: Inject ' OR '1'='1' -- in username field
   - Expected: Bypass authentication, gain admin access

Potential Flags/Secrets:
- Hardcoded admin password in config.php:line 12
- JWT secret key exposed in .env file

Exploitation Priority:
1. SQL Injection (High exploitability, Critical impact, 95% confidence)
2. Hardcoded credentials (High exploitability, Critical impact, 100% confidence)
```

---

## Summary Table

| Aspect | Regular Mode | CTF Mode |
|--------|-------------|----------|
| **Prioritization** | Question-relevant files | Vulnerability-prone files |
| **Analysis Focus** | Security weaknesses | Exploitable vulnerabilities |
| **Finding Description** | Security weakness | Exploitable vulnerability + flags |
| **Recommendation** | Remediation steps | Exploitation path |
| **Synthesis** | Executive summary + action plan | Exploitation roadmap + quick wins |
| **Payloads** | Verification/testing | Exploitation with expected results |
| **Annotations** | Flaw + Fix | Vulnerability + Exploit + Payload |
| **Cache** | `smart/` namespace | `ctf/` namespace |
| **Best For** | Production security reviews | CTF challenges, pentesting |

---

## Conclusion

CTF mode is not just a different prompt - it fundamentally changes the analysis approach from "find and fix security issues" to "find and exploit vulnerabilities quickly." The prompts, output format, and focus areas are all optimized for exploitation rather than remediation.

