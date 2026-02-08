# Agent Smith Profile Guide

Profiles customize the AI analysis to focus on specific security domains, compliance requirements, or code quality aspects. Each profile uses specialized prompts tailored to its domain.

## Listing All Profiles

To see all available profiles with descriptions and use cases:

```bash
python3 agentsmith.py hybrid . ./scanner --list-profiles
```

This command displays:
- Description and purpose of each profile
- Use cases and when to use each profile
- Focus areas and what vulnerabilities/issues they detect
- Command-line usage examples

## Available Profiles

### Security Profiles

#### `owasp` (Default)

**Focus:** OWASP Top 10 security vulnerabilities

**Description:** Comprehensive security analysis based on OWASP Top 10 vulnerabilities. Focuses on injection attacks, broken access control, cryptographic failures, and other critical security issues.

**Use Cases:**
- General security audits and vulnerability assessments
- Pre-production security reviews
- Security compliance checks
- Regular security scans

**Focus Areas:**
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection (SQL, XSS, Command)
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Software/Data Integrity
- A09: Logging/Monitoring Failures
- A10: Server-Side Request Forgery

**Examples:**
```bash
--profile owasp
--profile owasp --prioritize --prioritize-top 20
```

#### `ctf`

**Focus:** Exploitable vulnerabilities for CTF challenges

**Description:** Optimized for Capture The Flag challenges and exploitable vulnerabilities. Focuses on entry points, bypass techniques, hardcoded secrets, and attack chains that lead to unauthorized access.

**Use Cases:**
- CTF challenge analysis
- Bug bounty hunting
- Penetration testing
- Exploitation-focused reviews

**Focus Areas:**
- SQL/Command/File inclusion injection
- Path traversal and directory traversal
- Hardcoded secrets, passwords, API keys, flags
- Weak authentication and bypass techniques
- Insecure deserialization
- XSS (reflected/stored)
- SSRF vulnerabilities
- Race conditions and TOCTOU flaws
- Logic flaws and privilege escalation
- File upload vulnerabilities

**Examples:**
```bash
--profile ctf
--profile owasp,ctf --generate-payloads
```

#### `attacker`

**Focus:** Threat modeling and attack scenarios

**Description:** Threat modeling and attack scenario analysis. Analyzes entry points, data flow, attack chains, and potential exploitation paths from an attacker's perspective.

**Use Cases:**
- Threat modeling
- Attack surface analysis
- Penetration testing preparation
- Security architecture reviews

**Focus Areas:**
- Entry points and attack surfaces
- Data flow and trust boundaries
- Attack chains and exploitation paths
- Privilege escalation vectors
- Lateral movement opportunities

**Examples:**
```bash
--profile attacker
--threat-model  # Automatically uses attacker profile
```

**Note:** The `attacker` profile is automatically added when using `--threat-model` flag.

### Code Quality Profiles

#### `code_review`

**Focus:** Code quality and best practices

**Description:** Code quality and best practices analysis. Focuses on readability, maintainability, design patterns, error handling, and technical debt.

**Use Cases:**
- Pre-merge code reviews
- Code quality audits
- Technical debt assessment
- Onboarding reviews

**Focus Areas:**
- Code readability and maintainability
- Design patterns and SOLID principles
- Error handling and edge cases
- Documentation and comments
- Code complexity and refactoring opportunities
- Best practices and conventions

**Examples:**
```bash
--profile code_review
--profile owasp,code_review  # Security + Quality
```

#### `performance`

**Focus:** Performance anti-patterns

**Description:** Performance anti-patterns and optimization opportunities. Identifies inefficient algorithms, N+1 queries, memory leaks, blocking I/O, and other performance bottlenecks.

**Use Cases:**
- Performance audits
- Optimization reviews
- Scalability analysis
- Database query optimization

**Focus Areas:**
- N+1 query problems
- Inefficient loops and algorithms
- Memory leaks and large allocations
- Blocking I/O operations
- Inefficient string operations
- Caching opportunities

**Examples:**
```bash
--profile performance
--profile owasp,performance  # Security + Performance
```

### Modern Security Profiles

#### `modern`

**Focus:** Modern security practices

**Description:** Modern security practices for cloud-native, microservices, and DevSecOps environments. Focuses on zero-trust architecture, supply chain security, container security, and CI/CD security.

**Use Cases:**
- Modern application security reviews
- Cloud-native security audits
- DevSecOps pipeline reviews
- Microservices and serverless security

**Focus Areas:**
- Zero-trust architecture
- Supply chain security (SBOM, dependency checks)
- Container and Kubernetes security
- CI/CD pipeline security
- API security and microservices
- Serverless function security

**Examples:**
```bash
--profile modern
--profile owasp,modern  # Traditional + Modern
```

### Compliance Profiles

#### `soc2`

**Focus:** SOC 2 Type II compliance

**Description:** SOC 2 Type II compliance analysis. Focuses on access controls, encryption, monitoring, change management, and Trust Service Criteria (CC1-CC9).

**Use Cases:**
- SOC 2 audits and compliance reviews
- Security control assessments
- Access control reviews
- Change management compliance

**Focus Areas:**
- Access controls and authentication
- Encryption in transit and at rest
- Logging and monitoring
- Change management processes
- Incident response procedures
- Trust Service Criteria (CC1-CC9)

**Examples:**
```bash
--profile soc2
--profile soc2,compliance  # Comprehensive compliance
```

#### `pci`

**Focus:** PCI-DSS compliance

**Description:** PCI-DSS compliance analysis for payment processing applications. Focuses on cardholder data protection, encryption, tokenization, secure payment processing, and key management.

**Use Cases:**
- Payment processing application reviews
- PCI-DSS audits and compliance
- Cardholder data protection
- Payment gateway security

**Focus Areas:**
- Cardholder data protection (encryption, tokenization)
- Secure payment processing
- Access controls and authentication
- Logging and monitoring requirements
- Key management and cryptographic controls
- Network segmentation

**Examples:**
```bash
--profile pci
--profile pci,compliance  # PCI + General compliance
```

#### `compliance`

**Focus:** General regulatory compliance

**Description:** General regulatory compliance analysis covering HIPAA, GDPR, CCPA, FERPA, GLBA, SOX, and other frameworks. Focuses on data privacy, consent management, audit trails, and breach notification requirements.

**Use Cases:**
- Healthcare application reviews (HIPAA)
- EU/GDPR compliance reviews
- Financial application reviews (GLBA, SOX)
- Educational application reviews (FERPA)
- General regulatory compliance

**Focus Areas:**
- Data privacy and protection
- Consent management
- Audit trails and logging
- Data retention policies
- Breach notification procedures
- Access controls and encryption

**Examples:**
```bash
--profile compliance
--profile soc2,pci,compliance  # Comprehensive compliance
```

## Using Multiple Profiles

You can combine multiple profiles to get comprehensive analysis:

```bash
# Security + Code Quality
python3 agentsmith.py hybrid ./repo ./scanner --profile owasp,code_review

# Compliance Audit
python3 agentsmith.py hybrid ./repo ./scanner --profile soc2,pci,compliance

# Modern Security + Performance
python3 agentsmith.py hybrid ./repo ./scanner --profile modern,performance

# CTF + OWASP (comprehensive security)
python3 agentsmith.py hybrid ./repo ./scanner --profile owasp,ctf
```

## Profile Recommendations by Use Case

### Security Audit
```bash
--profile owasp,ctf,modern
```

### Compliance Review
```bash
--profile soc2,compliance  # General compliance
--profile pci,compliance   # Payment processing
--profile soc2,pci,compliance  # Comprehensive compliance
```

### Code Quality Review
```bash
--profile code_review,performance
```

### Pre-Merge Review
```bash
--profile owasp,code_review
```

### CTF Challenge
```bash
--profile ctf
```

### Modern Application Security
```bash
--profile modern,owasp
```

### Comprehensive Analysis
```bash
--profile owasp,code_review,modern,performance
```

## How Profiles Work

Each profile:
- Analyzes the same codebase using specialized prompts
- Tags findings with `source: 'claude-{profile}'`
- Results are merged into a single report
- Can be combined with other profiles for comprehensive analysis
- When used with `--deduplicate`, similar findings from multiple profiles are merged intelligently

## Important Notes

- **Default Profile:** If no profile is specified, `owasp` is used by default
- **Case Insensitive:** Profile names are case-insensitive (e.g., `OWASP`, `owasp`, `Owasp` all work)
- **Invalid Profiles:** Invalid profile names will cause an error with a list of available profiles
- **Cost Impact:** Multiple profiles increase analysis time and API costs
- **Prioritization:** Use `--prioritize` with multiple profiles to save time and cost
- **Deduplication:** Use `--deduplicate` to merge similar findings from multiple profiles (opt-in only)
- **Threat Modeling:** The `attacker` profile is automatically added when using `--threat-model` flag

## Getting Help

```bash
# List all profiles with descriptions
python3 agentsmith.py hybrid . ./scanner --list-profiles# Get help for hybrid mode
python3 agentsmith.py hybrid --help
```
