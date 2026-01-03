# SCRYNET Profile Guide

Profiles customize the AI analysis to focus on specific security domains, compliance requirements, or code quality aspects.

## Available Profiles

### Security Profiles

#### `owasp` (Default)
**Focus:** OWASP Top 10 security vulnerabilities
- A01-A10 vulnerabilities
- Injection attacks, broken access control, cryptographic failures
- **Use case:** General security audits, vulnerability assessments
- **Example:** `--profile owasp`

#### `ctf`
**Focus:** Exploitable vulnerabilities for CTF challenges
- SQL injection, command injection, file inclusion
- Hardcoded secrets, flags, credentials
- Logic flaws, bypass techniques
- **Use case:** CTF challenges, bug bounties, penetration testing
- **Example:** `--profile ctf` or `--profile owasp,ctf`

#### `attacker`
**Focus:** Threat modeling and attack scenarios
- Entry points, data flow analysis
- Attack chains and exploitation paths
- **Use case:** Threat modeling, penetration testing
- **Note:** Automatically added when using `--threat-model` flag
- **Example:** `--profile attacker` or use `--threat-model`

### Code Quality Profiles

#### `code_review`
**Focus:** Code quality and best practices
- Readability, maintainability, complexity
- Best practices, design patterns, SOLID principles
- Error handling, documentation, testing
- **Use case:** Pre-merge reviews, code quality audits, technical debt assessment
- **Example:** `--profile code_review` or `--profile owasp,code_review`

#### `performance`
**Focus:** Performance anti-patterns
- N+1 queries, inefficient algorithms
- Memory leaks, blocking I/O
- **Use case:** Performance audits, optimization reviews
- **Example:** `--profile performance` or `--profile owasp,performance`

### Modern Security Profiles

#### `modern`
**Focus:** Modern security practices
- Zero-trust architecture, supply chain security
- Cloud-native security, container security
- DevSecOps, CI/CD security
- Microservices, serverless security
- **Use case:** Modern applications, cloud deployments, DevSecOps
- **Example:** `--profile modern` or `--profile owasp,modern`

### Compliance Profiles

#### `soc2`
**Focus:** SOC 2 Type II compliance
- Access controls, encryption, monitoring
- Change management, incident response
- Trust Service Criteria (CC1-CC9)
- **Use case:** SOC 2 audits, compliance reviews
- **Example:** `--profile soc2` or `--profile soc2,compliance`

#### `pci`
**Focus:** PCI-DSS compliance
- Cardholder data protection (encryption, tokenization)
- Secure payment processing
- Access controls, logging, key management
- **Use case:** Payment processing applications, PCI audits
- **Example:** `--profile pci` or `--profile pci,compliance`

#### `compliance`
**Focus:** General regulatory compliance
- HIPAA, GDPR, CCPA, FERPA, GLBA, SOX
- Data privacy, consent management
- Audit trails, data retention, breach notification
- **Use case:** Healthcare, financial, EU applications
- **Example:** `--profile compliance` or `--profile soc2,compliance`

## Using Multiple Profiles

You can combine multiple profiles to get comprehensive analysis:

```bash
# Security + Code Quality
python3 scrynet.py hybrid ./repo ./scanner --profile owasp,code_review

# Compliance Audit
python3 scrynet.py hybrid ./repo ./scanner --profile soc2,pci,compliance

# Modern Security + Performance
python3 scrynet.py hybrid ./repo ./scanner --profile modern,performance

# CTF + OWASP (comprehensive security)
python3 scrynet.py hybrid ./repo ./scanner --profile owasp,ctf
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

## Profile Details

Each profile:
- Analyzes the same codebase
- Uses specialized prompts for its domain
- Tags findings with `source: 'claude-{profile}'`
- Results are merged into a single report
- Can be combined with other profiles

## Notes

- Profiles are case-insensitive
- Invalid profiles will cause an error
- The `attacker` profile is automatically added when using `--threat-model`
- Multiple profiles increase analysis time and API costs
- Use prioritization (`--prioritize`) with multiple profiles to save time

