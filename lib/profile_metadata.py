#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Profile metadata definitions for Agent Smith AI analysis profiles.

Each profile includes:
- Description: What the profile focuses on
- Use cases: When to use this profile
- Key focus areas: What vulnerabilities/issues it detects
- Examples: Command-line usage examples
- Prioritization hints: Guidance for the AI file-prioritization stage
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class PrioritizationHints:
    """Hints injected into the AI prioritization prompt so that
    profile-specific knowledge drives file selection."""
    file_patterns: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    focus_guidance: str = ""


@dataclass
class ProfileMetadata:
    """Metadata for an AI analysis profile."""
    name: str
    display_name: str
    description: str
    use_cases: List[str]
    focus_areas: List[str]
    examples: List[str]
    category: str  # "security", "compliance", "code_quality", "framework"
    default: bool = False
    prioritization_hints: Optional[PrioritizationHints] = None


# Profile metadata registry
PROFILE_METADATA: Dict[str, ProfileMetadata] = {
    "owasp": ProfileMetadata(
        name="owasp",
        display_name="OWASP Top 10",
        description="Comprehensive security analysis based on OWASP Top 10 vulnerabilities. Focuses on injection attacks, broken access control, cryptographic failures, and other critical security issues.",
        use_cases=[
            "General security audits and vulnerability assessments",
            "Pre-production security reviews",
            "Security compliance checks",
            "Regular security scans"
        ],
        focus_areas=[
            "A01: Broken Access Control",
            "A02: Cryptographic Failures",
            "A03: Injection (SQL, XSS, Command)",
            "A04: Insecure Design",
            "A05: Security Misconfiguration",
            "A06: Vulnerable Components",
            "A07: Authentication Failures",
            "A08: Software/Data Integrity",
            "A09: Logging/Monitoring Failures",
            "A10: Server-Side Request Forgery"
        ],
        examples=[
            "--profile owasp",
            "--profile owasp --prioritize --prioritize-top 20"
        ],
        category="security",
        default=True,
        prioritization_hints=PrioritizationHints(
            file_patterns=["*auth*", "*login*", "*session*", "*config*", "*route*", "*controller*", "*middleware*", "*api*"],
            extensions=[],
            focus_guidance="Prioritize files that handle authentication, authorization, user input, database queries, session management, and configuration. Entry points (routes, controllers, API handlers) and middleware are high value.",
        ),
    ),

    "ctf": ProfileMetadata(
        name="ctf",
        display_name="CTF / Exploitation",
        description="Optimized for Capture The Flag challenges and exploitable vulnerabilities. Focuses on entry points, bypass techniques, hardcoded secrets, and attack chains that lead to unauthorized access.",
        use_cases=[
            "CTF challenge analysis",
            "Bug bounty hunting",
            "Penetration testing",
            "Exploitation-focused reviews"
        ],
        focus_areas=[
            "SQL/Command/File inclusion injection",
            "Path traversal and directory traversal",
            "Hardcoded secrets, passwords, API keys, flags",
            "Weak authentication and bypass techniques",
            "Insecure deserialization",
            "XSS (reflected/stored)",
            "SSRF vulnerabilities",
            "Race conditions and TOCTOU flaws",
            "Logic flaws and privilege escalation",
            "File upload vulnerabilities"
        ],
        examples=[
            "--profile ctf",
            "--profile owasp,ctf --generate-payloads"
        ],
        category="security",
        prioritization_hints=PrioritizationHints(
            file_patterns=["*flag*", "*secret*", "*upload*", "*admin*", "*login*", "*exec*", "*cmd*", "*eval*", "*deserializ*"],
            extensions=[],
            focus_guidance="Prioritize files likely to contain exploitable vulnerabilities: entry points with user input, file upload handlers, admin panels, command execution wrappers, deserialization code, and anything referencing flags or secrets.",
        ),
    ),

    "attacker": ProfileMetadata(
        name="attacker",
        display_name="Attacker Perspective",
        description="Threat modeling and attack scenario analysis. Analyzes entry points, data flow, attack chains, and potential exploitation paths from an attacker's perspective.",
        use_cases=[
            "Threat modeling",
            "Attack surface analysis",
            "Penetration testing preparation",
            "Security architecture reviews"
        ],
        focus_areas=[
            "Entry points and attack surfaces",
            "Data flow and trust boundaries",
            "Attack chains and exploitation paths",
            "Privilege escalation vectors",
            "Lateral movement opportunities"
        ],
        examples=[
            "--profile attacker",
            "--threat-model  # Automatically uses attacker profile"
        ],
        category="security",
        prioritization_hints=PrioritizationHints(
            file_patterns=["*route*", "*handler*", "*controller*", "*gateway*", "*proxy*", "*api*", "*auth*", "*token*"],
            extensions=[],
            focus_guidance="Prioritize external-facing entry points (routes, API handlers, gateways, proxies), authentication/authorization code, and trust boundary crossings. Files that accept and process untrusted input are highest priority.",
        ),
    ),

    "code_review": ProfileMetadata(
        name="code_review",
        display_name="Code Review",
        description="Code quality and best practices analysis. Focuses on readability, maintainability, design patterns, error handling, and technical debt.",
        use_cases=[
            "Pre-merge code reviews",
            "Code quality audits",
            "Technical debt assessment",
            "Onboarding reviews"
        ],
        focus_areas=[
            "Code readability and maintainability",
            "Design patterns and SOLID principles",
            "Error handling and edge cases",
            "Documentation and comments",
            "Code complexity and refactoring opportunities",
            "Best practices and conventions"
        ],
        examples=[
            "--profile code_review",
            "--profile owasp,code_review  # Security + Quality"
        ],
        category="code_quality",
        prioritization_hints=PrioritizationHints(
            file_patterns=["*service*", "*manager*", "*helper*", "*util*", "*handler*", "*model*"],
            extensions=[],
            focus_guidance="Prioritize core business-logic files (services, managers, handlers) and utility modules where code complexity and technical debt tend to accumulate. Skip auto-generated and test files.",
        ),
    ),

    "performance": ProfileMetadata(
        name="performance",
        display_name="Performance",
        description="Performance anti-patterns and optimization opportunities. Identifies inefficient algorithms, N+1 queries, memory leaks, blocking I/O, and other performance bottlenecks.",
        use_cases=[
            "Performance audits",
            "Optimization reviews",
            "Scalability analysis",
            "Database query optimization"
        ],
        focus_areas=[
            "N+1 query problems",
            "Inefficient loops and algorithms",
            "Memory leaks and large allocations",
            "Blocking I/O operations",
            "Inefficient string operations",
            "Caching opportunities"
        ],
        examples=[
            "--profile performance",
            "--profile owasp,performance  # Security + Performance"
        ],
        category="code_quality",
        prioritization_hints=PrioritizationHints(
            file_patterns=["*repository*", "*dao*", "*query*", "*service*", "*handler*", "*worker*", "*cache*", "*batch*"],
            extensions=[],
            focus_guidance="Prioritize database access layers (repositories, DAOs, query builders), service classes with business logic loops, background workers, batch processors, and caching layers where performance bottlenecks are most likely.",
        ),
    ),

    "modern": ProfileMetadata(
        name="modern",
        display_name="Modern Security",
        description="Modern security practices for cloud-native, microservices, and DevSecOps environments. Focuses on zero-trust architecture, supply chain security, container security, and CI/CD security.",
        use_cases=[
            "Modern application security reviews",
            "Cloud-native security audits",
            "DevSecOps pipeline reviews",
            "Microservices and serverless security"
        ],
        focus_areas=[
            "Zero-trust architecture",
            "Supply chain security (SBOM, dependency checks)",
            "Container and Kubernetes security",
            "CI/CD pipeline security",
            "API security and microservices",
            "Serverless function security"
        ],
        examples=[
            "--profile modern",
            "--profile owasp,modern  # Traditional + Modern"
        ],
        category="security",
        prioritization_hints=PrioritizationHints(
            file_patterns=["Dockerfile*", "docker-compose*", "*.yml", "*.yaml", "*gateway*", "*proxy*", "*lambda*", "*serverless*", ".github/workflows/*", "Jenkinsfile*"],
            extensions=[".yml", ".yaml", ".tf", ".hcl"],
            focus_guidance="Prioritize infrastructure-as-code (Dockerfiles, Kubernetes manifests, Terraform), CI/CD pipeline configs, API gateway definitions, serverless function handlers, and dependency manifests. These are where modern security issues concentrate.",
        ),
    ),

    "soc2": ProfileMetadata(
        name="soc2",
        display_name="SOC 2 Compliance",
        description="SOC 2 Type II compliance analysis. Focuses on access controls, encryption, monitoring, change management, and Trust Service Criteria (CC1-CC9).",
        use_cases=[
            "SOC 2 audits and compliance reviews",
            "Security control assessments",
            "Access control reviews",
            "Change management compliance"
        ],
        focus_areas=[
            "Access controls and authentication",
            "Encryption in transit and at rest",
            "Logging and monitoring",
            "Change management processes",
            "Incident response procedures",
            "Trust Service Criteria (CC1-CC9)"
        ],
        examples=[
            "--profile soc2",
            "--profile soc2,compliance  # Comprehensive compliance"
        ],
        category="compliance",
        prioritization_hints=PrioritizationHints(
            file_patterns=["*auth*", "*encrypt*", "*crypto*", "*log*", "*audit*", "*monitor*", "*config*", "*access*"],
            extensions=[],
            focus_guidance="Prioritize authentication/authorization modules, encryption and cryptographic implementations, logging and audit-trail code, access-control configuration, and monitoring setup. SOC 2 cares about controls, not features.",
        ),
    ),

    "pci": ProfileMetadata(
        name="pci",
        display_name="PCI-DSS Compliance",
        description="PCI-DSS compliance analysis for payment processing applications. Focuses on cardholder data protection, encryption, tokenization, secure payment processing, and key management.",
        use_cases=[
            "Payment processing application reviews",
            "PCI-DSS audits and compliance",
            "Cardholder data protection",
            "Payment gateway security"
        ],
        focus_areas=[
            "Cardholder data protection (encryption, tokenization)",
            "Secure payment processing",
            "Access controls and authentication",
            "Logging and monitoring requirements",
            "Key management and cryptographic controls",
            "Network segmentation"
        ],
        examples=[
            "--profile pci",
            "--profile pci,compliance  # PCI + General compliance"
        ],
        category="compliance",
        prioritization_hints=PrioritizationHints(
            file_patterns=["*payment*", "*card*", "*checkout*", "*billing*", "*stripe*", "*token*", "*encrypt*", "*key*"],
            extensions=[],
            focus_guidance="Prioritize payment processing code, checkout flows, billing modules, tokenization logic, encryption/key-management files, and any file that handles or stores cardholder data (PAN, CVV, expiry).",
        ),
    ),

    "compliance": ProfileMetadata(
        name="compliance",
        display_name="Regulatory Compliance",
        description="General regulatory compliance analysis covering HIPAA, GDPR, CCPA, FERPA, GLBA, SOX, and other frameworks. Focuses on data privacy, consent management, audit trails, and breach notification requirements.",
        use_cases=[
            "Healthcare application reviews (HIPAA)",
            "EU/GDPR compliance reviews",
            "Financial application reviews (GLBA, SOX)",
            "Educational application reviews (FERPA)",
            "General regulatory compliance"
        ],
        focus_areas=[
            "Data privacy and protection",
            "Consent management",
            "Audit trails and logging",
            "Data retention policies",
            "Breach notification procedures",
            "Access controls and encryption"
        ],
        examples=[
            "--profile compliance",
            "--profile soc2,pci,compliance  # Comprehensive compliance"
        ],
        category="compliance",
        prioritization_hints=PrioritizationHints(
            file_patterns=["*privacy*", "*consent*", "*gdpr*", "*pii*", "*user*data*", "*audit*", "*retention*", "*log*"],
            extensions=[],
            focus_guidance="Prioritize files dealing with personal data (PII/PHI), consent management, data retention/deletion logic, audit trails, and user-data export. Any file that stores, processes, or transmits regulated data is high priority.",
        ),
    ),

    # ---- New framework-specific profiles ----

    "springboot": ProfileMetadata(
        name="springboot",
        display_name="Spring Boot / Microservices",
        description="Security analysis for Spring Boot and Java microservice architectures. Covers actuator exposure, SpEL injection, mass assignment, JPA/Hibernate injection, Spring Security misconfiguration, OAuth2/JWT issues, and service-mesh concerns.",
        use_cases=[
            "Spring Boot application security audits",
            "Java microservices security reviews",
            "Spring Security configuration reviews",
            "API gateway and service-mesh audits"
        ],
        focus_areas=[
            "Actuator endpoint exposure",
            "Spring Expression Language (SpEL) injection",
            "Mass assignment via @RequestBody / @ModelAttribute",
            "JPA/Hibernate HQL/JPQL injection",
            "Spring Security filter-chain misconfiguration",
            "CORS and CSRF misconfiguration",
            "OAuth2 / JWT token handling flaws",
            "Eureka / Zuul / Spring Cloud Gateway misconfig",
            "Insecure deserialization (Jackson, Kryo)",
            "Sensitive data in application.yml / application.properties"
        ],
        examples=[
            "--profile springboot",
            "--profile springboot,owasp --prioritize --prioritize-top 25",
            "--profile springboot,modern  # Microservices + modern security"
        ],
        category="framework",
        prioritization_hints=PrioritizationHints(
            file_patterns=[
                "*Controller.java", "*RestController*", "*SecurityConfig*",
                "*WebSecurityConfig*", "*AuthConfig*", "*JwtFilter*",
                "*Repository.java", "*Service.java", "*Config.java",
                "application.yml", "application.properties", "application-*.yml",
                "bootstrap.yml", "pom.xml", "build.gradle*",
            ],
            extensions=[".java", ".xml", ".yml", ".yaml", ".properties", ".gradle"],
            focus_guidance=(
                "This is a Spring Boot / Java microservices scan. Prioritize: "
                "(1) @RestController and @Controller classes (HTTP entry points), "
                "(2) Spring Security configuration (SecurityConfig, WebSecurityConfig, filter chains), "
                "(3) application.yml / application.properties (credentials, actuator exposure, debug flags), "
                "(4) @Repository / JPA entity classes (injection surface), "
                "(5) @Service classes with business logic, "
                "(6) Gateway/proxy configs (Zuul, Spring Cloud Gateway), "
                "(7) OAuth2/JWT token handling code. "
                "Files named *Controller*, *Security*, *Config*, *Repository* are almost always relevant."
            ),
        ),
    ),

    "cpp_conan": ProfileMetadata(
        name="cpp_conan",
        display_name="C++ / Conan / Native Security",
        description="Security analysis for C/C++ codebases with Conan, CMake, or vcpkg dependency management. Focuses on memory safety, buffer overflows, format string bugs, integer overflows, use-after-free, and supply-chain risks in native build systems.",
        use_cases=[
            "C/C++ application security audits",
            "Embedded and IoT firmware reviews",
            "Native library and SDK security reviews",
            "CMake / Conan supply-chain audits"
        ],
        focus_areas=[
            "Buffer overflows (stack and heap) — CWE-120, CWE-122",
            "Use-after-free — CWE-416",
            "Double-free — CWE-415",
            "Format string vulnerabilities — CWE-134",
            "Integer overflow / wraparound — CWE-190",
            "Unsafe C functions (gets, strcpy, sprintf, strcat)",
            "Null pointer dereference — CWE-476",
            "Race conditions in multithreaded code — CWE-362",
            "CMake FetchContent / ExternalProject without hash pinning",
            "Conan dependency vulnerabilities and version pinning",
            "Improper input validation on network/IPC buffers"
        ],
        examples=[
            "--profile cpp_conan",
            "--profile cpp_conan,owasp --prioritize --prioritize-top 30",
            "--profile cpp_conan,performance  # Memory safety + performance"
        ],
        category="framework",
        prioritization_hints=PrioritizationHints(
            file_patterns=[
                "main.cpp", "main.c", "CMakeLists.txt", "conanfile.py",
                "conanfile.txt", "vcpkg.json", "*socket*", "*network*",
                "*buffer*", "*parser*", "*protocol*", "*crypto*", "*auth*",
                "*serialize*", "*alloc*", "*memory*",
            ],
            extensions=[".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".cmake"],
            focus_guidance=(
                "This is a C/C++ native code security scan. Prioritize: "
                "(1) Files with network/socket I/O (attack surface for buffer overflows), "
                "(2) Parsers and protocol handlers (complex input processing = high vuln density), "
                "(3) Memory management code (allocators, custom containers, RAII wrappers), "
                "(4) Cryptographic implementations, "
                "(5) CMakeLists.txt and conanfile.py/txt (supply-chain: unpinned deps, FetchContent without hashes), "
                "(6) Any file using C string functions (strcpy, sprintf, gets, strcat), "
                "(7) Multithreaded code (mutex, atomic, thread). "
                "Header files (.h/.hpp) that define buffer sizes, struct layouts, or API contracts are also important."
            ),
        ),
    ),

    "flask": ProfileMetadata(
        name="flask",
        display_name="Flask / Python Web Security",
        description="Security analysis for Python Flask web applications. Covers SSTI via Jinja2, debug mode exposure, weak secret keys, SQLAlchemy injection, session fixation, unsafe file uploads, pickle deserialization, and blueprint authorization bypass.",
        use_cases=[
            "Flask application security audits",
            "Python web API security reviews",
            "Jinja2 template injection assessments",
            "SQLAlchemy / database security reviews"
        ],
        focus_areas=[
            "Server-Side Template Injection (SSTI) via Jinja2",
            "Debug mode exposure (app.run(debug=True))",
            "Weak or hardcoded SECRET_KEY",
            "SQLAlchemy raw SQL and text() injection",
            "Session fixation and cookie security",
            "CORS misconfiguration (flask-cors)",
            "Unsafe file uploads (path traversal, unrestricted types)",
            "Pickle / marshal deserialization of untrusted data",
            "Missing CSRF protection",
            "Blueprint authorization bypass",
            "Insecure direct object references in view functions"
        ],
        examples=[
            "--profile flask",
            "--profile flask,owasp --prioritize --prioritize-top 20",
            "--profile flask,code_review  # Security + quality"
        ],
        category="framework",
        prioritization_hints=PrioritizationHints(
            file_patterns=[
                "app.py", "wsgi.py", "config.py", "settings.py",
                "*routes*", "*views*", "*auth*", "*login*",
                "*models*", "*forms*", "*upload*", "*api*",
                "*__init__.py", "requirements.txt",
            ],
            extensions=[".py", ".html", ".jinja2", ".j2", ".cfg", ".ini"],
            focus_guidance=(
                "This is a Flask / Python web security scan. Prioritize: "
                "(1) app.py / wsgi.py / __init__.py (app factory, debug mode, secret_key), "
                "(2) Route/view files (user input entry points, IDOR, auth checks), "
                "(3) Template files (.html/.jinja2) for SSTI vectors, "
                "(4) Model files with SQLAlchemy queries (raw SQL, text() calls), "
                "(5) Auth/login modules (session handling, password storage, CSRF), "
                "(6) File upload handlers (path traversal, unrestricted types), "
                "(7) config.py / settings.py (hardcoded secrets, debug flags, database URIs). "
                "Blueprint __init__.py files often contain authorization decorators worth reviewing."
            ),
        ),
    ),
}


def get_all_profiles() -> Dict[str, ProfileMetadata]:
    """Get all available profiles."""
    return PROFILE_METADATA.copy()


def get_profile(name: str) -> ProfileMetadata:
    """Get metadata for a specific profile."""
    name_lower = name.lower()
    if name_lower not in PROFILE_METADATA:
        raise ValueError(f"Unknown profile: {name}. Available profiles: {', '.join(PROFILE_METADATA.keys())}")
    return PROFILE_METADATA[name_lower]


def get_prioritization_hints_for_profiles(profile_names: List[str]) -> List[PrioritizationHints]:
    """Collect prioritization hints for a list of active profiles."""
    hints = []
    for name in profile_names:
        name_lower = name.lower().strip()
        meta = PROFILE_METADATA.get(name_lower)
        if meta and meta.prioritization_hints:
            hints.append(meta.prioritization_hints)
    return hints


def list_profiles_by_category() -> Dict[str, List[ProfileMetadata]]:
    """List profiles grouped by category."""
    categories: Dict[str, List[ProfileMetadata]] = {}
    for profile in PROFILE_METADATA.values():
        if profile.category not in categories:
            categories[profile.category] = []
        categories[profile.category].append(profile)
    return categories


def validate_profiles(profile_names: List[str]) -> List[str]:
    """Validate a list of profile names and return normalized names."""
    valid = []
    invalid = []
    for name in profile_names:
        name_lower = name.lower().strip()
        if name_lower in PROFILE_METADATA:
            valid.append(name_lower)
        else:
            invalid.append(name)
    if invalid:
        available = ', '.join(PROFILE_METADATA.keys())
        raise ValueError(f"Invalid profiles: {', '.join(invalid)}. Available profiles: {available}")
    return valid
