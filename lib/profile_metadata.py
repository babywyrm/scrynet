#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Profile metadata definitions for SCRYNET AI analysis profiles.

Each profile includes:
- Description: What the profile focuses on
- Use cases: When to use this profile
- Key focus areas: What vulnerabilities/issues it detects
- Examples: Command-line usage examples
"""

from dataclasses import dataclass
from typing import List, Dict


@dataclass
class ProfileMetadata:
    """Metadata for an AI analysis profile."""
    name: str
    display_name: str
    description: str
    use_cases: List[str]
    focus_areas: List[str]
    examples: List[str]
    category: str  # "security", "compliance", "code_quality"
    default: bool = False


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
        default=True
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
        category="security"
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
        category="security"
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
        category="code_quality"
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
        category="code_quality"
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
        category="security"
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
        category="compliance"
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
        category="compliance"
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
        category="compliance"
    )
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

