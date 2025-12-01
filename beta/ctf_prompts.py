#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF-optimized prompt builders for quick vulnerability discovery.
Focused on finding flags, common CTF vulnerabilities, and quick wins.
"""

from __future__ import annotations
import json as _json
import os
from pathlib import Path
from typing import Any, List


class CTFPromptFactory:
    """Generates CTF-focused prompts optimized for quick vulnerability discovery."""

    @staticmethod
    def prioritization(all_files: List[Path], question: str, limit: int) -> str:
        """Prioritize files for CTF - focus on entry points, configs, auth, and vulnerable patterns."""
        filenames = [f.name for f in all_files]
        
        # CTF-specific guidance
        ctf_priority_hints = """
CTF PRIORITY CHECKLIST:
- Entry points: index.php, main.py, app.js, routes, controllers, handlers
- Authentication: login, auth, session, token files
- Configuration: config files, .env, secrets, credentials
- Database: SQL files, models with user input
- File operations: upload, download, file inclusion
- API endpoints: routes, REST handlers
- Admin panels: admin, dashboard, management interfaces
- Crypto/encoding: encryption, hashing, encoding functions
"""
        
        return f"""You are a CTF security expert. Your task is to identify the most likely files to contain vulnerabilities or flags for this CTF challenge.

User Question: "{question}"

{ctf_priority_hints}

File List:
{_json.dumps(filenames, indent=2)}

Return a JSON object with a single key "prioritized_files". This key should contain a list of objects, where each object has a "file_name" and a "reason" explaining why it's likely to contain vulnerabilities or flags. Prioritize files that:
1. Handle user input (forms, APIs, uploads)
2. Contain authentication/authorization logic
3. Perform file operations or database queries
4. Are entry points (index, main, routes)
5. Contain configuration or secrets

Limit the list to the top {limit} most relevant files. Your response must contain ONLY the JSON object.
Example:
{{
  "prioritized_files": [
    {{
      "file_name": "login.php",
      "reason": "Authentication entry point - likely contains SQL injection, weak password checks, or session vulnerabilities"
    }},
    {{
      "file_name": "upload.php",
      "reason": "File upload handler - common CTF target for path traversal, file inclusion, or arbitrary file upload"
    }}
  ]
}}"""

    @staticmethod
    def deep_dive(file_path: Path, content: str, question: str) -> str:
        """CTF-focused deep dive - look for exploitable vulnerabilities and flags."""
        return f"""You are a CTF security expert. Analyze this code for exploitable vulnerabilities that could lead to flags or unauthorized access.

FILE: {file_path}
QUESTION: {question}

CTF VULNERABILITY CHECKLIST:
✓ SQL Injection (unparameterized queries, string concatenation)
✓ Command Injection (system(), exec(), shell_exec(), backticks)
✓ File Inclusion (include, require, file_get_contents with user input)
✓ Path Traversal (../, directory traversal, file operations)
✓ Hardcoded Secrets (passwords, API keys, flags, tokens in code)
✓ Weak Authentication (bypassable login, default creds, weak checks)
✓ Insecure Deserialization (unpickle, unserialize, eval with user data)
✓ XSS (reflected/stored, unescaped output)
✓ SSRF (server-side requests with user-controlled URLs)
✓ Crypto Weaknesses (weak algorithms, hardcoded keys, predictable IVs)
✓ Race Conditions (file operations, TOCTOU)
✓ Logic Flaws (price manipulation, privilege escalation, bypasses)

Provide your analysis in this exact JSON format. Your entire response must be ONLY the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "insights": [
    {{
      "finding": "A concise description of the specific exploitable vulnerability. If you find a potential flag or secret, mention it explicitly.",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "effort": "HIGH|MEDIUM|LOW",
      "line_number": 45,
      "cwe": "CWE-ID (e.g., 'CWE-89' for SQL Injection). If not applicable or unsure, use 'N/A'.",
      "recommendation": "Specific exploitation path or remediation. For CTF, focus on how to exploit this."
    }}
  ]
}}

CODE TO ANALYZE:
{content}"""

    @staticmethod
    def deep_dive_yaml(file_path: Path, content: str, question: str) -> str:
        """Analyze YAML for CTF-relevant misconfigurations and secrets."""
        return f"""You are a CTF security expert. Analyze this YAML file for misconfigurations, exposed secrets, or vulnerabilities.

FILE: {file_path}
QUESTION: {question}

CTF YAML FOCUS AREAS:
- Hardcoded credentials, API keys, tokens, passwords
- Insecure configurations (privileged containers, hostPath mounts)
- Exposed services (NodePort, LoadBalancer without restrictions)
- Missing security contexts or overly permissive RBAC
- Environment variables with secrets
- Insecure image tags or pull policies

Provide a concise analysis in THIS EXACT JSON format. Respond ONLY with the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "detected_type": "k8s-manifest|helm-values|docker-compose|config|unknown",
  "insights": [
    {{
      "finding": "Description of the vulnerability, misconfig, or exposed secret. If you find credentials or flags, mention them explicitly.",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "effort": "HIGH|MEDIUM|LOW",
      "line_number": 1,
      "cwe": "CWE-ID (e.g., 'CWE-798'). If not applicable or unsure, use 'N/A'.",
      "recommendation": "How to exploit this misconfiguration or specific remediation."
    }}
  ]
}}
YAML TO ANALYZE:
{content}"""

    @staticmethod
    def deep_dive_helm(file_path: Path, content: str, question: str) -> str:
        """Analyze Helm templates for CTF-relevant vulnerabilities."""
        return f"""You are a CTF security expert. Analyze this Helm template for exploitable misconfigurations or vulnerabilities.

FILE: {file_path}
QUESTION: {question}

CTF HELM FOCUS:
- Insecure securityContext (privileged, hostPID, hostNetwork)
- Exposed secrets in values or templates
- Insecure volume mounts (hostPath, emptyDir with sensitive data)
- Overly permissive RBAC (cluster-admin, wildcard permissions)
- Insecure image sources or tags
- Environment variables leaking secrets

Provide a concise analysis in THIS EXACT JSON format. Respond ONLY with the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "detected_type": "helm-template",
  "insights": [
    {{
      "finding": "Specific exploitable vulnerability or misconfiguration. Mention any exposed secrets or flags.",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "effort": "HIGH|MEDIUM|LOW",
      "line_number": 1,
      "cwe": "CWE-ID. If not applicable or unsure, use 'N/A'.",
      "recommendation": "Exploitation path or fix."
    }}
  ]
}}
HELM TEMPLATE TO ANALYZE:
{content}"""
    
    @staticmethod
    def synthesis(all_findings: list, question: str) -> str:
        """Generate CTF-focused synthesis highlighting quick wins and exploitation paths."""
        from pathlib import Path as _Path
        condensed_findings = [
            f"- {finding.finding} (in {_Path(finding.file_path).name}, line {finding.line_number or '?'})" 
            for finding in all_findings
        ]
        
        synthesis_goal = """Your report must be in Markdown and contain the following sections EXACTLY:

1. **Quick Wins (Exploitable Now):** List the highest-impact, easiest-to-exploit vulnerabilities first. For each, provide:
   - The vulnerability type
   - The file and line number
   - A brief exploitation path (how to trigger it)
   - Expected outcome (what you can achieve)

2. **Potential Flags/Secrets:** List any hardcoded credentials, API keys, tokens, or potential flag locations you found.

3. **Exploitation Priority:** Rank vulnerabilities by:
   - Exploitability (easiest first)
   - Impact (what you can achieve)
   - Confidence (how sure you are it's exploitable)

4. **Next Steps:** Concrete actions to take - which files to examine next, what payloads to try, what to look for."""

        return f"""You are a CTF security expert creating an exploitation roadmap. Based on the findings, generate a prioritized action plan for capturing flags.

{synthesis_goal}

Original Question: "{question}"

Raw Findings:
{os.linesep.join(condensed_findings)}"""

    @staticmethod
    def annotation(finding: Any, code_content: str) -> str:
        """CTF-focused annotation showing exploitation points."""
        return f"""You are a CTF security expert. Create an annotated code snippet showing the exploitable vulnerability.

SECURITY FINDING:
- File: {finding.file_path}
- Line: {finding.line_number}
- Description: {finding.finding}
- Recommendation: {finding.recommendation}

FULL CODE CONTENT:
{code_content}

INSTRUCTIONS:
1. Extract a code snippet of 10-15 lines centered around the vulnerable line ({finding.line_number}).
2. Add a comment directly above the vulnerable line: `// VULN: [Brief description]`
3. Add a comment block directly below showing: `// EXPLOIT: [How to exploit this]` and `// PAYLOAD: [Example payload]`

Provide your response in a single, clean JSON object with one key, "annotated_snippet". Do not include any text outside the JSON.
Example format:
{{
  "annotated_snippet": "public void vulnerableMethod(String userInput) {{\\n    // ... some code ...\\n    // VULN: SQL Injection via unparameterized query\\n    Statement stmt = conn.createStatement();\\n    ResultSet rs = stmt.executeQuery(\\"SELECT * FROM users WHERE name = '\" + userInput + \"'\\");\\n    // EXPLOIT: Inject SQL to bypass authentication or extract data\\n    // PAYLOAD: ' OR '1'='1' --\\n    // ... more code ...\\n}}"
}}"""

    @staticmethod
    def payload_generation(finding: Any, code_snippet: str) -> str:
        """Generate CTF-focused exploitation payloads."""
        return f"""You are a CTF exploitation expert. For this vulnerability, generate practical, ready-to-use payloads for CTF exploitation.

VULNERABILITY CONTEXT:
File: {finding.file_path}
Line: {finding.line_number}
Finding: {finding.finding}
Recommendation: {finding.recommendation}

CODE SNIPPET:
{code_snippet}

TASK:
Generate actionable exploitation payloads that can be directly used in a CTF challenge. Be specific and practical.

Provide your response in a single, clean JSON object with the following structure. Do not include any text outside the JSON.
{{
  "exploitation_payload": {{
    "payload": "A working, ready-to-use payload to exploit this vulnerability (e.g., SQL injection string, path traversal path, command injection command)",
    "explanation": "Step-by-step explanation of how this payload works and why it exploits the vulnerability",
    "expected_result": "Specific expected outcome (e.g., 'Bypass authentication and login as admin', 'Read /etc/passwd file contents', 'Execute arbitrary commands', 'Retrieve flag from database')",
    "how_to_use": "Practical instructions on where and how to use this payload (e.g., 'Inject in username field', 'Use as filename in upload', 'Send as POST parameter')"
  }},
  "alternative_payloads": [
    {{
      "payload": "Alternative payload variant (e.g., encoded, obfuscated, or different technique)",
      "use_case": "When to use this variant (e.g., 'If basic payload is filtered', 'For URL-encoded contexts', 'To bypass WAF')",
      "expected_result": "What this alternative achieves"
    }}
  ],
  "exploitation_steps": [
    "Step 1: [Specific action to take]",
    "Step 2: [Next action]",
    "Step 3: [Final action to achieve goal]"
  ]
}}"""

