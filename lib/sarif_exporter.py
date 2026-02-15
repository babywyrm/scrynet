#!/usr/bin/env python3
"""
Export Agent Smith findings to SARIF 2.1.0 format.
For IDE integration (VS Code, GitHub Code Scanning).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List


def severity_to_sarif_level(severity: str) -> str:
    """Map our severity to SARIF result.level."""
    m = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    return m.get(severity.upper(), "warning")


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    tool_name: str = "Agent Smith",
    tool_version: str = "1.0",
    repo_root: str | Path = "",
) -> Dict[str, Any]:
    """Convert findings to SARIF 2.1.0 format."""
    repo_root = str(Path(repo_root).resolve()) if repo_root else ""
    rules_by_name: Dict[str, Dict] = {}
    results: List[Dict] = []

    for f in findings:
        rule_name = f.get("rule_name", f.get("title", "unknown"))
        if rule_name not in rules_by_name:
            rules_by_name[rule_name] = {
                "id": rule_name.replace(" ", "_")[:64],
                "name": rule_name,
                "shortDescription": {"text": f.get("description", rule_name)[:200]},
                "defaultConfiguration": {"level": severity_to_sarif_level(f.get("severity", "HIGH"))},
            }
            if f.get("remediation"):
                rules_by_name[rule_name]["help"] = {
                    "text": f.get("remediation", "")[:500],
                }

        file_path = f.get("file", f.get("file_path", "?"))
        line = f.get("line", f.get("line_number", 1))
        if isinstance(line, str):
            try:
                line = int(line)
            except ValueError:
                line = 1

        result = {
            "ruleId": rules_by_name[rule_name]["id"],
            "level": severity_to_sarif_level(f.get("severity", "HIGH")),
            "message": {"text": f.get("match", f.get("title", rule_name))[:500]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path, "uriBaseId": "REPO_ROOT"},
                        "region": {"startLine": max(1, int(line)), "startColumn": 1},
                    }
                }
            ],
        }
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/babywyrm/agentsmith",
                        "rules": list(rules_by_name.values()),
                    }
                },
                "results": results,
                "originalUriBaseIds": {"REPO_ROOT": {"uri": f"file://{repo_root}/"}} if repo_root else {},
            }
        ],
    }


def write_sarif(sarif_obj: Dict[str, Any], path: str | Path) -> None:
    """Write SARIF object to file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif_obj, f, indent=2)
