#!/usr/bin/env python3
"""
Data models for SCRYNET Smart Analyzer.

Centralized data structures used throughout the analysis pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(slots=True, frozen=False)
class Finding:
    """
    Represents a security finding or code insight.
    
    Attributes:
        file_path: Path to the file where the finding was discovered
        finding: Description of the finding
        recommendation: Suggested remediation
        relevance: Relevance level (HIGH, MEDIUM, LOW)
        impact: Impact level (CRITICAL, HIGH, MEDIUM, LOW)
        confidence: Confidence level (HIGH, MEDIUM, LOW)
        effort: Estimated effort to fix (HIGH, MEDIUM, LOW)
        cwe: CWE identifier (e.g., "CWE-78")
        line_number: Optional line number where finding occurs
        annotated_snippet: Optional code snippet with annotation
    """
    file_path: str
    finding: str
    recommendation: str
    relevance: str
    impact: str
    confidence: str
    effort: str
    cwe: str
    line_number: Optional[int] = None
    annotated_snippet: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict, file_path: str, relevance: str) -> Finding:
        """
        Create a Finding from a dictionary (typically from API response).
        
        Args:
            d: Dictionary containing finding data
            file_path: Path to the file
            relevance: Relevance level
            
        Returns:
            Finding instance
        """
        return cls(
            file_path=file_path,
            relevance=relevance,
            finding=str(d.get("finding", "N/A")),
            recommendation=str(d.get("recommendation", "N/A")),
            impact=str(d.get("impact", "N/A")),
            confidence=str(d.get("confidence", "N/A")),
            effort=str(d.get("effort", "N/A")),
            cwe=str(d.get("cwe", "N/A")),
            line_number=d.get("line_number"),
        )


@dataclass(slots=True, frozen=True)
class AnalysisReport:
    """
    Complete analysis report containing all findings and synthesis.
    
    Attributes:
        repo_path: Path to the analyzed repository
        question: Analysis question that was asked
        timestamp: When the analysis was performed
        file_count: Number of files analyzed
        insights: List of findings discovered
        synthesis: Synthesized summary report
    """
    repo_path: str
    question: str
    timestamp: str
    file_count: int
    insights: List[Finding]
    synthesis: str



