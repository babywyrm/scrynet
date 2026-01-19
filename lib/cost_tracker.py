#!/usr/bin/env python3
"""
Cost tracking utility for Anthropic API usage.

Tracks token usage and calculates estimated costs based on model pricing.

NOTE: Cost tracking only captures successful API calls. Failed calls that 
charge for input tokens (e.g., rate limit errors after request processing)
may not be fully tracked. Actual costs may be slightly higher than reported.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path


# Model pricing per 1M tokens (as of 2024)
# Format: (input_price_per_1M, output_price_per_1M)
MODEL_PRICING = {
    "claude-3-5-haiku-20241022": (0.25, 1.25),  # $0.25/$1.25 per 1M tokens
    "claude-3-5-sonnet-20241022": (3.00, 15.00),  # $3.00/$15.00 per 1M tokens
    "claude-3-opus-20240229": (15.00, 75.00),  # $15.00/$75.00 per 1M tokens
    "claude-3-5-sonnet": (3.00, 15.00),  # Same as sonnet-20241022
    "claude-3-haiku-20240307": (0.25, 1.25),  # $0.25/$1.25 per 1M tokens
    "claude-3-sonnet-20240229": (3.00, 15.00),  # $3.00/$15.00 per 1M tokens
}

# Default pricing for unknown models (conservative estimate using Haiku rates)
DEFAULT_PRICING = (0.25, 1.25)


@dataclass
class APICall:
    """Represents a single API call with token usage."""
    stage: str  # e.g., "prioritization", "analysis", "payload", "annotation", "threat_modeling"
    profile: Optional[str] = None  # AI profile used (e.g., "owasp", "ctf")
    model: str = "claude-3-5-haiku-20241022"
    input_tokens: int = 0
    output_tokens: int = 0
    file: Optional[str] = None  # File being analyzed (if applicable)
    finding_id: Optional[str] = None  # Finding ID (for payloads/annotations)
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def total_tokens(self) -> int:
        """Total tokens used in this call."""
        return self.input_tokens + self.output_tokens
    
    @property
    def cost(self) -> float:
        """Calculate estimated cost for this API call."""
        pricing = MODEL_PRICING.get(self.model, DEFAULT_PRICING)
        input_cost = (self.input_tokens / 1_000_000) * pricing[0]
        output_cost = (self.output_tokens / 1_000_000) * pricing[1]
        return input_cost + output_cost


class CostTracker:
    """Tracks API costs and token usage across a scanning session."""
    
    def __init__(self):
        self.calls: List[APICall] = []
    
    def record_call(
        self,
        stage: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        profile: Optional[str] = None,
        file: Optional[str] = None,
        finding_id: Optional[str] = None
    ) -> APICall:
        """Record an API call and return the APICall object."""
        call = APICall(
            stage=stage,
            profile=profile,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            file=file,
            finding_id=finding_id,
            timestamp=datetime.now()
        )
        self.calls.append(call)
        return call
    
    def record_from_response(
        self,
        response: Any,
        stage: str,
        model: str,
        profile: Optional[str] = None,
        file: Optional[str] = None,
        finding_id: Optional[str] = None
    ) -> APICall:
        """Record an API call from an Anthropic API response object."""
        # Extract token usage from response
        usage = getattr(response, 'usage', None)
        if usage:
            input_tokens = getattr(usage, 'input_tokens', 0)
            output_tokens = getattr(usage, 'output_tokens', 0)
        else:
            # Fallback: try to get from response dict if it's a dict
            if isinstance(response, dict):
                usage = response.get('usage', {})
                input_tokens = usage.get('input_tokens', 0)
                output_tokens = usage.get('output_tokens', 0)
            else:
                input_tokens = 0
                output_tokens = 0
        
        return self.record_call(
            stage=stage,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            profile=profile,
            file=file,
            finding_id=finding_id
        )
    
    @property
    def total_input_tokens(self) -> int:
        """Total input tokens across all calls."""
        return sum(call.input_tokens for call in self.calls)
    
    @property
    def total_output_tokens(self) -> int:
        """Total output tokens across all calls."""
        return sum(call.output_tokens for call in self.calls)
    
    @property
    def total_tokens(self) -> int:
        """Total tokens across all calls."""
        return sum(call.total_tokens for call in self.calls)
    
    @property
    def total_cost(self) -> float:
        """Total estimated cost across all calls."""
        return sum(call.cost for call in self.calls)
    
    def get_stage_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary statistics grouped by stage."""
        summary: Dict[str, Dict[str, Any]] = {}
        
        for call in self.calls:
            if call.stage not in summary:
                summary[call.stage] = {
                    'calls': 0,
                    'input_tokens': 0,
                    'output_tokens': 0,
                    'total_tokens': 0,
                    'cost': 0.0,
                    'profiles': set()
                }
            
            stage_sum = summary[call.stage]
            stage_sum['calls'] += 1
            stage_sum['input_tokens'] += call.input_tokens
            stage_sum['output_tokens'] += call.output_tokens
            stage_sum['total_tokens'] += call.total_tokens
            stage_sum['cost'] += call.cost
            if call.profile:
                stage_sum['profiles'].add(call.profile)
        
        # Convert sets to sorted lists for JSON serialization
        for stage_sum in summary.values():
            stage_sum['profiles'] = sorted(list(stage_sum['profiles']))
        
        return summary
    
    def get_profile_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary statistics grouped by profile."""
        summary: Dict[str, Dict[str, Any]] = {}
        
        for call in self.calls:
            profile_name = call.profile or "unknown"
            if profile_name not in summary:
                summary[profile_name] = {
                    'calls': 0,
                    'input_tokens': 0,
                    'output_tokens': 0,
                    'total_tokens': 0,
                    'cost': 0.0,
                    'stages': set()
                }
            
            profile_sum = summary[profile_name]
            profile_sum['calls'] += 1
            profile_sum['input_tokens'] += call.input_tokens
            profile_sum['output_tokens'] += call.output_tokens
            profile_sum['total_tokens'] += call.total_tokens
            profile_sum['cost'] += call.cost
            profile_sum['stages'].add(call.stage)
        
        # Convert sets to sorted lists
        for profile_sum in summary.values():
            profile_sum['stages'] = sorted(list(profile_sum['stages']))
        
        return summary
    
    def get_model_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary statistics grouped by model."""
        summary: Dict[str, Dict[str, Any]] = {}
        
        for call in self.calls:
            if call.model not in summary:
                summary[call.model] = {
                    'calls': 0,
                    'input_tokens': 0,
                    'output_tokens': 0,
                    'total_tokens': 0,
                    'cost': 0.0
                }
            
            model_sum = summary[call.model]
            model_sum['calls'] += 1
            model_sum['input_tokens'] += call.input_tokens
            model_sum['output_tokens'] += call.output_tokens
            model_sum['total_tokens'] += call.total_tokens
            model_sum['cost'] += call.cost
        
        return summary
    
    def export_to_json(self, output_file: Path) -> None:
        """Export detailed cost tracking data to JSON."""
        data = {
            'summary': {
                'total_calls': len(self.calls),
                'total_input_tokens': self.total_input_tokens,
                'total_output_tokens': self.total_output_tokens,
                'total_tokens': self.total_tokens,
                'total_cost': round(self.total_cost, 4),
                'by_stage': self.get_stage_summary(),
                'by_profile': self.get_profile_summary(),
                'by_model': self.get_model_summary()
            },
            'calls': [
                {
                    'stage': call.stage,
                    'profile': call.profile,
                    'model': call.model,
                    'input_tokens': call.input_tokens,
                    'output_tokens': call.output_tokens,
                    'total_tokens': call.total_tokens,
                    'cost': round(call.cost, 4),
                    'file': call.file,
                    'finding_id': call.finding_id,
                    'timestamp': call.timestamp.isoformat()
                }
                for call in self.calls
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def format_summary_table(self) -> str:
        """Format a human-readable summary table."""
        lines = []
        lines.append("\n💰 Cost Summary")
        lines.append("=" * 60)
        lines.append(f"Total API Calls:      {len(self.calls)}")
        lines.append(f"Total Input Tokens:   {self.total_input_tokens:,}")
        lines.append(f"Total Output Tokens:  {self.total_output_tokens:,}")
        lines.append(f"Total Tokens:         {self.total_tokens:,}")
        lines.append(f"Estimated Cost:       ${self.total_cost:.4f}")
        lines.append("")
        
        # By Stage
        stage_summary = self.get_stage_summary()
        if stage_summary:
            lines.append("By Stage:")
            for stage, stats in sorted(stage_summary.items()):
                lines.append(f"  {stage:20s}  {stats['calls']:3d} calls  ${stats['cost']:8.4f}  ({stats['total_tokens']:,} tokens)")
            lines.append("")
        
        # By Profile
        profile_summary = self.get_profile_summary()
        if profile_summary and any(p != "unknown" for p in profile_summary):
            lines.append("By Profile:")
            for profile, stats in sorted(profile_summary.items()):
                if profile != "unknown":
                    lines.append(f"  {profile:20s}  {stats['calls']:3d} calls  ${stats['cost']:8.4f}  ({stats['total_tokens']:,} tokens)")
            lines.append("")
        
        # By Model
        model_summary = self.get_model_summary()
        if model_summary:
            lines.append("By Model:")
            for model, stats in sorted(model_summary.items()):
                lines.append(f"  {model:30s}  {stats['calls']:3d} calls  ${stats['cost']:8.4f}  ({stats['total_tokens']:,} tokens)")
        
        return "\n".join(lines)

