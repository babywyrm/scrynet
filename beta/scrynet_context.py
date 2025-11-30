#!/usr/bin/env python3
"""
SCRYNET Context Library

A unified library for managing review context, API caching, and cost tracking.
Provides a clean, type-safe interface for persistent review sessions.

Usage:
    from scrynet_context import ReviewContextManager
    
    ctx = ReviewContextManager(cache_dir=".scrynet_cache")
    review = ctx.create_or_resume_review(repo_path, question)
    cached_response = ctx.get_cached_response(stage, prompt, repo_path, model)
    ctx.save_response(stage, prompt, response, repo_path, model)
    ctx.track_cost(input_tokens, output_tokens, cached=False)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# Data Models
# ============================================================================

@dataclass(frozen=True, slots=True)
class ReviewCheckpoint:
    """Represents a checkpoint in the review process."""
    stage: str  # "prioritization", "deep_dive", "synthesis", etc.
    timestamp: str
    data: Dict[str, Any] = field(default_factory=dict)
    files_analyzed: List[str] = field(default_factory=list)
    findings_count: int = 0


@dataclass
class ReviewState:
    """Complete state of a code review session."""
    review_id: str
    repo_path: str
    dir_fingerprint: str
    question: str
    status: str  # "in_progress", "completed", "paused"
    created_at: str
    updated_at: str
    checkpoints: List[ReviewCheckpoint] = field(default_factory=list)
    files_analyzed: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    synthesis: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CachedResponse:
    """Represents a cached API response."""
    stage: str
    file: Optional[str]
    prompt: str
    raw_response: str
    parsed: Optional[Dict[str, Any]]
    timestamp: str
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(slots=True)
class CostTracker:
    """Tracks API usage and costs across a session."""
    input_tokens: int = 0
    output_tokens: int = 0
    api_calls: int = 0
    cache_hits: int = 0
    
    def add_usage(self, input_tokens: int, output_tokens: int, cached: bool = False) -> None:
        """Record API usage."""
        if cached:
            self.cache_hits += 1
        else:
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            self.api_calls += 1
    
    def estimate_cost(self, model: str) -> float:
        """Estimate cost based on model pricing."""
        # Claude 3.5 Haiku pricing (as of 2024)
        pricing = {
            "claude-3-5-haiku-20241022": {"input": 0.80 / 1_000_000, "output": 4.00 / 1_000_000},
            "claude-3-5-sonnet-20241022": {"input": 3.00 / 1_000_000, "output": 15.00 / 1_000_000},
            "claude-3-opus-20240229": {"input": 15.00 / 1_000_000, "output": 75.00 / 1_000_000},
        }
        
        rates = pricing.get(model, pricing["claude-3-5-haiku-20241022"])
        return (self.input_tokens * rates["input"]) + (self.output_tokens * rates["output"])
    
    def summary(self, model: str) -> Dict[str, Any]:
        """Return summary statistics."""
        return {
            "api_calls": self.api_calls,
            "cache_hits": self.cache_hits,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            "estimated_cost_usd": self.estimate_cost(model),
        }
    
    def reset(self) -> None:
        """Reset all counters."""
        self.input_tokens = 0
        self.output_tokens = 0
        self.api_calls = 0
        self.cache_hits = 0


# ============================================================================
# Main Context Manager
# ============================================================================

class ReviewContextManager:
    """
    Unified manager for review state, API caching, and cost tracking.
    
    Provides a single interface for:
    - Creating and resuming review sessions
    - Caching API responses with namespacing
    - Tracking costs and usage
    - Directory fingerprinting and change detection
    """
    
    def __init__(
        self,
        cache_dir: Union[str, Path] = ".scrynet_cache",
        use_cache: bool = True,
        enable_cost_tracking: bool = True
    ):
        """
        Initialize the context manager.
        
        Args:
            cache_dir: Base directory for all cache and state files
            use_cache: Whether to use API response caching
            enable_cost_tracking: Whether to track API costs
        """
        self.cache_dir = Path(cache_dir).resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.use_cache = use_cache
        self.enable_cost_tracking = enable_cost_tracking
        
        # Subdirectories
        self.reviews_dir = self.cache_dir / "reviews"
        self.reviews_dir.mkdir(parents=True, exist_ok=True)
        self.cache_base = self.cache_dir / "api_cache"
        self.cache_base.mkdir(parents=True, exist_ok=True)
        
        # Cost tracker
        self.cost_tracker = CostTracker() if enable_cost_tracking else None
        
        logger.info(f"Initialized ReviewContextManager with cache_dir={self.cache_dir}")
    
    # ========================================================================
    # Directory Fingerprinting
    # ========================================================================
    
    def compute_dir_fingerprint(self, repo_path: Union[str, Path]) -> str:
        """
        Compute a deterministic hash of the directory structure.
        
        Uses file paths, sizes, and modification times to create a stable
        fingerprint that changes when files are added, removed, or modified.
        
        Args:
            repo_path: Path to repository root
            
        Returns:
            16-character hexadecimal fingerprint
            
        Raises:
            ValueError: If repo_path is not a directory
        """
        repo = Path(repo_path).resolve()
        if not repo.is_dir():
            raise ValueError(f"Repository path '{repo_path}' is not a directory")
        
        file_info = []
        for file_path in sorted(repo.rglob("*")):
            if not file_path.is_file():
                continue
            try:
                stat = file_path.stat()
                relative = file_path.relative_to(repo)
                file_info.append(f"{relative}:{stat.st_size}:{stat.st_mtime}")
            except (OSError, PermissionError) as e:
                logger.debug(f"Skipping {file_path}: {e}")
                continue
        
        content = "\n".join(file_info)
        fingerprint = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        logger.debug(f"Computed fingerprint for {repo_path}: {fingerprint}")
        return fingerprint
    
    def detect_changes(
        self,
        repo_path: Union[str, Path],
        stored_fingerprint: str
    ) -> tuple[bool, Optional[str]]:
        """
        Detect if codebase has changed since a stored fingerprint.
        
        Args:
            repo_path: Path to repository root
            stored_fingerprint: Previously stored fingerprint
            
        Returns:
            Tuple of (has_changed, current_fingerprint)
        """
        current = self.compute_dir_fingerprint(repo_path)
        changed = current != stored_fingerprint
        if changed:
            logger.info(f"Codebase changed: {stored_fingerprint[:8]} -> {current[:8]}")
        return changed, current
    
    # ========================================================================
    # Review State Management
    # ========================================================================
    
    def generate_review_id(self, repo_path: str, question: str) -> str:
        """Generate a unique review ID based on repo path and question."""
        content = f"{repo_path}|{question}|{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    
    def create_review(
        self,
        repo_path: Union[str, Path],
        question: str,
        dir_fingerprint: Optional[str] = None
    ) -> ReviewState:
        """
        Create a new review state.
        
        Args:
            repo_path: Path to repository
            question: Analysis question
            dir_fingerprint: Optional pre-computed fingerprint
            
        Returns:
            New ReviewState instance
        """
        repo_path_str = str(Path(repo_path).resolve())
        if dir_fingerprint is None:
            dir_fingerprint = self.compute_dir_fingerprint(repo_path)
        
        review_id = self.generate_review_id(repo_path_str, question)
        now = datetime.now(timezone.utc).isoformat()
        
        state = ReviewState(
            review_id=review_id,
            repo_path=repo_path_str,
            dir_fingerprint=dir_fingerprint,
            question=question,
            status="in_progress",
            created_at=now,
            updated_at=now,
        )
        
        self.save_review(state)
        logger.info(f"Created review {review_id} for {repo_path_str}")
        return state
    
    def save_review(self, state: ReviewState) -> None:
        """Save review state to disk."""
        state.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Save structured JSON
        state_file = self.reviews_dir / f"{state.review_id}.json"
        state_dict = {
            "review_id": state.review_id,
            "repo_path": state.repo_path,
            "dir_fingerprint": state.dir_fingerprint,
            "question": state.question,
            "status": state.status,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "checkpoints": [asdict(cp) for cp in state.checkpoints],
            "files_analyzed": state.files_analyzed,
            "findings": state.findings,
            "synthesis": state.synthesis,
            "metadata": state.metadata,
        }
        
        try:
            state_file.write_text(json.dumps(state_dict, indent=2), encoding="utf-8")
            self._generate_context_file(state)
            logger.debug(f"Saved review {state.review_id}")
        except Exception as e:
            logger.error(f"Failed to save review {state.review_id}: {e}")
            raise
    
    def load_review(self, review_id: str) -> ReviewState:
        """Load review state from disk."""
        state_file = self.reviews_dir / f"{review_id}.json"
        if not state_file.exists():
            raise FileNotFoundError(f"Review {review_id} not found")
        
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            checkpoints = [
                ReviewCheckpoint(**cp_data) for cp_data in data.get("checkpoints", [])
            ]
            
            return ReviewState(
                review_id=data["review_id"],
                repo_path=data["repo_path"],
                dir_fingerprint=data["dir_fingerprint"],
                question=data["question"],
                status=data["status"],
                created_at=data["created_at"],
                updated_at=data["updated_at"],
                checkpoints=checkpoints,
                files_analyzed=data.get("files_analyzed", []),
                findings=data.get("findings", []),
                synthesis=data.get("synthesis"),
                metadata=data.get("metadata", {}),
            )
        except Exception as e:
            logger.error(f"Failed to load review {review_id}: {e}")
            raise
    
    def find_matching_review(
        self,
        repo_path: Union[str, Path],
        dir_fingerprint: Optional[str] = None
    ) -> Optional[str]:
        """
        Find an existing review that matches the directory fingerprint.
        
        Args:
            repo_path: Path to repository
            dir_fingerprint: Optional pre-computed fingerprint
            
        Returns:
            review_id if found, None otherwise
        """
        repo_path_str = str(Path(repo_path).resolve())
        if dir_fingerprint is None:
            dir_fingerprint = self.compute_dir_fingerprint(repo_path)
        
        if not self.reviews_dir.exists():
            return None
        
        for review_file in self.reviews_dir.glob("*.json"):
            if review_file.name.startswith("_"):  # Skip context files
                continue
            try:
                state = self.load_review(review_file.stem)
                if (state.repo_path == repo_path_str and
                    state.dir_fingerprint == dir_fingerprint and
                    state.status == "in_progress"):
                    logger.debug(f"Found matching review: {state.review_id}")
                    return state.review_id
            except Exception as e:
                logger.debug(f"Skipping {review_file}: {e}")
                continue
        return None
    
    def add_checkpoint(
        self,
        review_id: str,
        stage: str,
        data: Dict[str, Any],
        files_analyzed: Optional[List[str]] = None,
        findings_count: int = 0
    ) -> None:
        """Add a checkpoint to the review."""
        state = self.load_review(review_id)
        
        checkpoint = ReviewCheckpoint(
            stage=stage,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
            files_analyzed=files_analyzed or [],
            findings_count=findings_count,
        )
        
        state.checkpoints.append(checkpoint)
        self.save_review(state)
        logger.debug(f"Added checkpoint {stage} to review {review_id}")
    
    def update_findings(self, review_id: str, findings: List[Any]) -> None:
        """Update findings in the review state."""
        state = self.load_review(review_id)
        # Convert Finding dataclass objects to dicts
        findings_dicts = []
        for f in findings:
            if hasattr(f, '__dataclass_fields__'):  # It's a dataclass
                findings_dicts.append(asdict(f))
            elif isinstance(f, dict):
                findings_dicts.append(f)
            else:
                findings_dicts.append(asdict(f) if hasattr(f, '__dict__') else {})
        state.findings = findings_dicts
        self.save_review(state)
    
    def update_synthesis(self, review_id: str, synthesis: str) -> None:
        """Update synthesis in the review state."""
        state = self.load_review(review_id)
        state.synthesis = synthesis
        self.save_review(state)
    
    def mark_completed(self, review_id: str) -> None:
        """Mark review as completed."""
        state = self.load_review(review_id)
        state.status = "completed"
        self.save_review(state)
        logger.info(f"Marked review {review_id} as completed")
    
    def list_reviews(self, status: Optional[str] = None) -> List[ReviewState]:
        """List all reviews, optionally filtered by status."""
        if not self.reviews_dir.exists():
            return []
        
        reviews = []
        for review_file in self.reviews_dir.glob("*.json"):
            if review_file.name.startswith("_"):
                continue
            try:
                state = self.load_review(review_file.stem)
                if status is None or state.status == status:
                    reviews.append(state)
            except Exception as e:
                logger.debug(f"Skipping {review_file}: {e}")
                continue
        
        # Sort by updated_at, most recent first
        reviews.sort(key=lambda r: r.updated_at, reverse=True)
        return reviews
    
    # ========================================================================
    # API Response Caching
    # ========================================================================
    
    def _hash_key(self, stage: str, file: Optional[str], prompt: str) -> str:
        """Generate cache key hash."""
        h = hashlib.sha256()
        h.update(f"{stage}|{file or ''}|{prompt}".encode("utf-8"))
        return h.hexdigest()[:16]
    
    def _namespace_dir(
        self,
        repo_path: Optional[Union[str, Path]],
        model: Optional[str],
        mode: Optional[str] = None
    ) -> Path:
        """
        Return namespaced cache directory for a given repo/model/mode combination.
        
        Args:
            repo_path: Repository path for namespacing
            model: Model name for namespacing
            mode: Optional mode identifier (e.g., "ctf", "smart") to separate different analysis types
        """
        ns_parts = []
        if mode:
            ns_parts.append(mode)  # Add mode first for clear separation
        if repo_path:
            try:
                # Use a simple hash of the repo path instead of computing fingerprint
                # Computing fingerprint scans entire repo which can hang on large repos
                repo_str = str(Path(repo_path).resolve())
                fp = hashlib.sha256(repo_str.encode("utf-8")).hexdigest()[:16]
                # Only compute fingerprint if we need it (for review state matching)
                # For cache namespace, simple path hash is sufficient
            except Exception:
                fp = hashlib.sha256(str(repo_path).encode("utf-8")).hexdigest()[:16]
            ns_parts.append(fp)
        if model:
            ns_parts.append(model.replace("/", "_"))
        if not ns_parts:
            return self.cache_base
        ns = self.cache_base.joinpath(*ns_parts)
        ns.mkdir(parents=True, exist_ok=True)
        return ns
    
    def get_cached_response(
        self,
        stage: str,
        prompt: str,
        file: Optional[str] = None,
        repo_path: Optional[Union[str, Path]] = None,
        model: Optional[str] = None,
        mode: Optional[str] = None
    ) -> Optional[CachedResponse]:
        """
        Get cached API response if available.
        
        Args:
            stage: Analysis stage (e.g., "prioritization", "deep_dive")
            prompt: The prompt text
            file: Optional file path being analyzed
            repo_path: Optional repository path for namespacing
            model: Optional model name for namespacing
            mode: Optional mode identifier (e.g., "ctf", "smart") to separate different analysis types
            
        Returns:
            CachedResponse if found, None otherwise
        """
        if not self.use_cache:
            return None
        
        key = self._hash_key(stage, file, prompt)
        base = self._namespace_dir(repo_path, model, mode=mode)
        path = base / f"{key}.json"
        
        if not path.exists():
            return None
        
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            response = CachedResponse(**data)
            if self.cost_tracker:
                self.cost_tracker.add_usage(0, 0, cached=True)
            logger.debug(f"Cache hit for {stage}/{key[:8]}")
            return response
        except Exception as e:
            logger.warning(f"Failed to load cache entry {path}: {e}")
            return None
    
    def save_response(
        self,
        stage: str,
        prompt: str,
        raw_response: str,
        parsed: Optional[Dict[str, Any]] = None,
        file: Optional[str] = None,
        repo_path: Optional[Union[str, Path]] = None,
        model: Optional[str] = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        mode: Optional[str] = None
    ) -> CachedResponse:
        """
        Save API response to cache.
        
        Args:
            stage: Analysis stage
            prompt: The prompt text
            raw_response: Raw API response text
            parsed: Optional parsed response (dict)
            file: Optional file path
            repo_path: Optional repository path for namespacing
            model: Optional model name for namespacing
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            mode: Optional mode identifier (e.g., "ctf", "smart") to separate different analysis types
            
        Returns:
            CachedResponse instance
        """
        if not self.use_cache:
            return CachedResponse(
                stage=stage,
                file=file,
                prompt=prompt,
                raw_response=raw_response,
                parsed=parsed,
                timestamp=datetime.now(timezone.utc).isoformat(),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        
        entry = CachedResponse(
            stage=stage,
            file=file,
            prompt=prompt,
            raw_response=raw_response,
            parsed=parsed,
            timestamp=datetime.now(timezone.utc).isoformat(),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        
        key = self._hash_key(stage, file, prompt)
        base = self._namespace_dir(repo_path, model, mode=mode)
        path = base / f"{key}.json"
        
        try:
            path.write_text(
                json.dumps(asdict(entry), indent=2),
                encoding="utf-8"
            )
            logger.debug(f"Cached response for {stage}/{key[:8]}")
        except Exception as e:
            logger.warning(f"Failed to save cache entry {path}: {e}")
        
        return entry
    
    # ========================================================================
    # Cost Tracking
    # ========================================================================
    
    def track_cost(
        self,
        input_tokens: int,
        output_tokens: int,
        cached: bool = False
    ) -> None:
        """Track API cost usage."""
        if self.cost_tracker:
            self.cost_tracker.add_usage(input_tokens, output_tokens, cached)
    
    def get_cost_summary(self, model: str) -> Dict[str, Any]:
        """Get cost tracking summary."""
        if not self.cost_tracker:
            return {}
        return self.cost_tracker.summary(model)
    
    def reset_cost_tracking(self) -> None:
        """Reset cost tracking counters."""
        if self.cost_tracker:
            self.cost_tracker.reset()
    
    # ========================================================================
    # Cache Management
    # ========================================================================
    
    def cache_stats(self) -> Dict[str, Any]:
        """Return basic statistics about cache usage."""
        total_files = 0
        total_bytes = 0
        for p in self.cache_base.rglob("*.json"):
            try:
                total_files += 1
                total_bytes += p.stat().st_size
            except OSError:
                pass
        return {
            "dir": str(self.cache_base),
            "files": total_files,
            "bytes": total_bytes,
            "bytes_mb": round(total_bytes / (1024 * 1024), 2)
        }
    
    def list_cache_entries(self, limit: int = 50) -> List[str]:
        """List cache files (most recent first)."""
        items = []
        files = sorted(
            self.cache_base.rglob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        for p in files[:limit]:
            items.append(str(p.relative_to(self.cache_base)))
        return items
    
    def prune_cache(self, days: int) -> int:
        """Delete cache files older than N days. Returns number deleted."""
        cutoff = time.time() - (days * 86400)
        deleted = 0
        for p in self.cache_base.rglob("*.json"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink(missing_ok=True)
                    deleted += 1
            except OSError:
                pass
        logger.info(f"Pruned {deleted} cache files older than {days} days")
        return deleted
    
    def clear_cache(self) -> int:
        """Clear all cache files. Returns number deleted."""
        deleted = 0
        for p in self.cache_base.rglob("*.json"):
            try:
                p.unlink(missing_ok=True)
                deleted += 1
            except OSError:
                pass
        logger.info(f"Cleared {deleted} cache files")
        return deleted
    
    # ========================================================================
    # Context File Generation
    # ========================================================================
    
    def _generate_context_file(self, state: ReviewState) -> None:
        """Generate human-readable context file for Cursor/Claude."""
        context_file = self.reviews_dir / f"_{state.review_id}_context.md"
        
        lines = [
            f"# Review Context: {state.review_id}",
            "",
            f"**Repository:** `{state.repo_path}`",
            f"**Question:** {state.question}",
            f"**Status:** {state.status}",
            f"**Created:** {state.created_at}",
            f"**Last Updated:** {state.updated_at}",
            f"**Directory Fingerprint:** `{state.dir_fingerprint}`",
            "",
            "---",
            "",
            "## Review Progress",
            "",
        ]
        
        if state.checkpoints:
            lines.append("### Checkpoints")
            for cp in state.checkpoints:
                lines.append(f"- **{cp.stage}** ({cp.timestamp})")
                if cp.files_analyzed:
                    lines.append(f"  - Files analyzed: {len(cp.files_analyzed)}")
                if cp.findings_count > 0:
                    lines.append(f"  - Findings: {cp.findings_count}")
            lines.append("")
        
        if state.files_analyzed:
            lines.extend([
                "## Files Analyzed",
                "",
                f"Total: {len(state.files_analyzed)}",
                "",
            ])
            for file_path in state.files_analyzed[:20]:  # Limit to first 20
                lines.append(f"- `{file_path}`")
            if len(state.files_analyzed) > 20:
                lines.append(f"- ... and {len(state.files_analyzed) - 20} more")
            lines.append("")
        
        if state.findings:
            lines.extend([
                "## Findings Summary",
                "",
                f"Total findings: {len(state.findings)}",
                "",
            ])
            # Group by impact
            impact_counts = {}
            for finding in state.findings:
                impact = finding.get("impact", "UNKNOWN")
                impact_counts[impact] = impact_counts.get(impact, 0) + 1
            
            for impact in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if impact in impact_counts:
                    lines.append(f"- **{impact}**: {impact_counts[impact]}")
            lines.append("")
        
        if state.synthesis:
            lines.extend([
                "## Synthesis",
                "",
                state.synthesis,
                "",
            ])
        
        lines.extend([
            "---",
            "",
            "## Next Steps",
            "",
            "To resume this review:",
            f"```bash",
            f"python3 smart__.py {state.repo_path} \"{state.question}\" --resume-review {state.review_id}",
            "```",
            "",
        ])
        
        try:
            context_file.write_text("\n".join(lines), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Failed to generate context file: {e}")

