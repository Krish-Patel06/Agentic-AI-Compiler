"""
Isolated Candidate Representation and Lineage Tree.
Enforces that Candidate 0 (baseline) is strictly immutable and acts as
the absolute fallback. Every branched candidate maintains lineage, parent IR hash,
pass pipeline, and execution metrics.
"""

from __future__ import annotations
import copy
import hashlib
from enum import Enum, unique
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@unique
class CandidateStatus(Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


@dataclass
class ResourceUsage:
    compilation_time_ms: float = 0.0
    memory_peak_mb: float = 0.0
    instruction_count: int = 0
    binary_size_bytes: int = 0


@dataclass
class Candidate:
    candidate_id: str
    parent_id: Optional[str]
    pass_pipeline: List[str]
    ir_text: str
    source_hash: str
    parent_ir_hash: str
    ir_fingerprint: str
    agent_name: str
    status: CandidateStatus = CandidateStatus.PENDING
    resource_usage: ResourceUsage = field(default_factory=ResourceUsage)
    benchmark_result: Dict[str, Any] = field(default_factory=dict)
    verification_report: Dict[str, Any] = field(default_factory=dict)
    rejection_reason: str = ""
    is_baseline: bool = False

    @classmethod
    def create_baseline(cls, ir_text: str, source_hash: str = "") -> Candidate:
        norm = "\n".join(l.strip() for l in ir_text.splitlines() if l.strip() and not l.strip().startswith(";"))
        fingerprint = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        cand = cls(
            candidate_id="baseline",
            parent_id=None,
            pass_pipeline=["default<O0>"],
            ir_text=ir_text,
            source_hash=source_hash,
            parent_ir_hash="",
            ir_fingerprint=fingerprint,
            agent_name="system_baseline",
            status=CandidateStatus.VERIFIED,
            is_baseline=True
        )
        return cand

    def branch(self, candidate_id: str, pass_pipeline: List[str], new_ir_text: str, agent_name: str = "ai_agent") -> Candidate:
        norm = "\n".join(l.strip() for l in new_ir_text.splitlines() if l.strip() and not l.strip().startswith(";"))
        fingerprint = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        return Candidate(
            candidate_id=candidate_id,
            parent_id=self.candidate_id,
            pass_pipeline=list(pass_pipeline),
            ir_text=new_ir_text,
            source_hash=self.source_hash,
            parent_ir_hash=self.ir_fingerprint,
            ir_fingerprint=fingerprint,
            agent_name=agent_name,
            status=CandidateStatus.PENDING,
            is_baseline=False
        )


class ImmutableBaselineError(Exception):
    """Raised when an illegal modification of the Candidate 0 baseline is attempted."""
    pass


class CandidateTree:
    """
    Candidate Lineage Coordinator and Transactional Rollback Manager.
    Guarantees Candidate 0 (baseline) is never removed or overwritten.
    """

    def __init__(self, baseline: Candidate):
        if not baseline.is_baseline:
            raise ValueError("Root candidate must be marked as baseline")
        self._baseline = copy.deepcopy(baseline)
        self._candidates: Dict[str, Candidate] = {
            self._baseline.candidate_id: self._baseline
        }

    @property
    def baseline(self) -> Candidate:
        return copy.deepcopy(self._baseline)

    @property
    def candidates(self) -> Dict[str, Candidate]:
        return {k: copy.deepcopy(v) for k, v in self._candidates.items()}

    def add(self, candidate: Candidate) -> None:
        if candidate.candidate_id == "baseline" and candidate is not self._baseline:
            raise ImmutableBaselineError("Cannot overwrite or replace immutable baseline candidate")
        self._candidates[candidate.candidate_id] = copy.deepcopy(candidate)

    def get(self, candidate_id: str) -> Optional[Candidate]:
        c = self._candidates.get(candidate_id)
        return copy.deepcopy(c) if c else None

    def rollback(self, candidate_id: str, reason: str = "") -> Candidate:
        """
        Transactional Rollback: marks candidate as ROLLED_BACK and returns its parent candidate.
        Baseline candidate can never be rolled back.
        """
        if candidate_id == "baseline":
            raise ImmutableBaselineError("Cannot roll back immutable baseline Candidate 0")

        cand = self._candidates.get(candidate_id)
        if not cand:
            raise KeyError(f"Candidate {candidate_id} not found in candidate tree")

        cand.status = CandidateStatus.ROLLED_BACK
        cand.rejection_reason = reason

        parent_id = cand.parent_id or "baseline"
        return self.get(parent_id) or self.baseline

    def get_best_verified_candidate(self) -> Candidate:
        """Returns the highest-scoring verified and accepted candidate, or baseline fallback."""
        accepted = [
            c for c in self._candidates.values()
            if c.status == CandidateStatus.ACCEPTED and not c.is_baseline
        ]
        if not accepted:
            return self.baseline

        # Sort by verified improvement percentage descending
        accepted.sort(
            key=lambda c: c.benchmark_result.get("improvement_pct", 0.0),
            reverse=True
        )
        return copy.deepcopy(accepted[0])
