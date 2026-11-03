"""
Secure Compiler — Candidate Model & Tree for Isolated Branching and Rollback
Maintains parent-child relationships, deterministic baseline, and reversible optimizations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any

from ..ir.fingerprint import IRFingerprinter


class CandidateStatus(str, Enum):
    PENDING = "pending"
    COMPILED = "compiled"
    VERIFIED = "verified"
    REJECTED = "rejected"
    ACCEPTED = "accepted"
    ROLLED_BACK = "rolled_back"


@dataclass
class ResourceUsage:
    """Resource metrics captured during candidate generation and execution."""
    compilation_time_ms: float = 0.0
    ir_bytes: int = 0
    instruction_count: int = 0
    binary_bytes: int = 0
    peak_memory_mb: float = 0.0


@dataclass
class Candidate:
    """
    An isolated compilation candidate branch.
    Never mutates production IR directly.
    """
    candidate_id: str
    parent_id: Optional[str]
    pass_pipeline: List[str]
    ir_text: str
    ir_fingerprint: str
    status: CandidateStatus = CandidateStatus.PENDING
    resource_usage: ResourceUsage = field(default_factory=ResourceUsage)
    rejection_reason: str = ""
    verification_report: Dict[str, Any] = field(default_factory=dict)
    benchmark_result: Dict[str, Any] = field(default_factory=dict)
    binary_path: Optional[str] = None
    is_baseline: bool = False
    depth: int = 0

    @classmethod
    def create_baseline(cls, ir_text: str, pass_pipeline: Optional[List[str]] = None) -> "Candidate":
        fp = IRFingerprinter.compute_hash(ir_text)
        return cls(
            candidate_id="baseline",
            parent_id=None,
            pass_pipeline=pass_pipeline or ["default<O0>"],
            ir_text=ir_text,
            ir_fingerprint=fp,
            status=CandidateStatus.VERIFIED,
            resource_usage=ResourceUsage(
                ir_bytes=len(ir_text.encode("utf-8")),
                instruction_count=ir_text.count("\n"),
            ),
            is_baseline=True,
            depth=0,
        )

    def branch(
        self,
        new_id: str,
        additional_passes: List[str],
        new_ir_text: str
    ) -> "Candidate":
        """Creates an isolated child candidate inheriting from this candidate."""
        fp = IRFingerprinter.compute_hash(new_ir_text)
        return Candidate(
            candidate_id=new_id,
            parent_id=self.candidate_id,
            pass_pipeline=list(self.pass_pipeline) + list(additional_passes),
            ir_text=new_ir_text,
            ir_fingerprint=fp,
            status=CandidateStatus.PENDING,
            resource_usage=ResourceUsage(
                ir_bytes=len(new_ir_text.encode("utf-8")),
            ),
            is_baseline=False,
            depth=self.depth + 1,
        )


class CandidateTree:
    """
    Manages candidate lineage and rollback mechanics.
    Guarantees baseline preservation at all times.
    """

    def __init__(self, baseline: Candidate):
        self.baseline = baseline
        self.candidates: Dict[str, Candidate] = {baseline.candidate_id: baseline}
        self.children: Dict[str, List[str]] = {baseline.candidate_id: []}

    def add(self, candidate: Candidate):
        self.candidates[candidate.candidate_id] = candidate
        parent = candidate.parent_id or self.baseline.candidate_id
        if parent not in self.children:
            self.children[parent] = []
        self.children[parent].append(candidate.candidate_id)

    def get(self, candidate_id: str) -> Optional[Candidate]:
        return self.candidates.get(candidate_id)

    def rollback(self, candidate_id: str, reason: str = ""):
        """Marks candidate and its descendants as rolled back."""
        cand = self.candidates.get(candidate_id)
        if cand and not cand.is_baseline:
            cand.status = CandidateStatus.ROLLED_BACK
            cand.rejection_reason = reason or "Rolled back by Decision Engine."
            # Roll back children
            for child_id in self.children.get(candidate_id, []):
                self.rollback(child_id, reason="Cascading rollback from parent.")

    def get_best_verified_candidate(self) -> Candidate:
        """
        Returns the best verified candidate according to benchmark results.
        If no candidates improved upon the baseline or passed verification,
        the deterministic baseline is safely returned.
        """
        verified = [
            c for c in self.candidates.values()
            if c.status in (CandidateStatus.VERIFIED, CandidateStatus.ACCEPTED)
        ]

        if not verified:
            return self.baseline

        # Rank by benchmark runtime improvement or instruction reduction
        def score(c: Candidate) -> float:
            if c.is_baseline:
                return 0.0
            bm = c.benchmark_result
            if bm and "improvement_pct" in bm:
                return float(bm["improvement_pct"])
            # Fallback to instruction reduction
            base_instr = max(self.baseline.resource_usage.instruction_count, 1)
            cand_instr = c.resource_usage.instruction_count
            return ((base_instr - cand_instr) / base_instr) * 100.0

        best = max(verified, key=score)
        if score(best) <= 0.0 and not best.is_baseline:
            # If no candidate performed better than baseline, return baseline
            return self.baseline
        return best
