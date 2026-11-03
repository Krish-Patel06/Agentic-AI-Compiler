"""
Secure Compiler — Deterministic Decision Engine
Implements the strict decision chain:
Candidate → Correctness → Security → Benchmark → Regression → Policy → Accept / Reject / Retry
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

from ..optimizer.candidate import Candidate, CandidateStatus
from ..verification.correctness_gate import CorrectnessReport
from ..security.security_gate import SecurityReport
from ..benchmark.benchmark_engine import BenchmarkMeasurement
from ..policy.policy_engine import PolicyDecision


class DecisionVerdict(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    RETRY = "retry"
    NEUTRAL = "neutral"


@dataclass
class DecisionResult:
    verdict: DecisionVerdict
    candidate_id: str
    rejection_code: str = ""
    explanation: str = ""
    can_retry: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        code_str = f" [{self.rejection_code}]" if self.rejection_code else ""
        return f"[DecisionEngine] {self.verdict.value.upper()}{code_str}: {self.explanation}"


class DecisionEngine:
    """
    Evaluates candidate verification, security, benchmarking, and policy results.
    Authoritatively determines whether a candidate is accepted, rejected, or retried.
    """

    def evaluate(
        self,
        candidate: Candidate,
        correctness: CorrectnessReport,
        security: SecurityReport,
        benchmark: BenchmarkMeasurement,
        policy: PolicyDecision,
        remaining_budget: int
    ) -> DecisionResult:
        cid = candidate.candidate_id

        # ── Gate 1: Correctness (Zero Tolerance) ──────────────────────
        if not correctness.passed:
            err_str = "; ".join(correctness.errors[:3])
            return DecisionResult(
                verdict=DecisionVerdict.REJECT,
                candidate_id=cid,
                rejection_code="ERR_CORRECTNESS_FAILED",
                explanation=f"Candidate failed correctness verification: {err_str}",
                can_retry=(remaining_budget > 0),
                details={"errors": correctness.errors}
            )

        # ── Gate 2: Security (Zero Tolerance) ─────────────────────────
        if not security.passed:
            viol_str = "; ".join(security.violations[:3])
            return DecisionResult(
                verdict=DecisionVerdict.REJECT,
                candidate_id=cid,
                rejection_code="ERR_SECURITY_VIOLATION",
                explanation=f"Candidate violated security policy: {viol_str}",
                can_retry=False,  # Security violations terminate this branch
                details={"violations": security.violations}
            )

        # ── Gate 3: Policy Limits ─────────────────────────────────────
        if not policy.allowed:
            return DecisionResult(
                verdict=DecisionVerdict.REJECT,
                candidate_id=cid,
                rejection_code="ERR_POLICY_DISALLOWED",
                explanation=f"Candidate violated compiler policy: {policy.reason}",
                can_retry=(remaining_budget > 0),
                details={"violations": policy.violations}
            )

        # ── Gate 4: Benchmark & Performance ───────────────────────────
        if benchmark.improvement_pct < 0.0:
            return DecisionResult(
                verdict=DecisionVerdict.REJECT,
                candidate_id=cid,
                rejection_code="ERR_PERFORMANCE_REGRESSION",
                explanation=f"Candidate introduced performance regression ({-benchmark.improvement_pct:.2f}% slower).",
                can_retry=(remaining_budget > 0),
                details={"benchmark": benchmark.to_dict()}
            )

        if benchmark.is_noisy:
            return DecisionResult(
                verdict=DecisionVerdict.RETRY if remaining_budget > 0 else DecisionVerdict.REJECT,
                candidate_id=cid,
                rejection_code="ERR_BENCHMARK_NOISY",
                explanation="Benchmark measurement was excessively noisy (CV > 15%).",
                can_retry=(remaining_budget > 0),
                details={"benchmark": benchmark.to_dict()}
            )

        if not benchmark.statistically_significant and benchmark.improvement_pct < 1.5:
            return DecisionResult(
                verdict=DecisionVerdict.NEUTRAL,
                candidate_id=cid,
                rejection_code="NEUTRAL_NO_SIGNIFICANT_IMPROVEMENT",
                explanation=f"Improvement ({benchmark.improvement_pct:.2f}%) did not reach statistical significance threshold (1.5%).",
                can_retry=(remaining_budget > 0),
                details={"benchmark": benchmark.to_dict()}
            )

        # ── All Gates Passed! ─────────────────────────────────────────
        return DecisionResult(
            verdict=DecisionVerdict.ACCEPT,
            candidate_id=cid,
            rejection_code="OK_VERIFIED_AND_BENCHMARKED",
            explanation=f"Candidate passed all gates with verified {benchmark.improvement_pct:.2f}% speedup.",
            can_retry=False,
            details={"benchmark": benchmark.to_dict()}
        )
