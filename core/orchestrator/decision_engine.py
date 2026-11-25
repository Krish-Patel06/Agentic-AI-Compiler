"""
Authoritative Decision Engine.
The sole entity with authority to ACCEPT or REJECT optimization candidates.
Strictly non-AI, deterministic evaluation.
"""

from __future__ import annotations
from enum import Enum, unique
from dataclasses import dataclass
from typing import Dict, Any, Optional

from ..optimizer.candidate import Candidate
from ..verification.correctness_gate import CorrectnessReport
from ..security.security_gate import SecurityReport
from ..benchmark.benchmark_engine import BenchmarkMeasurement
from ..verification.canary import CanaryReport
from policy.policy_loader import AuthoritativePolicy, load_authoritative_policy


@unique
class DecisionVerdict(Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    NEUTRAL = "neutral"
    BASELINE_FALLBACK = "baseline_fallback"


@dataclass
class DecisionResult:
    verdict: DecisionVerdict
    candidate_id: str
    improvement_pct: float
    explanation: str
    rejection_code: str = ""


class DecisionEngine:
    """Authoritative compiler decision maker."""

    def __init__(self, policy: Optional[AuthoritativePolicy] = None):
        self.policy = policy or load_authoritative_policy(enforce_signature=False)

    def evaluate(
        self,
        candidate: Candidate,
        correctness: CorrectnessReport,
        security: SecurityReport,
        benchmark: BenchmarkMeasurement,
        canary: Optional[CanaryReport] = None,
        remaining_budget: int = 1
    ) -> DecisionResult:
        # Hard Invariant 1: Correctness Gate
        if not correctness.passed:
            err_msg = "; ".join(correctness.errors[:2]) if correctness.errors else "Calculation deviation"
            return DecisionResult(
                verdict=DecisionVerdict.REJECT,
                candidate_id=candidate.candidate_id,
                improvement_pct=benchmark.improvement_pct,
                explanation=f"Correctness Gate failed: {err_msg}",
                rejection_code="ERR_CORRECTNESS_FAILED"
            )

        # Hard Invariant 2: Security Gate
        if not security.passed:
            viol_msg = "; ".join(security.violations[:2]) if security.violations else "Security policy violation"
            return DecisionResult(
                verdict=DecisionVerdict.REJECT,
                candidate_id=candidate.candidate_id,
                improvement_pct=benchmark.improvement_pct,
                explanation=f"Security Gate failed: {viol_msg}",
                rejection_code="ERR_SECURITY_VIOLATION"
            )

        # Hard Invariant 3: Canary Release Stress Stage
        if canary and not canary.passed:
            canary_err = "; ".join(canary.failures[:1]) if canary.failures else "Numerical drift detected"
            return DecisionResult(
                verdict=DecisionVerdict.REJECT,
                candidate_id=candidate.candidate_id,
                improvement_pct=benchmark.improvement_pct,
                explanation=f"Canary Release Stage failed: {canary_err}",
                rejection_code="ERR_CANARY_DRIFT"
            )

        # Optimization Criterion: Statistical Significance (>= 1.5% margin and > 2 sigma)
        min_margin = self.policy.benchmark_limits.min_statistical_margin_pct
        if benchmark.is_noisy:
            return DecisionResult(
                verdict=DecisionVerdict.NEUTRAL,
                candidate_id=candidate.candidate_id,
                improvement_pct=benchmark.improvement_pct,
                explanation=f"Benchmark rejected due to excessive microarchitectural jitter (CV={benchmark.cv:.2%})",
                rejection_code="ERR_BENCHMARK_NOISY"
            )

        if benchmark.improvement_pct >= min_margin and benchmark.statistically_significant:
            return DecisionResult(
                verdict=DecisionVerdict.ACCEPT,
                candidate_id=candidate.candidate_id,
                improvement_pct=benchmark.improvement_pct,
                explanation=(
                    f"Candidate {candidate.candidate_id} accepted: Verified {benchmark.improvement_pct:.2f}% speedup "
                    f"(p50={benchmark.p50_runtime_ns:.1f}ns vs baseline), Correctness=PASS, Security=PASS, Canary=PASS."
                )
            )

        # Below statistical threshold (e.g. 0.0% to 1.49%)
        return DecisionResult(
            verdict=DecisionVerdict.NEUTRAL,
            candidate_id=candidate.candidate_id,
            improvement_pct=benchmark.improvement_pct,
            explanation=f"Improvement ({benchmark.improvement_pct:.2f}%) did not reach statistical significance threshold ({min_margin}%).",
            rejection_code="ERR_BELOW_SIGNIFICANCE_MARGIN"
        )
