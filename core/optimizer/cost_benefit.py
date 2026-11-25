"""
Pre-Execution Cost/Benefit Scorer.
Evaluates AI optimization proposals BEFORE compilation or benchmarking.
Computes Expected Value (EV) and prunes negative-ROI proposals.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, List
from ..ir.profiler import ProgramProfile


@dataclass
class CostBenefitScore:
    expected_value: float
    predicted_improvement_pct: float
    predicted_compile_ms: float
    historical_success_prob: float
    risk_factor: float
    recommendation: str  # "HIGH_PRIORITY", "MEDIUM_PRIORITY", "PRUNE"

    @property
    def should_prune(self) -> bool:
        return self.recommendation == "PRUNE" or self.expected_value < 0.0


class CandidateCostBenefitScorer:
    """
    Pareto-aware Pre-Execution Cost/Benefit Scorer.
    Prunes candidates with poor expected value before burning compiler sandbox resources.
    """

    PASS_BASE_SPEEDUP = {
        "mem2reg": 18.0,
        "sroa": 12.0,
        "instcombine": 8.0,
        "gvn": 7.0,
        "loop-vectorize": 15.0,
        "slp-vectorizer": 9.0,
        "loop-unroll": 5.0,
        "simplifycfg": 4.0,
        "licm": 6.0,
        "reassociate": 3.0,
        "alignment-from-assumptions": 4.0
    }

    PASS_COMPILE_OVERHEAD_MS = {
        "mem2reg": 3.0,
        "sroa": 4.0,
        "instcombine": 5.0,
        "gvn": 12.0,
        "loop-vectorize": 15.0,
        "slp-vectorizer": 10.0,
        "loop-unroll": 8.0,
        "simplifycfg": 3.0,
        "licm": 6.0
    }

    @classmethod
    def score_proposal(
        cls,
        proposal: Dict[str, Any],
        profile: ProgramProfile,
        historical_success_rate: float = 0.85
    ) -> CostBenefitScore:
        passes = proposal.get("proposed_passes", [])
        risk_str = proposal.get("risk", "low").lower()
        risk_weights = {"low": 0.1, "medium": 0.35, "high": 0.75, "critical": 1.5}
        risk_factor = risk_weights.get(risk_str, 0.25)

        # 1. Estimate predicted benefit
        predicted_speedup = 0.0
        for p in passes:
            clean = p.lstrip("-")
            predicted_speedup += cls.PASS_BASE_SPEEDUP.get(clean, 2.0)
        # Apply diminishing returns formula: S = max_ceiling * (1 - e^(-total / k))
        predicted_speedup = min(45.0, predicted_speedup * 0.75)

        # 2. Estimate compilation cost
        total_compile_ms = 10.0 + sum(cls.PASS_COMPILE_OVERHEAD_MS.get(p.lstrip("-"), 3.0) for p in passes)

        # 3. Success probability
        success_prob = historical_success_rate * (1.0 - (risk_factor * 0.3))

        # 4. Expected Value formula
        # EV = (Probability * Benefit) - (CompileCostPenalty + RiskPenalty)
        compile_cost_penalty = total_compile_ms * 0.15
        risk_penalty = risk_factor * 12.0
        ev = (success_prob * predicted_speedup) - (compile_cost_penalty + risk_penalty)

        if ev >= 12.0:
            rec = "HIGH_PRIORITY"
        elif ev >= 3.0:
            rec = "MEDIUM_PRIORITY"
        else:
            rec = "PRUNE"

        return CostBenefitScore(
            expected_value=round(ev, 2),
            predicted_improvement_pct=round(predicted_speedup, 2),
            predicted_compile_ms=round(total_compile_ms, 1),
            historical_success_prob=round(success_prob, 2),
            risk_factor=round(risk_factor, 2),
            recommendation=rec
        )
