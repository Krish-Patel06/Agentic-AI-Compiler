"""
Secure Compiler — Pre-Execution Candidate Cost/Benefit Scoring
Evaluates proposals BEFORE expensive compilation and statistical benchmarking.
Computes an expected value (EV) based on historical success, predicted gains,
compilation overhead, verification expense, code-size impact, and risk.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class CostBenefitScore:
    expected_value: float            # Composite prioritization metric (higher is better)
    predicted_improvement_pct: float
    historical_success_prob: float
    estimated_compile_cost_ms: float
    estimated_verification_cost_ms: float
    code_size_impact_factor: float   # negative = shrinks, positive = grows
    risk_factor: float               # 0.0 (minimal) to 1.0 (extreme)
    recommendation: str              # "HIGH_PRIORITY", "MEDIUM_PRIORITY", "LOW_PRIORITY", "PRUNE"


class CandidateCostBenefitScorer:
    """
    Ranks optimization proposals before allocating budget or sandbox slots.
    Prioritizes proposals with optimal risk-adjusted ROI.
    """

    PASS_BASE_COMPILE_COSTS = {
        "mem2reg": 5.0,
        "sroa": 8.0,
        "dce": 3.0,
        "instcombine": 12.0,
        "gvn": 15.0,
        "licm": 10.0,
        "simplifycfg": 6.0,
        "loop-vectorize": 35.0,
        "slp-vectorizer": 30.0,
        "loop-unroll": 25.0,
        "-inline": 20.0,
        "always-inline": 15.0,
        "jump-threading": 12.0,
        "alignment-from-assumptions": 4.0,
        "reassociate": 8.0,
    }

    @classmethod
    def score_proposal(
        cls,
        proposal: Dict[str, Any],
        profile: Any,
        historical_success_rate: float = 0.85,
    ) -> CostBenefitScore:
        passes = proposal.get("passes", [])
        expected_benefit = float(proposal.get("expected_benefit", 10.0))
        if 0.0 < expected_benefit <= 1.0:
            expected_benefit *= 100.0
        risk_str = str(proposal.get("risk", "low")).lower()

        # Risk factor mapping
        risk_factor = {
            "low": 0.10,
            "medium": 0.40,
            "high": 0.80,
        }.get(risk_str, 0.30)

        # Estimate compilation overhead
        compile_cost = sum(cls.PASS_BASE_COMPILE_COSTS.get(p, 10.0) for p in passes)
        if hasattr(profile, "total_instructions") and profile.total_instructions > 500:
            compile_cost *= 1.3

        # Estimate verification cost based on risk
        verification_cost = 20.0 + (risk_factor * 80.0)

        # Estimate code size impact (unrolling & inlining can inflate size)
        code_size_impact = 0.0
        if any("unroll" in p for p in passes):
            code_size_impact += 0.15
        if any("inline" in p for p in passes):
            code_size_impact += 0.20
        if any(p in ("dce", "simplifycfg", "sroa") for p in passes):
            code_size_impact -= 0.10

        # Adjust success probability by pass length and risk
        prob = max(0.2, min(0.98, historical_success_rate - (risk_factor * 0.3) - (len(passes) * 0.01)))

        # Expected Value Formula:
        # EV = P(success) * benefit - (compile_cost * 0.05) - (verification_cost * 0.05) - (risk_factor * 12) - (max(0, code_size_impact) * 8)
        ev = (
            (prob * expected_benefit)
            - (compile_cost * 0.04)
            - (verification_cost * 0.04)
            - (risk_factor * 10.0)
            - (max(0.0, code_size_impact) * 10.0)
        )

        if ev >= 15.0:
            rec = "HIGH_PRIORITY"
        elif ev >= 5.0:
            rec = "MEDIUM_PRIORITY"
        elif ev >= 0.0:
            rec = "LOW_PRIORITY"
        else:
            rec = "PRUNE"

        return CostBenefitScore(
            expected_value=round(ev, 2),
            predicted_improvement_pct=round(expected_benefit, 2),
            historical_success_prob=round(prob, 3),
            estimated_compile_cost_ms=round(compile_cost, 1),
            estimated_verification_cost_ms=round(verification_cost, 1),
            code_size_impact_factor=round(code_size_impact, 2),
            risk_factor=risk_factor,
            recommendation=rec,
        )
