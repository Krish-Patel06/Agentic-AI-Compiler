"""
Secure Compiler — Risk-Aware Verification Router
Classifies candidate optimization pipelines into Risk Tiers (LOW, MEDIUM, HIGH)
and determines the mandatory verification strategy required before acceptance.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Set, Optional
from ..ir.profiler import ProgramProfile


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class VerificationStrategy:
    risk_tier: RiskTier
    run_ir_validation: bool = True
    run_differential: bool = True
    run_adversarial: bool = False
    run_semantic_equivalence: bool = False
    run_canary_stress: bool = False
    run_sanitizer: bool = True
    reasons: List[str] = field(default_factory=list)

    def summary(self) -> str:
        gates = []
        if self.run_ir_validation: gates.append("IRValidator")
        if self.run_differential: gates.append("Differential")
        if self.run_adversarial: gates.append("Adversarial")
        if self.run_semantic_equivalence: gates.append("SemanticEquiv")
        if self.run_canary_stress: gates.append("CanaryStress")
        if self.run_sanitizer: gates.append("Sanitizer")
        return f"[RiskRouter] Tier={self.risk_tier.value.upper()} | Required Gates: {', '.join(gates)}"


class RiskAwareVerificationRouter:
    """
    Evaluates pass pipelines and program profile characteristics to dynamically
    route candidates through appropriate levels of verification rigor.
    """

    LOW_RISK_PASSES: Set[str] = {
        "mem2reg", "instcombine", "simplifycfg", "dce", "adce", "bdce",
        "early-cse", "sccp", "reassociate", "ipsccp", "tailcallelim",
        "constmerge", "alignment-from-assumptions", "correlated-propagation",
    }

    MEDIUM_RISK_PASSES: Set[str] = {
        "loop-unroll", "loop-vectorize", "slp-vectorizer", "inline",
        "sroa", "gvn", "licm", "indvars", "loop-deletion", "loop-idiom",
        "mllvm -inline-threshold=250", "mllvm -inline-threshold=500",
    }

    HIGH_RISK_PASSES: Set[str] = {
        "ffast-math", "aggressive-instcombine", "loop-interchange",
        "loop-rotate", "flto", "fno-trapping-math", "funsafe-math-optimizations",
    }

    @classmethod
    def normalize_pass_name(cls, pass_name: str) -> str:
        p = pass_name.strip()
        # Unwrap function(pass)
        if p.startswith("function(") and p.endswith(")"):
            p = p[9:-1].strip()
        # Strip leading dashes
        p = p.lstrip("-")
        return p

    @classmethod
    def assess_risk(
        cls,
        passes: List[str],
        profile: Optional[ProgramProfile] = None
    ) -> VerificationStrategy:
        reasons: List[str] = []
        has_high = False
        has_medium = False
        unknown_passes = []

        for raw_p in passes:
            clean_p = raw_p.strip()
            norm_p = cls.normalize_pass_name(clean_p)

            if norm_p in cls.HIGH_RISK_PASSES or clean_p in cls.HIGH_RISK_PASSES:
                has_high = True
                reasons.append(f"Contains high-risk pass '{clean_p}' (fp reordering or loop interchange)")
            elif norm_p in cls.MEDIUM_RISK_PASSES or clean_p in cls.MEDIUM_RISK_PASSES:
                has_medium = True
            elif norm_p in cls.LOW_RISK_PASSES or clean_p in cls.LOW_RISK_PASSES:
                pass
            else:
                # Any unknown or custom pass defaults to HIGH risk for safety
                has_high = True
                unknown_passes.append(clean_p)
                reasons.append(f"Contains unclassified/novel pass '{clean_p}' requiring maximum verification")

        # Escalate if profile has deep loops or high branch density
        if profile:
            if profile.total_loops > 5 and has_medium:
                has_high = True
                reasons.append("High loop complexity with medium passes escalated to High Risk")
            if profile.overall_branch_density > 0.4 and has_medium:
                has_high = True
                reasons.append("High branch density with loop passes escalated to High Risk")

        if has_high:
            tier = RiskTier.HIGH
            return VerificationStrategy(
                risk_tier=tier,
                run_ir_validation=True,
                run_differential=True,
                run_adversarial=True,
                run_semantic_equivalence=True,
                run_canary_stress=True,
                run_sanitizer=True,
                reasons=reasons or ["High risk transformations detected"]
            )
        elif has_medium:
            tier = RiskTier.MEDIUM
            reasons.append("Medium risk transformations (vectorization/unrolling) present")
            return VerificationStrategy(
                risk_tier=tier,
                run_ir_validation=True,
                run_differential=True,
                run_adversarial=False,
                run_semantic_equivalence=True,
                run_canary_stress=False,
                run_sanitizer=True,
                reasons=reasons
            )
        else:
            tier = RiskTier.LOW
            reasons.append("All passes are standard canonicalization/cleanup transformations")
            return VerificationStrategy(
                risk_tier=tier,
                run_ir_validation=True,
                run_differential=True,
                run_adversarial=False,
                run_semantic_equivalence=False,
                run_canary_stress=False,
                run_sanitizer=True,
                reasons=reasons
            )
