"""
Security Analyzer Agent.
Performs pre-execution advisory security and undefined behavior analysis.
Emits advisory JSON matching /policy/schemas/advisory.json.
(Note: Security Analyzer is advisory; non-AI security gates remain authoritative).
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from .base_agent import BaseAgent
from ..ir.profiler import ProgramProfile


class SecurityAnalyzerAgent(BaseAgent):
    def __init__(self, name: str = "security_analyzer", model_id: Optional[str] = None):
        super().__init__(name=name, model_id=model_id)

    def analyze(self, proposal: Dict[str, Any], profile: ProgramProfile) -> Dict[str, Any]:
        passes = set(proposal.get("proposed_passes", []))
        flags: List[str] = []
        risk = "low"
        recommendation = "PROCEED"

        # Check for aggressive loop transformations on branch-heavy routines
        if "loop-unroll" in passes and profile.overall_branch_density > 0.35:
            flags.append("High branch density combined with loop-unroll may induce instruction cache blowout")
            risk = "medium"
            recommendation = "REQUIRE_ADVERSARIAL"

        if "loop-vectorize" in passes or "slp-vectorizer" in passes:
            flags.append("SIMD vectorization requires NaN and float subnormal differential checking")
            if risk != "high":
                risk = "medium"
                recommendation = "REQUIRE_ADVERSARIAL"

        # If any forbidden or dangerous pass was suggested
        if any(p in {"strip", "mergefunc", "internalize"} for p in passes):
            flags.append("Forbidden pass detected in AI proposal")
            risk = "critical"
            recommendation = "REJECT"

        reason = "Pass pipeline conforms to low-risk baseline criteria." if not flags else "; ".join(flags)

        return {
            "agent": "security_analyzer",
            "candidate_id": proposal.get("candidate_id", "unknown"),
            "risk": risk,
            "flags": flags,
            "recommendation": recommendation,
            "reason": reason
        }
