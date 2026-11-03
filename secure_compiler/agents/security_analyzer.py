"""
Secure Compiler — Specialized Security Analyzer Agent
Advisory agent assessing UB-sensitivity, security policy compliance, and transformation risks.
"""

from typing import Dict, Any, List
import json

from .schemas import AgentProposal
from ..ir.profiler import ProgramProfile


class SecurityAnalyzerAgent:
    """
    Audits proposed optimization passes for potential security violations,
    UB exploitation risks, or policy infractions.
    """

    def __init__(self, name: str = "SecurityAnalyzerAgent"):
        self.name = name

    def analyze(self, proposal: AgentProposal, profile: ProgramProfile) -> AgentProposal:
        warnings = []
        risk_level = "low"

        # Check for UB-sensitive transformations
        passes_set = set(proposal.passes)

        if "reassociate" in passes_set:
            # Reassociation of floating point might violate IEEE-754 precision guarantees
            has_fp = any(fp.fp_ops_count > 0 for fp in profile.function_profiles.values())
            if has_fp:
                warnings.append("Pass 'reassociate' on floating-point code may alter NaN/Inf semantics.")
                risk_level = "medium"

        if "loop-unroll" in passes_set:
            if profile.total_loops > 10:
                warnings.append("Aggressive loop unroll on high loop count may cause instruction cache thrashing.")
                risk_level = "medium"

        assessment = {
            "action": "security_assessment",
            "passes": proposal.passes,
            "parameters": {"audited_passes": len(proposal.passes)},
            "expected_benefit": proposal.expected_benefit,
            "risk": risk_level,
            "reason": " | ".join(warnings) if warnings else "All proposed passes comply with security baseline."
        }

        return AgentProposal.from_json(json.dumps(assessment), agent_name=self.name)
