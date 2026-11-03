"""
Secure Compiler — Specialized Hardware Tuner Agent
Proposes target-ISA, SIMD vectorization, cache alignment, and register-aware passes.
"""

from typing import Dict, Any, List
import json

from .schemas import AgentProposal
from ..ir.profiler import ProgramProfile


class HWTunerAgent:
    """
    Analyzes hardware target, SIMD vectorization opportunities, and cache alignment.
    Strictly outputs structured JSON proposals.
    """

    def __init__(self, name: str = "HWTunerAgent"):
        self.name = name

    def propose(self, profile: ProgramProfile, target_arch: str = "native") -> AgentProposal:
        passes: List[str] = []
        reasons: List[str] = []
        expected_gain = 0.12

        # 1. SIMD & Vectorization Opportunities
        has_vector_potential = any(
            fp.vectorization_potential for fp in profile.function_profiles.values()
        )
        if has_vector_potential:
            passes.extend(["loop-vectorize", "slp-vectorizer"])
            reasons.append("Identified SIMD vectorization opportunities in loop bodies.")
            expected_gain += 0.18

        # 2. Cache Line & Alignment
        passes.append("alignment-from-assumptions")
        reasons.append("Enforcing data alignment for 64-byte cache lines.")

        # 3. Target Architecture & Calling Conventions
        arch_lower = target_arch.lower()
        if "arm" in arch_lower or "aarch64" in arch_lower:
            reasons.append("Tuning for ARM64 NEON pipeline with 128-bit vector registers.")
        elif "x86" in arch_lower or "amd64" in arch_lower:
            reasons.append("Tuning for x86_64 superscalar execution with AVX2.")

        # 4. Small Loop Unrolling
        if profile.total_loops > 0:
            passes.append("loop-unroll")
            reasons.append("Loop unrolling applied to reduce branch misprediction latency.")

        # 5. Tail Call Elimination
        passes.append("tailcallelim")
        reasons.append("Tail call elimination to reduce stack frame overhead.")

        proposal_dict = {
            "action": "propose_pass_pipeline",
            "passes": passes,
            "parameters": {
                "target_arch": target_arch,
                "vectorize": has_vector_potential,
                "cache_line_bytes": 64
            },
            "expected_benefit": min(0.40, expected_gain),
            "risk": "medium" if has_vector_potential else "low",
            "reason": " | ".join(reasons)
        }

        return AgentProposal.from_json(json.dumps(proposal_dict), agent_name=self.name)
