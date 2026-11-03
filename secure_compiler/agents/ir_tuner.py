"""
Secure Compiler — Specialized IR Tuner Agent
Proposes algorithmic LLVM pass sequences and phase orderings based on
deterministic program profiles. Pure advisory agent (zero authority).
"""

from typing import Dict, Any, List
import json

from .schemas import AgentProposal
from ..ir.profiler import ProgramProfile


class IRTunerAgent:
    """
    Analyzes program profile and proposes scalar & loop LLVM pass sequences.
    Strictly outputs structured JSON proposals.
    """

    def __init__(self, name: str = "IRTunerAgent"):
        self.name = name

    def propose(self, profile: ProgramProfile, iteration: int = 1) -> AgentProposal:
        """Generates an optimization proposal based on profile characteristics."""
        passes: List[str] = []
        reasons: List[str] = []
        expected_gain = 0.15

        # 1. Memory Operation Optimization
        has_memory_pressure = any(
            fp.memory_op_density > 0.20 for fp in profile.function_profiles.values()
        )
        if has_memory_pressure:
            passes.extend(["mem2reg", "sroa", "early-cse"])
            reasons.append("High memory operation density detected; promoting memory to registers via sroa/mem2reg.")
            expected_gain += 0.10

        # 2. Control Flow & Branch Density
        if profile.overall_branch_density > 0.12:
            passes.extend(["simplifycfg", "jump-threading"])
            reasons.append(f"Branch density is {profile.overall_branch_density:.1%}; applying simplifycfg and jump-threading.")
            expected_gain += 0.08

        # 3. Arithmetic Redundancy & Reductions
        passes.extend(["instcombine", "gvn", "reassociate"])

        # 4. Loop Optimization
        if profile.total_loops > 0:
            passes.extend(["loop-rotate", "licm", "indvars", "loop-deletion"])
            reasons.append(f"{profile.total_loops} loop(s) detected; applying invariant code motion and index variable simplification.")
            expected_gain += 0.12

        # 5. Dead Code Elimination
        passes.extend(["dce", "adce"])

        # Alternate pipeline on later iterations to explore phase ordering variations
        if iteration == 2:
            # Phase-ordering swap: GVN before InstCombine
            passes = ["sroa", "gvn", "instcombine", "simplifycfg", "dce"]
            reasons.append("Iteration 2: Exploring alternative phase ordering (GVN prioritized).")
        elif iteration >= 3:
            # Conservative cleanup sequence
            passes = ["mem2reg", "early-cse", "simplifycfg", "dce"]
            reasons.append(f"Iteration {iteration}: Exploring minimal footprint scalar pipeline.")

        proposal_dict = {
            "action": "propose_pass_pipeline",
            "passes": passes,
            "parameters": {"iteration": iteration, "optimization_goal": "latency_reduction"},
            "expected_benefit": min(0.45, expected_gain),
            "risk": "low",
            "reason": " | ".join(reasons) or "Standard scalar optimization pipeline."
        }

        return AgentProposal.from_json(json.dumps(proposal_dict), agent_name=self.name)
