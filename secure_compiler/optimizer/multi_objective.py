"""
Secure Compiler — Multi-Objective Optimization & Pareto Selection
Supports optimization objectives: performance, binary size, compilation time,
memory usage, and balanced compromise. Implements Pareto dominance and
Pareto-optimal candidate selection.
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any, Optional


class OptimizationObjective(str, Enum):
    PERFORMANCE = "performance"
    BINARY_SIZE = "binary_size"
    COMPILATION_TIME = "compilation_time"
    MEMORY = "memory"
    BALANCED = "balanced"


@dataclass
class CandidateMetricsVector:
    """Normalized metrics vector for multi-objective comparison.
    All values are normalized where higher is better (positive improvement)."""
    candidate_id: str
    performance_gain_pct: float    # positive = faster
    size_reduction_pct: float      # positive = smaller code
    compile_time_overhead_ms: float# compilation time in ms (lower is better)
    memory_reduction_pct: float    # positive = less memory
    risk_penalty: float            # 0.0 (safe) to 1.0 (high risk)


class ParetoSelector:
    """
    Evaluates multi-objective trade-offs and extracts the Pareto-optimal frontier.
    Guarantees no dominated candidate is preferred over a non-dominated one.
    """

    @staticmethod
    def dominates(a: CandidateMetricsVector, b: CandidateMetricsVector, objective: OptimizationObjective) -> bool:
        """Returns True if candidate 'a' Pareto-dominates candidate 'b' under the given objective focus."""
        if objective == OptimizationObjective.PERFORMANCE:
            return a.performance_gain_pct >= b.performance_gain_pct and a.risk_penalty <= b.risk_penalty and (
                a.performance_gain_pct > b.performance_gain_pct or a.risk_penalty < b.risk_penalty
            )
        elif objective == OptimizationObjective.BINARY_SIZE:
            return a.size_reduction_pct >= b.size_reduction_pct and a.performance_gain_pct >= b.performance_gain_pct and (
                a.size_reduction_pct > b.size_reduction_pct or a.performance_gain_pct > b.performance_gain_pct
            )
        elif objective == OptimizationObjective.COMPILATION_TIME:
            return a.compile_time_overhead_ms <= b.compile_time_overhead_ms and a.performance_gain_pct >= b.performance_gain_pct and (
                a.compile_time_overhead_ms < b.compile_time_overhead_ms or a.performance_gain_pct > b.performance_gain_pct
            )
        elif objective == OptimizationObjective.MEMORY:
            return a.memory_reduction_pct >= b.memory_reduction_pct and a.performance_gain_pct >= b.performance_gain_pct and (
                a.memory_reduction_pct > b.memory_reduction_pct or a.performance_gain_pct > b.performance_gain_pct
            )
        else:  # BALANCED
            better_in_any = False
            # Check performance
            if a.performance_gain_pct < b.performance_gain_pct - 0.5:
                return False
            if a.performance_gain_pct > b.performance_gain_pct + 0.5:
                better_in_any = True

            # Check size
            if a.size_reduction_pct < b.size_reduction_pct - 1.0:
                return False
            if a.size_reduction_pct > b.size_reduction_pct + 1.0:
                better_in_any = True

            # Check compile time
            if a.compile_time_overhead_ms > b.compile_time_overhead_ms + 50.0:
                return False
            if a.compile_time_overhead_ms < b.compile_time_overhead_ms - 50.0:
                better_in_any = True

            return better_in_any

    @classmethod
    def get_pareto_front(
        cls, candidates: List[CandidateMetricsVector], objective: OptimizationObjective = OptimizationObjective.BALANCED
    ) -> List[CandidateMetricsVector]:
        """Extracts the non-dominated Pareto frontier from the candidate set."""
        if not candidates:
            return []

        pareto_front: List[CandidateMetricsVector] = []
        for cand in candidates:
            is_dominated = False
            for other in candidates:
                if cand.candidate_id != other.candidate_id and cls.dominates(other, cand, objective):
                    is_dominated = True
                    break
            if not is_dominated:
                pareto_front.append(cand)

        return pareto_front

    @classmethod
    def select_best(
        cls,
        candidates: List[CandidateMetricsVector],
        objective: OptimizationObjective = OptimizationObjective.BALANCED,
    ) -> Optional[CandidateMetricsVector]:
        """Selects the single best candidate by scalarizing over the Pareto frontier."""
        frontier = cls.get_pareto_front(candidates, objective)
        if not frontier:
            return None

        # Weights based on objective
        weights = {
            OptimizationObjective.PERFORMANCE:      {"perf": 0.80, "size": 0.05, "time": 0.05, "mem": 0.10},
            OptimizationObjective.BINARY_SIZE:      {"perf": 0.20, "size": 0.60, "time": 0.10, "mem": 0.10},
            OptimizationObjective.COMPILATION_TIME: {"perf": 0.25, "size": 0.05, "time": 0.60, "mem": 0.10},
            OptimizationObjective.MEMORY:           {"perf": 0.25, "size": 0.15, "time": 0.10, "mem": 0.50},
            OptimizationObjective.BALANCED:         {"perf": 0.50, "size": 0.20, "time": 0.15, "mem": 0.15},
        }[objective]

        best_score = -float("inf")
        best_cand = None

        for cand in frontier:
            # Score formula
            score = (
                weights["perf"] * cand.performance_gain_pct
                + weights["size"] * cand.size_reduction_pct
                - weights["time"] * (cand.compile_time_overhead_ms / 100.0)
                + weights["mem"] * cand.memory_reduction_pct
                - (cand.risk_penalty * 10.0)
            )
            if score > best_score:
                best_score = score
                best_cand = cand

        return best_cand
