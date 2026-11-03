"""
Secure Compiler — Optimization Budget Manager
Tracks and strictly governs resource consumption across:
  - wall-clock time budget
  - CPU execution time budget
  - peak memory consumption
  - candidate branch count
  - agent invocation count
  - benchmark execution count

Prevents infinite optimization loops and halts processing safely when budgets expire.
"""

from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, Any
import time


@dataclass
class BudgetLimits:
    max_wall_time_s: float = 60.0
    max_cpu_time_s: float = 120.0
    max_memory_mb: int = 4096
    max_candidates: int = 8
    max_agent_calls: int = 16
    max_benchmark_runs: int = 24


@dataclass
class BudgetUsage:
    wall_time_elapsed_s: float = 0.0
    cpu_time_spent_s: float = 0.0
    peak_memory_mb: float = 0.0
    candidates_created: int = 0
    agent_calls_made: int = 0
    benchmark_runs_executed: int = 0


class OptimizationBudgetManager:
    """
    Authoritative resource governor for compiler optimization.
    AI agents cannot request budget increases or bypass these quotas.
    """

    def __init__(self, limits: Optional[BudgetLimits] = None):
        self.limits = limits or BudgetLimits()
        self.usage = BudgetUsage()
        self._t_start = time.perf_counter()

    def update_wall_time(self) -> float:
        self.usage.wall_time_elapsed_s = round(time.perf_counter() - self._t_start, 2)
        return self.usage.wall_time_elapsed_s

    def can_branch_candidate(self) -> Tuple[bool, str]:
        self.update_wall_time()
        if self.usage.wall_time_elapsed_s >= self.limits.max_wall_time_s:
            return False, f"Wall-clock budget exhausted ({self.usage.wall_time_elapsed_s:.1f}s >= {self.limits.max_wall_time_s:.1f}s)."
        if self.usage.candidates_created >= self.limits.max_candidates:
            return False, f"Candidate branch quota exhausted ({self.usage.candidates_created} >= {self.limits.max_candidates})."
        return True, "OK"

    def can_call_agent(self) -> Tuple[bool, str]:
        self.update_wall_time()
        if self.usage.wall_time_elapsed_s >= self.limits.max_wall_time_s:
            return False, "Wall-clock budget exhausted."
        if self.usage.agent_calls_made >= self.limits.max_agent_calls:
            return False, f"Agent invocation quota exhausted ({self.usage.agent_calls_made} >= {self.limits.max_agent_calls})."
        return True, "OK"

    def can_run_benchmark(self) -> Tuple[bool, str]:
        self.update_wall_time()
        if self.usage.wall_time_elapsed_s >= self.limits.max_wall_time_s:
            return False, "Wall-clock budget exhausted."
        if self.usage.benchmark_runs_executed >= self.limits.max_benchmark_runs:
            return False, f"Benchmark trial quota exhausted ({self.usage.benchmark_runs_executed} >= {self.limits.max_benchmark_runs})."
        return True, "OK"

    def record_candidate(self, elapsed_ms: float = 0.0, memory_mb: float = 0.0):
        self.usage.candidates_created += 1
        self.usage.cpu_time_spent_s += (elapsed_ms / 1000.0)
        if memory_mb > self.usage.peak_memory_mb:
            self.usage.peak_memory_mb = memory_mb
        self.update_wall_time()

    def record_agent_call(self):
        self.usage.agent_calls_made += 1
        self.update_wall_time()

    def record_benchmark_run(self, elapsed_ms: float = 0.0):
        self.usage.benchmark_runs_executed += 1
        self.usage.cpu_time_spent_s += (elapsed_ms / 1000.0)
        self.update_wall_time()

    def to_dict(self) -> Dict[str, Any]:
        self.update_wall_time()
        return {
            "limits": {
                "max_wall_time_s": self.limits.max_wall_time_s,
                "max_cpu_time_s": self.limits.max_cpu_time_s,
                "max_memory_mb": self.limits.max_memory_mb,
                "max_candidates": self.limits.max_candidates,
                "max_agent_calls": self.limits.max_agent_calls,
                "max_benchmark_runs": self.limits.max_benchmark_runs,
            },
            "usage": {
                "wall_time_elapsed_s": self.usage.wall_time_elapsed_s,
                "cpu_time_spent_s": round(self.usage.cpu_time_spent_s, 2),
                "peak_memory_mb": round(self.usage.peak_memory_mb, 1),
                "candidates_created": self.usage.candidates_created,
                "agent_calls_made": self.usage.agent_calls_made,
                "benchmark_runs_executed": self.usage.benchmark_runs_executed,
            },
            "remaining_candidates": max(0, self.limits.max_candidates - self.usage.candidates_created),
            "remaining_time_s": max(0.0, round(self.limits.max_wall_time_s - self.usage.wall_time_elapsed_s, 2)),
        }
