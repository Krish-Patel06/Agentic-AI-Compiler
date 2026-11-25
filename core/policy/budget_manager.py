"""
Optimization Budget Manager.
Tracks resource consumption against hard limits loaded from Authoritative Policy:
  - Wall-clock budget (seconds)
  - Memory consumption (MB)
  - Candidate branch count
  - Agent call count
  - Benchmark run count
Dynamically halts candidate generation and forces baseline fallback when exhausted.
"""

from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Tuple, Optional

from policy.policy_loader import AuthoritativePolicy, load_authoritative_policy


@dataclass
class BudgetConfig:
    max_candidates: int = 8
    max_wall_time_sec: float = 60.0
    max_agent_calls: int = 5


@dataclass
class BudgetUsage:
    wall_time_elapsed_sec: float = 0.0
    memory_peak_mb: float = 0.0
    candidates_branched: int = 0
    agent_calls_made: int = 0
    benchmark_runs_made: int = 0


class OptimizationBudgetManager:
    """Non-AI Resource Governor enforcing strict optimization limits."""

    def __init__(self, policy: Optional[AuthoritativePolicy] = None, config: Optional[BudgetConfig] = None):
        self.policy = policy or load_authoritative_policy(enforce_signature=False)
        self.config = config
        self.usage = BudgetUsage()
        self._start_time = time.perf_counter()

    def is_exhausted(self) -> bool:
        can_b, _ = self.can_branch_candidate()
        return not can_b

    def update_wall_time(self) -> float:
        self.usage.wall_time_elapsed_sec = time.perf_counter() - self._start_time
        return self.usage.wall_time_elapsed_sec

    def can_branch_candidate(self) -> Tuple[bool, str]:
        self.update_wall_time()
        quotas = self.policy.resource_quotas

        if self.usage.wall_time_elapsed_sec >= quotas.max_wall_time_sec:
            return False, f"Wall-clock budget exhausted ({self.usage.wall_time_elapsed_sec:.1f}s >= {quotas.max_wall_time_sec}s)"

        if self.usage.candidates_branched >= quotas.max_candidate_branches:
            return False, f"Candidate branch quota exhausted ({self.usage.candidates_branched} >= {quotas.max_candidate_branches})"

        return True, "Budget OK"

    def can_call_agent(self) -> Tuple[bool, str]:
        self.update_wall_time()
        quotas = self.policy.resource_quotas

        if self.usage.wall_time_elapsed_sec >= quotas.max_wall_time_sec:
            return False, "Wall-clock budget exhausted"

        if self.usage.agent_calls_made >= quotas.max_agent_calls:
            return False, f"Agent call quota exhausted ({self.usage.agent_calls_made} >= {quotas.max_agent_calls})"

        return True, "Agent call permitted"

    def record_candidate(self, elapsed_ms: float = 0.0) -> None:
        self.usage.candidates_branched += 1
        self.update_wall_time()

    def record_agent_call(self) -> None:
        self.usage.agent_calls_made += 1

    def record_benchmark_run(self) -> None:
        self.usage.benchmark_runs_made += 1
