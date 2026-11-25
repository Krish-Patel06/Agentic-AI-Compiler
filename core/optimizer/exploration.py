"""
Exploration vs. Exploitation Optimization Manager.
Controls optimization strategy:
  - EXPLOITATION: Prioritizes proven pass combinations from the Experience Store.
  - EXPLORATION: Deliberately explores novel pass phase-orderings to prevent stagnation.
"""

from __future__ import annotations
import random
from enum import Enum, unique
from dataclasses import dataclass
from typing import List, Optional, Set


@unique
class OptimizationMode(Enum):
    EXPLOITATION = "exploitation"
    EXPLORATION = "exploration"


@dataclass
class StrategyDecision:
    mode: OptimizationMode
    selected_pipeline: Optional[List[str]]
    novelty_score: float
    rationale: str


class ExplorationManager:
    """Balances exploitation of historical success with targeted exploration."""

    def __init__(self, exploration_rate: float = 0.25, seed: Optional[int] = 42):
        self.exploration_rate = exploration_rate
        if seed is not None:
            random.seed(seed)

    def decide_strategy(
        self,
        historical_sequences: List[List[str]],
        allowlisted_passes: Set[str],
        iteration: int = 1
    ) -> StrategyDecision:
        # In iteration 1, if we have historical experience, default to exploitation
        if iteration == 1 and historical_sequences:
            return StrategyDecision(
                mode=OptimizationMode.EXPLOITATION,
                selected_pipeline=historical_sequences[0],
                novelty_score=0.0,
                rationale="Iteration 1: Exploiting top proven pass sequence from Verified Experience Store."
            )

        # Decide whether to explore
        is_explore = (random.random() < self.exploration_rate) or not historical_sequences

        if is_explore:
            # Generate novel pass order from allowlist
            candidates = list(allowlisted_passes)
            k = min(len(candidates), random.randint(4, 7))
            novel_passes = random.sample(candidates, k)
            return StrategyDecision(
                mode=OptimizationMode.EXPLORATION,
                selected_pipeline=novel_passes,
                novelty_score=0.85,
                rationale=f"Exploration iteration {iteration}: Investigating novel pass phase ordering to prevent stagnation."
            )
        else:
            idx = random.randint(0, len(historical_sequences) - 1)
            return StrategyDecision(
                mode=OptimizationMode.EXPLOITATION,
                selected_pipeline=historical_sequences[idx],
                novelty_score=0.1,
                rationale=f"Exploitation iteration {iteration}: Replaying historical verified sequence #{idx + 1}."
            )
