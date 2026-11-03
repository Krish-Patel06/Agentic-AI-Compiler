"""
Secure Compiler — Exploration vs. Exploitation Strategy Manager
Implements epsilon-greedy and novelty-driven pass candidate selection.
Prevents optimization stagnation in the Experience Store by deliberately
exploring novel pass orderings and under-utilized allowlisted transformations.
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
import random


class OptimizationMode(str, Enum):
    EXPLOITATION = "exploitation"   # Use proven, historically successful pass combinations
    EXPLORATION = "exploration"     # Deliberately investigate novel pass sequences


@dataclass
class StrategyDecision:
    mode: OptimizationMode
    selected_pipeline: List[str]
    rationale: str
    novelty_score: float            # 0.0 (completely familiar) to 1.0 (completely novel)


class ExplorationManager:
    """
    Balances exploitation of verified historical experience with active exploration of novel
    pass sequences. Guarantees the compiler does not get trapped in local optima.
    """

    def __init__(self, epsilon: float = 0.25, seed: Optional[int] = 42):
        self.epsilon = epsilon
        self.rng = random.Random(seed)
        self.tried_sequences: set = set()

    def decide_strategy(
        self,
        historical_sequences: List[List[str]],
        allowlisted_passes: List[str],
        iteration: int = 1,
    ) -> StrategyDecision:
        """
        Decides whether to exploit a known sequence or explore a novel combination.
        Exploitation uses verified experience store; exploration synthesizes novel variations.
        """
        # Epsilon-greedy check or if no historical sequences exist, force exploration
        should_explore = (self.rng.random() < self.epsilon) or (not historical_sequences)

        if should_explore or not historical_sequences:
            # EXPLORATION: synthesize novel pass sequence from allowlist
            novel_seq = self._synthesize_novel_sequence(allowlisted_passes, historical_sequences)
            self.tried_sequences.add(tuple(novel_seq))
            return StrategyDecision(
                mode=OptimizationMode.EXPLORATION,
                selected_pipeline=novel_seq,
                rationale=f"Exploration iteration {iteration}: Investigating novel pass phase ordering to avoid stagnation.",
                novelty_score=0.85,
            )
        else:
            # EXPLOITATION: pick top verified sequence
            best_seq = historical_sequences[0]
            self.tried_sequences.add(tuple(best_seq))
            return StrategyDecision(
                mode=OptimizationMode.EXPLOITATION,
                selected_pipeline=list(best_seq),
                rationale=f"Exploitation iteration {iteration}: Replaying verified high-yield sequence from experience store.",
                novelty_score=0.10,
            )

    def _synthesize_novel_sequence(
        self, allowlisted_passes: List[str], historical: List[List[str]]
    ) -> List[str]:
        """Synthesizes a novel, policy-compliant pass sequence."""
        core_canonical = ["mem2reg", "sroa", "dce", "instcombine"]
        exploratory_pool = [
            "gvn", "simplifycfg", "licm", "loop-rotate", "reassociate",
            "loop-vectorize", "slp-vectorizer", "loop-unroll", "jump-threading",
            "alignment-from-assumptions"
        ]

        # Filter against allowlist
        valid_core = [p for p in core_canonical if p in allowlisted_passes]
        valid_exploratory = [p for p in exploratory_pool if p in allowlisted_passes]

        # Combine core with 2-4 exploratory passes
        k = self.rng.randint(2, min(4, len(valid_exploratory)))
        sampled = self.rng.sample(valid_exploratory, k)
        seq = valid_core + sampled

        # Ensure we haven't tried this exact sequence yet
        for _ in range(5):
            if tuple(seq) not in self.tried_sequences:
                break
            self.rng.shuffle(seq)

        return seq
