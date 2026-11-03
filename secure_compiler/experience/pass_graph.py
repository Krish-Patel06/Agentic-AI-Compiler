"""
Secure Compiler — Pass Interaction Graph
Tracks historical relationships and synergies between LLVM optimization passes:
  - pairwise transition success rate
  - average verified performance improvement
  - compile-time overhead
  - code-size delta impact

Guides the IR Tuner and Hardware Tuner to prioritize high-yield pass sequences
and avoid known antagonistic pairings.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any
import json
import os
import random


@dataclass
class PassTransitionStats:
    total_executions: int = 0
    successes: int = 0
    total_speedup_pct: float = 0.0
    total_compile_ms: float = 0.0
    total_code_size_delta_pct: float = 0.0

    @property
    def success_rate(self) -> float:
        return (self.successes / self.total_executions) if self.total_executions > 0 else 0.85

    @property
    def avg_speedup(self) -> float:
        return (self.total_speedup_pct / self.total_executions) if self.total_executions > 0 else 0.0

    @property
    def avg_compile_ms(self) -> float:
        return (self.total_compile_ms / self.total_executions) if self.total_executions > 0 else 10.0

    @property
    def avg_code_size_delta(self) -> float:
        return (self.total_code_size_delta_pct / self.total_executions) if self.total_executions > 0 else 0.0

    def synergy_score(self) -> float:
        """Composite heuristic: high success rate + high speedup - compile cost penalty."""
        return (self.success_rate * 15.0) + (self.avg_speedup * 1.5) - (self.avg_compile_ms * 0.05)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_executions": self.total_executions,
            "successes": self.successes,
            "total_speedup_pct": round(self.total_speedup_pct, 2),
            "total_compile_ms": round(self.total_compile_ms, 2),
            "total_code_size_delta_pct": round(self.total_code_size_delta_pct, 2),
            "success_rate": round(self.success_rate, 3),
            "avg_speedup": round(self.avg_speedup, 2),
            "avg_compile_ms": round(self.avg_compile_ms, 1),
            "synergy_score": round(self.synergy_score(), 2),
        }


class PassInteractionGraph:
    """
    Directed graph of LLVM pass interactions.
    Persists historical compiler telemetry to guide future sequence proposals.
    """

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path
        # Edge key: "passA -> passB"
        self.edges: Dict[str, PassTransitionStats] = {}
        # Seed canonical high-yield transitions
        self._seed_default_synergies()
        if self.storage_path and os.path.exists(self.storage_path):
            self.load()

    def _seed_default_synergies(self):
        """Seed known synergistic compiler transitions (e.g. mem2reg -> sroa -> instcombine)."""
        seeds = [
            ("mem2reg", "sroa", 0.98, 18.5, 8.0, -0.05),
            ("sroa", "dce", 0.95, 12.0, 5.0, -0.08),
            ("sroa", "instcombine", 0.96, 16.0, 12.0, -0.04),
            ("instcombine", "loop-vectorize", 0.90, 28.0, 25.0, 0.05),
            ("loop-rotate", "licm", 0.92, 14.0, 10.0, -0.02),
            ("-inline", "simplifycfg", 0.94, 15.0, 8.0, -0.06),
            ("always-inline", "jump-threading", 0.91, 19.0, 10.0, -0.03),
            ("gvn", "dce", 0.97, 10.0, 4.0, -0.05),
            ("alignment-from-assumptions", "loop-unroll", 0.88, 22.0, 18.0, 0.10),
        ]
        for p1, p2, srate, speedup, comp_ms, size_d in seeds:
            key = f"{p1}->{p2}"
            self.edges[key] = PassTransitionStats(
                total_executions=10,
                successes=int(10 * srate),
                total_speedup_pct=speedup * 10,
                total_compile_ms=comp_ms * 10,
                total_code_size_delta_pct=size_d * 10,
            )

    def record_pipeline(
        self,
        passes: List[str],
        success: bool,
        speedup_pct: float,
        compile_time_ms: float = 0.0,
        code_size_delta_pct: float = 0.0,
        compile_ms: Optional[float] = None,
    ):
        """Record pairwise transitions for an entire executed pipeline."""
        if compile_ms is not None:
            compile_time_ms = compile_ms
        if len(passes) < 2:
            return

        per_step_ms = compile_time_ms / len(passes) if passes else 5.0
        for i in range(len(passes) - 1):
            p1, p2 = passes[i], passes[i + 1]
            key = f"{p1}->{p2}"
            if key not in self.edges:
                self.edges[key] = PassTransitionStats()

            stats = self.edges[key]
            stats.total_executions += 1
            if success:
                stats.successes += 1
                stats.total_speedup_pct += speedup_pct
            stats.total_compile_ms += per_step_ms
            stats.total_code_size_delta_pct += code_size_delta_pct

        if self.storage_path:
            self.save()

    def get_synergy(self, p1: str, p2: str) -> float:
        """Returns the synergy score of transition p1 -> p2."""
        key = f"{p1}->{p2}"
        if key in self.edges:
            return self.edges[key].synergy_score()
        return 5.0  # neutral default for untried pairs

    def rank_next_pass(self, current_pass: str, candidate_passes: List[str]) -> List[Tuple[str, float]]:
        """Ranks potential subsequent passes by historical synergy score."""
        scored = []
        for cand in candidate_passes:
            if cand != current_pass:
                score = self.get_synergy(current_pass, cand)
                scored.append((cand, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def save(self, path: Optional[str] = None):
        """Persist pass interaction telemetry to disk."""
        target_path = path or self.storage_path
        if not target_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        data = {k: v.to_dict() for k, v in self.edges.items()}
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save_json(self, path: Optional[str] = None):
        """Alias for save."""
        self.save(path)

    def load(self):
        """Load telemetry from disk."""
        if not self.storage_path or not os.path.exists(self.storage_path):
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            for k, d in data.items():
                self.edges[k] = PassTransitionStats(
                    total_executions=d.get("total_executions", 0),
                    successes=d.get("successes", 0),
                    total_speedup_pct=d.get("total_speedup_pct", 0.0),
                    total_compile_ms=d.get("total_compile_ms", 0.0),
                    total_code_size_delta_pct=d.get("total_code_size_delta_pct", 0.0),
                )
        except Exception:
            pass
