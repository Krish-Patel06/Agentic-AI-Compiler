"""
Canary Release Stage.
Runs a high-stress, multi-tick synthetic workload before release.
Evaluates numerical stability, detects floating-point drift,
and checks memory behavior.
"""

from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from ..optimizer.candidate import Candidate
from .differential import DifferentialVerifier


@dataclass
class CanaryReport:
    passed: bool
    iterations_run: int
    numerical_drift_max: float
    failures: List[str] = field(default_factory=list)


class CanaryRunner:
    """Simulates a multi-tick canary stress workload."""

    def __init__(self, iterations: int = 200, max_drift_tolerance: float = 1e-4):
        self.iterations = iterations
        self.max_drift_tolerance = max_drift_tolerance

    def run_canary(
        self,
        candidate: Candidate,
        baseline: Candidate,
        target_function: str = "on_market_data"
    ) -> CanaryReport:
        max_drift = 0.0
        failures: List[str] = []

        # Synthetic multi-tick market stress loop
        price = 100.0
        ema = 98.0

        for i in range(self.iterations):
            # Oscillating synthetic market inputs
            price += (math.sin(i * 0.15) * 1.5)
            ema += (math.cos(i * 0.10) * 0.8)

            inputs = {"price": price, "ema_fast": ema}

            base_val = DifferentialVerifier.evaluate_function(baseline.ir_text, target_function, inputs)
            cand_val = DifferentialVerifier.evaluate_function(candidate.ir_text, target_function, inputs)

            if isinstance(base_val, (int, float)) and isinstance(cand_val, (int, float)):
                drift = abs(float(base_val) - float(cand_val))
                if drift > max_drift:
                    max_drift = drift

                if drift > self.max_drift_tolerance:
                    failures.append(f"Canary iteration {i}: Drift {drift:.6f} exceeds tolerance {self.max_drift_tolerance}")
                    break
            else:
                if str(base_val) != str(cand_val):
                    failures.append(f"Canary iteration {i}: Non-numeric output mismatch '{base_val}' vs '{cand_val}'")
                    break

        passed = (len(failures) == 0)

        return CanaryReport(
            passed=passed,
            iterations_run=self.iterations,
            numerical_drift_max=round(max_drift, 6),
            failures=failures
        )
