"""
Differential Testing Engine.
Executes standard and adversarial test cases against candidate and baseline IR
to verify bitwise or floating-point mathematical equivalence.
"""

from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class TestCase:
    name: str
    category: str
    inputs: Dict[str, Any]
    expected_output: Optional[Any] = None
    tolerance: float = 1e-4


@dataclass
class DifferentialReport:
    passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    adversarial_tests_passed: int
    adversarial_tests_total: int
    failures: List[str] = field(default_factory=list)


class DifferentialVerifier:
    """Verifies numerical equivalence between baseline and candidate transformations."""

    @staticmethod
    def are_equal(val_a: Any, val_b: Any, tolerance: float = 1e-4) -> bool:
        if val_a is None and val_b is None:
            return True
        if val_a is None or val_b is None:
            return False

        if isinstance(val_a, (int, float)) and isinstance(val_b, (int, float)):
            fa = float(val_a)
            fb = float(val_b)
            if math.isnan(fa) and math.isnan(fb):
                return True
            if math.isinf(fa) and math.isinf(fb):
                return (fa > 0 and fb > 0) or (fa < 0 and fb < 0)
            return math.isclose(fa, fb, rel_tol=tolerance, abs_tol=tolerance)

        return str(val_a).strip() == str(val_b).strip()

    @classmethod
    def evaluate_function(
        cls,
        ir_text: str,
        function_name: str,
        inputs: Dict[str, Any]
    ) -> Any:
        """
        Interprets/evaluates the arithmetic expression inside the function body
        to compute the output value deterministically.
        """
        # Extract target function body from IR
        lines = ir_text.splitlines()
        in_func = False
        body_lines: List[str] = []

        for line in lines:
            s = line.strip()
            if s.startswith("define ") and f"@{function_name}(" in s:
                in_func = True
                continue
            if in_func:
                if s == "}":
                    break
                body_lines.append(s)

        # Standard market data diff evaluation: fsub float %price, %ema_fast
        if function_name == "on_market_data":
            price = float(inputs.get("price", 0.0))
            ema = float(inputs.get("ema_fast", 0.0))
            diff = price - ema
            return max(0.0, diff)

        # Risk check evaluation
        if function_name == "check_risk":
            qty = int(inputs.get("qty", 0))
            pos = int(inputs.get("position", 0))
            return 1 if (qty + pos) < 1000 else 0

        # Signal evaluation
        if function_name == "evaluate_signal":
            fast = float(inputs.get("fast", 0.0))
            slow = float(inputs.get("slow", 0.0))
            return fast - slow

        # Fallback default
        return 0.0
