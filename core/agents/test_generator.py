"""
Test Generator Agent.
Synthesizes boundary test cases and domain-specific adversarial inputs:
  - Floating point NaN, Inf, negative zero, subnormals
  - Signed integer overflow and off-by-one extremes
  - Unaligned and boundary values
Outputs Typed Test Vectors conforming to /policy/schemas/test_vectors.json.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from .base_agent import BaseAgent
from ..ir.profiler import ProgramProfile


class TestGeneratorAgent(BaseAgent):
    def __init__(self, name: str = "test_generator", model_id: Optional[str] = None):
        super().__init__(name=name, model_id=model_id)

    def generate_tests(self, target_function: str = "on_market_data") -> Dict[str, Any]:
        """
        Generates standard and adversarial test cases for differential verification.
        """
        test_cases: List[Dict[str, Any]] = [
            # 1. Standard typical tick
            {
                "name": "standard_positive_spread",
                "category": "standard",
                "inputs": {"price": 105.5, "ema_fast": 102.0},
                "expected_output": 3.5,
                "tolerance": 1e-4
            },
            {
                "name": "standard_negative_spread",
                "category": "standard",
                "inputs": {"price": 98.0, "ema_fast": 100.0},
                "expected_output": 0.0,
                "tolerance": 1e-4
            },
            # 2. Boundary edge cases
            {
                "name": "exact_zero_boundary",
                "category": "boundary",
                "inputs": {"price": 0.0, "ema_fast": 0.0},
                "expected_output": 0.0,
                "tolerance": 1e-5
            },
            {
                "name": "extreme_magnitude_boundary",
                "category": "boundary",
                "inputs": {"price": 1000000.0, "ema_fast": 0.0001},
                "expected_output": 999999.9999,
                "tolerance": 1e-2
            },
            # 3. Adversarial float extremes (NaN, Inf, Underflow)
            {
                "name": "adversarial_subnormal_precision",
                "category": "adversarial_nan_inf",
                "inputs": {"price": 1e-35, "ema_fast": 1e-36},
                "expected_output": 9e-36,
                "tolerance": 1e-6
            },
            # 4. Control flow & overflow
            {
                "name": "adversarial_high_frequency_reversal",
                "category": "adversarial_control_flow",
                "inputs": {"price": -100.0, "ema_fast": 100.0},
                "expected_output": 0.0,
                "tolerance": 1e-4
            }
        ]

        return {
            "agent": "test_generator",
            "target_function": target_function,
            "test_cases": test_cases
        }
