"""
Secure Compiler — Specialized Test Generator Agent
Generates comprehensive correctness test vectors, boundary edge cases,
and domain-specific adversarial inputs for differential verification.
"""

from typing import List, Dict, Any, Optional
import math
from ..verification.differential import TestCase
from ..ir.profiler import ProgramProfile


class TestGeneratorAgent:
    """
    Generates test suites for differential testing between baseline and candidate transformations.
    Includes both canonical functional tests and adversarial/fuzzing test cases targeting:
      - Integer overflow / underflow
      - Floating-point NaN / Infinity / Subnormals
      - Boundary values and off-by-one extremes
      - Aliasing and pointer overlap simulation
      - Undefined behavior triggers (zero division, signed overflow)
      - Unusual control flow and branch stress
    """

    def __init__(self, name: str = "TestGeneratorAgent"):
        self.name = name

    def generate_tests_for_profile(
        self,
        profile: ProgramProfile,
        include_adversarial: bool = True
    ) -> List[TestCase]:
        """
        Creates test vectors covering standard, boundary, and edge-case inputs,
        optionally combined with adversarial verification vectors.
        """
        test_cases: List[TestCase] = []

        # ── 1. Standard Operations ────────────────────────────────────
        test_cases.append(TestCase(
            name="standard_market_tick_positive",
            inputs={"price": 105.25, "ema_fast": 103.10},
            expected=2.15,
            category="standard",
            tags=["functional", "positive_spread"]
        ))
        test_cases.append(TestCase(
            name="standard_market_tick_negative",
            inputs={"price": 98.50, "ema_fast": 100.00},
            expected=0.0,
            category="standard",
            tags=["functional", "negative_spread"]
        ))

        # ── 2. Boundary & Zero Edge Cases ─────────────────────────────
        test_cases.append(TestCase(
            name="zero_boundary",
            inputs={"price": 0.0, "ema_fast": 0.0},
            expected=0.0,
            category="boundary",
            tags=["boundary", "zero"]
        ))
        test_cases.append(TestCase(
            name="exact_equality_edge",
            inputs={"price": 100.0, "ema_fast": 100.0},
            expected=0.0,
            category="boundary",
            tags=["boundary", "equality"]
        ))

        # ── 3. Risk Gate Boundary Checks ──────────────────────────────
        test_cases.append(TestCase(
            name="risk_under_limit",
            inputs={"qty": 200, "position": 500},
            expected=1,
            category="boundary",
            tags=["risk", "under_limit"]
        ))
        test_cases.append(TestCase(
            name="risk_exact_boundary",
            inputs={"qty": 500, "position": 500},
            expected=0,
            category="boundary",
            tags=["risk", "exact_boundary"]
        ))
        test_cases.append(TestCase(
            name="risk_over_limit",
            inputs={"qty": 600, "position": 500},
            expected=0,
            category="boundary",
            tags=["risk", "over_limit"]
        ))

        # ── 4. Numerical Scale & Micro-Tick Precision ─────────────────
        test_cases.append(TestCase(
            name="micro_fraction_tick",
            inputs={"price": 0.00015, "ema_fast": 0.00010},
            expected=0.00005,
            category="standard",
            tags=["precision", "micro_tick"]
        ))
        test_cases.append(TestCase(
            name="large_notional_tick",
            inputs={"price": 1_000_000.0, "ema_fast": 999_900.0},
            expected=100.0,
            category="standard",
            tags=["precision", "macro_tick"]
        ))

        if include_adversarial:
            test_cases.extend(self.generate_adversarial_tests(profile))

        return test_cases

    def generate_adversarial_tests(self, profile: Optional[ProgramProfile] = None) -> List[TestCase]:
        """
        Synthesizes adversarial test vectors designed to break optimizations that make
        unsound assumptions about data ranges, memory layouts, or IEEE 754 compliance.
        """
        adversarial_cases: List[TestCase] = []

        # ── A. Integer Overflow / Underflow Bounds ─────────────────────
        adversarial_cases.append(TestCase(
            name="adv_int32_overflow_boundary",
            inputs={"price": float(2**31 - 1), "ema_fast": float(2**31 - 2)},
            expected=1.0,
            category="adversarial_overflow",
            tags=["adversarial", "overflow", "int32_max"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_int32_negative_underflow",
            inputs={"price": float(-2**31), "ema_fast": 0.0},
            expected=0.0,
            category="adversarial_overflow",
            tags=["adversarial", "underflow", "int32_min"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_int64_boundary_saturation",
            inputs={"price": float(2**63 - 1000), "ema_fast": float(2**63 - 2000)},
            expected=1000.0,
            category="adversarial_overflow",
            tags=["adversarial", "overflow", "int64"]
        ))

        # ── B. Floating-Point NaN, Infinity & Subnormals ──────────────
        adversarial_cases.append(TestCase(
            name="adv_fp_nan_robustness",
            inputs={"price": float("nan"), "ema_fast": 100.0},
            expected=0.0,  # Strategy should reject or evaluate to 0 on NaN
            category="adversarial_nan_inf",
            tags=["adversarial", "fp_special", "nan"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_fp_pos_infinity",
            inputs={"price": float("inf"), "ema_fast": 1e308},
            expected=float("inf"),
            category="adversarial_nan_inf",
            tags=["adversarial", "fp_special", "pos_inf"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_fp_neg_infinity",
            inputs={"price": float("-inf"), "ema_fast": 100.0},
            expected=0.0,
            category="adversarial_nan_inf",
            tags=["adversarial", "fp_special", "neg_inf"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_fp_subnormal_underflow",
            inputs={"price": 1e-308, "ema_fast": 5e-309},
            expected=5e-309,
            category="adversarial_nan_inf",
            tags=["adversarial", "fp_special", "subnormal"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_fp_negative_zero",
            inputs={"price": -0.0, "ema_fast": 0.0},
            expected=0.0,
            category="adversarial_nan_inf",
            tags=["adversarial", "fp_special", "signed_zero"]
        ))

        # ── C. Aliasing and Memory Overlap Simulation ──────────────────
        adversarial_cases.append(TestCase(
            name="adv_pointer_aliasing_overlap",
            inputs={"price": 102.5, "ema_fast": 102.5, "alias_stride": 0},
            expected=0.0,
            category="adversarial_aliasing",
            tags=["adversarial", "aliasing", "pointer_overlap"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_pointer_null_boundary",
            inputs={"price": 0.0, "ema_fast": 0.0, "null_ptr_flag": 1},
            expected=0.0,
            category="adversarial_aliasing",
            tags=["adversarial", "aliasing", "null_guard"]
        ))

        # ── D. Undefined Behavior Triggers ────────────────────────────
        adversarial_cases.append(TestCase(
            name="adv_ub_division_by_zero",
            inputs={"price": 100.0, "ema_fast": 0.0, "divisor": 0.0},
            expected=0.0,  # Div by zero guard should yield safe default
            category="adversarial_ub",
            tags=["adversarial", "ub_trigger", "div_zero"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_ub_signed_shift_limit",
            inputs={"price": 1.0, "ema_fast": 0.0, "shift_bits": 64},
            expected=0.0,
            category="adversarial_ub",
            tags=["adversarial", "ub_trigger", "shift_overflow"]
        ))

        # ── E. Unusual Control Flow & Oscillation Paths ───────────────
        adversarial_cases.append(TestCase(
            name="adv_cf_rapid_flip_flop",
            inputs={"price": 100.01, "ema_fast": 100.02, "invert_condition": True},
            expected=0.0,
            category="adversarial_control_flow",
            tags=["adversarial", "control_flow", "oscillation"]
        ))
        adversarial_cases.append(TestCase(
            name="adv_cf_empty_loop_boundary",
            inputs={"price": 105.0, "ema_fast": 100.0, "loop_iterations": 0},
            expected=5.0,
            category="adversarial_control_flow",
            tags=["adversarial", "control_flow", "zero_trip_count"]
        ))

        return adversarial_cases
