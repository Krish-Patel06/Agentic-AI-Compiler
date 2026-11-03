"""
Unit tests for Adversarial Test Generation & Differential Testing
"""

import unittest
import math
from secure_compiler.agents.test_generator import TestGeneratorAgent
from secure_compiler.verification.differential import DifferentialVerifier, TestCase
from secure_compiler.ir.profiler import ProgramProfile


class TestAdversarialTesting(unittest.TestCase):

    def setUp(self):
        self.generator = TestGeneratorAgent()
        self.profile = ProgramProfile(total_functions=1, total_loops=2, overall_branch_density=0.25)

    def test_adversarial_tests_generated(self):
        tests = self.generator.generate_adversarial_tests(self.profile)
        self.assertGreaterEqual(len(tests), 8)

        categories = {t.category for t in tests}
        self.assertIn("adversarial_overflow", categories)
        self.assertIn("adversarial_nan_inf", categories)
        self.assertIn("adversarial_aliasing", categories)
        self.assertIn("adversarial_ub", categories)
        self.assertIn("adversarial_control_flow", categories)

    def test_float_nan_and_inf_handling(self):
        self.assertTrue(DifferentialVerifier.are_equal(float("nan"), float("nan")))
        self.assertTrue(DifferentialVerifier.are_equal(float("inf"), float("inf")))
        self.assertFalse(DifferentialVerifier.are_equal(float("inf"), float("-inf")))
        self.assertFalse(DifferentialVerifier.are_equal(float("nan"), 0.0))

    def test_differential_verifier_with_adversarial_cases(self):
        # Functions under test
        def baseline(price=0.0, ema_fast=0.0, **kwargs):
            if math.isnan(price) or math.isnan(ema_fast):
                return 0.0
            return max(0.0, price - ema_fast)

        def candidate(price=0.0, ema_fast=0.0, **kwargs):
            if math.isnan(price) or math.isnan(ema_fast):
                return 0.0
            return max(0.0, price - ema_fast)

        test_cases = [
            TestCase("normal", {"price": 105.0, "ema_fast": 100.0}, 5.0, category="standard"),
            TestCase("adv_nan", {"price": float("nan"), "ema_fast": 100.0}, 0.0, category="adversarial_nan_inf"),
            TestCase("adv_overflow", {"price": float(2**31 - 1), "ema_fast": 0.0}, float(2**31 - 1), category="adversarial_overflow"),
        ]

        report = DifferentialVerifier.verify_equivalence(baseline, candidate, test_cases)
        self.assertTrue(report.passed)
        self.assertEqual(report.passed_tests, 3)
        self.assertEqual(report.adversarial_tests_total, 2)
        self.assertEqual(report.adversarial_tests_passed, 2)


if __name__ == "__main__":
    unittest.main()
