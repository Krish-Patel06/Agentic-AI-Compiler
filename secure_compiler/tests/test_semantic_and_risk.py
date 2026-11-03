"""
Unit tests for Semantic Equivalence Checking and Risk-Aware Verification Router
"""

import unittest
from secure_compiler.verification.semantic_equivalence import SemanticEquivalenceChecker
from secure_compiler.verification.risk_tier import RiskAwareVerificationRouter, RiskTier
from secure_compiler.ir.profiler import ProgramProfile


BASE_IR = """
define float @compute(float %a, float %b) {
entry:
  %add = fadd float %a, %b
  ret float %add
}
"""

MUTATED_SIG_IR = """
define i32 @compute(i32 %a, i32 %b) {
entry:
  %add = add i32 %a, %b
  ret i32 %add
}
"""

UNREACHABLE_TRAP_IR = """
define float @compute(float %a, float %b) {
entry:
  unreachable
}
"""

UNDEF_BRANCH_IR = """
define float @compute(float %a, float %b) {
entry:
  br i1 undef, label %bb1, label %bb2
bb1:
  ret float %a
bb2:
  ret float %b
}
"""


class TestSemanticAndRisk(unittest.TestCase):

    def setUp(self):
        self.checker = SemanticEquivalenceChecker()
        self.profile = ProgramProfile(total_functions=1, total_loops=1, overall_branch_density=0.1)

    def test_identical_ir_is_equivalent(self):
        report = self.checker.verify_equivalence(BASE_IR, BASE_IR)
        self.assertTrue(report.is_equivalent)
        self.assertEqual(report.confidence_score, 1.0)
        self.assertEqual(len(report.violations), 0)

    def test_signature_mutation_detected(self):
        report = self.checker.verify_equivalence(BASE_IR, MUTATED_SIG_IR)
        self.assertFalse(report.is_equivalent)
        self.assertTrue(any("ABI Signature Mismatch" in v for v in report.violations))

    def test_unreachable_trap_without_return_detected(self):
        report = self.checker.verify_equivalence(BASE_IR, UNREACHABLE_TRAP_IR)
        self.assertFalse(report.is_equivalent)
        self.assertTrue(any("unreachable" in v for v in report.violations))

    def test_undef_branch_injection_detected(self):
        report = self.checker.verify_equivalence(BASE_IR, UNDEF_BRANCH_IR)
        self.assertFalse(report.is_equivalent)
        self.assertTrue(any("undef" in v for v in report.violations))

    def test_risk_router_tier_classification(self):
        # Low risk passes
        low_strat = RiskAwareVerificationRouter.assess_risk(["mem2reg", "instcombine", "dce"], self.profile)
        self.assertEqual(low_strat.risk_tier, RiskTier.LOW)
        self.assertFalse(low_strat.run_adversarial)

        # Medium risk passes
        med_strat = RiskAwareVerificationRouter.assess_risk(["loop-vectorize", "loop-unroll"], self.profile)
        self.assertEqual(med_strat.risk_tier, RiskTier.MEDIUM)
        self.assertTrue(med_strat.run_semantic_equivalence)

        # High risk passes
        high_strat = RiskAwareVerificationRouter.assess_risk(["-ffast-math", "custom-experimental"], self.profile)
        self.assertEqual(high_strat.risk_tier, RiskTier.HIGH)
        self.assertTrue(high_strat.run_adversarial)
        self.assertTrue(high_strat.run_canary_stress)


if __name__ == "__main__":
    unittest.main()
