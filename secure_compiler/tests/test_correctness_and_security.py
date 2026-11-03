"""
Unit tests for Correctness Gate, Differential Testing, and Security Gate
"""

import unittest
from secure_compiler.optimizer.candidate import Candidate
from secure_compiler.verification.correctness_gate import CorrectnessGate
from secure_compiler.verification.differential import TestCase
from secure_compiler.security.security_gate import SecurityGate


SAMPLE_IR = """
define float @on_market_data(float %price, float %ema_fast) {
entry:
  %diff = fsub float %price, %ema_fast
  ret float %diff
}
"""

MUTATED_ABI_IR = """
define i32 @on_market_data(i32 %price) {
entry:
  ret i32 %price
}
"""

MALICIOUS_INJECTION_IR = """
define float @on_market_data(float %price, float %ema_fast) {
entry:
  %diff = fsub float %price, %ema_fast
  call void @system(i8* null)
  ret float %diff
}
"""


class TestCorrectnessAndSecurity(unittest.TestCase):

    def setUp(self):
        self.correctness_gate = CorrectnessGate()
        self.security_gate = SecurityGate()

    def test_correctness_passes_identical(self):
        base = Candidate.create_baseline(SAMPLE_IR)
        cand = base.branch("cand1", ["mem2reg"], SAMPLE_IR)

        tests = [
            TestCase(name="t1", inputs={"price": 105.0, "ema_fast": 100.0}, expected=5.0)
        ]
        res = self.correctness_gate.verify(cand, base, tests)
        self.assertTrue(res.passed, f"Expected pass, got: {res.errors}")

    def test_abi_mutation_rejected_by_security_gate(self):
        base = Candidate.create_baseline(SAMPLE_IR)
        cand = base.branch("cand_mutated", ["bad_pass"], MUTATED_ABI_IR)

        sec_res = self.security_gate.verify(cand, base)
        self.assertFalse(sec_res.passed)
        self.assertFalse(sec_res.abi_valid)
        self.assertTrue(any("ABI" in v for v in sec_res.violations))

    def test_malicious_injection_detected(self):
        base = Candidate.create_baseline(SAMPLE_IR)
        cand = base.branch("cand_injected", ["bad_pass"], MALICIOUS_INJECTION_IR)

        sec_res = self.security_gate.verify(cand, base)
        self.assertFalse(sec_res.passed)
        self.assertTrue(sec_res.suspicious_behavior_detected)
        self.assertTrue(any("system" in v for v in sec_res.violations))


if __name__ == "__main__":
    unittest.main()
