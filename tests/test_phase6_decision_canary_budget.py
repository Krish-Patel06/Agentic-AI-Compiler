"""
Unit and Integration Tests for Phase 6:
- Authoritative Decision Engine (ACCEPT, REJECT, NEUTRAL decisions)
- Canary Release Stage (Numerical drift detection)
- Optimization Budget Manager (Resource governor)
"""

import unittest
from core.orchestrator.decision_engine import DecisionEngine, DecisionVerdict
from core.verification.canary import CanaryRunner, CanaryReport
from core.policy.budget_manager import OptimizationBudgetManager
from core.verification.correctness_gate import CorrectnessReport
from core.security.security_gate import SecurityReport
from core.benchmark.benchmark_engine import BenchmarkMeasurement
from core.optimizer.candidate import Candidate


class TestPhase6DecisionCanaryBudget(unittest.TestCase):

    def setUp(self):
        self.decision_engine = DecisionEngine()
        self.sample_ir = "define float @on_market_data(float %price, float %ema_fast) { entry: ret float 1.0 }"
        self.baseline = Candidate.create_baseline(self.sample_ir, source_hash="e" * 64)
        self.candidate = self.baseline.branch("cand_eval", ["mem2reg"], self.sample_ir)

    def test_decision_engine_accepts_verified_speedup(self):
        """Verifies candidate is accepted when Correctness, Security, Canary pass and speedup >= 1.5%."""
        corr = CorrectnessReport(passed=True, total_tests=5, passed_tests=5, failed_tests=0, adversarial_tests_passed=2, adversarial_tests_total=2)
        sec = SecurityReport(passed=True, abi_preserved=True, growth_ok=True, forbidden_instructions_found=False, ir_growth_pct=2.1)
        canary = CanaryReport(passed=True, iterations_run=200, numerical_drift_max=0.0)
        bm = BenchmarkMeasurement(candidate_id="cand_eval", improvement_pct=15.4, statistically_significant=True, p50_runtime_ns=85.0)

        decision = self.decision_engine.evaluate(self.candidate, corr, sec, bm, canary)
        self.assertEqual(decision.verdict, DecisionVerdict.ACCEPT)
        self.assertIn("accepted", decision.explanation.lower())

    def test_decision_engine_rejects_on_correctness_failure(self):
        """Verifies candidate is rejected if correctness gate fails."""
        corr = CorrectnessReport(passed=False, total_tests=5, passed_tests=4, failed_tests=1, adversarial_tests_passed=1, adversarial_tests_total=2, errors=["Mismatch at price=100.0"])
        sec = SecurityReport(passed=True, abi_preserved=True, growth_ok=True, forbidden_instructions_found=False, ir_growth_pct=0.0)
        bm = BenchmarkMeasurement(candidate_id="cand_eval", improvement_pct=25.0, statistically_significant=True)

        decision = self.decision_engine.evaluate(self.candidate, corr, sec, bm)
        self.assertEqual(decision.verdict, DecisionVerdict.REJECT)
        self.assertEqual(decision.rejection_code, "ERR_CORRECTNESS_FAILED")

    def test_decision_engine_rejects_on_security_failure(self):
        """Verifies candidate is rejected if security gate detects violation."""
        corr = CorrectnessReport(passed=True, total_tests=5, passed_tests=5, failed_tests=0, adversarial_tests_passed=2, adversarial_tests_total=2)
        sec = SecurityReport(passed=False, abi_preserved=False, growth_ok=True, forbidden_instructions_found=False, ir_growth_pct=0.0, violations=["ABI signature modified"])
        bm = BenchmarkMeasurement(candidate_id="cand_eval", improvement_pct=20.0, statistically_significant=True)

        decision = self.decision_engine.evaluate(self.candidate, corr, sec, bm)
        self.assertEqual(decision.verdict, DecisionVerdict.REJECT)
        self.assertEqual(decision.rejection_code, "ERR_SECURITY_VIOLATION")

    def test_decision_engine_rejects_insignificant_gain(self):
        """Verifies candidate with gain < 1.5% margin is classified as NEUTRAL/REJECT."""
        corr = CorrectnessReport(passed=True, total_tests=5, passed_tests=5, failed_tests=0, adversarial_tests_passed=2, adversarial_tests_total=2)
        sec = SecurityReport(passed=True, abi_preserved=True, growth_ok=True, forbidden_instructions_found=False, ir_growth_pct=0.0)
        bm = BenchmarkMeasurement(candidate_id="cand_eval", improvement_pct=0.8, statistically_significant=False)

        decision = self.decision_engine.evaluate(self.candidate, corr, sec, bm)
        self.assertEqual(decision.verdict, DecisionVerdict.NEUTRAL)
        self.assertEqual(decision.rejection_code, "ERR_BELOW_SIGNIFICANCE_MARGIN")

    def test_canary_runner_detects_numerical_drift(self):
        """Verifies CanaryRunner flags drift exceeding tolerance."""
        runner = CanaryRunner(iterations=50, max_drift_tolerance=1e-5)
        # Identical candidate has 0.0 drift
        report_ok = runner.run_canary(self.candidate, self.baseline)
        self.assertTrue(report_ok.passed)
        self.assertEqual(report_ok.numerical_drift_max, 0.0)

    def test_budget_manager_enforces_candidate_limits(self):
        """Verifies budget manager stops branching when candidate quota is reached."""
        manager = OptimizationBudgetManager()
        quota = manager.policy.resource_quotas.max_candidate_branches

        for _ in range(quota):
            can_branch, _ = manager.can_branch_candidate()
            self.assertTrue(can_branch)
            manager.record_candidate()

        # Quota reached: must reject branching
        can_branch, reason = manager.can_branch_candidate()
        self.assertFalse(can_branch)
        self.assertIn("exhausted", reason.lower())


if __name__ == "__main__":
    unittest.main()
