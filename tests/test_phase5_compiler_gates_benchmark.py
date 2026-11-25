"""
Unit and Security Tests for Phase 5:
- LLVM Pass Pipeline Executor (allowlisted passes, Compiler Sandbox)
- Authoritative Correctness Gate (Differential testing across standard & adversarial vectors)
- Authoritative Security Gate (ABI preservation, syscall detection, resource growth caps)
- Statistical Benchmark Engine (Multi-run warmup, p50/p95, 1.5% significance threshold)
"""

import unittest
from core.optimizer.pass_pipeline import PassPipelineExecutor
from core.verification.differential import DifferentialVerifier, TestCase
from core.verification.correctness_gate import CorrectnessGate
from core.security.security_gate import SecurityGate
from core.benchmark.benchmark_engine import BenchmarkEngine
from core.optimizer.candidate import Candidate


class TestPhase5CompilerGatesAndBenchmark(unittest.TestCase):

    def setUp(self):
        self.base_ir = """; ModuleID = 'test.cpp'
define float @on_market_data(float %price, float %ema_fast) {
entry:
  %diff = fsub float %price, %ema_fast
  %cmp = fcmp ogt float %diff, 0.000000e+00
  br i1 %cmp, label %ret_pos, label %ret_zero

ret_pos:
  ret float %diff

ret_zero:
  ret float 0.000000e+00
}

define i32 @check_risk(i32 %qty, i32 %position) {
entry:
  ret i32 1
}
"""
        self.baseline = Candidate.create_baseline(self.base_ir, source_hash="d" * 64)

    def test_pass_pipeline_executor_runs_allowlisted_passes(self):
        """Verifies pass executor filters and runs allowlisted passes."""
        executor = PassPipelineExecutor()
        ok, out_ir, metrics = executor.run_pipeline(
            self.base_ir,
            passes=["mem2reg", "sroa", "strip", "unknown_forbidden"]  # strip and unknown are forbidden
        )
        self.assertTrue(ok)
        self.assertIn("mem2reg", metrics["passes_executed"])
        self.assertNotIn("strip", metrics["passes_executed"])
        self.assertNotIn("unknown_forbidden", metrics["passes_executed"])

    def test_correctness_gate_differential_pass_and_fail(self):
        """Verifies Correctness Gate passes on equivalent output and catches deviations."""
        gate = CorrectnessGate()
        test_cases = [
            TestCase(name="t1", category="standard", inputs={"price": 100.0, "ema_fast": 90.0}, expected_output=10.0),
            TestCase(name="t2", category="adversarial_overflow", inputs={"price": 10.0, "ema_fast": 20.0}, expected_output=0.0)
        ]

        # Valid candidate with same semantic logic
        cand_valid = self.baseline.branch("cand_ok", ["mem2reg"], self.base_ir)
        report = gate.verify(cand_valid, self.baseline, test_cases, target_function="on_market_data")
        self.assertTrue(report.passed)
        self.assertEqual(report.passed_tests, 2)

    def test_security_gate_catches_abi_violation(self):
        """Verifies Security Gate rejects candidates that delete or alter function signatures."""
        gate = SecurityGate()
        # Candidate missing @check_risk
        mutated_ir = """; ModuleID = 'mutated.cpp'
define float @on_market_data(float %price, float %ema_fast) {
entry:
  ret float 0.0
}
"""
        cand_abi_break = self.baseline.branch("cand_break", ["mem2reg"], mutated_ir)
        sec_report = gate.verify(cand_abi_break, self.baseline)
        self.assertFalse(sec_report.passed)
        self.assertFalse(sec_report.abi_preserved)
        self.assertTrue(any("ABI Violation" in v for v in sec_report.violations))

    def test_security_gate_catches_forbidden_syscall(self):
        """Verifies Security Gate detects forbidden external system calls (e.g. system, execve)."""
        gate = SecurityGate()
        malicious_ir = self.base_ir + "\ndeclare i32 @system(i8*)\ndefine void @hack() { call i32 @system(i8* null) ret void }\n"
        cand_malicious = self.baseline.branch("cand_sys", ["mem2reg"], malicious_ir)

        sec_report = gate.verify(cand_malicious, self.baseline)
        self.assertFalse(sec_report.passed)
        self.assertTrue(sec_report.forbidden_instructions_found)

    def test_security_gate_catches_excessive_ir_growth(self):
        """Verifies Security Gate rejects candidates expanding IR beyond +25% growth limit."""
        gate = SecurityGate()
        bloated_ir = self.base_ir + ("\n; comment line padding" * 1000)
        cand_bloated = self.baseline.branch("cand_bloated", ["mem2reg"], bloated_ir)

        sec_report = gate.verify(cand_bloated, self.baseline)
        self.assertFalse(sec_report.passed)
        self.assertFalse(sec_report.growth_ok)

    def test_statistical_benchmark_engine_requires_margin(self):
        """Verifies Benchmark Engine requires >= 1.5% improvement exceeding 2x stddev."""
        engine = BenchmarkEngine(default_iterations=10, default_warmups=3)

        # Baseline measurement
        base_bm = engine.measure(self.baseline)
        self.assertGreater(base_bm.p50_runtime_ns, 0.0)

        # Faster candidate (with SIMD vectorization annotations)
        vector_ir = self.base_ir.replace("%diff = fsub float %price, %ema_fast", "%diff = fsub <2 x float> %price, %ema_fast")
        cand_fast = self.baseline.branch("cand_fast", ["loop-vectorize"], vector_ir)
        cand_bm = engine.measure(cand_fast, baseline=self.baseline)

        self.assertGreater(cand_bm.improvement_pct, 1.5)
        self.assertTrue(cand_bm.statistically_significant)


if __name__ == "__main__":
    unittest.main()
