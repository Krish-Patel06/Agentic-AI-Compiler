"""
Unit tests for Sandbox and Statistical Benchmark Engine
"""

import unittest
import os
from secure_compiler.sandbox.sandbox import ProcessSandbox, SandboxConfig
from secure_compiler.benchmark.benchmark_engine import BenchmarkEngine
from secure_compiler.optimizer.candidate import Candidate


SAMPLE_IR = """
define float @fn(float %a, float %b) {
entry:
  %c = fadd float %a, %b
  %d = fmul float %c, 2.000000e+00
  ret float %d
}
"""


class TestSandboxAndBenchmark(unittest.TestCase):

    def test_sandbox_strips_secrets(self):
        # Set a dummy secret environment variable
        os.environ["SECRET_API_TOKEN_FOR_TEST"] = "supersecret123"
        try:
            with ProcessSandbox() as box:
                env = box.get_sanitized_env()
                self.assertNotIn("SECRET_API_TOKEN_FOR_TEST", env)
        finally:
            del os.environ["SECRET_API_TOKEN_FOR_TEST"]

    def test_sandbox_executes_isolated(self):
        with ProcessSandbox() as box:
            res = box.run_command(["python", "-c", "print('hello from sandbox')"])
            self.assertTrue(res.success)
            self.assertIn("hello from sandbox", res.stdout)

    def test_statistical_benchmark(self):
        base = Candidate.create_baseline(SAMPLE_IR)
        bench = BenchmarkEngine(default_iterations=5, default_warmups=2)
        meas = bench.measure(base)

        self.assertGreater(meas.median_runtime_ns, 0.0)
        self.assertGreaterEqual(meas.p95_runtime_ns, meas.median_runtime_ns)
        self.assertEqual(meas.iterations, 5)


if __name__ == "__main__":
    unittest.main()
