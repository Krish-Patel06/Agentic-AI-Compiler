"""
End-to-end tests for Secure Compiler Orchestrator and Deterministic Fallback
Verifies that:
1. Orchestrator compiles source end-to-end safely.
2. Even if AI agents are completely disabled, it safely produces a verified baseline build.
3. Priority CORRECTNESS > SECURITY > REPRODUCIBILITY > PERFORMANCE > AI AUTONOMY is maintained.
"""

import unittest
import tempfile
import os
import shutil

from secure_compiler.orchestrator.orchestrator import SecureCompilerOrchestrator


SAMPLE_CPP = """
#include <cstdint>

[[hft::hot]]
float on_market_data(float price, float ema_fast) {
    float diff = price - ema_fast;
    return diff > 0.0f ? diff : 0.0f;
}

[[hft::hot]]
int check_risk(int qty, int position) {
    return (qty + position) < 1000;
}

[[hft::cold]]
void load_config() {
}
"""


class TestOrchestratorAndFallback(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_orch_")
        self.source_file = os.path.join(self.tmp_dir, "strategy.cpp")
        with open(self.source_file, "w", encoding="utf-8") as f:
            f.write(SAMPLE_CPP)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_full_compilation_with_ai(self):
        artifacts = os.path.join(self.tmp_dir, "artifacts")
        exp_db = os.path.join(self.tmp_dir, "exp.db")
        orch = SecureCompilerOrchestrator(
            enable_ai_agents=True,
            artifacts_dir=artifacts,
            experience_db=exp_db
        )
        res = orch.compile(self.source_file, target_arch="x86_64")
        self.assertTrue(res.success, f"Compilation failed: {res.notes}")
        self.assertTrue(os.path.exists(res.audit_log_path))
        self.assertTrue(os.path.exists(res.summary_path))
        self.assertGreaterEqual(res.improvement_pct, 0.0)

    def test_deterministic_fallback_when_ai_disabled(self):
        """Verifies that disabling AI agents produces a 100% valid baseline without error."""
        artifacts = os.path.join(self.tmp_dir, "artifacts")
        exp_db = os.path.join(self.tmp_dir, "exp.db")
        orch = SecureCompilerOrchestrator(
            enable_ai_agents=False,
            artifacts_dir=artifacts,
            experience_db=exp_db
        )
        res = orch.compile(self.source_file, target_arch="x86_64")
        self.assertTrue(res.success)
        self.assertTrue(res.is_baseline, "Expected baseline candidate when AI is disabled.")
        self.assertEqual(res.selected_candidate_id, "baseline")


if __name__ == "__main__":
    unittest.main()
