"""
Unit tests for Non-AI Policy Engine
"""

import unittest
from secure_compiler.policy.policy_engine import PolicyEngine, PolicyConfig


class TestPolicyEngine(unittest.TestCase):

    def setUp(self):
        self.engine = PolicyEngine(PolicyConfig(
            max_agent_iterations=3,
            max_candidate_pipelines=3,
            max_ir_growth_ratio=1.5,
        ))

    def test_allowed_pass_proposal(self):
        proposal = {
            "action": "propose_pass_pipeline",
            "passes": ["mem2reg", "sroa", "instcombine", "dce"],
        }
        dec = self.engine.evaluate_proposal(proposal, current_iteration=1, active_candidates_count=1)
        self.assertTrue(dec.allowed, f"Expected allowed, got reason: {dec.reason}")
        self.assertEqual(len(dec.filtered_passes), 4)

    def test_forbidden_pass_rejected(self):
        proposal = {
            "action": "propose_pass_pipeline",
            "passes": ["mem2reg", "strip", "bugpoint"],
        }
        dec = self.engine.evaluate_proposal(proposal, current_iteration=1, active_candidates_count=1)
        self.assertFalse(dec.allowed)
        self.assertTrue(any("strip" in v or "bugpoint" in v for v in dec.violations))

    def test_iteration_budget_exhausted(self):
        proposal = {"action": "propose_pass_pipeline", "passes": ["mem2reg"]}
        dec = self.engine.evaluate_proposal(proposal, current_iteration=4, active_candidates_count=1)
        self.assertFalse(dec.allowed)
        self.assertTrue(any("exceeded max limit" in v for v in dec.violations))

    def test_ir_growth_policy(self):
        base_bytes = 1000
        # 1400 bytes -> 1.4x (allowed under 1.5x)
        dec_ok = self.engine.evaluate_ir_growth(base_bytes, 1400)
        self.assertTrue(dec_ok.allowed)

        # 1600 bytes -> 1.6x (exceeds 1.5x)
        dec_fail = self.engine.evaluate_ir_growth(base_bytes, 1600)
        self.assertFalse(dec_fail.allowed)


if __name__ == "__main__":
    unittest.main()
