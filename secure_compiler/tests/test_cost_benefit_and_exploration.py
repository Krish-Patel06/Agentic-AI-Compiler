"""
Unit tests for Cost/Benefit EV Scoring and Exploration vs Exploitation
"""

import unittest
from secure_compiler.optimizer.cost_benefit import CandidateCostBenefitScorer, CostBenefitScore
from secure_compiler.optimizer.exploration import ExplorationManager, OptimizationMode
from secure_compiler.ir.profiler import ProgramProfile


class TestCostBenefitAndExploration(unittest.TestCase):

    def setUp(self):
        self.profile = ProgramProfile(total_functions=2, total_loops=3, overall_branch_density=0.15)

    def test_cost_benefit_high_priority_proposal(self):
        proposal = {
            "agent_name": "IRTunerAgent",
            "passes": ["mem2reg", "instcombine", "simplifycfg"],
            "expected_benefit": 35.0,
            "risk": "low"
        }
        score: CostBenefitScore = CandidateCostBenefitScorer.score_proposal(proposal, self.profile)
        self.assertGreater(score.expected_value, 15.0)
        self.assertEqual(score.recommendation, "HIGH_PRIORITY")
        self.assertLess(score.risk_factor, 0.3)

    def test_cost_benefit_prune_risky_proposal(self):
        proposal = {
            "agent_name": "UnknownAgent",
            "passes": ["-ffast-math", "custom-experimental-pass"],
            "expected_benefit": 2.0,
            "risk": "high"
        }
        score: CostBenefitScore = CandidateCostBenefitScorer.score_proposal(proposal, self.profile)
        self.assertLess(score.expected_value, 5.0)
        self.assertGreater(score.risk_factor, 0.7)

    def test_exploration_mode_synthesis(self):
        manager = ExplorationManager(epsilon=1.0)  # Force exploration
        decision = manager.decide_strategy(
            historical_sequences=[["mem2reg", "instcombine"]],
            allowlisted_passes=["mem2reg", "sroa", "gvn", "simplifycfg", "loop-unroll"],
            iteration=1
        )
        self.assertEqual(decision.mode, OptimizationMode.EXPLORATION)
        self.assertGreater(len(decision.selected_pipeline), 0)
        self.assertGreater(decision.novelty_score, 0.5)

    def test_exploitation_mode_selection(self):
        manager = ExplorationManager(epsilon=0.0)  # Force exploitation
        decision = manager.decide_strategy(
            historical_sequences=[["mem2reg", "sroa", "gvn"]],
            allowlisted_passes=["mem2reg", "sroa", "gvn"],
            iteration=1
        )
        self.assertEqual(decision.mode, OptimizationMode.EXPLOITATION)
        self.assertEqual(decision.selected_pipeline, ["mem2reg", "sroa", "gvn"])


if __name__ == "__main__":
    unittest.main()
