"""
Unit tests for Multi-Objective Optimization and Pareto Selection
"""

import unittest
from secure_compiler.optimizer.multi_objective import (
    OptimizationObjective,
    CandidateMetricsVector,
    ParetoSelector,
)


class TestMultiObjectiveOptimization(unittest.TestCase):

    def setUp(self):
        self.c1 = CandidateMetricsVector(
            candidate_id="cand_1",
            performance_gain_pct=40.0,
            size_reduction_pct=5.0,
            compile_time_overhead_ms=100.0,
            memory_reduction_pct=2.0,
            risk_penalty=0.1,
        )
        self.c2 = CandidateMetricsVector(
            candidate_id="cand_2",
            performance_gain_pct=25.0,
            size_reduction_pct=30.0,
            compile_time_overhead_ms=50.0,
            memory_reduction_pct=15.0,
            risk_penalty=0.05,
        )
        self.c3_dominated = CandidateMetricsVector(
            candidate_id="cand_3_dominated",
            performance_gain_pct=10.0,
            size_reduction_pct=2.0,
            compile_time_overhead_ms=200.0,
            memory_reduction_pct=0.0,
            risk_penalty=0.5,
        )

    def test_pareto_front_excludes_dominated(self):
        candidates = [self.c1, self.c2, self.c3_dominated]
        frontier = ParetoSelector.get_pareto_front(candidates, OptimizationObjective.PERFORMANCE)
        frontier_ids = [c.candidate_id for c in frontier]
        self.assertIn("cand_1", frontier_ids)
        self.assertNotIn("cand_3_dominated", frontier_ids)

    def test_select_best_performance_focus(self):
        candidates = [self.c1, self.c2]
        best = ParetoSelector.select_best(candidates, OptimizationObjective.PERFORMANCE)
        self.assertIsNotNone(best)
        self.assertEqual(best.candidate_id, "cand_1")

    def test_select_best_binary_size_focus(self):
        candidates = [self.c1, self.c2]
        best = ParetoSelector.select_best(candidates, OptimizationObjective.BINARY_SIZE)
        self.assertIsNotNone(best)
        self.assertEqual(best.candidate_id, "cand_2")


if __name__ == "__main__":
    unittest.main()
