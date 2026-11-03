"""
Unit tests for Candidate Model, Branching, and Transactional Rollback
"""

import unittest
from secure_compiler.optimizer.candidate import Candidate, CandidateTree, CandidateStatus


SAMPLE_IR = """
define float @fn(float %x) {
entry:
  ret float %x
}
"""


class TestCandidateBranching(unittest.TestCase):

    def test_baseline_creation(self):
        base = Candidate.create_baseline(SAMPLE_IR)
        self.assertTrue(base.is_baseline)
        self.assertEqual(base.candidate_id, "baseline")
        self.assertEqual(base.status, CandidateStatus.VERIFIED)

    def test_isolated_branching(self):
        base = Candidate.create_baseline(SAMPLE_IR)
        tree = CandidateTree(base)

        cand_a = base.branch("cand_a", ["mem2reg", "sroa"], SAMPLE_IR + "\n; opt")
        tree.add(cand_a)

        self.assertEqual(cand_a.parent_id, "baseline")
        self.assertEqual(cand_a.depth, 1)
        self.assertEqual(len(tree.candidates), 2)
        # Ensure baseline IR was not modified
        self.assertNotIn("; opt", base.ir_text)

    def test_rollback(self):
        base = Candidate.create_baseline(SAMPLE_IR)
        tree = CandidateTree(base)

        cand_a = base.branch("cand_a", ["mem2reg"], SAMPLE_IR)
        cand_a_1 = cand_a.branch("cand_a_1", ["gvn"], SAMPLE_IR)
        tree.add(cand_a)
        tree.add(cand_a_1)

        tree.rollback("cand_a", reason="Regression detected")
        self.assertEqual(cand_a.status, CandidateStatus.ROLLED_BACK)
        self.assertEqual(cand_a_1.status, CandidateStatus.ROLLED_BACK)

        # Baseline remains untouched
        self.assertEqual(base.status, CandidateStatus.VERIFIED)
        best = tree.get_best_verified_candidate()
        self.assertEqual(best.candidate_id, "baseline")


if __name__ == "__main__":
    unittest.main()
