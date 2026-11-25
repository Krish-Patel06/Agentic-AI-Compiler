"""
Unit and Security Tests for Phase 3:
- Candidate 0 Immutable Baseline & Candidate Lineage Tree
- Transactional Rollback Controller
- Zero-Trust Verified Experience Store (Poisoning defense & cryptographic chain)
- Decision-Engine Exclusive Authorization Gate
"""

import unittest
import tempfile
from pathlib import Path

from core.optimizer.candidate import Candidate, CandidateTree, CandidateStatus, ImmutableBaselineError
from core.experience.experience_store import (
    VerifiedExperienceStore,
    ExperiencePoisoningError,
    DECISION_ENGINE_COMMIT_TOKEN
)


class TestPhase3BaselineAndExperience(unittest.TestCase):

    def setUp(self):
        self.sample_ir = "define i32 @main() { entry: ret i32 0 }"
        self.baseline = Candidate.create_baseline(self.sample_ir, source_hash="a" * 64)
        self.tree = CandidateTree(self.baseline)

    def test_baseline_is_immutable(self):
        """Verifies Candidate 0 cannot be overwritten or replaced in the tree."""
        fake_baseline = Candidate.create_baseline("define void @fake() { ret void }")
        with self.assertRaises(ImmutableBaselineError):
            self.tree.add(fake_baseline)

    def test_candidate_branching_and_lineage(self):
        """Verifies branching preserves parent ID, sets PENDING status, and adds to tree."""
        cand_1 = self.baseline.branch(
            candidate_id="cand_1_irt",
            pass_pipeline=["mem2reg", "instcombine"],
            new_ir_text="define i32 @main() { entry: ret i32 10 }",
            agent_name="ir_tuner"
        )
        self.assertEqual(cand_1.parent_id, "baseline")
        self.assertEqual(cand_1.status, CandidateStatus.PENDING)
        self.assertEqual(cand_1.pass_pipeline, ["mem2reg", "instcombine"])

        self.tree.add(cand_1)
        retrieved = self.tree.get("cand_1_irt")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.candidate_id, "cand_1_irt")

    def test_transactional_rollback(self):
        """Verifies rollback marks candidate as ROLLED_BACK and returns parent."""
        cand_1 = self.baseline.branch(
            candidate_id="cand_1_irt",
            pass_pipeline=["mem2reg"],
            new_ir_text="define i32 @main() { ret i32 1 }",
            agent_name="ir_tuner"
        )
        self.tree.add(cand_1)

        parent = self.tree.rollback("cand_1_irt", reason="Differential test failure")
        self.assertEqual(parent.candidate_id, "baseline")

        updated = self.tree.get("cand_1_irt")
        self.assertEqual(updated.status, CandidateStatus.ROLLED_BACK)
        self.assertEqual(updated.rejection_reason, "Differential test failure")

        # Rollback on baseline itself must raise ImmutableBaselineError
        with self.assertRaises(ImmutableBaselineError):
            self.tree.rollback("baseline")

    def test_experience_store_successful_commit_and_integrity(self):
        """Verifies Decision Engine can commit verified candidate and hash chain validates."""
        store = VerifiedExperienceStore(":memory:")
        cand = self.baseline.branch("cand_verified", ["mem2reg", "gvn"], self.sample_ir)

        entry_hash = store.commit_verified_candidate(
            candidate=cand,
            source_hash="b" * 64,
            target_arch="x86_64",
            decision_token=DECISION_ENGINE_COMMIT_TOKEN,
            correctness_report={"passed": True},
            security_report={"passed": True},
            benchmark_measurement={"improvement_pct": 14.5, "p50_runtime_ns": 110.0}
        )
        self.assertEqual(len(entry_hash), 64)
        self.assertTrue(store.verify_store_integrity())

        similar = store.query_similar_passes(target_arch="x86_64")
        self.assertEqual(len(similar), 1)
        self.assertEqual(similar[0], ["mem2reg", "gvn"])

    def test_experience_store_poisoning_defense(self):
        """Verifies unverified, failed, or unauthorized writes are strictly rejected."""
        store = VerifiedExperienceStore(":memory:")
        cand = self.baseline.branch("cand_bad", ["bad_pass"], self.sample_ir)

        # 1. Unauthorized token (e.g. AI agent trying to write directly)
        with self.assertRaises(ExperiencePoisoningError):
            store.commit_verified_candidate(
                candidate=cand,
                source_hash="c" * 64,
                target_arch="native",
                decision_token="AI_AGENT_FAKE_TOKEN",
                correctness_report={"passed": True},
                security_report={"passed": True},
                benchmark_measurement={"improvement_pct": 5.0}
            )

        # 2. Gate failure (correctness failed)
        with self.assertRaises(ExperiencePoisoningError):
            store.commit_verified_candidate(
                candidate=cand,
                source_hash="c" * 64,
                target_arch="native",
                decision_token=DECISION_ENGINE_COMMIT_TOKEN,
                correctness_report={"passed": False},
                security_report={"passed": True},
                benchmark_measurement={"improvement_pct": 5.0}
            )

        # 3. Regression (negative improvement)
        with self.assertRaises(ExperiencePoisoningError):
            store.commit_verified_candidate(
                candidate=cand,
                source_hash="c" * 64,
                target_arch="native",
                decision_token=DECISION_ENGINE_COMMIT_TOKEN,
                correctness_report={"passed": True},
                security_report={"passed": True},
                benchmark_measurement={"improvement_pct": -8.5}
            )


if __name__ == "__main__":
    unittest.main()
