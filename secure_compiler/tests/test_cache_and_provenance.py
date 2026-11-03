"""
Unit tests for 4-Tier Cryptographic Caching & Provenance Replay Manifest
"""

import unittest
import tempfile
import shutil
import os
from secure_compiler.artifacts.cache import FourTierCache
from secure_compiler.artifacts.provenance import ProvenanceGenerator, ReplayManifest


class TestCacheAndProvenance(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cache_test_")
        self.cache = FourTierCache(cache_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_tier1_ir_cache_roundtrip(self):
        self.assertIsNone(self.cache.get_ir("hash123", "O3", "x86_64"))
        self.assertEqual(self.cache.stats.tier1_misses, 1)

        self.cache.put_ir("hash123", "O3", "x86_64", "define void @f() { ret void }")
        cached = self.cache.get_ir("hash123", "O3", "x86_64")
        self.assertIsNotNone(cached)
        self.assertIn("ret void", cached)
        self.assertEqual(self.cache.stats.tier1_hits, 1)

    def test_tier2_pass_result_cache_roundtrip(self):
        out_ir, metrics = "define void @opt() {}", {"execution_time_ms": 12.5}
        self.cache.put_pass_result("in_hash", ["mem2reg", "sroa"], "x86_64", out_ir, metrics)

        retrieved = self.cache.get_pass_result("in_hash", ["mem2reg", "sroa"], "x86_64")
        self.assertIsNotNone(retrieved)
        ir, met = retrieved
        self.assertEqual(ir, out_ir)
        self.assertEqual(met["execution_time_ms"], 12.5)

    def test_provenance_manifest_generation_and_export(self):
        manifest: ReplayManifest = ProvenanceGenerator.generate(
            build_id="build_unit_001",
            source_path="main.cpp",
            source_hash="sha_source_abc",
            target_arch="x86_64",
            opt_level="O3",
            baseline_ir_hash="sha_baseline_xyz",
            selected_candidate_id="candidate_1_irt",
            is_baseline=False,
            pass_pipeline=["mem2reg", "sroa"],
            improvement_pct=42.5,
            candidate_summaries=[{"candidate_id": "candidate_1_irt", "status": "accepted"}],
            gate_results={"correctness": {"passed": True}},
            signing_result={"signed": True, "key_id": "test-key"},
            total_time_ms=150.0,
        )

        out_path = os.path.join(self.test_dir, "replay_manifest.json")
        manifest.export_json(out_path)
        self.assertTrue(os.path.exists(out_path))

        data = manifest.to_dict()
        self.assertEqual(data["build_id"], "build_unit_001")
        self.assertEqual(data["decision"]["selected_candidate_id"], "candidate_1_irt")
        self.assertEqual(data["decision"]["measured_improvement_pct"], 42.5)
        self.assertIn("replay_instructions", data)


if __name__ == "__main__":
    unittest.main()
