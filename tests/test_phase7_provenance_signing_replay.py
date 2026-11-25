"""
Phase 7 Unit Tests: Provenance Generator, Isolated Signing Service, Artifact Packager, and Deterministic Replay Engine.
"""

import unittest
import tempfile
import shutil
import os
import json
import hashlib

from core.security.signing_service import IsolatedSigningService
from core.provenance.provenance_generator import ProvenanceGenerator
from core.provenance.replay_engine import ReplayEngine
from core.artifacts.artifact_packager import ArtifactPackager
from core.optimizer.pass_pipeline import PassPipelineExecutor


class TestPhase7ProvenanceSigningReplay(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.signing_service = IsolatedSigningService()
        self.provenance_gen = ProvenanceGenerator()
        self.replay_engine = ReplayEngine()
        self.packager = ArtifactPackager(signing_service=self.signing_service)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_isolated_signing_service_authorizes_valid_release(self):
        artifact_bytes = b"define i32 @main() { ret i32 0 }"
        manifest = {"build_id": "test-build-123"}
        
        result = self.signing_service.authorize_and_sign(
            artifact_bytes=artifact_bytes,
            manifest_data=manifest,
            correctness_passed=True,
            security_passed=True,
            canary_passed=True,
            decision_verdict="accept"
        )

        self.assertTrue(result.signed)
        self.assertTrue(len(result.signature) > 16)
        self.assertTrue(result.certificate.startswith("CERT-SIG-"))

        # Verify signature with valid payload
        is_valid = self.signing_service.verify_signature(
            artifact_bytes=artifact_bytes,
            manifest_data=manifest,
            signature=result.signature,
            timestamp_utc=result.timestamp_utc
        )
        self.assertTrue(is_valid)

        # Tampered bytes must fail verification
        tampered_valid = self.signing_service.verify_signature(
            artifact_bytes=b"tampered byte stream",
            manifest_data=manifest,
            signature=result.signature,
            timestamp_utc=result.timestamp_utc
        )
        self.assertFalse(tampered_valid)

    def test_isolated_signing_service_refuses_when_gate_fails(self):
        artifact = b"define void @bad() { ret void }"
        manifest = {"build_id": "test-build-fail"}

        # Correctness failure
        res1 = self.signing_service.authorize_and_sign(
            artifact, manifest, correctness_passed=False, security_passed=True, canary_passed=True, decision_verdict="accept"
        )
        self.assertFalse(res1.signed)
        self.assertIn("Correctness gate", res1.rejection_reason)

        # Security failure
        res2 = self.signing_service.authorize_and_sign(
            artifact, manifest, correctness_passed=True, security_passed=False, canary_passed=True, decision_verdict="accept"
        )
        self.assertFalse(res2.signed)
        self.assertIn("Security gate", res2.rejection_reason)

        # Canary failure
        res3 = self.signing_service.authorize_and_sign(
            artifact, manifest, correctness_passed=True, security_passed=True, canary_passed=False, decision_verdict="accept"
        )
        self.assertFalse(res3.signed)
        self.assertIn("Canary stress", res3.rejection_reason)

    def test_provenance_generator_manifest_structure(self):
        source = "int compute() { return 42; }"
        baseline_ir = "define i32 @compute() { ret i32 42 }"
        final_ir = "define i32 @compute() { ret i32 42 }"

        manifest = self.provenance_gen.generate_manifest(
            build_id="uuid-999",
            source_code=source,
            source_sha256="",
            target_triple="x86_64-pc-linux-gnu",
            clang_version="17.0.6",
            llvm_version="17.0.6",
            compiler_flags=["-O0"],
            baseline_ir=baseline_ir,
            baseline_ir_sha256="",
            final_ir=final_ir,
            final_ir_sha256="",
            pass_sequence=["mem2reg", "simplifycfg"],
            correctness_report={"passed": True, "output_digest": "abc", "test_cases_count": 5},
            security_report={"passed": True, "abi_preserved": True, "violations": []},
            benchmark_report={"speedup": 1.15, "is_significant": True},
            audit_chain_head="hash-abc-123",
            decision_verdict="accept"
        )

        self.assertEqual(manifest["build_id"], "uuid-999")
        self.assertEqual(manifest["provenance"]["optimization"]["decision_verdict"], "accept")
        self.assertIn("manifest_sha256", manifest)
        self.assertEqual(len(manifest["manifest_sha256"]), 64)

    def test_deterministic_replay_engine(self):
        baseline_ir = (
            "define i32 @main() {\n"
            "entry:\n"
            "  %a = alloca i32, align 4\n"
            "  store i32 42, i32* %a, align 4\n"
            "  %0 = load i32, i32* %a, align 4\n"
            "  ret i32 %0\n"
            "}\n"
        )
        pass_seq = ["mem2reg"]

        # Run pipeline once to get expected output
        executor = PassPipelineExecutor()
        success, expected_final_ir, _ = executor.run_pipeline(baseline_ir, pass_seq)
        self.assertTrue(success)
        expected_final_hash = hashlib.sha256(expected_final_ir.encode("utf-8")).hexdigest()
        baseline_hash = hashlib.sha256(baseline_ir.encode("utf-8")).hexdigest()

        manifest = {
            "provenance": {
                "baseline": {"ir_sha256": baseline_hash},
                "optimization": {
                    "pass_pipeline": pass_seq,
                    "final_ir_sha256": expected_final_hash
                }
            }
        }

        # Replay must succeed with 100% hash match
        replay_res = self.replay_engine.replay(manifest, baseline_ir)
        self.assertTrue(replay_res.reproduced)
        self.assertTrue(replay_res.baseline_hash_match)
        self.assertTrue(replay_res.final_hash_match)

        # Tampered manifest final hash must fail replay
        manifest_tampered = {
            "provenance": {
                "baseline": {"ir_sha256": baseline_hash},
                "optimization": {
                    "pass_pipeline": pass_seq,
                    "final_ir_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        }
        tampered_res = self.replay_engine.replay(manifest_tampered, baseline_ir)
        self.assertFalse(tampered_res.reproduced)
        self.assertFalse(tampered_res.final_hash_match)

    def test_artifact_packager_creates_valid_bundle(self):
        output_dir = os.path.join(self.temp_dir, "release_pkg")
        baseline_ir = "define i32 @fn() { ret i32 0 }"
        opt_ir = "define i32 @fn() { ret i32 0 }"

        manifest = {"build_id": "pkg-001"}
        report = {"passes": ["dce"], "speedup": 1.05}
        audit = [{"event": "COMMIT", "hash": "aaa"}]

        pkg_res = self.packager.package_release(
            output_dir=output_dir,
            baseline_ir=baseline_ir,
            optimized_ir=opt_ir,
            optimization_report=report,
            audit_log_entries=audit,
            replay_manifest=manifest,
            correctness_passed=True,
            security_passed=True,
            canary_passed=True,
            decision_verdict="accept",
            create_archive=True
        )

        self.assertTrue(pkg_res.success)
        self.assertTrue(os.path.exists(os.path.join(output_dir, "baseline.ll")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "optimized.ll")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "release.sig")))
        self.assertTrue(os.path.exists(pkg_res.archive_path))
        self.assertTrue(pkg_res.signing_result.signed)


if __name__ == "__main__":
    unittest.main()
