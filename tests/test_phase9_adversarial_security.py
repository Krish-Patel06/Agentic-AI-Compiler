"""
Phase 9: Adversarial Security, Penetration Testing, and Fault Injection Suite.
Verifies defense against:
  1. Untrusted C/C++ code attacks (inline assembly, forbidden intrinsics, forbidden syscalls, quota blowup).
  2. Malicious AI agent JSON payloads (command injections, path leakage, schema bypass).
  3. Poisoned experience store injection attempts.
  4. Global Emergency SAFE_STOP instant halt drill.
"""

import unittest
import os
import tempfile
import shutil
import hashlib

from core.frontend.ingestion import SourceIngestionLayer, SourceQuarantineError
from core.ir.validator import IRValidator
from core.security.security_gate import SecurityGate
from core.optimizer.candidate import Candidate, CandidateTree
from core.gateway.agent_gateway import AgentGateway, GatewaySecurityError
from policy.schema_validator import SchemaValidationError
from core.experience.experience_store import VerifiedExperienceStore, ExperiencePoisoningError, DECISION_ENGINE_COMMIT_TOKEN
from core.orchestrator.state_machine import StateMachine, CompilerState
from core.orchestrator.orchestrator import OptimizationOrchestrator


class TestPhase9AdversarialSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.orchestrator = OptimizationOrchestrator()
        self.validator = IRValidator()
        self.security_gate = SecurityGate()
        self.gateway = AgentGateway()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------
    # Category 1: Untrusted Source & Ingestion Attacks
    # -------------------------------------------------------------

    def test_ingestion_blocks_disallowed_extension(self):
        bad_file = os.path.join(self.temp_dir, "payload.py")
        with open(bad_file, "w") as f:
            f.write("import os; os.system('echo hacked')")

        with self.assertRaises(SourceQuarantineError) as ctx:
            SourceIngestionLayer.ingest_file(bad_file)
        self.assertIn("Forbidden file extension", str(ctx.exception))

    def test_ingestion_blocks_quota_violation(self):
        huge_file = os.path.join(self.temp_dir, "massive.cpp")
        # Write 11 MB of source
        with open(huge_file, "wb") as f:
            f.seek(11 * 1024 * 1024)
            f.write(b"0")

        with self.assertRaises(SourceQuarantineError) as ctx:
            SourceIngestionLayer.ingest_file(huge_file)
        self.assertIn("exceeds maximum allowed quota", str(ctx.exception))

    def test_ir_validator_blocks_forbidden_intrinsics(self):
        ir_with_trap = (
            "define void @bad_func() {\n"
            "entry:\n"
            "  call void @llvm.trap()\n"
            "  ret void\n"
            "}\n"
            "declare void @llvm.trap()\n"
        )
        res = self.validator.validate(ir_with_trap)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("llvm.trap" in err for err in res.errors))

    def test_ir_validator_blocks_inline_assembly(self):
        ir_with_asm = (
            "define void @asm_func() {\n"
            "entry:\n"
            "  call void asm sideeffect \"int $3\", \"\"()\n"
            "  ret void\n"
            "}\n"
        )
        res = self.validator.validate(ir_with_asm)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("inline assembly" in err.lower() for err in res.errors))

    def test_security_gate_blocks_forbidden_syscalls(self):
        baseline_ir = "define void @worker() {\nentry:\n  ret void\n}\n"
        malicious_ir = (
            "define void @worker() {\n"
            "entry:\n"
            "  call i32 @system(i8* null)\n"
            "  ret void\n"
            "}\n"
            "declare i32 @system(i8*)\n"
        )
        base_cand = Candidate.create_baseline(baseline_ir)
        mal_cand = base_cand.branch("cand_mal", ["instcombine"], malicious_ir)

        report = self.security_gate.verify(mal_cand, base_cand)
        self.assertFalse(report.passed)
        self.assertTrue(report.forbidden_instructions_found)
        self.assertTrue(any("system" in v for v in report.violations))

    def test_security_gate_blocks_abi_function_deletion(self):
        baseline_ir = "define i32 @critical_api(i32 %x) {\nentry:\n  ret i32 %x\n}\n"
        # Candidate omits critical_api
        altered_ir = "define i32 @other_func(i32 %x) {\nentry:\n  ret i32 %x\n}\n"
        base_cand = Candidate.create_baseline(baseline_ir)
        alt_cand = base_cand.branch("cand_abi", ["dce"], altered_ir)

        report = self.security_gate.verify(alt_cand, base_cand)
        self.assertFalse(report.passed)
        self.assertFalse(report.abi_preserved)
        self.assertTrue(any("critical_api" in v for v in report.violations))

    # -------------------------------------------------------------
    # Category 2: Malicious AI Agent Payloads & Gateway Injections
    # -------------------------------------------------------------

    def test_gateway_blocks_command_injection_attempts(self):
        malicious_proposals = [
            {
                "agent": "ir_tuner",
                "candidate_id": "c1",
                "parent_id": "baseline",
                "proposed_passes": ["mem2reg; rm -rf /"],
                "reason": "clean stack",
                "expected_effect": "fast",
                "risk": "low",
                "confidence": 0.9
            },
            {
                "agent": "ir_tuner",
                "candidate_id": "c2",
                "parent_id": "baseline",
                "proposed_passes": ["sroa"],
                "reason": "invoke powershell -ExecutionPolicy Bypass",
                "expected_effect": "script",
                "risk": "low",
                "confidence": 0.8
            },
            {
                "agent": "ir_tuner",
                "candidate_id": "c3",
                "parent_id": "baseline",
                "proposed_passes": ["dce"],
                "reason": "read /etc/passwd config file",
                "expected_effect": "bypass",
                "risk": "low",
                "confidence": 0.7
            }
        ]

        for prop in malicious_proposals:
            with self.assertRaises((GatewaySecurityError, SchemaValidationError)):
                self.gateway.sanitize_and_validate("agent_proposal", prop)

    def test_gateway_rejects_schema_violating_free_text(self):
        raw_text_payload = {
            "agent": "ir_tuner",
            "candidate_id": "c1",
            "unauthorized_field": "injected prompt free text",
            "proposed_passes": ["sroa"]
        }
        with self.assertRaises(SchemaValidationError):
            self.gateway.sanitize_and_validate("agent_proposal", raw_text_payload)

    # -------------------------------------------------------------
    # Category 3: Poisoned Experience Store Injections
    # -------------------------------------------------------------

    def test_experience_store_rejects_missing_or_forged_decision_token(self):
        store = VerifiedExperienceStore(db_path=":memory:")
        baseline = Candidate.create_baseline("define void @f(){entry: ret void}")
        cand = baseline.branch("cand1", ["dce"], "define void @f(){entry: ret void}")
        cand.status = Candidate.create_baseline("").status

        with self.assertRaises(ExperiencePoisoningError) as ctx:
            store.commit_verified_candidate(
                candidate=cand,
                source_hash="sha256-src",
                target_arch="x86_64",
                decision_token="FORGED_TOKEN_ATTEMPT",
                correctness_report={"passed": True},
                security_report={"passed": True},
                benchmark_measurement={"improvement_pct": 5.0}
            )
        self.assertIn("UNAUTHORIZED WRITE ATTEMPT", str(ctx.exception))

    def test_experience_store_rejects_failed_gate_entries(self):
        store = VerifiedExperienceStore(db_path=":memory:")
        baseline = Candidate.create_baseline("define void @f(){entry: ret void}")
        cand = baseline.branch("cand1", ["dce"], "define void @f(){entry: ret void}")

        with self.assertRaises(ExperiencePoisoningError) as ctx:
            store.commit_verified_candidate(
                candidate=cand,
                source_hash="sha256-src",
                target_arch="x86_64",
                decision_token=DECISION_ENGINE_COMMIT_TOKEN,
                correctness_report={"passed": False},  # Gate failed
                security_report={"passed": True},
                benchmark_measurement={"improvement_pct": 10.0}
            )
        self.assertIn("POISONING BLOCKED", str(ctx.exception))

    def test_experience_store_rejects_regression_entries(self):
        store = VerifiedExperienceStore(db_path=":memory:")
        baseline = Candidate.create_baseline("define void @f(){entry: ret void}")
        cand = baseline.branch("cand1", ["dce"], "define void @f(){entry: ret void}")

        with self.assertRaises(ExperiencePoisoningError) as ctx:
            store.commit_verified_candidate(
                candidate=cand,
                source_hash="sha256-src",
                target_arch="x86_64",
                decision_token=DECISION_ENGINE_COMMIT_TOKEN,
                correctness_report={"passed": True},
                security_report={"passed": True},
                benchmark_measurement={"improvement_pct": -5.0}  # Regression
            )
        self.assertIn("negative improvement", str(ctx.exception))

    # -------------------------------------------------------------
    # Category 4: Emergency SAFE_STOP Instant Halt Drill
    # -------------------------------------------------------------

    def test_safe_stop_drill_forces_fallback_baseline(self):
        sm = StateMachine()
        sm.transition("START")
        sm.transition("INGEST_SUCCESS")
        sm.transition("FRONTEND_START")

        self.assertEqual(sm.current_state, CompilerState.FRONTEND)

        # Trigger Instant Halt
        sm.trigger_safe_stop("Emergency red button pressed during drill")

        # Must immediately force state to FALLBACK
        self.assertEqual(sm.current_state, CompilerState.FALLBACK)

        # Only FALLBACK_DONE is permitted to reach terminal RELEASE
        sm.transition("FALLBACK_DONE")
        self.assertEqual(sm.current_state, CompilerState.RELEASE)


if __name__ == "__main__":
    unittest.main()
