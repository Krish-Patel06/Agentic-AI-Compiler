"""
Unit and Integration Tests for Phase 1 Scaffolding:
- 22-State Machine & Transition Table completeness
- Hash-chained Audit Log integrity and tamper-detection
- Authoritative Policy configuration & signature verification
- Agent Gateway JSON Schema enforcement
"""

import unittest
import tempfile
import json
from pathlib import Path

from core.orchestrator.state_machine import CompilerState, StateMachine, InvalidTransitionError, TRANSITION_TABLE
from core.observability.audit_log import HashChainedAuditLog, AuditRecord
from policy.policy_loader import (
    load_authoritative_policy,
    sign_policy_file,
    PolicyTamperedError,
    CONFIG_PATH,
    SIGNATURE_PATH
)
from policy.schema_validator import AgentSchemaValidator, SchemaValidationError


class TestPhase1Scaffolding(unittest.TestCase):

    def test_state_machine_has_exactly_22_states(self):
        """Verifies the state machine enum contains exactly 22 distinct states."""
        states = list(CompilerState)
        self.assertEqual(len(states), 22, f"Expected exactly 22 states, got {len(states)}: {states}")
        expected_names = {
            "INIT", "INGEST", "QUARANTINE_OK", "FRONTEND", "IR_GATE", "PROFILE",
            "BASELINE_FROZEN", "EXPERIENCE_LOOKUP", "BUDGET_ASSIGN", "ADVISE", "SCORE",
            "CANDIDATE_BUILD", "COMPILE", "CORRECTNESS_GATE", "SECURITY_GATE", "BENCHMARK",
            "DECIDE", "CANARY", "COMMIT", "ROLLBACK", "FALLBACK", "RELEASE"
        }
        actual_names = {s.value for s in states}
        self.assertEqual(actual_names, expected_names)

    def test_state_machine_valid_happy_path(self):
        """Tests the standard nominal progression through the state machine to RELEASE."""
        audit = HashChainedAuditLog("test_build_nominal")
        sm = StateMachine(audit_log=audit)
        self.assertEqual(sm.current_state, CompilerState.INIT)

        sm.transition("START")
        self.assertEqual(sm.current_state, CompilerState.INGEST)

        sm.transition("INGEST_SUCCESS")
        self.assertEqual(sm.current_state, CompilerState.QUARANTINE_OK)

        sm.transition("FRONTEND_START")
        self.assertEqual(sm.current_state, CompilerState.FRONTEND)

        sm.transition("FRONTEND_SUCCESS")
        self.assertEqual(sm.current_state, CompilerState.IR_GATE)

        sm.transition("IR_VALID")
        self.assertEqual(sm.current_state, CompilerState.PROFILE)

        sm.transition("PROFILE_DONE")
        self.assertEqual(sm.current_state, CompilerState.BASELINE_FROZEN)

        sm.transition("BASELINE_READY")
        self.assertEqual(sm.current_state, CompilerState.EXPERIENCE_LOOKUP)

        sm.transition("LOOKUP_DONE")
        self.assertEqual(sm.current_state, CompilerState.BUDGET_ASSIGN)

        sm.transition("BUDGET_OK")
        self.assertEqual(sm.current_state, CompilerState.ADVISE)

        sm.transition("PROPOSAL_RECEIVED")
        self.assertEqual(sm.current_state, CompilerState.SCORE)

        sm.transition("SCORE_ACCEPT")
        self.assertEqual(sm.current_state, CompilerState.CANDIDATE_BUILD)

        sm.transition("BUILD_READY")
        self.assertEqual(sm.current_state, CompilerState.COMPILE)

        sm.transition("COMPILE_SUCCESS")
        self.assertEqual(sm.current_state, CompilerState.CORRECTNESS_GATE)

        sm.transition("CORRECTNESS_PASS")
        self.assertEqual(sm.current_state, CompilerState.SECURITY_GATE)

        sm.transition("SECURITY_PASS")
        self.assertEqual(sm.current_state, CompilerState.BENCHMARK)

        sm.transition("BENCHMARK_DONE")
        self.assertEqual(sm.current_state, CompilerState.DECIDE)

        sm.transition("DECIDE_SPEEDUP")
        self.assertEqual(sm.current_state, CompilerState.CANARY)

        sm.transition("CANARY_PASS")
        self.assertEqual(sm.current_state, CompilerState.COMMIT)

        sm.transition("COMMIT_DONE")
        self.assertEqual(sm.current_state, CompilerState.RELEASE)
        self.assertTrue(sm.is_terminal)

    def test_state_machine_invalid_transition_raises_error(self):
        """Verifies that an illegal event raises InvalidTransitionError without mutating state."""
        sm = StateMachine()
        self.assertEqual(sm.current_state, CompilerState.INIT)
        with self.assertRaises(InvalidTransitionError):
            sm.transition("FRONTEND_START")  # Illegal from INIT
        self.assertEqual(sm.current_state, CompilerState.INIT)

    def test_state_machine_safe_stop(self):
        """Verifies that trigger_safe_stop immediately forces state to FALLBACK."""
        sm = StateMachine()
        sm.transition("START")
        sm.transition("INGEST_SUCCESS")
        self.assertEqual(sm.current_state, CompilerState.QUARANTINE_OK)

        sm.trigger_safe_stop("Security violation detected")
        self.assertEqual(sm.current_state, CompilerState.FALLBACK)

        # From fallback, can safely finish to RELEASE
        sm.transition("FALLBACK_DONE")
        self.assertEqual(sm.current_state, CompilerState.RELEASE)

    def test_audit_log_hash_chain_integrity_and_tamper_detection(self):
        """Verifies append-only hash-chaining and tamper detection."""
        log = HashChainedAuditLog("build_test_101")
        log.append_event("SOURCE_INGESTED", state="INGEST", data={"size": 1024})
        log.append_event("PASS_RUN", state="COMPILE", data={"pass": "mem2reg"})
        log.append_event("VERIFIED", state="COMMIT", data={"status": "PASS"})

        self.assertEqual(len(log.entries), 3)
        self.assertTrue(log.verify_chain_integrity())

        # Tamper test: modify payload of entry 1
        log.entries[1].data["pass"] = "malicious_injected_pass"
        # Directly modifying internal record
        log._entries[1].data["pass"] = "malicious_injected_pass"
        self.assertFalse(log.verify_chain_integrity())

    def test_authoritative_policy_loading_and_tampering(self):
        """Verifies policy signature verification and pass allowlisting."""
        policy = load_authoritative_policy(enforce_signature=True)
        self.assertEqual(policy.security_level, "strict")
        self.assertEqual(policy.growth_limits.max_ir_growth_pct, 25.0)
        self.assertEqual(policy.growth_limits.max_binary_growth_pct, 15.0)

        # Allowlist checks
        self.assertTrue(policy.is_pass_allowed("mem2reg"))
        self.assertTrue(policy.is_pass_allowed("sroa"))
        self.assertTrue(policy.is_pass_allowed("-instcombine"))

        # Forbidden pass checks
        self.assertFalse(policy.is_pass_allowed("strip"))
        self.assertFalse(policy.is_pass_allowed("mergefunc"))
        self.assertFalse(policy.is_pass_allowed("unknown_pass_xyz"))

        # Tampering test: temporary config with invalid signature
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write('{"tampered": true}')
            tampered_path = Path(tf.name)
        sig_path = tampered_path.with_suffix(".sig")
        sig_path.write_text("invalid_signature_hex", encoding="utf-8")

        try:
            with self.assertRaises(PolicyTamperedError):
                load_authoritative_policy(config_path=tampered_path, sig_path=sig_path)
        finally:
            tampered_path.unlink(missing_ok=True)
            sig_path.unlink(missing_ok=True)

    def test_agent_schema_validator(self):
        """Verifies JSON schema enforcement on agent proposals and rejection of raw shell/code."""
        validator = AgentSchemaValidator()

        valid_proposal = {
            "agent": "ir_tuner",
            "candidate_id": "cand_1_irt",
            "parent_id": "baseline",
            "proposed_passes": ["mem2reg", "sroa", "instcombine"],
            "reason": "Eliminates alloca overhead and simplifies expressions",
            "expected_effect": "Significant memory load latency reduction",
            "risk": "low",
            "confidence": 0.88,
            "target_hints": {
                "unroll_factor": 4
            }
        }
        # Valid proposal passes
        validator.enforce("agent_proposal", valid_proposal)

        # Malformed proposal: forbidden extra property (e.g. attempted shell injection)
        malicious_proposal = dict(valid_proposal)
        malicious_proposal["shell_command"] = "rm -rf /"
        with self.assertRaises(SchemaValidationError):
            validator.enforce("agent_proposal", malicious_proposal)

        # Malformed proposal: missing required field
        incomplete_proposal = dict(valid_proposal)
        del incomplete_proposal["risk"]
        with self.assertRaises(SchemaValidationError):
            validator.enforce("agent_proposal", incomplete_proposal)


if __name__ == "__main__":
    unittest.main()
