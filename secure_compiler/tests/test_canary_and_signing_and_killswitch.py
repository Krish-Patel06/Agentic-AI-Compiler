"""
Unit tests for CanaryRunner, IsolatedSigningService, and EmergencyKillSwitch
"""

import unittest
from secure_compiler.verification.canary import CanaryRunner, CanaryReport
from secure_compiler.security.signing import IsolatedSigningService, SigningResult
from secure_compiler.security.kill_switch import EmergencyKillSwitch, KillSwitchState
from secure_compiler.optimizer.candidate import Candidate


SAMPLE_IR = """
define float @calc(float %p) {
entry:
  ret float %p
}
"""


class TestCanarySigningAndKillSwitch(unittest.TestCase):

    def setUp(self):
        EmergencyKillSwitch.reset()
        self.kill_switch = EmergencyKillSwitch.get_instance()
        self.signing_service = IsolatedSigningService(key_id="test-enclave-key")
        self.canary_runner = CanaryRunner(default_iterations=100)
        self.base = Candidate.create_baseline(SAMPLE_IR)
        self.cand = self.base.branch("cand_1", ["mem2reg"], SAMPLE_IR)

    def test_canary_success_on_valid_candidate(self):
        report: CanaryReport = self.canary_runner.run_canary(self.cand, self.base, iterations=100)
        self.assertTrue(report.passed)
        self.assertEqual(report.crashes_detected, 0)
        self.assertFalse(report.memory_leak_detected)
        self.assertLessEqual(report.numerical_drift_max, 1e-4)

    def test_isolated_signing_service_authorizes_when_all_gates_pass(self):
        res: SigningResult = self.signing_service.authorize_and_sign(
            artifact_bytes=b"sample_binary_payload",
            manifest_data={"build_id": "b1", "candidate": "c1"},
            correctness_passed=True,
            security_passed=True,
            canary_passed=True,
            decision_verdict="accept"
        )
        self.assertTrue(res.signed)
        self.assertEqual(res.key_id, "test-enclave-key")
        self.assertGreater(len(res.signature), 32)

        # Verification check
        is_valid = self.signing_service.verify_signature(
            artifact_bytes=b"sample_binary_payload",
            manifest_data={"build_id": "b1", "candidate": "c1"},
            signature=res.signature,
            decision_verdict="accept"
        )
        self.assertTrue(is_valid)

    def test_isolated_signing_refuses_when_gate_fails(self):
        res: SigningResult = self.signing_service.authorize_and_sign(
            artifact_bytes=b"sample_binary_payload",
            manifest_data={"build_id": "b1"},
            correctness_passed=False,  # FAILED GATE
            security_passed=True,
            canary_passed=True,
            decision_verdict="accept"
        )
        self.assertFalse(res.signed)
        self.assertIn("Correctness gate", res.error)

    def test_emergency_kill_switch_trigger_and_state(self):
        self.assertEqual(self.kill_switch.state, KillSwitchState.ARMED)
        self.assertFalse(self.kill_switch.is_triggered)

        terminated_called = []
        self.kill_switch.register_termination_hook(lambda: terminated_called.append(True))

        self.kill_switch.trigger("Policy breach detected in sandbox", source_component="sandbox_monitor")

        self.assertEqual(self.kill_switch.state, KillSwitchState.TRIGGERED)
        self.assertTrue(self.kill_switch.is_triggered)
        self.assertEqual(len(terminated_called), 1)
        self.assertEqual(len(self.kill_switch.events), 1)
        self.assertIn("Policy breach", self.kill_switch.events[0].trigger_reason)


if __name__ == "__main__":
    unittest.main()
