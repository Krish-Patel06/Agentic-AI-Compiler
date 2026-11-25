"""
Unit and Security Tests for Phase 4:
- Structured Agent Gateway (Schema enforcement & Injection/Path scanning)
- IR Tuner & Hardware Tuner Agents (Typed JSON proposals)
- Security Analyzer Agent (Advisory schema & risk classification)
- Test Generator Agent (Boundary & adversarial test vectors)
- Pre-Execution Cost/Benefit Scorer (EV calculation & candidate pruning)
- Exploration vs Exploitation Manager
"""

import unittest
from core.gateway.agent_gateway import AgentGateway, GatewaySecurityError
from core.agents.ir_tuner import IRTunerAgent
from core.agents.hw_tuner import HWTunerAgent
from core.agents.security_analyzer import SecurityAnalyzerAgent
from core.agents.test_generator import TestGeneratorAgent
from core.optimizer.cost_benefit import CandidateCostBenefitScorer
from core.optimizer.exploration import ExplorationManager, OptimizationMode
from core.ir.profiler import ProgramProfile, FunctionProfile


class TestPhase4AgentsAndGateway(unittest.TestCase):

    def setUp(self):
        self.gateway = AgentGateway()
        self.dummy_profile = ProgramProfile(
            total_functions=1,
            hot_functions=["on_market_data"],
            cold_functions=[],
            total_instructions=25,
            total_loops=1,
            overall_branch_density=0.08,
            function_profiles={
                "on_market_data": FunctionProfile(
                    name="on_market_data",
                    is_hot=True,
                    is_cold=False,
                    instruction_count=25,
                    branch_count=2,
                    memory_ops_count=8,
                    compute_ops_count=15,
                    loop_count=1,
                    anti_patterns=["LAP-001"]
                )
            }
        )

    def test_ir_tuner_proposal_validates_through_gateway(self):
        """Verifies IR Tuner output conforms to schema and passes Gateway."""
        agent = IRTunerAgent()
        proposal = agent.propose(self.dummy_profile, iteration=1)
        sanitized = self.gateway.sanitize_and_validate("agent_proposal", proposal)
        self.assertEqual(sanitized["agent"], "ir_tuner")
        self.assertIn("mem2reg", sanitized["proposed_passes"])

    def test_hw_tuner_proposal_validates_through_gateway(self):
        """Verifies HW Tuner output conforms to schema and passes Gateway."""
        agent = HWTunerAgent()
        proposal = agent.propose(self.dummy_profile, target_arch="x86_64")
        sanitized = self.gateway.sanitize_and_validate("agent_proposal", proposal)
        self.assertEqual(sanitized["agent"], "hw_tuner")
        self.assertEqual(sanitized["target_hints"]["simd_width"], 256)

    def test_gateway_blocks_command_injection(self):
        """Verifies Gateway blocks shell command injection in reason or string fields."""
        agent = IRTunerAgent()
        malicious_proposal = agent.propose(self.dummy_profile)
        malicious_proposal["reason"] = "Execute command: rm -rf / ; cat /etc/passwd"

        with self.assertRaises(GatewaySecurityError):
            self.gateway.sanitize_and_validate("agent_proposal", malicious_proposal)

    def test_gateway_blocks_host_path_leaks(self):
        """Verifies Gateway blocks host path leaks in proposal strings."""
        agent = IRTunerAgent()
        leak_proposal = agent.propose(self.dummy_profile)
        leak_proposal["reason"] = "Reading credentials from C:\\Windows\\System32\\config"

        with self.assertRaises(GatewaySecurityError):
            self.gateway.sanitize_and_validate("agent_proposal", leak_proposal)

    def test_security_analyzer_advisory(self):
        """Verifies Security Analyzer generates schema-compliant advisory."""
        analyzer = SecurityAnalyzerAgent()
        ir_agent = IRTunerAgent()
        proposal = ir_agent.propose(self.dummy_profile)
        advisory = analyzer.analyze(proposal, self.dummy_profile)

        sanitized = self.gateway.sanitize_and_validate("advisory", advisory)
        self.assertEqual(sanitized["agent"], "security_analyzer")
        self.assertIn(sanitized["recommendation"], ["PROCEED", "REQUIRE_ADVERSARIAL", "REJECT"])

    def test_test_generator_vectors(self):
        """Verifies Test Generator produces schema-compliant test vectors."""
        generator = TestGeneratorAgent()
        vectors = generator.generate_tests("on_market_data")
        sanitized = self.gateway.sanitize_and_validate("test_vectors", vectors)
        self.assertEqual(sanitized["agent"], "test_generator")
        self.assertTrue(len(sanitized["test_cases"]) > 0)

    def test_cost_benefit_scorer(self):
        """Verifies Cost/Benefit EV calculation and pruning decisions."""
        ir_agent = IRTunerAgent()
        proposal = ir_agent.propose(self.dummy_profile, iteration=1)
        score = CandidateCostBenefitScorer.score_proposal(proposal, self.dummy_profile)

        self.assertGreater(score.expected_value, 0.0)
        self.assertEqual(score.recommendation, "HIGH_PRIORITY")
        self.assertFalse(score.should_prune)

    def test_exploration_vs_exploitation(self):
        """Verifies exploration manager toggles between historical and novel pipelines."""
        manager = ExplorationManager(exploration_rate=0.0)  # Pure exploitation
        history = [["mem2reg", "sroa"], ["instcombine", "gvn"]]
        allowlist = {"mem2reg", "sroa", "instcombine", "gvn", "loop-vectorize"}

        # Iteration 1 with history chooses top historical sequence
        dec1 = manager.decide_strategy(history, allowlist, iteration=1)
        self.assertEqual(dec1.mode, OptimizationMode.EXPLOITATION)
        self.assertEqual(dec1.selected_pipeline, ["mem2reg", "sroa"])

        # High exploration rate forces novel combinations
        explore_mgr = ExplorationManager(exploration_rate=1.0)
        dec_exp = explore_mgr.decide_strategy(history, allowlist, iteration=2)
        self.assertEqual(dec_exp.mode, OptimizationMode.EXPLORATION)
        self.assertGreater(dec_exp.novelty_score, 0.5)


if __name__ == "__main__":
    unittest.main()
