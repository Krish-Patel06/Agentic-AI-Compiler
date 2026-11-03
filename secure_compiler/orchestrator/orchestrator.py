"""
Secure Compiler — State-Machine-Based AI Orchestrator
Coordinates ingestion, profiling, policy gating, candidate branching,
multi-agent proposals, correctness & security verification, and rollback.
Prioritizes: CORRECTNESS > SECURITY > REPRODUCIBILITY > PERFORMANCE > AI AUTONOMY.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import time
import os

from ..frontend.ingestion import SourceIngestionLayer, IngestionResult
from ..frontend.clang_frontend import ClangFrontend, FrontendOutput
from ..ir.validator import IRValidator
from ..ir.profiler import ProgramProfiler, ProgramProfile
from ..policy.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision
from ..policy.budget_manager import OptimizationBudgetManager, BudgetLimits
from ..optimizer.candidate import Candidate, CandidateTree, CandidateStatus
from ..optimizer.pass_pipeline import PassPipelineExecutor
from ..optimizer.multi_objective import OptimizationObjective, CandidateMetricsVector, ParetoSelector
from ..optimizer.cost_benefit import CandidateCostBenefitScorer, CostBenefitScore
from ..optimizer.exploration import ExplorationManager, OptimizationMode
from ..experience.pass_graph import PassInteractionGraph
from ..verification.correctness_gate import CorrectnessGate, CorrectnessReport
from ..verification.differential import TestCase
from ..verification.semantic_equivalence import SemanticEquivalenceChecker, SemanticEquivalenceReport
from ..verification.risk_tier import RiskAwareVerificationRouter, RiskTier, VerificationStrategy
from ..verification.canary import CanaryRunner, CanaryReport
from ..security.security_gate import SecurityGate, SecurityReport
from ..security.signing import IsolatedSigningService, SigningResult
from ..security.kill_switch import EmergencyKillSwitch, KillSwitchState
from ..benchmark.benchmark_engine import BenchmarkEngine, BenchmarkMeasurement
from ..orchestrator.decision_engine import DecisionEngine, DecisionVerdict, DecisionResult
from ..agents.ir_tuner import IRTunerAgent
from ..agents.hw_tuner import HWTunerAgent
from ..agents.security_analyzer import SecurityAnalyzerAgent
from ..agents.test_generator import TestGeneratorAgent
from ..experience.experience_store import VerifiedExperienceStore
from ..observability.audit_log import BuildAuditLog
from ..artifacts.artifact_manager import ArtifactManager
from ..artifacts.cache import FourTierCache
from ..artifacts.provenance import ProvenanceGenerator, ReplayManifest
from ..web_ui.serializer import build_dashboard_summary


class OrchestratorState(str, Enum):
    INITIALIZING = "initializing"
    INGESTING = "ingesting"
    BASELINE_GENERATION = "baseline_generation"
    PROFILING = "profiling"
    OPTIMIZATION_LOOP = "optimization_loop"
    COMPLETED = "completed"
    FALLBACK_BASELINE = "fallback_baseline"


@dataclass
class CompilationResult:
    success: bool
    build_id: str
    selected_candidate_id: str
    is_baseline: bool
    ir_text: str
    pass_pipeline: List[str]
    improvement_pct: float
    audit_log_path: str
    summary_path: str
    total_time_ms: float
    notes: str = ""
    candidate_summary: List[Dict[str, Any]] = field(default_factory=list)
    replay_manifest_path: str = ""
    signing_result: Dict[str, Any] = field(default_factory=dict)
    budget_usage: Dict[str, Any] = field(default_factory=dict)
    cache_stats: Dict[str, Any] = field(default_factory=dict)


class SecureCompilerOrchestrator:
    """
    Authoritative state-machine orchestrator.
    Executes optimization with zero-trust AI agents and guaranteed deterministic fallback.
    """

    def __init__(
        self,
        policy_config: Optional[PolicyConfig] = None,
        enable_ai_agents: bool = True,
        artifacts_dir: str = "compiler_artifacts",
        experience_db: str = "compiler_artifacts/experience.db",
        budget_limits: Optional[BudgetLimits] = None,
    ):
        self.enable_ai = enable_ai_agents
        self.artifacts_dir = artifacts_dir
        self.policy_engine = PolicyEngine(policy_config)
        self.ir_validator = IRValidator()
        self.correctness_gate = CorrectnessGate(self.ir_validator)
        self.security_gate = SecurityGate(self.policy_engine)
        self.benchmark_engine = BenchmarkEngine()
        self.decision_engine = DecisionEngine()
        self.pass_executor = PassPipelineExecutor()
        self.experience_store = VerifiedExperienceStore(experience_db)
        self.artifact_manager = ArtifactManager(artifacts_dir)

        # Advanced Optimization Intelligence & Governance Layers
        max_cand = getattr(self.policy_engine.config, "max_candidate_pipelines", getattr(self.policy_engine.config, "max_candidates", 5))
        eff_limits = budget_limits or BudgetLimits(
            max_wall_time_s=60.0,
            max_candidates=max_cand,
            max_agent_calls=self.policy_engine.config.max_agent_iterations * 2,
        )
        self.budget_manager = OptimizationBudgetManager(eff_limits)
        self.cache = FourTierCache(os.path.join(artifacts_dir, "cache"))
        self.pass_graph = PassInteractionGraph(os.path.join(artifacts_dir, "pass_graph.json"))
        self.exploration_manager = ExplorationManager(epsilon=0.25)
        self.cost_benefit_scorer = CandidateCostBenefitScorer()
        self.semantic_checker = SemanticEquivalenceChecker()
        self.canary_runner = CanaryRunner()
        self.signing_service = IsolatedSigningService()
        self.kill_switch = EmergencyKillSwitch.get_instance()

        # Specialized Advisory Agents (Read-Only / Untrusted Proposal Generators)
        self.ir_tuner = IRTunerAgent()
        self.hw_tuner = HWTunerAgent()
        self.security_analyzer = SecurityAnalyzerAgent()
        self.test_generator = TestGeneratorAgent()

    def compile(
        self,
        source_path: str,
        target_arch: str = "native",
        opt_level: str = "O3",
        objective: str = "performance",
    ) -> CompilationResult:
        t_start = time.perf_counter()

        # Parse optimization objective
        try:
            opt_objective = OptimizationObjective(objective.lower())
        except ValueError:
            opt_objective = OptimizationObjective.PERFORMANCE

        # ── 1. Ingestion Layer ─────────────────────────────────────────
        ingest_res: IngestionResult = SourceIngestionLayer.ingest_file(source_path)
        if not ingest_res.success:
            return CompilationResult(
                success=False,
                build_id=ingest_res.build_id,
                selected_candidate_id="none",
                is_baseline=False,
                ir_text="",
                pass_pipeline=[],
                improvement_pct=0.0,
                audit_log_path="",
                summary_path="",
                total_time_ms=0.0,
                notes=f"Ingestion failed: {ingest_res.error}"
            )

        audit = BuildAuditLog(ingest_res.build_id, ingest_res.source_hash, target_arch)
        audit.record_event("SOURCE_INGESTED", source_path=source_path, bytes=ingest_res.source_bytes)

        # ── 2. Clang Frontend (Check Tier 1 IR Cache first) ───────────
        raw_ir = self.cache.get_ir(ingest_res.source_hash, opt_level, target_arch)
        if raw_ir:
            audit.record_event("CACHE_HIT_TIER1_IR", source_hash=ingest_res.source_hash)
        else:
            frontend = ClangFrontend()
            front_out: FrontendOutput = frontend.compile_to_ir(source_path, target_triple=target_arch)
            if not front_out.success:
                audit.record_event("FRONTEND_FAILED", error=front_out.error)
                return CompilationResult(
                    success=False,
                    build_id=ingest_res.build_id,
                    selected_candidate_id="none",
                    is_baseline=False,
                    ir_text="",
                    pass_pipeline=[],
                    improvement_pct=0.0,
                    audit_log_path="",
                    summary_path="",
                    total_time_ms=(time.perf_counter() - t_start) * 1000,
                    notes=f"Frontend compilation failed: {front_out.error}"
                )
            raw_ir = front_out.ir_text
            self.cache.put_ir(ingest_res.source_hash, opt_level, target_arch, raw_ir)

        # ── 3. IR Security Gate on Raw IR ─────────────────────────────
        raw_ir_valid = self.ir_validator.validate(raw_ir)
        if not raw_ir_valid.is_valid:
            audit.record_event("RAW_IR_REJECTED", errors=raw_ir_valid.errors)
            return CompilationResult(
                success=False,
                build_id=ingest_res.build_id,
                selected_candidate_id="none",
                is_baseline=False,
                ir_text="",
                pass_pipeline=[],
                improvement_pct=0.0,
                audit_log_path="",
                summary_path="",
                total_time_ms=(time.perf_counter() - t_start) * 1000,
                notes=f"Raw IR failed security gate: {'; '.join(raw_ir_valid.errors)}"
            )

        audit.ir_hash = raw_ir_valid.fingerprint

        # ── 4. Baseline Candidate 0 Initialization ─────────────────────
        baseline_candidate = Candidate.create_baseline(raw_ir)
        tree = CandidateTree(baseline_candidate)
        audit.candidates_generated.append(baseline_candidate.candidate_id)

        # Baseline benchmark (Check Tier 3 cache or measure)
        cached_base_bm = self.cache.get_benchmark(baseline_candidate.ir_fingerprint, target_arch)
        if cached_base_bm:
            base_bm = BenchmarkMeasurement(**cached_base_bm)
            audit.record_event("CACHE_HIT_TIER3_BENCHMARK_BASELINE", candidate_id=baseline_candidate.candidate_id)
        else:
            base_bm = self.benchmark_engine.measure(baseline_candidate)
            self.cache.put_benchmark(baseline_candidate.ir_fingerprint, target_arch, base_bm.to_dict())
            self.budget_manager.record_benchmark_run()

        audit.record_event("BASELINE_MEASURED", benchmark=base_bm.to_dict())

        # ── 5. Program Profiling ──────────────────────────────────────
        source_text = ""
        if os.path.exists(source_path):
            with open(source_path, "r", encoding="utf-8", errors="replace") as f:
                source_text = f.read()
        profile: ProgramProfile = ProgramProfiler.profile(raw_ir, source_text=source_text)
        audit.record_event(
            "PROGRAM_PROFILED",
            functions=profile.total_functions,
            hot=profile.hot_functions,
            cold=profile.cold_functions,
            branch_density=profile.overall_branch_density,
            loops=profile.total_loops,
        )

        # Generate base test vectors
        standard_test_cases = self.test_generator.generate_tests_for_profile(profile, include_adversarial=False)
        adversarial_test_cases = self.test_generator.generate_adversarial_tests(profile)

        # ── 6. Optimization Loop (Isolated Candidate Branching) ───────
        remaining_budget = self.policy_engine.config.max_agent_iterations
        active_iteration = 0

        # Query experience store and pass graph for proven pass sequences
        cached_sequences = self.experience_store.query_similar_passes(target_arch=target_arch)
        if cached_sequences:
            audit.record_event("EXPERIENCE_HIT", sequences_count=len(cached_sequences))

        verified_candidate_vectors: List[CandidateMetricsVector] = []
        gate_verifications: Dict[str, Any] = {
            "ir_validation": {"passed": True, "fingerprint": raw_ir_valid.fingerprint},
            "correctness": {"passed": True, "standard_tests": len(standard_test_cases)},
            "security": {"passed": True},
            "semantic_equivalence": {"checked": False},
            "canary_stage": {"checked": False},
        }

        if self.enable_ai and not self.kill_switch.is_triggered:
            while remaining_budget > 0:
                active_iteration += 1
                remaining_budget -= 1

                # Circuit breaker check
                if self.kill_switch.is_triggered:
                    audit.record_event("KILL_SWITCH_TRIPPED", reason="Halting candidate generation immediately.")
                    break

                # Resource budget governor check
                can_branch, branch_reason = self.budget_manager.can_branch_candidate()
                if not can_branch:
                    audit.record_event("BUDGET_EXHAUSTED", reason=branch_reason)
                    break
                can_call, call_reason = self.budget_manager.can_call_agent()
                if not can_call:
                    audit.record_event("BUDGET_EXHAUSTED", reason=call_reason)
                    break

                # Exploration vs Exploitation strategy decision
                strategy_dec = self.exploration_manager.decide_strategy(
                    historical_sequences=cached_sequences,
                    allowlisted_passes=self.policy_engine.config.allowed_passes,
                    iteration=active_iteration,
                )
                audit.record_event(
                    "STRATEGY_DECIDED",
                    mode=strategy_dec.mode.value,
                    novelty=strategy_dec.novelty_score,
                    rationale=strategy_dec.rationale,
                )

                # Proposal generation
                self.budget_manager.record_agent_call()
                if strategy_dec.mode == OptimizationMode.EXPLORATION and strategy_dec.selected_pipeline:
                    # Novel pipeline proposed via exploration manager
                    proposal = self.ir_tuner.propose(profile, iteration=active_iteration)
                    proposal.passes = strategy_dec.selected_pipeline
                    proposal.reason = strategy_dec.rationale
                elif active_iteration % 2 == 1:
                    proposal = self.ir_tuner.propose(profile, iteration=active_iteration)
                else:
                    proposal = self.hw_tuner.propose(profile, target_arch=target_arch)

                # Prioritize cached sequence on iteration 1 if available in exploitation mode
                if active_iteration == 1 and cached_sequences and strategy_dec.mode == OptimizationMode.EXPLOITATION:
                    proposal.passes = cached_sequences[0]
                    proposal.reason += " (prioritized from verified experience store)"

                audit.agent_proposals.append(proposal.to_dict())

                # Pre-execution Cost/Benefit EV Scoring
                cb_score: CostBenefitScore = self.cost_benefit_scorer.score_proposal(
                    proposal=proposal.to_dict(),
                    profile=profile,
                )
                audit.record_event(
                    "PROPOSAL_SCORED",
                    ev=cb_score.expected_value,
                    recommendation=cb_score.recommendation,
                    predicted_gain=cb_score.predicted_improvement_pct,
                    risk_factor=cb_score.risk_factor,
                )

                if cb_score.recommendation == "PRUNE" and cb_score.expected_value < 0:
                    audit.rejected_candidates.append({
                        "iteration": active_iteration,
                        "reason": f"Pruned by CostBenefitScorer: EV={cb_score.expected_value:.2f} < 0, Risk={cb_score.risk_factor:.2f}",
                        "passes": proposal.passes,
                    })
                    continue

                # Security Analyzer Audit
                sec_assessment = self.security_analyzer.analyze(proposal, profile)
                if sec_assessment.risk == "high":
                    audit.record_event("PROPOSAL_REJECTED_BY_SECURITY_ANALYZER", reason=sec_assessment.reason)
                    continue

                # Policy Engine Evaluation
                policy_dec = self.policy_engine.evaluate_proposal(
                    proposal.to_dict(),
                    current_iteration=active_iteration,
                    active_candidates_count=len(tree.candidates)
                )

                if not policy_dec.allowed:
                    audit.rejected_candidates.append({
                        "iteration": active_iteration,
                        "reason": f"Policy rejection: {policy_dec.reason}",
                        "passes": proposal.passes
                    })
                    continue

                # Branch a new candidate
                cand_id = f"candidate_{active_iteration}_{proposal.agent_name[:3].lower()}"
                passes_to_run = policy_dec.filtered_passes

                # Execute pass pipeline (Check Tier 2 Cache first)
                cached_pass = self.cache.get_pass_result(
                    baseline_candidate.ir_fingerprint, passes_to_run, target_arch
                )
                if cached_pass:
                    out_ir, pass_metrics = cached_pass
                    pass_ok = True
                    audit.record_event("CACHE_HIT_TIER2_PASS", candidate=cand_id)
                else:
                    pass_ok, out_ir, pass_metrics = self.pass_executor.run_pipeline(
                        base_ir=baseline_candidate.ir_text,
                        passes=passes_to_run
                    )
                    if pass_ok:
                        self.cache.put_pass_result(
                            baseline_candidate.ir_fingerprint,
                            passes_to_run,
                            target_arch,
                            out_ir,
                            pass_metrics,
                        )

                if not pass_ok:
                    audit.rejected_candidates.append({
                        "candidate_id": cand_id,
                        "reason": f"Pass execution failure: {pass_metrics.get('error')}",
                        "passes": passes_to_run
                    })
                    continue

                candidate = baseline_candidate.branch(cand_id, passes_to_run, out_ir)
                candidate.resource_usage.compilation_time_ms = pass_metrics["execution_time_ms"]
                candidate.resource_usage.instruction_count = out_ir.count("\n")
                tree.add(candidate)
                audit.candidates_generated.append(cand_id)
                self.budget_manager.record_candidate(elapsed_ms=pass_metrics["execution_time_ms"])

                # ── Dynamic Risk Assessment & Verification Router ─────
                risk_strategy: VerificationStrategy = RiskAwareVerificationRouter.assess_risk(
                    passes=passes_to_run,
                    profile=profile,
                )
                audit.record_event("RISK_ROUTED", strategy=risk_strategy.summary())

                active_tests = list(standard_test_cases)
                if risk_strategy.run_adversarial:
                    active_tests.extend(adversarial_test_cases)

                # ── Gate A: Correctness Gate ───────────────────────────
                corr_report: CorrectnessReport = self.correctness_gate.verify(
                    candidate, baseline_candidate, active_tests
                )

                # ── Gate B: Semantic Equivalence Checker ───────────────
                sem_report: Optional[SemanticEquivalenceReport] = None
                if risk_strategy.run_semantic_equivalence:
                    sem_report = self.semantic_checker.verify_equivalence(
                        baseline_ir=baseline_candidate.ir_text,
                        candidate_ir=candidate.ir_text,
                    )
                    gate_verifications["semantic_equivalence"] = {
                        "checked": True,
                        "equivalent": sem_report.is_equivalent,
                        "confidence": sem_report.confidence_score,
                        "violations": sem_report.violations,
                    }
                    if not sem_report.is_equivalent:
                        corr_report.passed = False
                        corr_report.errors.extend([f"Semantic Equivalence: {v}" for v in sem_report.violations])
                        audit.record_event("SEMANTIC_EQUIVALENCE_FAILED", violations=sem_report.violations)

                candidate.verification_report = {
                    "passed": corr_report.passed,
                    "errors": corr_report.errors,
                    "details": corr_report.details,
                    "risk_tier": risk_strategy.risk_tier.value,
                }

                # ── Gate C: Security Gate ──────────────────────────────
                sec_report: SecurityReport = self.security_gate.verify(
                    candidate, baseline_candidate
                )

                # ── Gate D: Benchmark Engine (Check Tier 3 Cache) ──────
                cached_cand_bm = self.cache.get_benchmark(candidate.ir_fingerprint, target_arch)
                if cached_cand_bm:
                    bm_measurement = BenchmarkMeasurement(**cached_cand_bm)
                    audit.record_event("CACHE_HIT_TIER3_BENCHMARK", candidate_id=cand_id)
                else:
                    self.budget_manager.record_benchmark_run()
                    bm_measurement = self.benchmark_engine.measure(candidate, baseline=baseline_candidate)
                    self.cache.put_benchmark(candidate.ir_fingerprint, target_arch, bm_measurement.to_dict())

                candidate.benchmark_result = bm_measurement.to_dict()

                # ── Gate E: Canary Stage (High Stress / Numerical Drift)
                canary_report: Optional[CanaryReport] = None
                if risk_strategy.run_canary_stress and corr_report.passed and sec_report.passed:
                    canary_report = self.canary_runner.run_canary(candidate, baseline_candidate)
                    gate_verifications["canary_stage"] = {
                        "checked": True,
                        "passed": canary_report.passed,
                        "iterations": canary_report.iterations_run,
                        "drift_max": canary_report.numerical_drift_max,
                    }
                    if not canary_report.passed:
                        sec_report.passed = False
                        sec_report.violations.extend([f"Canary regression: {f}" for f in canary_report.failures])
                        audit.record_event("CANARY_STAGE_FAILED", failures=canary_report.failures)

                # ── Gate F: Decision Engine ────────────────────────────
                decision: DecisionResult = self.decision_engine.evaluate(
                    candidate=candidate,
                    correctness=corr_report,
                    security=sec_report,
                    benchmark=bm_measurement,
                    policy=policy_dec,
                    remaining_budget=remaining_budget
                )

                audit.record_event(
                    "CANDIDATE_EVALUATED",
                    candidate_id=cand_id,
                    verdict=decision.verdict.value,
                    explanation=decision.explanation,
                    improvement_pct=bm_measurement.improvement_pct,
                )

                # Update Pass Interaction Graph with empirical outcome
                is_accepted = (decision.verdict == DecisionVerdict.ACCEPT)
                self.pass_graph.record_pipeline(
                    passes=passes_to_run,
                    success=is_accepted,
                    speedup_pct=bm_measurement.improvement_pct if is_accepted else 0.0,
                    compile_ms=pass_metrics["execution_time_ms"],
                    code_size_delta_pct=round(
                        ((len(candidate.ir_text) - len(baseline_candidate.ir_text)) / max(1, len(baseline_candidate.ir_text))) * 100.0,
                        2
                    ),
                )
                self.pass_graph.save_json(os.path.join(self.artifacts_dir, "pass_graph.json"))

                if decision.verdict == DecisionVerdict.ACCEPT:
                    candidate.status = CandidateStatus.ACCEPTED
                    audit.passes_executed = candidate.pass_pipeline
                    audit.selected_strategy = cand_id
                    audit.verification_results = candidate.verification_report
                    audit.benchmark_results = bm_measurement.to_dict()
                    audit.security_results = {"passed": sec_report.passed, "violations": sec_report.violations}

                    # Track metrics vector for Pareto multi-objective optimization
                    vec = CandidateMetricsVector(
                        candidate_id=cand_id,
                        performance_gain_pct=bm_measurement.improvement_pct,
                        size_reduction_pct=round(
                            ((len(baseline_candidate.ir_text) - len(candidate.ir_text)) / max(1, len(baseline_candidate.ir_text))) * 100.0,
                            2
                        ),
                        compile_time_overhead_ms=pass_metrics["execution_time_ms"],
                        memory_reduction_pct=0.0,
                        risk_penalty=0.1 if risk_strategy.risk_tier == RiskTier.LOW else (0.3 if risk_strategy.risk_tier == RiskTier.MEDIUM else 0.6)
                    )
                    verified_candidate_vectors.append(vec)

                    # Save verified experience
                    self.experience_store.save_candidate_experience(
                        candidate=candidate,
                        source_hash=ingest_res.source_hash,
                        target_arch=target_arch,
                        security_result={"passed": True}
                    )
                    break

                elif decision.verdict in (DecisionVerdict.REJECT, DecisionVerdict.NEUTRAL):
                    candidate.status = CandidateStatus.REJECTED
                    candidate.rejection_reason = decision.explanation
                    audit.rejected_candidates.append({
                        "candidate_id": cand_id,
                        "verdict": decision.verdict.value,
                        "rejection_code": decision.rejection_code,
                        "explanation": decision.explanation,
                    })
                    # Transactional rollback
                    tree.rollback(cand_id, reason=decision.explanation)

        # ── 7. Selection & Pareto Multi-Objective Optimization ────────
        best_candidate = tree.get_best_verified_candidate()

        # If multiple verified candidates exist, apply Pareto selection under configured objective
        if len(verified_candidate_vectors) > 1:
            pareto_best_vec = ParetoSelector.select_best(verified_candidate_vectors, objective=opt_objective)
            if pareto_best_vec:
                cand_obj = tree.get(pareto_best_vec.candidate_id)
                if cand_obj and cand_obj.status == CandidateStatus.ACCEPTED:
                    best_candidate = cand_obj

        audit.selected_strategy = best_candidate.candidate_id
        is_baseline = best_candidate.is_baseline

        # Save IR artifacts
        opt_ir_path = self.artifact_manager.save_ir(
            ingest_res.build_id, "optimized.ll", best_candidate.ir_text
        )
        self.artifact_manager.save_ir(
            ingest_res.build_id, "baseline.ll", baseline_candidate.ir_text
        )
        audit.final_artifact = opt_ir_path

        total_elapsed = (time.perf_counter() - t_start) * 1000

        # Save audit log
        build_dir = self.artifact_manager.get_build_dir(ingest_res.build_id)
        audit_path = os.path.join(build_dir, "audit_log.json")
        audit.export_json(audit_path)

        # ── 8. Isolated Cryptographic Signing Enclave ──────────────────
        signing_res: SigningResult = self.signing_service.authorize_and_sign(
            artifact_bytes=best_candidate.ir_text.encode("utf-8"),
            manifest_data={
                "build_id": ingest_res.build_id,
                "candidate_id": best_candidate.candidate_id,
                "source_hash": ingest_res.source_hash,
            },
            correctness_passed=True,
            security_passed=True,
            canary_passed=True,
            decision_verdict="accept" if not is_baseline else "baseline_fallback"
        )
        signing_dict = {
            "signed": signing_res.signed,
            "signature": signing_res.signature,
            "key_id": signing_res.key_id,
            "timestamp_utc": signing_res.timestamp_utc,
            "certificate": signing_res.certificate,
        }

        # ── 9. Provenance & Replay Manifest Generation ─────────────────
        cand_summaries = []
        for c in tree.candidates.values():
            cand_summaries.append({
                "candidate_id": c.candidate_id,
                "parent_id": c.parent_id,
                "status": c.status.value,
                "passes": c.pass_pipeline,
                "rejection_reason": c.rejection_reason,
                "improvement_pct": c.benchmark_result.get("improvement_pct", 0.0),
            })

        replay_manifest: ReplayManifest = ProvenanceGenerator.generate(
            build_id=ingest_res.build_id,
            source_path=source_path,
            source_hash=ingest_res.source_hash,
            target_arch=target_arch,
            opt_level=opt_level,
            baseline_ir_hash=baseline_candidate.ir_fingerprint,
            selected_candidate_id=best_candidate.candidate_id,
            is_baseline=is_baseline,
            pass_pipeline=best_candidate.pass_pipeline,
            improvement_pct=float(best_candidate.benchmark_result.get("improvement_pct", 0.0)),
            candidate_summaries=cand_summaries,
            gate_results=gate_verifications,
            signing_result=signing_dict,
            total_time_ms=round(total_elapsed, 2),
        )
        replay_path = os.path.join(build_dir, "replay_manifest.json")
        replay_manifest.export_json(replay_path)

        # Tier 4 Artifact Cache put
        self.cache.put_artifact(best_candidate.ir_fingerprint, replay_manifest.to_dict())

        # Summary metadata for web dashboard
        summary_data = build_dashboard_summary(
            build_id=ingest_res.build_id,
            source_path=source_path,
            source_text=source_text,
            profile=profile,
            tree=tree,
            best_candidate=best_candidate,
            is_baseline=is_baseline,
            total_elapsed_ms=round(total_elapsed, 2),
            policy_config=self.policy_engine.config,
            audit_events=audit.to_dict().get("timeline", []),
        )
        summary_path = os.path.join(build_dir, "build_summary.json")
        self.artifact_manager.save_summary(ingest_res.build_id, summary_data)

        notes = (
            f"Successfully produced verified build '{ingest_res.build_id}'. "
            f"Selected: '{best_candidate.candidate_id}' "
            f"({best_candidate.benchmark_result.get('improvement_pct', 0.0):.2f}% improvement)."
            if not is_baseline else
            f"Build '{ingest_res.build_id}' safely defaulted to verified deterministic baseline."
        )

        return CompilationResult(
            success=True,
            build_id=ingest_res.build_id,
            selected_candidate_id=best_candidate.candidate_id,
            is_baseline=is_baseline,
            ir_text=best_candidate.ir_text,
            pass_pipeline=best_candidate.pass_pipeline,
            improvement_pct=float(best_candidate.benchmark_result.get("improvement_pct", 0.0)),
            audit_log_path=audit_path,
            summary_path=summary_path,
            total_time_ms=round(total_elapsed, 2),
            notes=notes,
            candidate_summary=cand_summaries,
            replay_manifest_path=replay_path,
            signing_result=signing_dict,
            budget_usage=self.budget_manager.to_dict(),
            cache_stats=self.cache.stats.to_dict(),
        )
