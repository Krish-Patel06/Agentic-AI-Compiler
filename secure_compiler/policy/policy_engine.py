"""
Secure Compiler — Non-AI Policy Engine
Authoritative control layer enforcing resource budgets, pass allowlists,
compilation boundaries, and security constraints over all AI proposals.
"""

from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Any
import copy


# Standard, safe LLVM New Pass Manager optimization passes
DEFAULT_ALLOWED_PASSES: Set[str] = {
    # Scalar optimizations
    "mem2reg", "sroa", "instcombine", "early-cse", "gvn",
    "simplifycfg", "jump-threading", "correlated-propagation",
    "reassociate", "dce", "adce", "bdce", "tailcallelim",
    "alignment-from-assumptions", "constmerge", "ipsccp",
    # Loop optimizations
    "loop-rotate", "loop-unroll", "loop-vectorize", "slp-vectorizer",
    "licm", "indvars", "loop-deletion", "loop-idiom",
    # Module & interprocedural
    "function(sroa)", "function(instcombine)", "function(gvn)",
    "function(simplifycfg)", "function(loop-vectorize)",
    "default<O1>", "default<O2>", "default<O3>", "default<Os>", "default<Oz>",
}

# Forbidden passes that introduce security or stability risks
DEFAULT_FORBIDDEN_PASSES: Set[str] = {
    "strip", "mergefunc", "extract-blocks", "bugpoint",
    "sanitizer-coverage", "rewrite-statepoints-for-gc",
    "internalize", "safe-stack", "shadow-stack", "cfguard",
}


@dataclass
class PolicyConfig:
    """Configurable security and operational policies."""
    max_compilation_time_s: float = 45.0
    max_agent_iterations: int = 4
    max_candidate_pipelines: int = 5
    max_memory_mb: int = 512
    max_ir_growth_ratio: float = 1.50       # Candidate IR cannot exceed 1.5x baseline size
    max_binary_growth_ratio: float = 1.30   # Candidate binary cannot exceed 1.3x baseline size
    allowed_passes: Set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_PASSES))
    forbidden_passes: Set[str] = field(default_factory=lambda: set(DEFAULT_FORBIDDEN_PASSES))
    target_architecture: str = "native"
    security_level: str = "strict"          # "strict" | "moderate" | "permissive"
    sandbox_permissions: Dict[str, Any] = field(default_factory=lambda: {
        "allow_network": False,
        "allow_fs_write": True,
        "read_only_root": True,
        "isolated_tmp": True,
        "cpu_limit_s": 5.0,
        "memory_limit_mb": 256,
    })


@dataclass
class PolicyDecision:
    """Outcome of policy evaluation on an AI agent proposal or candidate."""
    allowed: bool
    reason: str
    filtered_passes: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)


class PolicyEngine:
    """
    Authoritative Policy Engine.
    All agent optimization proposals must pass this gate before execution.
    """

    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()

    def evaluate_proposal(
        self,
        proposal: Dict[str, Any],
        current_iteration: int,
        active_candidates_count: int
    ) -> PolicyDecision:
        """
        Validates an AI proposal against iteration budgets and pass allowlists.
        """
        violations = []

        # 1. Check Iteration Budget
        if current_iteration > self.config.max_agent_iterations:
            violations.append(
                f"Agent iterations ({current_iteration}) exceeded max limit ({self.config.max_agent_iterations})."
            )

        # 2. Check Candidate Population Budget
        if active_candidates_count >= self.config.max_candidate_pipelines:
            violations.append(
                f"Active candidates ({active_candidates_count}) reached capacity ({self.config.max_candidate_pipelines})."
            )

        # 3. Validate Proposed Passes
        raw_passes = proposal.get("passes", [])
        if not isinstance(raw_passes, list):
            violations.append("Proposal 'passes' field must be a valid list.")
            raw_passes = []

        if len(raw_passes) == 0:
            violations.append("Proposal contains no optimization passes.")

        filtered_passes = []
        for p in raw_passes:
            p_clean = str(p).strip()
            # Normalize syntax (e.g. opt pass names)
            base_pass = p_clean.split("<")[0]

            if p_clean in self.config.forbidden_passes or base_pass in self.config.forbidden_passes:
                violations.append(f"Pass '{p_clean}' is strictly FORBIDDEN by security policy.")
                continue

            if p_clean not in self.config.allowed_passes and base_pass not in self.config.allowed_passes:
                if self.config.security_level == "strict":
                    violations.append(f"Pass '{p_clean}' is not in the allowlist (strict mode).")
                    continue
                else:
                    violations.append(f"Warning: Pass '{p_clean}' not in allowlist.")

            filtered_passes.append(p_clean)

        allowed = len(violations) == 0 and len(filtered_passes) > 0
        reason = "Proposal approved by Policy Engine." if allowed else "; ".join(violations)

        return PolicyDecision(
            allowed=allowed,
            reason=reason,
            filtered_passes=filtered_passes,
            violations=violations,
        )

    def evaluate_ir_growth(self, baseline_bytes: int, candidate_bytes: int) -> PolicyDecision:
        """Enforces maximum code / IR bloat limits."""
        if baseline_bytes <= 0:
            return PolicyDecision(allowed=True, reason="Valid baseline size.")

        ratio = candidate_bytes / baseline_bytes
        if ratio > self.config.max_ir_growth_ratio:
            msg = (
                f"Candidate IR size ({candidate_bytes} bytes, ratio {ratio:.2f}) "
                f"exceeds max IR growth policy limit ({self.config.max_ir_growth_ratio:.2f})."
            )
            return PolicyDecision(allowed=False, reason=msg, violations=[msg])

        return PolicyDecision(allowed=True, reason="IR growth within policy bounds.")

    def evaluate_binary_growth(self, baseline_bytes: int, candidate_bytes: int) -> PolicyDecision:
        """Enforces maximum binary bloat limits."""
        if baseline_bytes <= 0:
            return PolicyDecision(allowed=True, reason="Valid baseline binary size.")

        ratio = candidate_bytes / baseline_bytes
        if ratio > self.config.max_binary_growth_ratio:
            msg = (
                f"Candidate binary size ({candidate_bytes} bytes, ratio {ratio:.2f}) "
                f"exceeds max binary growth policy limit ({self.config.max_binary_growth_ratio:.2f})."
            )
            return PolicyDecision(allowed=False, reason=msg, violations=[msg])

        return PolicyDecision(allowed=True, reason="Binary growth within policy bounds.")

    def check_time_budget(self, elapsed_seconds: float) -> bool:
        """Returns True if compilation is within the time budget."""
        return elapsed_seconds <= self.config.max_compilation_time_s
