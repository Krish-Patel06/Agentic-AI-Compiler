"""
Deterministic 22-State Machine for the Agentic AI Compiler Orchestrator.
Defines exactly 22 explicit states, an exhaustive transition table,
and disallows any implicit transitions.
"""

from __future__ import annotations
from enum import Enum, unique
from typing import Dict, Tuple, Set, Optional, Callable, Any
from ..observability.audit_log import HashChainedAuditLog


@unique
class CompilerState(Enum):
    INIT = "INIT"
    INGEST = "INGEST"
    QUARANTINE_OK = "QUARANTINE_OK"
    FRONTEND = "FRONTEND"
    IR_GATE = "IR_GATE"
    PROFILE = "PROFILE"
    BASELINE_FROZEN = "BASELINE_FROZEN"
    EXPERIENCE_LOOKUP = "EXPERIENCE_LOOKUP"
    BUDGET_ASSIGN = "BUDGET_ASSIGN"
    ADVISE = "ADVISE"
    SCORE = "SCORE"
    CANDIDATE_BUILD = "CANDIDATE_BUILD"
    COMPILE = "COMPILE"
    CORRECTNESS_GATE = "CORRECTNESS_GATE"
    SECURITY_GATE = "SECURITY_GATE"
    BENCHMARK = "BENCHMARK"
    DECIDE = "DECIDE"
    CANARY = "CANARY"
    COMMIT = "COMMIT"
    ROLLBACK = "ROLLBACK"
    FALLBACK = "FALLBACK"
    RELEASE = "RELEASE"


# Explicit transition table: (CurrentState, EventName) -> NextState
TRANSITION_TABLE: Dict[Tuple[CompilerState, str], CompilerState] = {
    # Initialization and Ingestion
    (CompilerState.INIT, "START"): CompilerState.INGEST,
    (CompilerState.INGEST, "INGEST_SUCCESS"): CompilerState.QUARANTINE_OK,
    (CompilerState.INGEST, "INGEST_ERROR"): CompilerState.FALLBACK,
    
    # Frontend Clang Sandbox
    (CompilerState.QUARANTINE_OK, "FRONTEND_START"): CompilerState.FRONTEND,
    (CompilerState.FRONTEND, "FRONTEND_SUCCESS"): CompilerState.IR_GATE,
    (CompilerState.FRONTEND, "FRONTEND_ERROR"): CompilerState.FALLBACK,
    
    # IR Security Gate & Profiling
    (CompilerState.IR_GATE, "IR_VALID"): CompilerState.PROFILE,
    (CompilerState.IR_GATE, "IR_INVALID"): CompilerState.FALLBACK,
    (CompilerState.PROFILE, "PROFILE_DONE"): CompilerState.BASELINE_FROZEN,
    
    # Dual Foundation: Baseline Frozen & Experience Lookup
    (CompilerState.BASELINE_FROZEN, "BASELINE_READY"): CompilerState.EXPERIENCE_LOOKUP,
    (CompilerState.EXPERIENCE_LOOKUP, "LOOKUP_DONE"): CompilerState.BUDGET_ASSIGN,
    
    # Budget Manager & AI Advisory
    (CompilerState.BUDGET_ASSIGN, "BUDGET_OK"): CompilerState.ADVISE,
    (CompilerState.BUDGET_ASSIGN, "BUDGET_EXHAUSTED"): CompilerState.FALLBACK,
    (CompilerState.ADVISE, "PROPOSAL_RECEIVED"): CompilerState.SCORE,
    (CompilerState.ADVISE, "AI_DISABLED"): CompilerState.FALLBACK,
    (CompilerState.ADVISE, "ADVISE_ERROR"): CompilerState.FALLBACK,
    
    # Pre-Execution Scoring & Candidate Branching
    (CompilerState.SCORE, "SCORE_ACCEPT"): CompilerState.CANDIDATE_BUILD,
    (CompilerState.SCORE, "SCORE_PRUNE"): CompilerState.ROLLBACK,
    (CompilerState.CANDIDATE_BUILD, "BUILD_READY"): CompilerState.COMPILE,
    
    # Compiler Sandbox & Pass Execution
    (CompilerState.COMPILE, "COMPILE_SUCCESS"): CompilerState.CORRECTNESS_GATE,
    (CompilerState.COMPILE, "COMPILE_ERROR"): CompilerState.ROLLBACK,
    
    # Verification Gates
    (CompilerState.CORRECTNESS_GATE, "CORRECTNESS_PASS"): CompilerState.SECURITY_GATE,
    (CompilerState.CORRECTNESS_GATE, "CORRECTNESS_FAIL"): CompilerState.ROLLBACK,
    (CompilerState.SECURITY_GATE, "SECURITY_PASS"): CompilerState.BENCHMARK,
    (CompilerState.SECURITY_GATE, "SECURITY_FAIL"): CompilerState.ROLLBACK,
    
    # Benchmarking & Decision Engine
    (CompilerState.BENCHMARK, "BENCHMARK_DONE"): CompilerState.DECIDE,
    (CompilerState.DECIDE, "DECIDE_SPEEDUP"): CompilerState.CANARY,
    (CompilerState.DECIDE, "DECIDE_REJECT"): CompilerState.ROLLBACK,
    (CompilerState.DECIDE, "DECIDE_NO_GAIN"): CompilerState.ROLLBACK,
    
    # Canary Release Stage
    (CompilerState.CANARY, "CANARY_PASS"): CompilerState.COMMIT,
    (CompilerState.CANARY, "CANARY_FAIL"): CompilerState.ROLLBACK,
    
    # Transactional Commit vs Rollback vs Fallback
    (CompilerState.COMMIT, "COMMIT_DONE"): CompilerState.RELEASE,
    (CompilerState.ROLLBACK, "RETRY_ALLOWED"): CompilerState.BUDGET_ASSIGN,
    (CompilerState.ROLLBACK, "NO_RETRIES_LEFT"): CompilerState.FALLBACK,
    (CompilerState.FALLBACK, "FALLBACK_DONE"): CompilerState.RELEASE,
}


class InvalidTransitionError(Exception):
    """Raised when an illegal or undefined state transition is attempted."""
    def __init__(self, current_state: CompilerState, event: str):
        super().__init__(
            f"Invalid state transition: State '{current_state.value}' does not accept event '{event}'."
        )
        self.current_state = current_state
        self.event = event


class StateMachine:
    """
    Deterministic State Machine enforcing the exact 22 compiler states.
    All transitions are validated against TRANSITION_TABLE and audited.
    """

    def __init__(self, audit_log: Optional[HashChainedAuditLog] = None):
        self._current_state = CompilerState.INIT
        self._audit_log = audit_log or HashChainedAuditLog()
        self._history: list[Tuple[CompilerState, str, CompilerState]] = []
        self._safe_stopped = False

        # Record initial state
        self._audit_log.append_event(
            event_type="STATE_INITIALIZED",
            state=self._current_state.value,
            data={"state": self._current_state.value}
        )

    @property
    def current_state(self) -> CompilerState:
        return self._current_state

    @property
    def history(self) -> list[Tuple[CompilerState, str, CompilerState]]:
        return list(self._history)

    @property
    def is_terminal(self) -> bool:
        return self._current_state == CompilerState.RELEASE

    def transition(self, event: str, metadata: Optional[Dict[str, Any]] = None) -> CompilerState:
        """
        Executes a deterministic state transition according to the transition table.
        Throws InvalidTransitionError if the transition is illegal.
        """
        if self._safe_stopped and self._current_state != CompilerState.RELEASE:
            if event != "FALLBACK_DONE":
                self._current_state = CompilerState.FALLBACK
                return self._current_state

        key = (self._current_state, event)
        if key not in TRANSITION_TABLE:
            self._audit_log.append_event(
                event_type="INVALID_TRANSITION_ATTEMPTED",
                state=self._current_state.value,
                data={"event": event, "metadata": metadata or {}}
            )
            raise InvalidTransitionError(self._current_state, event)

        next_state = TRANSITION_TABLE[key]
        old_state = self._current_state
        self._current_state = next_state
        self._history.append((old_state, event, next_state))

        self._audit_log.append_event(
            event_type="STATE_TRANSITION",
            state=next_state.value,
            data={
                "from_state": old_state.value,
                "event": event,
                "to_state": next_state.value,
                "metadata": metadata or {}
            }
        )
        return next_state

    def trigger_safe_stop(self, reason: str = "Emergency kill switch triggered") -> None:
        """
        Global Emergency Kill Switch (Instant Halt).
        Immediately forces active state to FALLBACK and locks future branching.
        """
        old_state = self._current_state
        self._safe_stopped = True
        self._current_state = CompilerState.FALLBACK
        self._history.append((old_state, "SAFE_STOP", CompilerState.FALLBACK))

        self._audit_log.append_event(
            event_type="EMERGENCY_SAFE_STOP_TRIGGERED",
            state=CompilerState.FALLBACK.value,
            data={
                "from_state": old_state.value,
                "reason": reason,
                "action": "Immediate transition to FALLBACK baseline"
            }
        )
