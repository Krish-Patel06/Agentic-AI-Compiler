"""
Secure Compiler — Global Emergency Kill Switch
Authoritative circuit-breaker mechanism to halt untrusted AI/compiler activity
and force instant fail-safe fallback to deterministic Candidate 0 (Baseline).
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Callable, Optional, Dict, Any
import time


class KillSwitchState(str, Enum):
    ARMED = "armed"
    TRIGGERED = "triggered"
    DISARMED = "disarmed"


@dataclass
class KillSwitchEvent:
    timestamp_epoch: float
    trigger_reason: str
    source_component: str
    severity: str  # WARNING, CRITICAL, EMERGENCY
    details: Dict[str, Any] = field(default_factory=dict)


class EmergencyKillSwitch:
    """
    Emergency kill-switch and circuit breaker.
    Can be triggered programmatically by policy violations, sandbox anomalies,
    resource exhaustion, or operator manual intervention.
    """

    _instance: Optional['EmergencyKillSwitch'] = None

    def __init__(self):
        self.state = KillSwitchState.ARMED
        self.events: List[KillSwitchEvent] = []
        self._termination_hooks: List[Callable[[], None]] = []

    @classmethod
    def get_instance(cls) -> 'EmergencyKillSwitch':
        if cls._instance is None:
            cls._instance = EmergencyKillSwitch()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Resets the singleton for clean testing runs."""
        cls._instance = EmergencyKillSwitch()

    def register_termination_hook(self, hook: Callable[[], None]) -> None:
        """Registers a callback to kill subprocesses or sandboxes upon trigger."""
        self._termination_hooks.append(hook)

    def trigger(
        self,
        reason: str,
        source_component: str = "security_monitor",
        severity: str = "EMERGENCY",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Activates the kill switch: halts optimization and triggers fail-safe procedures.
        """
        self.state = KillSwitchState.TRIGGERED
        event = KillSwitchEvent(
            timestamp_epoch=time.time(),
            trigger_reason=reason,
            source_component=source_component,
            severity=severity,
            details=details or {}
        )
        self.events.append(event)

        # Execute all termination hooks immediately
        for hook in self._termination_hooks:
            try:
                hook()
            except Exception:
                pass

    @property
    def is_triggered(self) -> bool:
        return self.state == KillSwitchState.TRIGGERED

    def disarm(self) -> None:
        self.state = KillSwitchState.DISARMED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "triggered": self.is_triggered,
            "events_count": len(self.events),
            "latest_event": self.events[-1].__dict__ if self.events else None
        }
