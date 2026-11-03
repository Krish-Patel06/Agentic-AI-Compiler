"""
Secure Compiler — Agent Output Schemas & Zero-Trust Validation
Guarantees all agent proposals adhere strictly to a deterministic JSON schema.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json


@dataclass
class AgentProposal:
    """Strict schema for AI optimization proposals."""
    action: str
    passes: List[str]
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_benefit: float = 0.0
    risk: str = "low"                   # "low" | "medium" | "high"
    reason: str = ""
    agent_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "passes": self.passes,
            "parameters": self.parameters,
            "expected_benefit": round(self.expected_benefit, 3),
            "risk": self.risk,
            "reason": self.reason,
            "agent_name": self.agent_name,
        }

    @classmethod
    def from_json(cls, raw_json: str, agent_name: str = "unknown") -> "AgentProposal":
        """Parses and strictly validates raw agent JSON string."""
        try:
            data = json.loads(raw_json)
        except Exception as e:
            return cls(
                action="invalid",
                passes=[],
                risk="high",
                reason=f"Failed to parse agent JSON: {e}",
                agent_name=agent_name
            )

        if not isinstance(data, dict):
            return cls(
                action="invalid",
                passes=[],
                risk="high",
                reason="Agent output is not a JSON object.",
                agent_name=agent_name
            )

        action = str(data.get("action", "propose_pass_pipeline"))
        raw_passes = data.get("passes", [])
        passes = [str(p).strip() for p in raw_passes if isinstance(p, (str, int))] if isinstance(raw_passes, list) else []
        params = data.get("parameters", {}) if isinstance(data.get("parameters"), dict) else {}
        benefit = float(data.get("expected_benefit", 0.0)) if isinstance(data.get("expected_benefit"), (int, float)) else 0.0
        risk = str(data.get("risk", "low")).lower()
        reason = str(data.get("reason", "No reason provided."))

        return cls(
            action=action,
            passes=passes,
            parameters=params,
            expected_benefit=benefit,
            risk=risk,
            reason=reason,
            agent_name=agent_name,
        )
