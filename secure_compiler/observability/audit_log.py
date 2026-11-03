"""
Secure Compiler — Observability & Build Audit Log
Maintains comprehensive, immutable audit trails for every build and optimization step.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import os


@dataclass
class AuditLogEntry:
    timestamp: str
    event_type: str
    candidate_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)


class BuildAuditLog:
    """
    Immutable audit recorder capturing all agent proposals, pass pipelines,
    verification outcomes, benchmark measurements, and decision logs.
    """

    def __init__(self, build_id: str, source_hash: str, target: str):
        self.build_id = build_id
        self.source_hash = source_hash
        self.ir_hash = ""
        self.target = target
        self.selected_strategy = "baseline"
        self.agent_proposals: List[Dict[str, Any]] = []
        self.passes_executed: List[str] = []
        self.candidates_generated: List[str] = []
        self.verification_results: Dict[str, Any] = {}
        self.benchmark_results: Dict[str, Any] = {}
        self.security_results: Dict[str, Any] = {}
        self.rejected_candidates: List[Dict[str, Any]] = []
        self.final_artifact: str = ""
        self.entries: List[AuditLogEntry] = []

    def record_event(self, event_type: str, candidate_id: Optional[str] = None, **kwargs):
        entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            candidate_id=candidate_id,
            data=kwargs
        )
        self.entries.append(entry)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "build_id": self.build_id,
            "source_hash": self.source_hash,
            "ir_hash": self.ir_hash,
            "target": self.target,
            "selected_strategy": self.selected_strategy,
            "passes_executed": self.passes_executed,
            "candidates_generated": self.candidates_generated,
            "agent_proposals": self.agent_proposals,
            "verification_results": self.verification_results,
            "benchmark_results": self.benchmark_results,
            "security_results": self.security_results,
            "rejected_candidates": self.rejected_candidates,
            "final_artifact": self.final_artifact,
            "total_events": len(self.entries),
            "timeline": [
                {
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "candidate_id": e.candidate_id,
                    "data": e.data,
                }
                for e in self.entries
            ],
        }

    def export_json(self, filepath: str):
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    def summary(self) -> str:
        return (
            f"[BuildAuditLog] BuildID={self.build_id} | Target={self.target} | "
            f"Candidates={len(self.candidates_generated)} | "
            f"Rejected={len(self.rejected_candidates)} | Strategy='{self.selected_strategy}'"
        )
