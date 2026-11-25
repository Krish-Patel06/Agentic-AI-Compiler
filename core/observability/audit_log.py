"""
Immutable, Cryptographically Hash-Chained Audit Log.
Every compiler action, state transition, security check, and decision
is recorded as an append-only, tamper-evident audit record.
"""

from __future__ import annotations
import json
import hashlib
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from pathlib import Path


GENESIS_HASH = "0" * 64


@dataclass
class AuditRecord:
    entry_id: int
    timestamp: str
    build_id: str
    event_type: str
    state: str
    data: Dict[str, Any]
    previous_hash: str
    entry_hash: str = ""

    def calculate_hash(self) -> str:
        payload = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "build_id": self.build_id,
            "event_type": self.event_type,
            "state": self.state,
            "data": self.data,
            "previous_hash": self.previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HashChainedAuditLog:
    """
    Append-only, hash-chained audit log.
    Any attempt to mutate, reorder, or delete an entry invalidates the chain.
    """

    def __init__(self, build_id: str = "default_build"):
        self.build_id = build_id
        self._entries: List[AuditRecord] = []
        self._last_hash = GENESIS_HASH

    @property
    def entries(self) -> List[AuditRecord]:
        return list(self._entries)

    @property
    def head_hash(self) -> str:
        return self._last_hash

    def get_entries(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._entries]

    def append_event(
        self,
        event_type: str,
        state: str = "UNKNOWN",
        data: Optional[Dict[str, Any]] = None
    ) -> AuditRecord:
        data_payload = data or {}
        entry_id = len(self._entries)
        now_utc = datetime.now(timezone.utc).isoformat()

        record = AuditRecord(
            entry_id=entry_id,
            timestamp=now_utc,
            build_id=self.build_id,
            event_type=event_type,
            state=state,
            data=data_payload,
            previous_hash=self._last_hash,
        )
        record.entry_hash = record.calculate_hash()
        self._last_hash = record.entry_hash
        self._entries.append(record)
        return record

    def verify_chain_integrity(self) -> bool:
        """
        Validates the entire hash chain from entry 0 to the latest entry.
        Returns True if intact, False if tampered.
        """
        expected_prev = GENESIS_HASH
        for idx, rec in enumerate(self._entries):
            if rec.entry_id != idx:
                return False
            if rec.previous_hash != expected_prev:
                return False
            calculated = rec.calculate_hash()
            if rec.entry_hash != calculated:
                return False
            expected_prev = rec.entry_hash
        return True

    def export_json(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        records_dict = [r.to_dict() for r in self._entries]
        with open(p, "w", encoding="utf-8") as f:
            json.dump({
                "build_id": self.build_id,
                "chain_length": len(self._entries),
                "head_hash": self._last_hash,
                "verified": self.verify_chain_integrity(),
                "records": records_dict
            }, f, indent=2)

    @classmethod
    def load_from_json(cls, path: str | Path) -> HashChainedAuditLog:
        p = Path(path)
        with open(p, "r", encoding="utf-8") as f:
            doc = json.load(f)
        log = cls(build_id=doc.get("build_id", "imported_build"))
        for rec_dict in doc.get("records", []):
            rec = AuditRecord(
                entry_id=rec_dict["entry_id"],
                timestamp=rec_dict["timestamp"],
                build_id=rec_dict["build_id"],
                event_type=rec_dict["event_type"],
                state=rec_dict["state"],
                data=rec_dict["data"],
                previous_hash=rec_dict["previous_hash"],
                entry_hash=rec_dict["entry_hash"],
            )
            log._entries.append(rec)
            log._last_hash = rec.entry_hash
        return log
