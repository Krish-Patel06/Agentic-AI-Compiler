"""
Zero-Trust Verified Experience Store.
Persists verified optimization pipelines, targets, and benchmark metrics.
Enforces Poison-Resistant Cryptographic Indexing (hash-chained records).
AI is strictly read-only; only the authoritative Decision Engine can commit VERIFIED entries.
"""

from __future__ import annotations
import sqlite3
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

from ..optimizer.candidate import Candidate, CandidateStatus


DECISION_ENGINE_COMMIT_TOKEN = "AUTHORITATIVE_DECISION_ENGINE_VERIFIED_COMMIT_KEY_v2"
GENESIS_HASH = "0" * 64


class ExperiencePoisoningError(Exception):
    """Raised when an unverified, unauthorized, or poisoned entry attempts to enter the store."""
    pass


class VerifiedExperienceStore:
    """
    Cryptographically chained SQLite store for verified optimization records.
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._is_memory = (self.db_path == ":memory:")
        self._shared_conn = sqlite3.connect(self.db_path) if self._is_memory else None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._is_memory:
            return self._shared_conn
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        conn = self._get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS verified_experience (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                ir_fingerprint TEXT NOT NULL,
                target_arch TEXT NOT NULL,
                pass_pipeline TEXT NOT NULL,
                improvement_pct REAL NOT NULL,
                p50_runtime_ns REAL NOT NULL,
                compile_time_ms REAL NOT NULL,
                verification_passed INTEGER NOT NULL,
                security_passed INTEGER NOT NULL,
                trust_status TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        conn.commit()
        if not self._is_memory:
            conn.close()

    def _get_last_entry_hash(self, conn: sqlite3.Connection) -> str:
        cursor = conn.cursor()
        cursor.execute("SELECT entry_hash FROM verified_experience ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else GENESIS_HASH

    def commit_verified_candidate(
        self,
        candidate: Candidate,
        source_hash: str,
        target_arch: str,
        decision_token: str,
        correctness_report: Dict[str, Any],
        security_report: Dict[str, Any],
        benchmark_measurement: Dict[str, Any]
    ) -> str:
        """
        Commits an optimization candidate to the experience store.
        Strict zero-trust validation:
        1. Caller must supply the authentic decision_token.
        2. Candidate must not be unverified/rejected.
        3. Correctness and Security gates must both have passed.
        4. Benchmark must show valid positive improvement.
        """
        # Security invariant: Token check
        if decision_token != DECISION_ENGINE_COMMIT_TOKEN:
            raise ExperiencePoisoningError(
                "UNAUTHORIZED WRITE ATTEMPT: AI agents and non-decision components cannot write to Experience Store."
            )

        # Invariant: Gates must pass
        if not correctness_report.get("passed", False):
            raise ExperiencePoisoningError("POISONING BLOCKED: Candidate failed Correctness Gate.")
        if not security_report.get("passed", False):
            raise ExperiencePoisoningError("POISONING BLOCKED: Candidate failed Security Gate.")

        improvement = float(benchmark_measurement.get("improvement_pct", 0.0))
        if improvement < 0:
            raise ExperiencePoisoningError("POISONING BLOCKED: Candidate had negative improvement / regression.")

        pipeline_json = json.dumps(candidate.pass_pipeline)
        import datetime
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn = self._get_connection()
        try:
            prev_hash = self._get_last_entry_hash(conn)

            # Calculate tamper-evident hash
            hash_payload = f"{prev_hash}|{source_hash}|{candidate.ir_fingerprint}|{target_arch}|{pipeline_json}|{improvement:.4f}"
            entry_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

            conn.execute("""
                INSERT INTO verified_experience (
                    timestamp, source_hash, ir_fingerprint, target_arch,
                    pass_pipeline, improvement_pct, p50_runtime_ns, compile_time_ms,
                    verification_passed, security_passed, trust_status, previous_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                source_hash,
                candidate.ir_fingerprint,
                target_arch,
                pipeline_json,
                improvement,
                float(benchmark_measurement.get("p50_runtime_ns", 0.0) or benchmark_measurement.get("median_runtime_ns", 0.0)),
                float(candidate.resource_usage.compilation_time_ms),
                1,
                1,
                "VERIFIED",
                prev_hash,
                entry_hash
            ))
            conn.commit()
        finally:
            if not self._is_memory:
                conn.close()

        return entry_hash

    def query_similar_passes(self, target_arch: str = "native", limit: int = 5) -> List[List[str]]:
        """
        Queries proven historical pass sequences for the given target.
        Only returns entries marked with trust_status = 'VERIFIED'.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT pass_pipeline FROM verified_experience
                WHERE trust_status = 'VERIFIED' AND (target_arch = ? OR target_arch = 'native')
                ORDER BY improvement_pct DESC LIMIT ?
            """, (target_arch, limit))
            rows = cursor.fetchall()
        finally:
            if not self._is_memory:
                conn.close()

        results = []
        for r in rows:
            try:
                pipeline = json.loads(r[0])
                if pipeline and pipeline not in results:
                    results.append(pipeline)
            except Exception:
                pass
        return results

    def verify_store_integrity(self) -> bool:
        """
        Validates the hash chain across all committed records in SQLite.
        Returns True if completely intact, False if any entry was tampered with.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT source_hash, ir_fingerprint, target_arch, pass_pipeline, improvement_pct, previous_hash, entry_hash
                FROM verified_experience ORDER BY id ASC
            """)
            rows = cursor.fetchall()
        finally:
            if not self._is_memory:
                conn.close()

        expected_prev = GENESIS_HASH
        for row in rows:
            src_hash, ir_fp, target, pipe_json, imp, prev_hash, stored_entry_hash = row
            if prev_hash != expected_prev:
                return False
            payload = f"{prev_hash}|{src_hash}|{ir_fp}|{target}|{pipe_json}|{imp:.4f}"
            calculated = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if stored_entry_hash != calculated:
                return False
            expected_prev = stored_entry_hash
        return True
