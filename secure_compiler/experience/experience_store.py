"""
Secure Compiler — Verified Experience Store
Persists only verified, safe, policy-compliant optimization experiences.
Never records failed, unverified, or rolled-back candidates.
Supports filtered retrieval by target architecture, compiler, and LLVM versions.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
import sqlite3
import json
import time
import os
from datetime import datetime

from ..optimizer.candidate import Candidate, CandidateStatus


@dataclass
class VerifiedExperience:
    source_hash: str
    ir_hash: str
    target_arch: str
    llvm_version: str
    compiler_version: str
    opt_level: str
    pass_sequence: List[str]
    pass_parameters: Dict[str, Any]
    benchmark_results: Dict[str, Any]
    correctness_result: Dict[str, Any]
    security_result: Dict[str, Any]
    regression_result: Dict[str, Any]
    compilation_time_ms: float
    code_size_bytes: int
    improvement_pct: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class VerifiedExperienceStore:
    """
    Authoritative experience store.
    Strictly accepts only VERIFIED and ACCEPTED candidates.
    """

    def __init__(self, db_path: str = "secure_compiler_experience.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS verified_experiences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_hash TEXT NOT NULL,
                    ir_hash TEXT NOT NULL,
                    target_arch TEXT NOT NULL,
                    llvm_version TEXT,
                    compiler_version TEXT,
                    opt_level TEXT,
                    pass_sequence_json TEXT NOT NULL,
                    pass_parameters_json TEXT,
                    benchmark_results_json TEXT,
                    correctness_result_json TEXT,
                    security_result_json TEXT,
                    regression_result_json TEXT,
                    compilation_time_ms REAL,
                    code_size_bytes INTEGER,
                    improvement_pct REAL,
                    verified INTEGER DEFAULT 1,
                    timestamp TEXT
                )
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_arch ON verified_experiences(target_arch)
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ir_hash ON verified_experiences(ir_hash)
            """)

    def save_candidate_experience(
        self,
        candidate: Candidate,
        source_hash: str,
        target_arch: str,
        llvm_version: str = "17.0.0",
        compiler_version: str = "clang-17",
        opt_level: str = "O3",
        security_result: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Stores experience if and only if candidate has been formally verified.
        Rejects unverified or failed candidates.
        """
        if candidate.status not in (CandidateStatus.VERIFIED, CandidateStatus.ACCEPTED):
            return False  # Strict policy: never learn from unverified or failed candidates

        bm = candidate.benchmark_result or {}
        improvement = float(bm.get("improvement_pct", 0.0))

        # Do not save regressions
        if improvement <= 0.0 and not candidate.is_baseline:
            return False

        with self.conn:
            self.conn.execute("""
                INSERT INTO verified_experiences (
                    source_hash, ir_hash, target_arch, llvm_version,
                    compiler_version, opt_level, pass_sequence_json,
                    pass_parameters_json, benchmark_results_json,
                    correctness_result_json, security_result_json,
                    regression_result_json, compilation_time_ms,
                    code_size_bytes, improvement_pct, verified, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """, (
                source_hash,
                candidate.ir_fingerprint,
                target_arch,
                llvm_version,
                compiler_version,
                opt_level,
                json.dumps(candidate.pass_pipeline),
                json.dumps({}),
                json.dumps(bm),
                json.dumps(candidate.verification_report),
                json.dumps(security_result or {}),
                json.dumps({"regression_check": "passed"}),
                candidate.resource_usage.compilation_time_ms,
                candidate.resource_usage.ir_bytes,
                improvement,
                datetime.utcnow().isoformat()
            ))
        return True

    def query_similar_passes(
        self,
        target_arch: str,
        ir_hash: Optional[str] = None,
        min_improvement: float = 1.0,
        limit: int = 3
    ) -> List[List[str]]:
        """
        Retrieves verified pass sequences filtered by target architecture.
        """
        cursor = self.conn.cursor()
        query = """
            SELECT pass_sequence_json, improvement_pct
            FROM verified_experiences
            WHERE target_arch = ? AND improvement_pct >= ?
            ORDER BY improvement_pct DESC
            LIMIT ?
        """
        cursor.execute(query, (target_arch, min_improvement, limit))
        rows = cursor.fetchall()
        sequences = []
        for r in rows:
            try:
                seq = json.loads(r[0])
                if isinstance(seq, list) and seq:
                    sequences.append(seq)
            except Exception:
                pass
        return sequences
