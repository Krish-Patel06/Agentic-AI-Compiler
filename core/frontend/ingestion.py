"""
Input Quarantine and Source Ingestion Layer.
Accepts untrusted C/C++ source code, applies strict size quotas,
sanitizes encoding, computes canonical SHA-256 digest, and isolates
the file within the quarantine workspace.
"""

from __future__ import annotations
import os
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB quota
ALLOWED_EXTENSIONS = {".cpp", ".cxx", ".cc", ".c"}


class SourceQuarantineError(Exception):
    """Raised when untrusted source violates quarantine admission criteria."""
    pass


@dataclass(frozen=True)
class IngestionResult:
    build_id: str
    source_path: str
    quarantine_path: str
    source_hash: str
    size_bytes: int
    extension: str
    timestamp_utc: str
    normalized_source: str
    diagnostics: List[str] = field(default_factory=list)

    def to_manifest(self) -> Dict[str, Any]:
        return {
            "build_id": self.build_id,
            "source_hash": self.source_hash,
            "source_type": self.extension.lstrip("."),
            "size_bytes": self.size_bytes,
            "timestamp": self.timestamp_utc,
            "quarantine_path": self.quarantine_path,
            "diagnostics": list(self.diagnostics)
        }


class SourceIngestionLayer:
    """
    Quarantine admission controller.
    Validates file extension, size, encoding, and generates immutable input manifest.
    """

    @classmethod
    def ingest_file(
        cls,
        source_path: str | Path,
        quarantine_dir: Optional[str | Path] = None,
        build_id: Optional[str] = None
    ) -> IngestionResult:
        src = Path(source_path)
        if not src.exists() or not src.is_file():
            raise SourceQuarantineError(f"Input source file not found: {source_path}")

        ext = src.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise SourceQuarantineError(
                f"Forbidden file extension '{ext}'. Allowed extensions: {sorted(ALLOWED_EXTENSIONS)}"
            )

        file_size = src.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            raise SourceQuarantineError(
                f"Source size {file_size} bytes exceeds maximum allowed quota of {MAX_FILE_SIZE_BYTES} bytes (10MB)"
            )

        # Read and enforce UTF-8 sanitization
        raw_bytes = src.read_bytes()
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Normalize with lossy replacement and record diagnostic
            content = raw_bytes.decode("utf-8", errors="replace")

        # Normalize line endings to UNIX LF for deterministic hashing
        normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
        sha256_hash = hashlib.sha256(normalized_content.encode("utf-8")).hexdigest()

        assigned_build_id = build_id or f"build_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{sha256_hash[:8]}"

        # Write sanitized source into isolated quarantine directory
        if quarantine_dir:
            q_dir = Path(quarantine_dir)
        else:
            q_dir = Path("compiler_artifacts") / assigned_build_id / "quarantine"
        q_dir.mkdir(parents=True, exist_ok=True)

        quarantine_file = q_dir / f"quarantined_source{ext}"
        quarantine_file.write_text(normalized_content, encoding="utf-8")

        return IngestionResult(
            build_id=assigned_build_id,
            source_path=str(src.resolve()),
            quarantine_path=str(quarantine_file.resolve()),
            source_hash=sha256_hash,
            size_bytes=len(normalized_content.encode("utf-8")),
            extension=ext,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            normalized_source=normalized_content,
            diagnostics=[]
        )

    @classmethod
    def ingest_source(
        cls,
        source_text: str,
        filename: str = "program.cpp",
        quarantine_dir: Optional[str | Path] = None,
        build_id: Optional[str] = None
    ) -> Any:
        @dataclass
        class IngestWrapper:
            valid: bool
            sha256: str
            rejection_reason: str
            ingestion_result: Optional[IngestionResult] = None

        ext = Path(filename).suffix.lower() or ".cpp"
        if ext not in ALLOWED_EXTENSIONS:
            return IngestWrapper(valid=False, sha256="", rejection_reason=f"Forbidden file extension '{ext}'")

        content_bytes = source_text.encode("utf-8")
        if len(content_bytes) > MAX_FILE_SIZE_BYTES:
            return IngestWrapper(valid=False, sha256="", rejection_reason="Source code exceeds 10MB quota")

        normalized = source_text.replace("\r\n", "\n").replace("\r", "\n")
        sha256_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        assigned_id = build_id or f"build_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{sha256_hash[:8]}"
        q_dir = Path(quarantine_dir or (Path("compiler_artifacts") / assigned_id / "quarantine"))
        q_dir.mkdir(parents=True, exist_ok=True)
        q_file = q_dir / f"quarantined_source{ext}"
        q_file.write_text(normalized, encoding="utf-8")

        res = IngestionResult(
            build_id=assigned_id,
            source_path=str(q_file.resolve()),
            quarantine_path=str(q_file.resolve()),
            source_hash=sha256_hash,
            size_bytes=len(content_bytes),
            extension=ext,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            normalized_source=normalized,
            diagnostics=[]
        )
        return IngestWrapper(valid=True, sha256=sha256_hash, rejection_reason="", ingestion_result=res)
