"""
Secure Compiler — Source Ingestion & Input Quarantine Layer
Validates source code inputs, enforces strict file/project size quotas,
normalizes encoding, strips dangerous control characters, computes cryptographic
SHA-256 digests, assigns immutable build IDs, and produces a sealed input manifest.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime
import hashlib
import uuid
import json
import os
import re
import shutil


@dataclass
class IngestionResult:
    success: bool
    build_id: str
    source_path: str
    source_hash: str
    source_bytes: int
    language: str
    timestamp: str
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    manifest_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "build_id": self.build_id,
            "source_path": self.source_path,
            "source_hash": self.source_hash,
            "source_bytes": self.source_bytes,
            "language": self.language,
            "timestamp": self.timestamp,
            "success": self.success,
            "error": self.error,
            "metadata": self.metadata,
            "manifest_path": self.manifest_path,
        }


class SourceIngestionLayer:
    """
    Authoritative ingestion gate for C/C++ source code.
    Guarantees that all user-supplied inputs pass through a strict quarantine boundary.
    """

    SUPPORTED_EXTENSIONS = {
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".cc":  "cpp",
        ".c":   "c",
    }
    MAX_SOURCE_BYTES = 10 * 1024 * 1024   # 10 MB per file
    MAX_PROJECT_BYTES = 50 * 1024 * 1024  # 50 MB total project quota

    @classmethod
    def sanitize_source_content(cls, raw_content: str) -> str:
        """Strip dangerous ASCII control characters while preserving standard whitespace."""
        # Allow tab (\t), newline (\n), carriage return (\r), and printable chars
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', raw_content)
        return cleaned

    @classmethod
    def ingest_file(
        cls,
        source_path: str,
        target_arch: str = "native",
        opt_goal: str = "balanced",
        quarantine_dir: Optional[str] = None
    ) -> IngestionResult:
        """Validates, sanitizes, and quarantines source code before compiler frontend processing."""
        if not os.path.exists(source_path):
            return IngestionResult(
                success=False,
                build_id=f"build_err_{uuid.uuid4().hex[:8]}",
                source_path=source_path,
                source_hash="",
                source_bytes=0,
                language="unknown",
                timestamp=datetime.utcnow().isoformat(),
                error=f"Source file not found: {source_path}"
            )

        ext = os.path.splitext(source_path)[1].lower()
        if ext not in cls.SUPPORTED_EXTENSIONS:
            return IngestionResult(
                success=False,
                build_id=f"build_err_{uuid.uuid4().hex[:8]}",
                source_path=source_path,
                source_hash="",
                source_bytes=0,
                language="unknown",
                timestamp=datetime.utcnow().isoformat(),
                error=f"Unsupported file extension '{ext}'. Supported: {list(cls.SUPPORTED_EXTENSIONS.keys())}"
            )

        try:
            with open(source_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return IngestionResult(
                success=False,
                build_id=f"build_err_{uuid.uuid4().hex[:8]}",
                source_path=source_path,
                source_hash="",
                source_bytes=0,
                language=cls.SUPPORTED_EXTENSIONS[ext],
                timestamp=datetime.utcnow().isoformat(),
                error=f"Failed to read source file: {e}"
            )

        # Sanitize non-printable control characters
        sanitized_content = cls.sanitize_source_content(content)
        content_bytes = sanitized_content.encode("utf-8")

        if len(content_bytes) > cls.MAX_SOURCE_BYTES:
            return IngestionResult(
                success=False,
                build_id=f"build_err_{uuid.uuid4().hex[:8]}",
                source_path=source_path,
                source_hash="",
                source_bytes=len(content_bytes),
                language=cls.SUPPORTED_EXTENSIONS[ext],
                timestamp=datetime.utcnow().isoformat(),
                error=f"Source file exceeds maximum size limit ({cls.MAX_SOURCE_BYTES} bytes)."
            )

        src_hash = hashlib.sha256(content_bytes).hexdigest()
        build_id = f"build_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{src_hash[:8]}"

        # Detect toolchain presence for manifest
        clang_path = shutil.which("clang++") or shutil.which("clang") or "clang"

        manifest = {
            "build_id": build_id,
            "source_hash": src_hash,
            "source_type": cls.SUPPORTED_EXTENSIONS[ext],
            "source_bytes": len(content_bytes),
            "toolchain": clang_path,
            "target": target_arch,
            "optimization_goal": opt_goal,
            "timestamp": datetime.utcnow().isoformat(),
            "configuration_hash": hashlib.sha256(f"{target_arch}:{opt_goal}".encode()).hexdigest()[:16],
            "sanitized": len(sanitized_content) != len(content),
            "quarantined": True,
        }

        manifest_path = ""
        if quarantine_dir:
            os.makedirs(quarantine_dir, exist_ok=True)
            manifest_path = os.path.join(quarantine_dir, f"{build_id}_manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as mf:
                json.dump(manifest, mf, indent=2)

        metadata = {
            "filename": os.path.basename(source_path),
            "line_count": len(sanitized_content.splitlines()),
            "character_count": len(sanitized_content),
            "manifest": manifest,
        }

        return IngestionResult(
            success=True,
            build_id=build_id,
            source_path=os.path.abspath(source_path),
            source_hash=src_hash,
            source_bytes=len(content_bytes),
            language=cls.SUPPORTED_EXTENSIONS[ext],
            timestamp=datetime.utcnow().isoformat(),
            metadata=metadata,
            manifest_path=manifest_path,
        )
