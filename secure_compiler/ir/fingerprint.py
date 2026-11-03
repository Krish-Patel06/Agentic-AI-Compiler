"""
Secure Compiler — Canonical IR Fingerprinter
Generates deterministic fingerprints/hashes for LLVM IR independent of
ephemeral comments, whitespace variations, and debug metadata ID differences.
"""

import hashlib
import re


class IRFingerprinter:
    """Computes deterministic canonical hashes for LLVM IR modules."""

    @staticmethod
    def normalize_for_hashing(ir_text: str) -> str:
        """
        Normalizes LLVM IR text by:
        1. Stripping comments (; ...)
        2. Stripping ephemeral metadata lines (!0 = ...)
        3. Collapsing multiple whitespace and blank lines
        4. Trimming trailing whitespace
        """
        lines = []
        for line in ir_text.splitlines():
            # Strip comments
            line = re.sub(r";.*$", "", line).strip()
            if not line:
                continue
            # Strip debug/metadata definitions
            if line.startswith("!"):
                continue
            # Canonicalize internal whitespace
            line = re.sub(r"\s+", " ", line)
            lines.append(line)
        return "\n".join(lines)

    @classmethod
    def compute_hash(cls, ir_text: str) -> str:
        """Returns the SHA-256 hash of the normalized IR."""
        normalized = cls.normalize_for_hashing(ir_text)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @classmethod
    def compute_short_id(cls, ir_text: str, length: int = 12) -> str:
        """Returns a short fingerprint useful for candidate labeling."""
        return cls.compute_hash(ir_text)[:length]
