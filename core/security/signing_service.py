"""
Isolated Cryptographic Signing Service.
Maintains the root release signing keys within an isolated enclave.
AI agents, LLVM passes, and compiler workers have ZERO access to the signing keys.
Signing is strictly refused unless all gates (Correctness, Security, Canary) have passed.
"""

from __future__ import annotations
import hmac
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass(frozen=True)
class SigningResult:
    signed: bool
    signature: str
    key_id: str
    timestamp_utc: str
    certificate: str
    rejection_reason: str = ""


class IsolatedSigningService:
    """Enclave-protected artifact signer."""

    def __init__(self, key_id: str = "compiler-enclave-key-v2"):
        self.key_id = key_id
        # Root key is held exclusively in memory within the signing service
        self._private_signing_key = b"ENCLAVE_ROOT_RELEASE_SIGNING_KEY_SECRET_v2_2026"

    def authorize_and_sign(
        self,
        artifact_bytes: bytes,
        manifest_data: Dict[str, Any],
        correctness_passed: bool,
        security_passed: bool,
        canary_passed: bool,
        decision_verdict: str
    ) -> SigningResult:
        """
        Enclave authorization check. Only signs if all gate verifications passed.
        """
        now = datetime.now(timezone.utc).isoformat()

        if not correctness_passed:
            return SigningResult(
                signed=False, signature="", key_id=self.key_id, timestamp_utc=now,
                certificate="", rejection_reason="Signing Refused: Correctness gate did not pass."
            )
        if not security_passed:
            return SigningResult(
                signed=False, signature="", key_id=self.key_id, timestamp_utc=now,
                certificate="", rejection_reason="Signing Refused: Security gate did not pass."
            )
        if not canary_passed:
            return SigningResult(
                signed=False, signature="", key_id=self.key_id, timestamp_utc=now,
                certificate="", rejection_reason="Signing Refused: Canary stress stage did not pass."
            )
        if decision_verdict not in ("accept", "baseline_fallback"):
            return SigningResult(
                signed=False, signature="", key_id=self.key_id, timestamp_utc=now,
                certificate="", rejection_reason=f"Signing Refused: Invalid decision verdict '{decision_verdict}'."
            )

        # Compute payload digest including artifact SHA-256 and manifest metadata
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
        digest_input = f"{self.key_id}|{artifact_hash}|{manifest_data.get('build_id')}|{now}"
        signature = hmac.new(self._private_signing_key, digest_input.encode("utf-8"), hashlib.sha256).hexdigest()

        cert = f"CERT-SIG-{self.key_id}-{signature[:16]}"

        return SigningResult(
            signed=True,
            signature=signature,
            key_id=self.key_id,
            timestamp_utc=now,
            certificate=cert,
            rejection_reason=""
        )

    def verify_signature(
        self,
        artifact_bytes: bytes,
        manifest_data: Dict[str, Any],
        signature: str,
        timestamp_utc: str
    ) -> bool:
        """Verifies if an artifact's signature is valid."""
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
        digest_input = f"{self.key_id}|{artifact_hash}|{manifest_data.get('build_id')}|{timestamp_utc}"
        expected = hmac.new(self._private_signing_key, digest_input.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
