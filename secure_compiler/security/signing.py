"""
Secure Compiler — Isolated Cryptographic Signing Enclave
Isolates release authorization and signing keys from untrusted AI agents and compiler workers.
Authorizes binary and provenance artifact release IF AND ONLY IF all correctness, security,
canary, and decision gates have formally succeeded.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import hmac
import hashlib
import time
import os
import json


@dataclass
class SigningResult:
    signed: bool
    signature: str = ""
    key_id: str = ""
    timestamp_utc: str = ""
    certificate: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def summary(self) -> str:
        if self.signed:
            return f"[SigningEnclave] AUTHORIZED & SIGNED | KeyID={self.key_id} | Sig={self.signature[:16]}..."
        return f"[SigningEnclave] SIGNING REFUSED: {self.error}"


class IsolatedSigningService:
    """
    Isolated signing enclave.
    Enforces the invariant: AI agents NEVER have access to private signing keys.
    Release signing requires formal proof of passing all security & correctness gates.
    """

    def __init__(self, key_id: str = "compiler-enclave-key-v1"):
        self.key_id = key_id
        # Secret simulated enclave key (never accessible to AI agents)
        self._enclave_secret = b"Enclave_Root_Authorization_Key_SECURE_COMPILER_2026"

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
        Validates all prerequisites before signing.
        """
        # Strict gate prerequisites check
        if not correctness_passed:
            return SigningResult(signed=False, error="Correctness gate verification failed.")
        if not security_passed:
            return SigningResult(signed=False, error="Security gate validation failed.")
        if not canary_passed:
            return SigningResult(signed=False, error="Canary stress verification failed.")
        if decision_verdict not in ("accept", "baseline_fallback"):
            return SigningResult(signed=False, error=f"Decision verdict '{decision_verdict}' does not authorize release.")

        # Compute HMAC-SHA256 signature over artifact + manifest canonical digest
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
        manifest_canonical = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
        manifest_hash = hashlib.sha256(manifest_canonical).hexdigest()

        sign_payload = f"{self.key_id}:{artifact_hash}:{manifest_hash}:{decision_verdict}".encode("utf-8")
        sig = hmac.new(self._enclave_secret, sign_payload, hashlib.sha256).hexdigest()

        cert = {
            "key_id": self.key_id,
            "artifact_sha256": artifact_hash,
            "manifest_sha256": manifest_hash,
            "decision_verdict": decision_verdict,
            "timestamp_epoch": time.time(),
            "status": "RELEASE_AUTHORIZED"
        }

        return SigningResult(
            signed=True,
            signature=sig,
            key_id=self.key_id,
            timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            certificate=cert,
        )

    def verify_signature(
        self,
        artifact_bytes: bytes,
        manifest_data: Dict[str, Any],
        signature: str,
        decision_verdict: str
    ) -> bool:
        """
        Verifies a detached cryptographic signature.
        """
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
        manifest_canonical = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
        manifest_hash = hashlib.sha256(manifest_canonical).hexdigest()

        sign_payload = f"{self.key_id}:{artifact_hash}:{manifest_hash}:{decision_verdict}".encode("utf-8")
        expected_sig = hmac.new(self._enclave_secret, sign_payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_sig)
