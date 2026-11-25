"""
Deterministic Artifact Packager.
Packages production artifacts:
  - optimized.ll
  - baseline.ll
  - optimization_report.json
  - audit_log.json
  - replay_manifest.json
  - release.sig (cryptographic signature)
"""

from __future__ import annotations
import json
import os
import zipfile
from dataclasses import dataclass
from typing import Dict, Any, Optional

from core.security.signing_service import IsolatedSigningService, SigningResult


@dataclass(frozen=True)
class PackagingResult:
    success: bool
    output_dir: str
    archive_path: Optional[str]
    signing_result: Optional[SigningResult]
    error_message: str = ""


class ArtifactPackager:
    """Collects and packages all build outputs with detached signatures."""

    def __init__(self, signing_service: Optional[IsolatedSigningService] = None):
        self.signer = signing_service or IsolatedSigningService()

    def package_release(
        self,
        output_dir: str,
        baseline_ir: str,
        optimized_ir: str,
        optimization_report: Dict[str, Any],
        audit_log_entries: list,
        replay_manifest: Dict[str, Any],
        correctness_passed: bool,
        security_passed: bool,
        canary_passed: bool,
        decision_verdict: str,
        create_archive: bool = True
    ) -> PackagingResult:
        """
        Writes all output artifacts, requests isolated signature, and packages into zip.
        """
        try:
            os.makedirs(output_dir, exist_ok=True)

            baseline_path = os.path.join(output_dir, "baseline.ll")
            optimized_path = os.path.join(output_dir, "optimized.ll")
            report_path = os.path.join(output_dir, "optimization_report.json")
            audit_path = os.path.join(output_dir, "audit_log.json")
            manifest_path = os.path.join(output_dir, "replay_manifest.json")

            with open(baseline_path, "w", encoding="utf-8") as f:
                f.write(baseline_ir)

            with open(optimized_path, "w", encoding="utf-8") as f:
                f.write(optimized_ir)

            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(optimization_report, f, indent=2)

            with open(audit_path, "w", encoding="utf-8") as f:
                json.dump(audit_log_entries, f, indent=2)

            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(replay_manifest, f, indent=2)

            # Isolated Signing Service Authorization & Signing
            opt_bytes = optimized_ir.encode("utf-8")
            sign_res = self.signer.authorize_and_sign(
                artifact_bytes=opt_bytes,
                manifest_data=replay_manifest,
                correctness_passed=correctness_passed,
                security_passed=security_passed,
                canary_passed=canary_passed,
                decision_verdict=decision_verdict
            )

            sig_path = os.path.join(output_dir, "release.sig")
            with open(sig_path, "w", encoding="utf-8") as f:
                if sign_res.signed:
                    sig_payload = {
                        "signature": sign_res.signature,
                        "key_id": sign_res.key_id,
                        "timestamp_utc": sign_res.timestamp_utc,
                        "certificate": sign_res.certificate,
                    }
                    json.dump(sig_payload, f, indent=2)
                else:
                    json.dump({
                        "signed": False,
                        "error": sign_res.rejection_reason
                    }, f, indent=2)

            archive_path = None
            if create_archive:
                archive_path = os.path.join(output_dir, "artifact_bundle.zip")
                with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(baseline_path, arcname="baseline.ll")
                    zf.write(optimized_path, arcname="optimized.ll")
                    zf.write(report_path, arcname="optimization_report.json")
                    zf.write(audit_path, arcname="audit_log.json")
                    zf.write(manifest_path, arcname="replay_manifest.json")
                    zf.write(sig_path, arcname="release.sig")

            return PackagingResult(
                success=True,
                output_dir=output_dir,
                archive_path=archive_path,
                signing_result=sign_res,
                error_message=""
            )

        except Exception as e:
            return PackagingResult(
                success=False,
                output_dir=output_dir,
                archive_path=None,
                signing_result=None,
                error_message=str(e)
            )
