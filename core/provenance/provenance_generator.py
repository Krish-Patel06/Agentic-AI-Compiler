"""
Provenance Generator.
Constructs the complete, immutable replay_manifest.json containing exact compiler flags,
target triple, pass sequence, baseline and candidate IR hashes, verification digests,
and benchmark statistics for 100% deterministic replay.
"""

from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class ProvenanceGenerator:
    """Generates deterministic replay manifests and audit proofs."""

    @staticmethod
    def compute_sha256(content: str | bytes) -> str:
        if isinstance(content, str):
            content = content.encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    def generate_manifest(
        self,
        build_id: str,
        source_code: str,
        source_sha256: str,
        target_triple: str,
        clang_version: str,
        llvm_version: str,
        compiler_flags: List[str],
        baseline_ir: str,
        baseline_ir_sha256: str,
        final_ir: str,
        final_ir_sha256: str,
        pass_sequence: List[str],
        correctness_report: Dict[str, Any],
        security_report: Dict[str, Any],
        benchmark_report: Dict[str, Any],
        audit_chain_head: str,
        decision_verdict: str
    ) -> Dict[str, Any]:
        """
        Creates a complete replay manifest mapping every stage and hash.
        """
        now = datetime.now(timezone.utc).isoformat()

        manifest = {
            "schema_version": "2.0.0",
            "build_id": build_id,
            "created_at_utc": now,
            "provenance": {
                "source_sha256": source_sha256 or self.compute_sha256(source_code),
                "compiler_environment": {
                    "clang_version": clang_version,
                    "llvm_version": llvm_version,
                    "target_triple": target_triple,
                    "frontend_flags": compiler_flags,
                },
                "baseline": {
                    "candidate_id": 0,
                    "ir_sha256": baseline_ir_sha256 or self.compute_sha256(baseline_ir),
                    "lineage": "root_reference_O0"
                },
                "optimization": {
                    "pass_pipeline": pass_sequence,
                    "final_ir_sha256": final_ir_sha256 or self.compute_sha256(final_ir),
                    "decision_verdict": decision_verdict
                },
                "verification_proofs": {
                    "correctness": {
                        "passed": correctness_report.get("passed", False),
                        "output_digest": correctness_report.get("output_digest", ""),
                        "test_cases_count": correctness_report.get("test_cases_count", 0)
                    },
                    "security": {
                        "passed": security_report.get("passed", False),
                        "abi_preserved": security_report.get("abi_preserved", False),
                        "violations": security_report.get("violations", [])
                    },
                    "benchmark": {
                        "speedup": benchmark_report.get("speedup", 1.0),
                        "is_significant": benchmark_report.get("is_significant", False),
                        "baseline_mean_ns": benchmark_report.get("baseline_mean_ns", 0.0),
                        "candidate_mean_ns": benchmark_report.get("candidate_mean_ns", 0.0)
                    }
                },
                "audit_trail": {
                    "audit_chain_head": audit_chain_head
                }
            }
        }
        # Compute canonical manifest digest
        manifest_canonical = json.dumps(manifest, sort_keys=True)
        manifest["manifest_sha256"] = self.compute_sha256(manifest_canonical)
        return manifest
