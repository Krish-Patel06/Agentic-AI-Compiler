"""
Replay Engine for 100% Deterministic IR Optimization Reproduction.
Given a replay manifest and baseline IR, it deterministically runs the exact pass sequence
and checks that the resulting IR matches the manifest's final_ir_sha256 bit-for-bit.
"""

from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Dict, Any, Optional

from core.optimizer.pass_pipeline import PassPipelineExecutor


@dataclass(frozen=True)
class ReplayResult:
    reproduced: bool
    baseline_hash_match: bool
    final_hash_match: bool
    computed_final_hash: str
    expected_final_hash: str
    pass_count: int
    message: str


class ReplayEngine:
    """Deterministically replays an optimization manifest."""

    def __init__(self, pass_executor: Optional[PassPipelineExecutor] = None):
        self.pass_executor = pass_executor or PassPipelineExecutor()

    def replay(self, manifest: Dict[str, Any], baseline_ir: str) -> ReplayResult:
        """
        Replays the pass sequence from baseline IR and verifies hashes.
        """
        provenance = manifest.get("provenance", {})
        baseline_info = provenance.get("baseline", {})
        opt_info = provenance.get("optimization", {})

        expected_baseline_hash = baseline_info.get("ir_sha256", "")
        expected_final_hash = opt_info.get("final_ir_sha256", "")
        pass_pipeline = opt_info.get("pass_pipeline", [])

        # 1. Verify baseline IR hash
        actual_baseline_hash = hashlib.sha256(baseline_ir.encode("utf-8")).hexdigest()
        baseline_match = (actual_baseline_hash == expected_baseline_hash)
        if not baseline_match and expected_baseline_hash:
            return ReplayResult(
                reproduced=False,
                baseline_hash_match=False,
                final_hash_match=False,
                computed_final_hash="",
                expected_final_hash=expected_final_hash,
                pass_count=len(pass_pipeline),
                message=f"Baseline IR hash mismatch! Expected {expected_baseline_hash[:12]}, got {actual_baseline_hash[:12]}"
            )

        # 2. Execute exact pass sequence deterministically
        current_ir = baseline_ir
        if pass_pipeline:
            success, output_ir, metrics = self.pass_executor.run_pipeline(current_ir, pass_pipeline)
            if not success:
                return ReplayResult(
                    reproduced=False,
                    baseline_hash_match=baseline_match,
                    final_hash_match=False,
                    computed_final_hash="",
                    expected_final_hash=expected_final_hash,
                    pass_count=len(pass_pipeline),
                    message=f"Replay pass pipeline execution failed: {metrics.get('error', 'unknown error')}"
                )
            current_ir = output_ir

        # 3. Check final IR hash
        computed_final_hash = hashlib.sha256(current_ir.encode("utf-8")).hexdigest()
        final_match = (computed_final_hash == expected_final_hash)

        if not final_match:
            return ReplayResult(
                reproduced=False,
                baseline_hash_match=baseline_match,
                final_hash_match=False,
                computed_final_hash=computed_final_hash,
                expected_final_hash=expected_final_hash,
                pass_count=len(pass_pipeline),
                message=f"Deterministic replay mismatch! Expected final IR {expected_final_hash[:12]}, got {computed_final_hash[:12]}"
            )

        return ReplayResult(
            reproduced=True,
            baseline_hash_match=baseline_match,
            final_hash_match=True,
            computed_final_hash=computed_final_hash,
            expected_final_hash=expected_final_hash,
            pass_count=len(pass_pipeline),
            message="Replay verified: 100% deterministic bit-for-bit IR reproduction confirmed."
        )
