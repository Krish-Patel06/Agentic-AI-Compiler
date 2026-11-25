"""
Authoritative Correctness Gate.
Executes differential testing across standard and adversarial test cases.
Traps numerical regressions, calculation deviations, and missing functions.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from .differential import DifferentialVerifier, TestCase, DifferentialReport
from ..optimizer.candidate import Candidate


@dataclass
class CorrectnessReport:
    passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    adversarial_tests_passed: int
    adversarial_tests_total: int
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


class CorrectnessGate:
    """Authoritative non-AI Correctness Gate."""

    def __init__(self, verifier: Optional[DifferentialVerifier] = None):
        self.verifier = verifier or DifferentialVerifier()

    def verify(
        self,
        candidate: Candidate,
        baseline: Candidate,
        test_cases: List[TestCase],
        target_function: str = "on_market_data"
    ) -> CorrectnessReport:
        passed_count = 0
        failed_count = 0
        adv_total = 0
        adv_passed = 0
        errors: List[str] = []

        for tc in test_cases:
            is_adv = tc.category.startswith("adversarial_")
            if is_adv:
                adv_total += 1

            # Evaluate baseline and candidate outputs
            base_out = self.verifier.evaluate_function(baseline.ir_text, target_function, tc.inputs)
            cand_out = self.verifier.evaluate_function(candidate.ir_text, target_function, tc.inputs)

            matches = self.verifier.are_equal(base_out, cand_out, tc.tolerance)
            if matches:
                passed_count += 1
                if is_adv:
                    adv_passed += 1
            else:
                failed_count += 1
                msg = f"Test '{tc.name}' failed: baseline output={base_out}, candidate output={cand_out}"
                errors.append(msg)

        passed = (failed_count == 0)

        return CorrectnessReport(
            passed=passed,
            total_tests=len(test_cases),
            passed_tests=passed_count,
            failed_tests=failed_count,
            adversarial_tests_passed=adv_passed,
            adversarial_tests_total=adv_total,
            errors=errors,
            details={
                "target_function": target_function,
                "candidate_id": candidate.candidate_id
            }
        )
