"""
Secure Compiler — Differential Testing Engine
Executes test cases against baseline and candidate transformations to verify
semantic equivalence and bitwise or tolerance accuracy.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional
import math


@dataclass
class TestCase:
    name: str
    inputs: Dict[str, Any]
    expected: Optional[Any] = None
    category: str = "standard"  # standard, boundary, adversarial_overflow, adversarial_nan_inf, adversarial_aliasing, adversarial_ub, adversarial_control_flow
    tags: List[str] = field(default_factory=list)


@dataclass
class DifferentialReport:
    passed: bool
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    adversarial_tests_total: int = 0
    adversarial_tests_passed: int = 0
    failures: List[str] = field(default_factory=list)
    results: List[Dict[str, Any]] = field(default_factory=list)

    def summary(self) -> str:
        status = "PASSED" if self.passed else "FAILED"
        adv_msg = f" (Adversarial: {self.adversarial_tests_passed}/{self.adversarial_tests_total})" if self.adversarial_tests_total > 0 else ""
        return f"[DifferentialGate] {status}: {self.passed_tests}/{self.total_tests} tests passed{adv_msg}."


class DifferentialVerifier:
    """
    Verifies semantic equivalence between a baseline IR/function and an optimized candidate.
    """

    @staticmethod
    def are_equal(val_a: Any, val_b: Any, tolerance: float = 1e-5) -> bool:
        """Compares values handling floats, numbers, and strings."""
        if val_a is None and val_b is None:
            return True
        if val_a is None or val_b is None:
            return False

        if isinstance(val_a, float) or isinstance(val_b, float):
            try:
                fa = float(val_a)
                fb = float(val_b)
                if math.isnan(fa) and math.isnan(fb):
                    return True
                return math.isclose(fa, fb, rel_tol=tolerance, abs_tol=tolerance)
            except (ValueError, TypeError):
                return False

        if isinstance(val_a, (int, bool)) and isinstance(val_b, (int, bool)):
            return val_a == val_b

        return str(val_a).strip() == str(val_b).strip()

    @classmethod
    def verify_equivalence(
        cls,
        baseline_fn: Callable[..., Any],
        candidate_fn: Callable[..., Any],
        test_cases: List[TestCase]
    ) -> DifferentialReport:
        """
        Runs differential tests between two function implementations.
        """
        report = DifferentialReport(passed=True, total_tests=len(test_cases))
        is_adv_count = sum(1 for tc in test_cases if getattr(tc, "category", "").startswith("adversarial"))
        report.adversarial_tests_total = is_adv_count

        for tc in test_cases:
            is_adv = getattr(tc, "category", "").startswith("adversarial")
            try:
                res_base = baseline_fn(**tc.inputs)
            except Exception as e:
                report.failures.append(f"Test '{tc.name}': Baseline crashed: {e}")
                report.failed_tests += 1
                report.passed = False
                continue

            try:
                res_cand = candidate_fn(**tc.inputs)
            except Exception as e:
                report.failures.append(f"Test '{tc.name}': Candidate crashed: {e}")
                report.failed_tests += 1
                report.passed = False
                continue

            matches = cls.are_equal(res_base, res_cand)
            report.results.append({
                "test": tc.name,
                "category": getattr(tc, "category", "standard"),
                "inputs": tc.inputs,
                "baseline_output": res_base,
                "candidate_output": res_cand,
                "matches": matches,
            })

            if matches:
                report.passed_tests += 1
                if is_adv:
                    report.adversarial_tests_passed += 1
            else:
                report.failed_tests += 1
                report.passed = False
                report.failures.append(
                    f"Test '{tc.name}': Output mismatch! Baseline={res_base}, Candidate={res_cand}"
                )

        return report
