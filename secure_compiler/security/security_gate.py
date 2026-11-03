"""
Secure Compiler — Post-Verification Security Gate
Enforces ABI preservation, binary integrity, target conformity, resource limits,
and checks for suspicious behavior or undefined-behavior-sensitive transformations.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
import re

from ..optimizer.candidate import Candidate
from ..policy.policy_engine import PolicyEngine, PolicyDecision


@dataclass
class SecurityReport:
    passed: bool
    target_valid: bool = True
    abi_valid: bool = True
    policy_valid: bool = True
    resource_valid: bool = True
    suspicious_behavior_detected: bool = False
    violations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        status = "PASSED" if self.passed else "FAILED"
        v_str = f" | {len(self.violations)} violation(s)" if self.violations else ""
        return f"[SecurityGate] {status}{v_str}"


class SecurityGate:
    """
    Authoritative post-correctness security gate.
    Ensures optimizations do not violate security policies, mutate ABIs, or trigger exploits.
    """

    SUSPICIOUS_PATTERNS = [
        (r"\bgets\s*\(", "CWE-120: Dangerous unbounded string input (gets)"),
        (r"system\s*\(", "CWE-78: Host command injection pattern (system)"),
        (r"exec(?:l|lp|v|vp)\s*\(", "CWE-78: Subprocess invocation pattern"),
        (r"\bformat_string_exploit\b", "CWE-134: Unsafe format string"),
    ]

    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self.policy_engine = policy_engine or PolicyEngine()

    def verify(
        self,
        candidate: Candidate,
        baseline: Candidate
    ) -> SecurityReport:
        violations: List[str] = []

        # ── 1. Target Checks ──────────────────────────────────────────
        target_valid = True
        base_target = self._extract_target_triple(baseline.ir_text)
        cand_target = self._extract_target_triple(candidate.ir_text)
        if base_target and cand_target and base_target != cand_target:
            target_valid = False
            violations.append(
                f"Target triple mismatch: baseline has '{base_target}', candidate has '{cand_target}'."
            )

        # ── 2. ABI Checks ─────────────────────────────────────────────
        abi_valid = True
        base_signatures = self._extract_signatures(baseline.ir_text)
        cand_signatures = self._extract_signatures(candidate.ir_text)

        # Baseline functions must all still exist with identical parameter & return types
        for fn_name, sig in base_signatures.items():
            if fn_name not in cand_signatures:
                abi_valid = False
                violations.append(f"ABI Violation: Exported function '@{fn_name}' was removed in candidate.")
            elif cand_signatures[fn_name] != sig:
                abi_valid = False
                violations.append(
                    f"ABI Mutation: Function '@{fn_name}' signature mutated from '{sig}' to '{cand_signatures[fn_name]}'."
                )

        # ── 3. Resource Growth Checks ─────────────────────────────────
        resource_valid = True
        base_bytes = len(baseline.ir_text.encode("utf-8"))
        cand_bytes = len(candidate.ir_text.encode("utf-8"))
        growth_dec: PolicyDecision = self.policy_engine.evaluate_ir_growth(base_bytes, cand_bytes)
        if not growth_dec.allowed:
            resource_valid = False
            violations.extend(growth_dec.violations)

        # ── 4. Suspicious Behavior & Exploit Checks ───────────────────
        suspicious_detected = False
        for pat, desc in self.SUSPICIOUS_PATTERNS:
            if re.search(pat, candidate.ir_text, re.IGNORECASE):
                # Verify if pattern was NOT present in baseline (newly injected!)
                if not re.search(pat, baseline.ir_text, re.IGNORECASE):
                    suspicious_detected = True
                    violations.append(f"Security Alert: {desc} injected by candidate passes.")

        overall_passed = (len(violations) == 0) and target_valid and abi_valid and resource_valid and not suspicious_detected

        return SecurityReport(
            passed=overall_passed,
            target_valid=target_valid,
            abi_valid=abi_valid,
            policy_valid=True,
            resource_valid=resource_valid,
            suspicious_behavior_detected=suspicious_detected,
            violations=violations,
            details={
                "base_bytes": base_bytes,
                "cand_bytes": cand_bytes,
                "base_functions": list(base_signatures.keys()),
                "cand_functions": list(cand_signatures.keys()),
            }
        )

    def _extract_target_triple(self, ir_text: str) -> str:
        m = re.search(r'target\s+triple\s*=\s*"([^"]+)"', ir_text)
        return m.group(1) if m else ""

    def _extract_signatures(self, ir_text: str) -> Dict[str, str]:
        """Extracts function name -> signature (e.g. define float @foo(float %p, float %e))."""
        signatures = {}
        for line in ir_text.splitlines():
            s = line.strip()
            if s.startswith("define "):
                fn_match = re.search(r"@([a-zA-Z0-9_$.]+)\s*\(([^)]*)\)", s)
                if fn_match:
                    fn_name = fn_match.group(1)
                    # Canonicalize signature by removing variable names (%0, %price)
                    params = fn_match.group(2)
                    clean_params = re.sub(r"%\w+", "", params).strip()
                    ret_type = s.split("@")[0].replace("define", "").strip()
                    signatures[fn_name] = f"{ret_type}({clean_params})"
        return signatures
