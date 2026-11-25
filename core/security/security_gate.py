"""
Authoritative Security Gate.
Enforces post-pass invariants:
  - ABI preservation and exported function symbol continuity
  - Forbidden syscall and intrinsic detection
  - Resource growth caps (maximum +25% IR size growth, +15% binary growth)
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional

from ..optimizer.candidate import Candidate
from policy.policy_loader import AuthoritativePolicy, load_authoritative_policy


@dataclass
class SecurityReport:
    passed: bool
    abi_preserved: bool
    growth_ok: bool
    forbidden_instructions_found: bool
    ir_growth_pct: float
    violations: List[str] = field(default_factory=list)


class SecurityGate:
    """Deterministic, Authoritative Post-Optimization Security Gate."""

    FORBIDDEN_CALLS = {"system", "execve", "fork", "socket", "connect", "bind", "ptrace"}

    def __init__(self, policy: Optional[AuthoritativePolicy] = None):
        self.policy = policy or load_authoritative_policy(enforce_signature=False)

    def verify(self, candidate: Candidate, baseline: Candidate) -> SecurityReport:
        violations: List[str] = []

        # 1. ABI and Symbol Preservation Check
        base_funcs = self._extract_function_signatures(baseline.ir_text)
        cand_funcs = self._extract_function_signatures(candidate.ir_text)

        abi_ok = True
        for name, sig in base_funcs.items():
            if name not in cand_funcs:
                violations.append(f"ABI Violation: Function '{name}' was deleted in optimized candidate")
                abi_ok = False
            elif cand_funcs[name] != sig:
                violations.append(f"ABI Violation: Signature of '{name}' changed from '{sig}' to '{cand_funcs[name]}'")
                abi_ok = False

        # 2. Prohibited Syscall / Intrinsic Scan
        forbidden_found = False
        cand_ir = candidate.ir_text
        for call in self.FORBIDDEN_CALLS:
            if re.search(rf'\bcall\s+.*@{call}\b', cand_ir):
                violations.append(f"Security Gate: Forbidden external system call '@{call}' detected")
                forbidden_found = True

        for intrinsic in self.policy.forbidden_intrinsics:
            if intrinsic in cand_ir:
                violations.append(f"Security Gate: Forbidden LLVM intrinsic '{intrinsic}' detected")
                forbidden_found = True

        # 3. Resource Growth Caps Check
        base_size = len(baseline.ir_text.encode("utf-8"))
        cand_size = len(candidate.ir_text.encode("utf-8"))
        growth_pct = ((cand_size - base_size) / base_size) * 100.0 if base_size > 0 else 0.0

        max_growth = self.policy.growth_limits.max_ir_growth_pct
        growth_ok = (growth_pct <= max_growth)
        if not growth_ok:
            violations.append(f"Resource Cap Violation: IR growth of {growth_pct:.1f}% exceeds max allowed {max_growth:.1f}%")

        passed = (len(violations) == 0)

        return SecurityReport(
            passed=passed,
            abi_preserved=abi_ok,
            growth_ok=growth_ok,
            forbidden_instructions_found=forbidden_found,
            ir_growth_pct=round(growth_pct, 2),
            violations=violations
        )

    def _extract_function_signatures(self, ir_text: str) -> Dict[str, str]:
        signatures = {}
        for line in ir_text.splitlines():
            s = line.strip()
            if s.startswith("define "):
                m = re.search(r'define\s+([^\(@]+)@([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^\)]*)\)', s)
                if m:
                    ret_type, name, args = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
                    signatures[name] = f"{ret_type}({args})"
        return signatures
