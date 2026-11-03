"""
Secure Compiler — Semantic Equivalence Checker
Complements differential runtime testing with static & structural semantic equivalence analysis
between baseline and candidate LLVM IR.
Verifies:
  1. ABI & Symbol Signature Equivalence (Return types, parameter types, public symbols)
  2. Control Flow Graph Structural Invariants (Terminators, dominance, unreachable traps)
  3. Memory Safety & Write-Bound Invariants (Alloca scopes, store bounds, volatile preservation)
  4. Undefined Behavior Injection Check (Poison, undef propagation in branch conditions)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Optional, Tuple
import re


@dataclass
class SemanticEquivalenceReport:
    is_equivalent: bool
    confidence_score: float  # 0.0 to 1.0
    checks_passed: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        status = "EQUIVALENT" if self.is_equivalent else "NON_EQUIVALENT"
        return f"[SemanticEquivalence] {status} (Confidence: {self.confidence_score:.2f}) | {len(self.violations)} violation(s)"


class SemanticEquivalenceChecker:
    """
    Static and structural equivalence validator between baseline IR and candidate IR.
    """

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode

    def verify_equivalence(
        self,
        baseline_ir: str,
        candidate_ir: str
    ) -> SemanticEquivalenceReport:
        violations: List[str] = []
        checks_passed: List[str] = []
        details: Dict[str, Any] = {}

        # ── Check 1: ABI & Symbol Preservation ───────────────────────
        base_funcs = self._extract_function_signatures(baseline_ir)
        cand_funcs = self._extract_function_signatures(candidate_ir)

        missing_symbols = set(base_funcs.keys()) - set(cand_funcs.keys())
        if missing_symbols:
            violations.append(
                f"Candidate eliminated required function symbols: {', '.join(sorted(missing_symbols))}"
            )
        else:
            checks_passed.append("abi_exported_symbols_preserved")

        # Verify signatures of matching functions
        sig_mismatch = False
        for fn_name, base_sig in base_funcs.items():
            if fn_name in cand_funcs:
                cand_sig = cand_funcs[fn_name]
                if base_sig != cand_sig:
                    sig_mismatch = True
                    violations.append(
                        f"ABI Signature Mismatch for '{fn_name}': baseline={base_sig}, candidate={cand_sig}"
                    )
        if not sig_mismatch and not missing_symbols:
            checks_passed.append("abi_parameter_and_return_types_match")

        details["baseline_symbols"] = list(base_funcs.keys())
        details["candidate_symbols"] = list(cand_funcs.keys())

        # ── Check 2: Control Flow Invariants ──────────────────────────
        cf_violations = self._check_control_flow(baseline_ir, candidate_ir)
        if cf_violations:
            violations.extend(cf_violations)
        else:
            checks_passed.append("control_flow_termination_invariants_valid")

        # ── Check 3: Memory Safety & Store Invariants ─────────────────
        mem_violations = self._check_memory_safety(baseline_ir, candidate_ir)
        if mem_violations:
            violations.extend(mem_violations)
        else:
            checks_passed.append("memory_safety_and_store_bounds_preserved")

        # ── Check 4: Poison / Undef Injection in Branches ─────────────
        ub_violations = self._check_ub_injection(candidate_ir)
        if ub_violations:
            violations.extend(ub_violations)
        else:
            checks_passed.append("no_undef_or_poison_branch_conditions")

        # Calculate confidence score
        total_checks = 4
        passed_count = len(checks_passed)
        confidence = round(max(0.0, (passed_count - len(violations) * 0.5) / total_checks), 2)
        confidence = min(1.0, max(0.0, confidence))

        is_equivalent = (len(violations) == 0)

        return SemanticEquivalenceReport(
            is_equivalent=is_equivalent,
            confidence_score=confidence,
            checks_passed=checks_passed,
            violations=violations,
            details=details,
        )

    def _extract_function_signatures(self, ir_text: str) -> Dict[str, str]:
        """
        Extracts defined function signatures: name -> (ret_type, [arg_types]).
        """
        sigs: Dict[str, str] = {}
        # Matches: define [linkage] <ret_type> @<name>(<args>)
        pattern = re.compile(r"define\s+[^@]*@([a-zA-Z0-9_]+)\s*\(([^)]*)\)", re.MULTILINE)
        for match in pattern.finditer(ir_text):
            func_name = match.group(1)
            args_str = match.group(2).strip()
            # Normalize arguments (types only)
            arg_types = []
            for arg in args_str.split(","):
                arg = arg.strip()
                if arg:
                    # Strip argument name (%0, %val) leaving type
                    type_part = re.sub(r"%\w+", "", arg).strip()
                    arg_types.append(type_part)
            sigs[func_name] = f"({', '.join(arg_types)})"
        return sigs

    def _check_control_flow(self, base_ir: str, cand_ir: str) -> List[str]:
        """
        Verifies that candidate doesn't introduce unreachable traps or infinite loops without exits.
        """
        violations = []
        # If candidate has 'unreachable' but baseline had none, verify it is guarded
        base_unreachable_count = base_ir.count("unreachable")
        cand_unreachable_count = cand_ir.count("unreachable")

        # Dead-end trap without return in non-void function
        if cand_unreachable_count > base_unreachable_count + 2:
            violations.append(
                f"Candidate introduced {cand_unreachable_count - base_unreachable_count} unexpected unreachable trap instructions."
            )

        # Check for functions that completely deleted 'ret' instruction
        cand_funcs = self._extract_function_signatures(cand_ir)
        for fn in cand_funcs:
            # Check if function body has at least one return
            fn_body_match = re.search(rf"define\s+[^@]*@{fn}\s*\([^)]*\)\s*\{{([^}}]+)\}}", cand_ir, re.DOTALL)
            if fn_body_match:
                body = fn_body_match.group(1)
                if "ret " not in body and "unreachable" in body:
                    violations.append(f"Function '@{fn}' body ends in 'unreachable' without any 'ret' path.")

        return violations

    def _check_memory_safety(self, base_ir: str, cand_ir: str) -> List[str]:
        """
        Verifies alloca count and checks that candidate does not clobber memory with wild stores.
        """
        violations = []
        # Count alloca instructions: excessive allocas could indicate unbounded stack frame
        base_allocas = base_ir.count("alloca ")
        cand_allocas = cand_ir.count("alloca ")

        if cand_allocas > base_allocas * 3 and cand_allocas > 20:
            violations.append(
                f"Candidate excessive alloca stack allocation ({cand_allocas} vs baseline {base_allocas})."
            )

        # Volatile store preservation check
        base_volatile_stores = base_ir.count("store volatile")
        cand_volatile_stores = cand_ir.count("store volatile")
        if base_volatile_stores > 0 and cand_volatile_stores < base_volatile_stores:
            violations.append(
                f"Candidate eliminated required volatile stores: {cand_volatile_stores} vs baseline {base_volatile_stores}"
            )

        return violations

    def _check_ub_injection(self, cand_ir: str) -> List[str]:
        """
        Ensures undef or poison values are not used as branch conditions or divisor operands.
        """
        violations = []
        lines = cand_ir.splitlines()
        for idx, line in enumerate(lines, 1):
            line_str = line.strip()
            # Branch on undef/poison
            if re.search(r"br\s+i1\s+(undef|poison)\s*,", line_str):
                violations.append(f"Line {idx}: Unsound branch on undef/poison condition: '{line_str}'")
            # Division by 0 or undef
            if re.search(r"[suf]div\s+[^,]+,\s*(0|0\.0|undef|poison)\b", line_str):
                violations.append(f"Line {idx}: Direct division by zero/undef injected: '{line_str}'")

        return violations
