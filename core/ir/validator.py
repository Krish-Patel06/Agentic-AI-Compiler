"""
Deterministic IR Security Gate.
Inspects LLVM IR for resource amplification, malformed CFGs,
prohibited inline assembly, and forbidden intrinsics before any AI agent sees it.
Generates canonical normalized IR fingerprints.
"""

from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional


@dataclass
class IRValidationLimits:
    max_instructions: int = 25000
    max_functions: int = 200
    max_basic_blocks: int = 500
    max_ir_bytes: int = 5 * 1024 * 1024  # 5 MB


@dataclass
class IRValidationResult:
    is_valid: bool
    fingerprint: str
    instruction_count: int
    function_count: int
    basic_block_count: int
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class IRValidator:
    """Authoritative non-AI IR Security Gate."""

    FORBIDDEN_INTRINSICS = {
        "llvm.trap", "llvm.debugtrap", "llvm.frameaddress", "llvm.returnaddress"
    }

    TERMINATOR_OPCODES = {"ret", "br", "switch", "indirectbr", "invoke", "resume", "catchswitch", "catchret", "cleanupret", "unreachable"}

    def __init__(self, limits: Optional[IRValidationLimits] = None):
        self.limits = limits or IRValidationLimits()

    def validate(self, ir_text: str) -> IRValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        if not ir_text or not ir_text.strip():
            return IRValidationResult(
                is_valid=False,
                fingerprint="",
                instruction_count=0,
                function_count=0,
                basic_block_count=0,
                errors=["IR content is empty"]
            )

        ir_bytes = len(ir_text.encode("utf-8"))
        if ir_bytes > self.limits.max_ir_bytes:
            errors.append(f"IR size {ir_bytes} bytes exceeds quota of {self.limits.max_ir_bytes} bytes")

        # 1. Prohibited inline assembly check
        if re.search(r'\bmodule\s+asm\b', ir_text) or re.search(r'\bcall\s+.*\basm\b', ir_text):
            errors.append("Prohibited inline assembly detected in LLVM IR")

        # 2. Forbidden intrinsics check
        for intrinsic in self.FORBIDDEN_INTRINSICS:
            if intrinsic in ir_text:
                errors.append(f"Forbidden intrinsic '{intrinsic}' detected in LLVM IR")

        # 3. Instruction and structure counting
        lines = ir_text.splitlines()
        instr_count = 0
        func_count = 0
        bb_count = 0
        in_function = False
        current_bb_has_terminator = True

        for line in lines:
            s = line.strip()
            if not s or s.startswith(";"):
                continue

            if s.startswith("define "):
                func_count += 1
                in_function = True
                block_instr_count = 0
                current_bb_has_terminator = True
                continue

            if in_function:
                if s == "}":
                    if not current_bb_has_terminator:
                        errors.append(f"Function closing brace without valid basic block terminator")
                    in_function = False
                    continue

                if s.endswith(":"):
                    # New basic block label
                    if not current_bb_has_terminator and block_instr_count > 0:
                        errors.append(f"Basic block before label '{s}' lacks a valid terminator instruction")
                    bb_count += 1
                    block_instr_count = 0
                    current_bb_has_terminator = False
                    continue

                # Count valid instructions
                instr_count += 1
                block_instr_count += 1
                tokens = s.split()
                opcode = tokens[0]
                if len(tokens) >= 3 and tokens[1] == "=":
                    opcode = tokens[2]
                opcode = opcode.lower().rstrip(":")

                if opcode in self.TERMINATOR_OPCODES:
                    current_bb_has_terminator = True

        if func_count > self.limits.max_functions:
            errors.append(f"Function count {func_count} exceeds limit of {self.limits.max_functions}")
        if instr_count > self.limits.max_instructions:
            errors.append(f"Instruction count {instr_count} exceeds limit of {self.limits.max_instructions}")
        if bb_count > self.limits.max_basic_blocks:
            errors.append(f"Basic block count {bb_count} exceeds limit of {self.limits.max_basic_blocks}")

        # Canonical Normalized IR fingerprint
        normalized_ir = "\n".join(l.strip() for l in lines if l.strip() and not l.strip().startswith(";"))
        fingerprint = hashlib.sha256(normalized_ir.encode("utf-8")).hexdigest()

        return IRValidationResult(
            is_valid=(len(errors) == 0),
            fingerprint=fingerprint,
            instruction_count=instr_count,
            function_count=func_count,
            basic_block_count=bb_count,
            errors=errors,
            warnings=warnings
        )
