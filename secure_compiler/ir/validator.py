"""
Secure Compiler — IR Security Gate & Validator
Deterministic validation layer executed before any AI agent sees or modifies IR.
Enforces structural, syntactic, CFG, and security limits.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import re

from .fingerprint import IRFingerprinter


@dataclass
class IRValidationLimits:
    """Configurable boundaries for LLVM IR modules to prevent DoS and memory exhaustion."""
    max_bytes: int = 5 * 1024 * 1024       # 5 MB
    max_lines: int = 50_000
    max_functions: int = 500
    max_blocks_per_function: int = 2000
    max_instructions_per_block: int = 5000
    allow_inline_asm: bool = False
    forbidden_asm_tokens: tuple = (
        "syscall", "int 0x80", "int $0x80", "sysenter", "inb", "outb",
        "cli", "sti", "cpuid", "rdmsr", "wrmsr", "invd", "wbinvd"
    )


@dataclass
class IRValidationResult:
    """Outcome of IR Security Gate verification."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metrics: Dict[str, int] = field(default_factory=dict)
    fingerprint: str = ""

    def summary(self) -> str:
        status = "VALID" if self.is_valid else "INVALID"
        err_str = f" | {len(self.errors)} error(s)" if self.errors else ""
        return f"[IRSecurityGate] {status}{err_str} (fingerprint={self.fingerprint[:10]}...)"


class IRValidator:
    """
    Deterministic IR Security Gate.
    Verifies module, function, CFG consistency and enforces security constraints.
    """

    TERMINATORS = {
        "ret", "br", "switch", "indirectbr", "invoke", "resume",
        "catchswitch", "catchret", "cleanupret", "unreachable"
    }

    def __init__(self, limits: Optional[IRValidationLimits] = None):
        self.limits = limits or IRValidationLimits()

    def validate(self, ir_text: str) -> IRValidationResult:
        errors = []
        warnings = []
        metrics = {
            "byte_count": len(ir_text.encode("utf-8")),
            "line_count": len(ir_text.splitlines()),
            "function_count": 0,
            "instruction_count": 0,
            "block_count": 0,
        }

        # 1. Size Limits
        if metrics["byte_count"] > self.limits.max_bytes:
            errors.append(
                f"IR size ({metrics['byte_count']} bytes) exceeds limit ({self.limits.max_bytes} bytes)."
            )
        if metrics["line_count"] > self.limits.max_lines:
            errors.append(
                f"IR line count ({metrics['line_count']}) exceeds limit ({self.limits.max_lines})."
            )

        if errors:
            fp = IRFingerprinter.compute_hash(ir_text) if ir_text else ""
            return IRValidationResult(is_valid=False, errors=errors, warnings=warnings, metrics=metrics, fingerprint=fp)

        # 2. Dangerous Construct Detection (Inline ASM, Syscalls)
        for token in self.limits.forbidden_asm_tokens:
            if re.search(r"\b" + re.escape(token) + r"\b", ir_text, re.IGNORECASE):
                errors.append(f"Forbidden inline assembly or instruction detected: '{token}'")

        if not self.limits.allow_inline_asm and "asm sideeffect" in ir_text:
            errors.append("Inline assembly ('asm sideeffect') is disallowed by current security policy.")

        # 3. Structural Parse & CFG Consistency Check
        brace_depth = 0
        in_function = False
        current_func_name = ""
        current_block_name = "entry"
        func_blocks: Dict[str, List[str]] = {}
        func_block_terminators: Dict[str, bool] = {}
        func_block_instructions: Dict[str, int] = {}
        branch_targets: Set[str] = set()
        block_labels: Set[str] = set()

        for line_num, line in enumerate(ir_text.splitlines(), start=1):
            clean_line = re.sub(r";.*$", "", line).strip()
            if not clean_line:
                continue

            # Track Braces
            brace_depth += clean_line.count("{") - clean_line.count("}")
            if brace_depth < 0:
                errors.append(f"Line {line_num}: Unexpected closing brace without matching open brace.")
                break

            # Function Declaration / Definition
            if clean_line.startswith("define "):
                if in_function:
                    errors.append(f"Line {line_num}: Nested function definition not allowed in LLVM IR.")
                in_function = True
                metrics["function_count"] += 1
                fn_match = re.search(r"@([a-zA-Z0-9_$.]+)\s*\(", clean_line)
                current_func_name = fn_match.group(1) if fn_match else f"func_{metrics['function_count']}"
                current_block_name = "entry"
                func_blocks[current_func_name] = [current_block_name]
                func_block_terminators[f"{current_func_name}:{current_block_name}"] = False
                func_block_instructions[f"{current_func_name}:{current_block_name}"] = 0
                block_labels.add(current_block_name)
                continue

            if clean_line == "}":
                if in_function:
                    # Check terminator of last block in function
                    last_block_key = f"{current_func_name}:{current_block_name}"
                    if not func_block_terminators.get(last_block_key, False):
                        errors.append(
                            f"Function '@{current_func_name}' block '{current_block_name}' lacks a terminator instruction."
                        )
                in_function = False
                current_func_name = ""
                continue

            if in_function:
                # Basic block label check (e.g. 'label_1:' or '1:')
                label_match = re.match(r"^([a-zA-Z0-9_$.]+):\s*$", clean_line)
                if label_match:
                    new_label = label_match.group(1)
                    prev_block_key = f"{current_func_name}:{current_block_name}"
                    prev_instr_count = func_block_instructions.get(prev_block_key, 0)

                    # Only require terminator if previous block actually contained instructions
                    if prev_instr_count > 0 and not func_block_terminators.get(prev_block_key, False):
                        errors.append(
                            f"Line {line_num}: Basic block '{current_block_name}' in '@{current_func_name}' "
                            f"is not properly terminated before new label '{new_label}:'."
                        )

                    current_block_name = new_label
                    metrics["block_count"] += 1
                    if current_block_name not in func_blocks[current_func_name]:
                        func_blocks[current_func_name].append(current_block_name)
                    func_block_terminators[f"{current_func_name}:{current_block_name}"] = False
                    func_block_instructions[f"{current_func_name}:{current_block_name}"] = 0
                    block_labels.add(current_block_name)
                    continue

                # Count instructions
                metrics["instruction_count"] += 1
                block_key = f"{current_func_name}:{current_block_name}"
                func_block_instructions[block_key] = func_block_instructions.get(block_key, 0) + 1

                # Check terminator instruction
                opcode = clean_line.split()[0].rstrip(":")
                if opcode in self.TERMINATORS or any(clean_line.startswith(t + " ") or clean_line == t for t in self.TERMINATORS):
                    func_block_terminators[block_key] = True

                # Capture branch targets (e.g. 'br label %exit', 'br i1 %c, label %t, label %f')
                for target in re.findall(r"label\s+%([a-zA-Z0-9_$.]+)", clean_line):
                    branch_targets.add(target)

        # Module-level sanity checks
        if brace_depth != 0:
            errors.append(f"Unbalanced braces in LLVM IR module (depth={brace_depth}).")

        if metrics["function_count"] > self.limits.max_functions:
            errors.append(
                f"Function count ({metrics['function_count']}) exceeds limit ({self.limits.max_functions})."
            )

        # Check block and instruction limits per function
        for fn_name, blocks in func_blocks.items():
            if len(blocks) > self.limits.max_blocks_per_function:
                errors.append(
                    f"Function '@{fn_name}' has {len(blocks)} blocks, exceeding limit of {self.limits.max_blocks_per_function}."
                )
            for b in blocks:
                key = f"{fn_name}:{b}"
                instrs = func_block_instructions.get(key, 0)
                if instrs > self.limits.max_instructions_per_block:
                    errors.append(
                        f"Block '{b}' in '@{fn_name}' has {instrs} instructions, exceeding limit of {self.limits.max_instructions_per_block}."
                    )

        # Check missing branch targets
        missing_targets = branch_targets - block_labels
        # Filter out entry block which may not have explicit label header
        missing_targets.discard("entry")
        if missing_targets:
            for mt in list(missing_targets)[:5]:
                warnings.append(f"Branch references undeclared label '%{mt}'.")

        fingerprint = IRFingerprinter.compute_hash(ir_text)
        is_valid = len(errors) == 0
        return IRValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            metrics=metrics,
            fingerprint=fingerprint,
        )
