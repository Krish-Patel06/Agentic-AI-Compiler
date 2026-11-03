"""
Secure Compiler — Deterministic Program Profiler
Extracts structural, CFG, memory, loop, and call-graph characteristics
directly from LLVM IR without relying on LLM inference.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Any
import re


@dataclass
class FunctionProfile:
    """Detailed deterministic analysis of an individual function."""
    name: str
    is_hot: bool = False
    hotness_reason: str = ""
    instruction_count: int = 0
    basic_block_count: int = 0
    loop_count: int = 0
    branch_count: int = 0
    branch_density: float = 0.0          # branches / instructions
    memory_ops_count: int = 0            # load, store, alloca, getelementptr
    memory_op_density: float = 0.0       # memory_ops / instructions
    fp_ops_count: int = 0                # floating point operations
    vector_ops_count: int = 0            # SIMD / vector instructions
    vectorization_potential: bool = False
    estimated_reg_pressure: int = 0      # peak live variables estimate
    callees: List[str] = field(default_factory=list)


@dataclass
class ProgramProfile:
    """Module-level deterministic profile."""
    total_functions: int = 0
    total_instructions: int = 0
    total_blocks: int = 0
    total_loops: int = 0
    overall_branch_density: float = 0.0
    hot_functions: List[str] = field(default_factory=list)
    cold_functions: List[str] = field(default_factory=list)
    call_graph: Dict[str, List[str]] = field(default_factory=dict)
    target_characteristics: Dict[str, Any] = field(default_factory=dict)
    function_profiles: Dict[str, FunctionProfile] = field(default_factory=dict)

    def summary(self) -> str:
        return (
            f"[ProgramProfiler] Functions={self.total_functions} "
            f"(HOT={len(self.hot_functions)}, COLD={len(self.cold_functions)}) | "
            f"Instructions={self.total_instructions} | Loops={self.total_loops} | "
            f"BranchDensity={self.overall_branch_density:.2%}"
        )


class ProgramProfiler:
    """
    Deterministic static analyzer for LLVM IR modules.
    Extracts metrics required by policy and optimization agents.
    """

    MEMORY_OPCODES = {"alloca", "load", "store", "getelementptr", "atomicrmw", "cmpxchg"}
    BRANCH_OPCODES = {"br", "switch", "indirectbr"}
    FP_OPCODES = {"fadd", "fsub", "fmul", "fdiv", "frem", "fcmp", "fneg"}
    HOT_NAME_PATTERNS = [
        r"market", r"tick", r"order", r"eval", r"calc", r"signal",
        r"risk", r"match", r"compute", r"execute", r"trade", r"fast"
    ]
    COLD_NAME_PATTERNS = [
        r"init", r"setup", r"config", r"log", r"dump", r"print",
        r"teardown", r"cleanup", r"destroy", r"stats", r"telemetry"
    ]

    @classmethod
    def profile(cls, ir_text: str, source_text: str = "") -> ProgramProfile:
        profile = ProgramProfile()
        func_lines: Dict[str, List[str]] = {}
        in_func = False
        current_func = ""

        # Extract target information if present
        target_triple_match = re.search(r'target\s+triple\s*=\s*"([^"]+)"', ir_text)
        datalayout_match = re.search(r'target\s+datalayout\s*=\s*"([^"]+)"', ir_text)
        profile.target_characteristics = {
            "target_triple": target_triple_match.group(1) if target_triple_match else "unknown",
            "datalayout": datalayout_match.group(1) if datalayout_match else "unknown",
            "has_64bit_pointers": "p:64:64" in (datalayout_match.group(1) if datalayout_match else ""),
        }

        # Check explicit attributes in source code if available
        explicit_hot: Set[str] = set()
        explicit_cold: Set[str] = set()
        if source_text:
            for m in re.finditer(r'\[\[hft::hot\]\][\s\w:*&]+?\b(\w+)\s*\(', source_text):
                explicit_hot.add(m.group(1))
            for m in re.finditer(r'\[\[hft::cold\]\][\s\w:*&]+?\b(\w+)\s*\(', source_text):
                explicit_cold.add(m.group(1))

        # Split IR into per-function bodies
        for line in ir_text.splitlines():
            s = line.strip()
            if s.startswith("define "):
                in_func = True
                fn_match = re.search(r"@([a-zA-Z0-9_$.]+)\s*\(", s)
                current_func = fn_match.group(1) if fn_match else f"func_{len(func_lines)+1}"
                func_lines[current_func] = [line]
            elif in_func:
                func_lines[current_func].append(line)
                if s == "}":
                    in_func = False

        profile.total_functions = len(func_lines)

        # Profile each function individually
        total_instr = 0
        total_branches = 0
        total_loops = 0

        for fn_name, lines in func_lines.items():
            fprof = cls._profile_function(fn_name, lines, explicit_hot, explicit_cold)
            profile.function_profiles[fn_name] = fprof
            profile.call_graph[fn_name] = fprof.callees

            total_instr += fprof.instruction_count
            total_branches += fprof.branch_count
            total_loops += fprof.loop_count

            if fprof.is_hot:
                profile.hot_functions.append(fn_name)
            else:
                profile.cold_functions.append(fn_name)

        profile.total_instructions = total_instr
        profile.total_loops = total_loops
        profile.overall_branch_density = (
            total_branches / total_instr if total_instr > 0 else 0.0
        )

        return profile

    @classmethod
    def _profile_function(
        cls,
        fn_name: str,
        lines: List[str],
        explicit_hot: Set[str],
        explicit_cold: Set[str]
    ) -> FunctionProfile:
        instr_count = 0
        block_count = 1  # entry block
        branch_count = 0
        memory_ops = 0
        fp_ops = 0
        vector_ops = 0
        callees: List[str] = []

        block_order: List[str] = ["entry"]
        current_block = "entry"
        branch_targets: List[str] = []
        ssa_vars_per_block: Dict[str, Set[str]] = {"entry": set()}

        for line in lines[1:]:  # skip 'define' line
            s = re.sub(r";.*$", "", line).strip()
            if not s or s == "}":
                continue

            # Check for block label
            label_match = re.match(r"^([a-zA-Z0-9_$.]+):\s*$", s)
            if label_match:
                block_count += 1
                current_block = label_match.group(1)
                block_order.append(current_block)
                ssa_vars_per_block[current_block] = set()
                continue

            instr_count += 1
            tokens = s.split()
            opcode = tokens[0] if tokens else ""

            # Assignment check (%var = opcode ...)
            if len(tokens) >= 3 and tokens[1] == "=":
                ssa_var = tokens[0]
                opcode = tokens[2]
                ssa_vars_per_block[current_block].add(ssa_var)

            # Opcode checks
            if opcode in cls.BRANCH_OPCODES:
                branch_count += 1
                for target in re.findall(r"label\s+%([a-zA-Z0-9_$.]+)", s):
                    branch_targets.append(target)

            if opcode in cls.MEMORY_OPCODES:
                memory_ops += 1

            if opcode in cls.FP_OPCODES:
                fp_ops += 1

            if re.search(r"<\s*\d+\s*x\s*(?:float|double|i32|i64|i16|i8)\s*>", s):
                vector_ops += 1

            # Callees
            if opcode in ("call", "invoke") or "call " in s or "invoke " in s:
                call_match = re.search(r"@([a-zA-Z0-9_$.]+)\s*\(", s)
                if call_match:
                    target_fn = call_match.group(1)
                    if target_fn not in callees:
                        callees.append(target_fn)

        # Detect loops via back-edges (a branch target that precedes current block)
        loop_count = 0
        block_indices = {b: i for i, b in enumerate(block_order)}
        for target in branch_targets:
            if target in block_indices and block_indices[target] <= block_indices.get(current_block, 0):
                loop_count += 1

        branch_density = branch_count / max(instr_count, 1)
        mem_density = memory_ops / max(instr_count, 1)

        # Estimate peak register pressure
        peak_vars = max((len(v) for v in ssa_vars_per_block.values()), default=0)

        # Vectorization potential: function has loops + arithmetic, or vector ops already
        vector_potential = (loop_count > 0 and (fp_ops > 2 or instr_count > 15)) or (vector_ops > 0)

        # Hot / Cold determination
        is_hot = False
        reason = "cold_by_default"

        if fn_name in explicit_hot:
            is_hot = True
            reason = "explicit_hot_attribute"
        elif fn_name in explicit_cold:
            is_hot = False
            reason = "explicit_cold_attribute"
        else:
            # Check pattern matches and heuristics
            name_lower = fn_name.lower()
            if any(re.search(pat, name_lower) for pat in cls.HOT_NAME_PATTERNS):
                is_hot = True
                reason = "hot_name_pattern_match"
            elif any(re.search(pat, name_lower) for pat in cls.COLD_NAME_PATTERNS):
                is_hot = False
                reason = "cold_name_pattern_match"
            elif loop_count > 0 or branch_density > 0.15:
                is_hot = True
                reason = "high_density_or_loops"

        return FunctionProfile(
            name=fn_name,
            is_hot=is_hot,
            hotness_reason=reason,
            instruction_count=instr_count,
            basic_block_count=block_count,
            loop_count=loop_count,
            branch_count=branch_count,
            branch_density=round(branch_density, 4),
            memory_ops_count=memory_ops,
            memory_op_density=round(mem_density, 4),
            fp_ops_count=fp_ops,
            vector_ops_count=vector_ops,
            vectorization_potential=vector_potential,
            estimated_reg_pressure=peak_vars,
            callees=callees,
        )
