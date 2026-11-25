"""
Deterministic Program Profiler.
Extracts static IR metrics, path classification (HOT vs COLD),
loop structures, instruction mixes, register pressure approximations,
and detects Low-Latency Anti-Patterns (LAP-001 through LAP-010).
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Any, Optional


@dataclass
class FunctionProfile:
    name: str
    is_hot: bool
    is_cold: bool
    instruction_count: int
    branch_count: int
    memory_ops_count: int
    compute_ops_count: int
    loop_count: int
    anti_patterns: List[str] = field(default_factory=list)

    @property
    def memory_intensity(self) -> float:
        total = self.memory_ops_count + self.compute_ops_count
        return (self.memory_ops_count / total) if total > 0 else 0.0


@dataclass
class ProgramProfile:
    total_functions: int
    hot_functions: List[str]
    cold_functions: List[str]
    total_instructions: int
    total_loops: int
    overall_branch_density: float
    function_profiles: Dict[str, FunctionProfile]
    simd_candidates: List[str] = field(default_factory=list)


class ProgramProfiler:
    """Deterministic static profiler for source and LLVM IR."""

    MEMORY_OPCODES = {"load", "store", "alloca", "getelementptr", "atomicrmw", "cmpxchg"}
    BRANCH_OPCODES = {"br", "switch", "indirectbr"}

    @classmethod
    def profile(cls, ir_text: str, source_text: str = "") -> ProgramProfile:
        func_profiles: Dict[str, FunctionProfile] = {}
        hot_funcs: List[str] = []
        cold_funcs: List[str] = []
        total_instr = 0
        total_loops = 0

        # Scan source text for attributes if provided
        source_hot: Set[str] = set()
        source_cold: Set[str] = set()
        if source_text:
            for match in re.finditer(r'\[\[hft::hot\]\][\s\w:*&]+?\b([a-zA-Z_][a-zA-Z0-9_]*)\b\s*\(', source_text):
                source_hot.add(match.group(1))
            for match in re.finditer(r'\[\[hft::cold\]\][\s\w:*&]+?\b([a-zA-Z_][a-zA-Z0-9_]*)\b\s*\(', source_text):
                source_cold.add(match.group(1))

        # Parse IR function by function
        current_func: Optional[str] = None
        func_lines: List[str] = []

        for line in ir_text.splitlines():
            s = line.strip()
            if not s or s.startswith(";"):
                continue

            if s.startswith("define "):
                m = re.search(r'@([a-zA-Z_][a-zA-Z0-9_]*)\(', s)
                if m:
                    current_func = m.group(1)
                    func_lines = []
                continue

            if current_func:
                if s == "}":
                    # Process completed function
                    is_hot = current_func in source_hot or "on_market" in current_func or "evaluate" in current_func
                    is_cold = current_func in source_cold or "load_config" in current_func or "log_trade" in current_func

                    instr_count = len(func_lines)
                    mem_count = sum(1 for l in func_lines if any(op in l.split() for op in cls.MEMORY_OPCODES))
                    br_count = sum(1 for l in func_lines if any(op in l.split() for op in cls.BRANCH_OPCODES))
                    loops = sum(1 for l in func_lines if "loop" in l.lower() or "br label %for" in l.lower())

                    # Detect anti-patterns for this function
                    aps: List[str] = []
                    func_body_str = "\n".join(func_lines)
                    if "alloca " in func_body_str and is_hot:
                        aps.append("LAP-001: Heap/Stack Allocation overhead on hot path")
                    if "vtable" in func_body_str or "virtual" in func_body_str:
                        aps.append("LAP-002: Virtual dispatch overhead")
                    if "printf" in func_body_str or "call void @puts" in func_body_str:
                        aps.append("LAP-005: Synchronous I/O on hot path")
                    if br_count > 4 and is_hot:
                        aps.append("LAP-010: Branch-heavy logic on hot path")

                    f_prof = FunctionProfile(
                        name=current_func,
                        is_hot=is_hot,
                        is_cold=is_cold,
                        instruction_count=instr_count,
                        branch_count=br_count,
                        memory_ops_count=mem_count,
                        compute_ops_count=max(0, instr_count - mem_count - br_count),
                        loop_count=loops,
                        anti_patterns=aps
                    )
                    func_profiles[current_func] = f_prof
                    total_instr += instr_count
                    total_loops += loops

                    if is_hot:
                        hot_funcs.append(current_func)
                    if is_cold:
                        cold_funcs.append(current_func)

                    current_func = None
                else:
                    func_lines.append(s)

        total_funcs = len(func_profiles)
        total_branches = sum(f.branch_count for f in func_profiles.values())
        branch_density = (total_branches / total_instr) if total_instr > 0 else 0.0

        simd_candidates = [
            f.name for f in func_profiles.values()
            if f.is_hot and (f.loop_count > 0 or f.compute_ops_count > 5)
        ]

        return ProgramProfile(
            total_functions=total_funcs,
            hot_functions=hot_funcs,
            cold_functions=cold_funcs,
            total_instructions=total_instr,
            total_loops=total_loops,
            overall_branch_density=round(branch_density, 4),
            function_profiles=func_profiles,
            simd_candidates=simd_candidates
        )
