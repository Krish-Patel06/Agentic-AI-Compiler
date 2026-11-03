"""
Secure Compiler — IR Normalizer
Cleans and standardizes LLVM IR text into a predictable canonical representation.
"""

import re


class IRNormalizer:
    """Normalizes LLVM IR for consistent processing across agents and gates."""

    @staticmethod
    def clean_comments(ir_text: str) -> str:
        """Removes comment lines and inline comments."""
        cleaned_lines = []
        for line in ir_text.splitlines():
            stripped = re.sub(r";.*$", "", line).rstrip()
            if stripped.strip():
                cleaned_lines.append(stripped)
        return "\n".join(cleaned_lines)

    @staticmethod
    def standardize_formatting(ir_text: str) -> str:
        """Standardizes indentation and spacing for functions and instructions."""
        out_lines = []
        in_func = False
        for line in ir_text.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("define "):
                in_func = True
                out_lines.append(s)
            elif s == "}":
                in_func = False
                out_lines.append(s)
            elif in_func:
                if s.endswith(":"):
                    # Basic block label
                    out_lines.append(s)
                else:
                    # Instruction inside block
                    out_lines.append("  " + s)
            else:
                out_lines.append(s)
        return "\n".join(out_lines) + "\n"
