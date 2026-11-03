"""
Unit tests for IR Validator & Fingerprinter
"""

import unittest
from secure_compiler.ir.validator import IRValidator, IRValidationLimits
from secure_compiler.ir.fingerprint import IRFingerprinter


VALID_IR = """
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define float @compute(float %a, float %b) {
entry:
  %res = fadd float %a, %b
  ret float %res
}
"""

UNTERMINATED_IR = """
define i32 @broken() {
entry:
  %val = add i32 1, 2
}
"""

FORBIDDEN_ASM_IR = """
define void @dangerous() {
entry:
  call void asm sideeffect "int 0x80", ""()
  ret void
}
"""


class TestIRValidator(unittest.TestCase):

    def setUp(self):
        self.validator = IRValidator()

    def test_valid_ir(self):
        res = self.validator.validate(VALID_IR)
        self.assertTrue(res.is_valid, f"Expected valid, got errors: {res.errors}")
        self.assertTrue(len(res.fingerprint) > 0)
        self.assertEqual(res.metrics["function_count"], 1)

    def test_unterminated_block_rejected(self):
        res = self.validator.validate(UNTERMINATED_IR)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("lacks a terminator" in e for e in res.errors))

    def test_forbidden_asm_rejected(self):
        res = self.validator.validate(FORBIDDEN_ASM_IR)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Forbidden" in e or "asm" in e for e in res.errors))

    def test_size_limits_enforced(self):
        strict_validator = IRValidator(IRValidationLimits(max_bytes=50))
        res = strict_validator.validate(VALID_IR)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("exceeds limit" in e for e in res.errors))

    def test_deterministic_fingerprint(self):
        fp1 = IRFingerprinter.compute_hash(VALID_IR)
        # Adding comments or whitespace should not change normalized fingerprint
        modified_ir = VALID_IR + "\n; This is a comment\n   \n"
        fp2 = IRFingerprinter.compute_hash(modified_ir)
        self.assertEqual(fp1, fp2)


if __name__ == "__main__":
    unittest.main()
