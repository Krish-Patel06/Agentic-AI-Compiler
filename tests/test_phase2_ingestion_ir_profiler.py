"""
Unit and Integration Tests for Phase 2:
- Source Ingestion & Quarantine Layer (extension, quota, hashing)
- Sandboxed Clang Frontend & Deterministic Reference IR
- Deterministic IR Security Gate (inline asm, forbidden intrinsics, terminators)
- Deterministic Program Profiler (HOT/COLD paths, instruction metrics, LAP anti-patterns)
"""

import unittest
import tempfile
import os
from pathlib import Path

from core.frontend.ingestion import SourceIngestionLayer, SourceQuarantineError, MAX_FILE_SIZE_BYTES
from core.frontend.clang_frontend import ClangFrontend, FrontendOutput
from core.ir.validator import IRValidator, IRValidationLimits
from core.ir.profiler import ProgramProfiler


class TestPhase2IngestionAndIR(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_phase2_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_source_ingestion_valid_file(self):
        """Verifies ingestion of valid C++ source, quarantine copying, and manifest hashing."""
        src_path = Path(self.temp_dir) / "strategy.cpp"
        src_path.write_text("#include <cstdio>\nint main() { return 0; }\n", encoding="utf-8")

        res = SourceIngestionLayer.ingest_file(src_path, quarantine_dir=Path(self.temp_dir) / "quarantine")
        self.assertTrue(Path(res.quarantine_path).exists())
        self.assertEqual(res.extension, ".cpp")
        self.assertTrue(len(res.source_hash) == 64)
        self.assertTrue(res.build_id.startswith("build_"))

        manifest = res.to_manifest()
        self.assertEqual(manifest["source_type"], "cpp")
        self.assertEqual(manifest["source_hash"], res.source_hash)

    def test_source_ingestion_forbidden_extension(self):
        """Verifies rejection of non-C/C++ file extensions."""
        bad_path = Path(self.temp_dir) / "exploit.py"
        bad_path.write_text("import os; os.system('sh')", encoding="utf-8")

        with self.assertRaises(SourceQuarantineError):
            SourceIngestionLayer.ingest_file(bad_path)

    def test_source_ingestion_file_size_quota(self):
        """Verifies rejection of files exceeding the 10 MB quota."""
        large_path = Path(self.temp_dir) / "huge.cpp"
        with open(large_path, "wb") as f:
            f.seek(MAX_FILE_SIZE_BYTES + 1024)
            f.write(b"0")

        with self.assertRaises(SourceQuarantineError):
            SourceIngestionLayer.ingest_file(large_path)

    def test_clang_frontend_compilation_and_reference_fallback(self):
        """Verifies ClangFrontend compiles to valid LLVM IR and includes versions and target triple."""
        frontend = ClangFrontend()
        sample_path = Path(self.temp_dir) / "sample.cpp"
        sample_path.write_text("int foo(int x) { return x + 1; }\n", encoding="utf-8")

        out = frontend.compile_to_ir(sample_path)
        self.assertTrue(out.success)
        self.assertTrue(len(out.ir_text) > 0)
        self.assertIn("define ", out.ir_text)
        self.assertIn("target triple", out.ir_text)

    def test_ir_validator_accepts_valid_ir(self):
        """Verifies IRValidator passes clean, well-formed LLVM IR and generates fingerprint."""
        valid_ir = """; ModuleID = 'test.cpp'
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

define i32 @add(i32 %a, i32 %b) {
entry:
  %res = add nsw i32 %a, %b
  ret i32 %res
}
"""
        validator = IRValidator()
        result = validator.validate(valid_ir)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.function_count, 1)
        self.assertEqual(result.instruction_count, 2)
        self.assertEqual(len(result.fingerprint), 64)
        self.assertEqual(len(result.errors), 0)

    def test_ir_validator_rejects_inline_assembly(self):
        """Verifies IRValidator catches and blocks inline assembly constructs."""
        asm_ir = """; ModuleID = 'malicious_asm.cpp'
define void @run_asm() {
entry:
  call void asm sideeffect "int3", ""()
  ret void
}
"""
        validator = IRValidator()
        result = validator.validate(asm_ir)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("inline assembly" in e.lower() for e in result.errors))

    def test_ir_validator_rejects_forbidden_intrinsics(self):
        """Verifies IRValidator detects forbidden intrinsics like llvm.trap."""
        trap_ir = """; ModuleID = 'trap.cpp'
declare void @llvm.trap()

define void @bad() {
entry:
  call void @llvm.trap()
  ret void
}
"""
        validator = IRValidator()
        result = validator.validate(trap_ir)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("forbidden intrinsic" in e.lower() for e in result.errors))

    def test_program_profiler_hot_cold_and_anti_patterns(self):
        """Verifies ProgramProfiler correctly identifies HOT/COLD paths and flags anti-patterns."""
        source_code = """
        [[hft::hot]]
        float on_market_data(float price) { return price * 2.0f; }

        [[hft::cold]]
        void load_config() {}
        """
        ir_code = """; ModuleID = 'demo.cpp'
define float @on_market_data(float %price) {
entry:
  %x = alloca float, align 4
  %res = fmul float %price, 2.000000e+00
  ret float %res
}

define void @load_config() {
entry:
  ret void
}
"""
        profile = ProgramProfiler.profile(ir_code, source_text=source_code)
        self.assertEqual(profile.total_functions, 2)
        self.assertIn("on_market_data", profile.hot_functions)
        self.assertIn("load_config", profile.cold_functions)

        # Verify LAP-001 flagged on hot function with alloca
        hot_prof = profile.function_profiles["on_market_data"]
        self.assertTrue(any("LAP-001" in ap for ap in hot_prof.anti_patterns))


if __name__ == "__main__":
    unittest.main()
