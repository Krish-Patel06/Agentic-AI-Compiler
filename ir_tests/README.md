# LLVM IR Tests & lit/FileCheck Specifications

Contains reference LLVM IR samples:
- `baseline_O0.ll`: Canonical unoptimized LLVM IR representing Candidate 0.
- `candidate_mem2reg.ll`: Optimized IR candidate with promoted SSA registers and eliminated stack traffic.
- `test_opt_filecheck.ll`: lit/FileCheck regression test asserting valid terminator and pass transformations.
