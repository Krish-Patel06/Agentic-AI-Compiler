# C++17 Toolchain & LLVM Plugins

Contains native C++17 implementations targeting LLVM 17+:
- `ir_scanner/`: Static LLVM IR parser, terminator verifier, and intrinsic checker.
- `profiler/`: AST and IR feature extractor detecting LAP-001 through LAP-010 anti-patterns.
- `benchmark/`: Statistical multi-run timing harness with cycle counting and variance checks.
- `CMakeLists.txt`: CMake build system configuration.
