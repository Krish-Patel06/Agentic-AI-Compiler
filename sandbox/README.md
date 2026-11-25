# Multi-Domain Isolation Sandbox

Provides isolation boundaries across the 4 security domains:
- **Domain 1 (Frontend)**: Clang AST/IR lowering, read-only system toolchain, minimal FS.
- **Domain 2 (AI Advisor)**: No host FS, no network, strictly structured JSON input/output.
- **Domain 3 (Compiler)**: LLVM opt pass pipeline execution, resource limits, no network.
- **Domain 4 (Execution)**: Differential testing and benchmarking, execution timeouts, non-root.

Includes process scrubbing for environment variables, API tokens, and host secrets.
