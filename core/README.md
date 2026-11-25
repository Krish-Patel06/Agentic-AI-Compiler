# Core Optimization & Enclave Engine

This module contains the non-AI control plane, deterministic state machine, isolation boundaries, and verification gates.

## Subpackages
- `orchestrator/`: 22-state machine (`state_machine.py`), master workflow coordinator (`orchestrator.py`), and non-AI decision engine (`decision_engine.py`).
- `frontend/`: Source quarantine admission layer (`ingestion.py`) and Clang -O0 lowering (`clang_frontend.py`).
- `ir/`: Deterministic IR security scanner (`validator.py`) and static AST/IR profiler (`profiler.py`).
- `optimizer/`: Candidate lineage tree (`candidate.py`), Expected Value cost/benefit scorer (`cost_benefit.py`), and LLVM New Pass Manager runner (`pass_pipeline.py`).
- `gateway/`: Zero-trust schema validation boundary and command injection scanner (`agent_gateway.py`).
- `agents/`: Pluggable AI advisor agents (`ir_tuner.py`, `hw_tuner.py`, `security_analyzer.py`, `test_generator.py`).
- `verification/`: Authoritative differential tester (`differential.py`), correctness gate (`correctness_gate.py`), and canary drift check (`canary.py`).
- `security/`: ABI preservation and symbol diff gate (`security_gate.py`) and isolated root signing enclave (`signing_service.py`).
- `benchmark/`: Statistical benchmark engine requiring >2σ significance and ≥1.5% margin (`benchmark_engine.py`).
- `experience/`: Poison-resistant hash-chained SQLite store (`experience_store.py`).
- `provenance/`: Replay manifest generator (`provenance_generator.py`) and 100% bit-for-bit IR replay engine (`replay_engine.py`).
- `artifacts/`: Production release bundle packager with detached signatures (`artifact_packager.py`).
- `observability/`: Append-only, tamper-evident cryptographic audit log (`audit_log.py`).
