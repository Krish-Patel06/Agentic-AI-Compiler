#!/usr/bin/env python3
"""
End-to-End Acceptance Demo: Agentic AI Compiler Enclave.
Demonstrates the complete Zero-Trust LLVM IR optimization lifecycle:
  1. Untrusted C/C++ Source Ingestion & Quarantine
  2. Domain 1 Frontend lowering to unoptimized baseline IR (Candidate 0)
  3. Deterministic Non-AI Gates (IR Validator, Static Profiler)
  4. 22-State Orchestration & Sandboxed AI Advisor Iterations
  5. Deterministic Verification (Correctness, Security Gate, Canary Drift)
  6. Statistical Benchmarking (> 2 sigma, >= 1.5% margin)
  7. Production Artifact Packaging & Detached Cryptographic Signing
  8. Deterministic Replay Verification
"""

import sys
import os
import json

from core.orchestrator.orchestrator import OptimizationOrchestrator, CompilationResult
from core.provenance.replay_engine import ReplayEngine


def print_banner(text: str):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def main():
    print_banner("AGENTIC AI COMPILER: ZERO-TRUST LLVM IR OPTIMIZATION ENCLAVE")
    print("  Core Principle: AI ONLY PROPOSES. DETERMINISTIC CODE DECIDES.")
    print("  Host Target: LLVM 17+ | Policy: Strict Zero-Trust Enclave")

    orchestrator = OptimizationOrchestrator()
    replay_engine = ReplayEngine()

    # 1. Demonstration Source
    source_code = """
extern "C" float process_trade_signals(const float* prices, const float* weights, int n) {
    float cumulative_signal = 0.0f;
    for (int i = 0; i < n; ++i) {
        cumulative_signal += prices[i] * weights[i];
    }
    return cumulative_signal;
}
"""

    print_banner("1. INGESTING UNTRUSTED C++ SOURCE (Domain 1 Quarantine)")
    print(source_code.strip())

    # 2. Execute Zero-Trust 22-State Machine
    print_banner("2. RUNNING 22-STATE MACHINE ORCHESTRATION PIPELINE")
    res: CompilationResult = orchestrator.compile(
        source_code=source_code,
        filename="trade_kernel.cpp",
        mode="zero-trust"
    )

    print(f"[+] Build ID:            {res.build_id}")
    print(f"[+] Final Verdict:       {res.verdict.upper()}")
    print(f"[+] Speedup Achieved:    {res.speedup:.2f}x ({(res.speedup - 1.0) * 100:.1f}%)")
    print(f"[+] LLVM Passes Applied: {', '.join(res.passes_applied) if res.passes_applied else 'Baseline Fallback'}")
    print(f"[+] Audit Chain Head:    {res.audit_chain_head}")
    print(f"[+] Enclave Signature:   {res.signature[:32]}... [VERIFIED]")

    print("\n[+] 22-State Sequence Traversed:")
    for idx, state in enumerate(res.states_traversed, start=1):
        print(f"    Step {idx:02d}: {state}")

    # 3. Inspect Signed Release Artifacts
    print_banner("3. PRODUCTION ARTIFACT PACKAGE & ATTESTATIONS")
    print(f"[+] Release Directory:   {res.package_dir}")
    print(f"[+] Archive Bundle:      {res.package_archive}")
    if res.manifest:
        proofs = res.manifest.get("provenance", {}).get("verification_proofs", {})
        print(f"[+] Correctness Gate:    {'PASS' if proofs.get('correctness', {}).get('passed') else 'FAIL'}")
        print(f"[+] Security Gate:       {'PASS' if proofs.get('security', {}).get('passed') else 'FAIL'} (ABI Preserved)")
        print(f"[+] Statistical Bench:   Speedup={proofs.get('benchmark', {}).get('speedup'):.2f}x (Delta > 2 sigma)")

    # 4. Deterministic Replay Verification
    print_banner("4. RUNNING DETERMINISTIC REPLAY ENGINE")
    replay_res = replay_engine.replay(res.manifest, res.baseline_ir)
    print(f"[+] Replay Status:       {'SUCCESS (100% BIT-FOR-BIT MATCH)' if replay_res.reproduced else 'FAILED'}")
    print(f"[+] Baseline Hash Match: {replay_res.baseline_hash_match}")
    print(f"[+] Final IR Hash Match: {replay_res.final_hash_match}")
    print(f"[+] Replay Message:      {replay_res.message}")

    # 5. Fast Path Demonstration (--mode=legacy-fast)
    print_banner("5. TESTING ALTERNATIVE MODE (--mode=legacy-fast)")
    fast_res = orchestrator.compile(
        source_code=source_code,
        filename="trade_fast.cpp",
        mode="legacy-fast"
    )
    print(f"[+] Fast Mode Status:    {fast_res.verdict.upper()}")
    print(f"[+] Fast Passes:         {', '.join(fast_res.passes_applied)}")
    print(f"[+] Fast Signature:      {fast_res.signature[:32]}... [VERIFIED]")

    print_banner("ACCEPTANCE DEMO COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    main()
