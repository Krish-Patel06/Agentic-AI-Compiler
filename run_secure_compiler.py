"""
Secure Compiler — Command Line Interface Runner
Executes the secure, deterministic, modular agentic compiler.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import argparse
import os
import json

from secure_compiler.orchestrator.orchestrator import SecureCompilerOrchestrator
from secure_compiler.policy.policy_engine import PolicyConfig
from secure_compiler.web_ui.server import SecureWebUIServer


def main():
    parser = argparse.ArgumentParser(
        description="Secure Agentic AI Compiler (Zero-Trust, Deterministic Architecture)"
    )
    parser.add_argument("source", nargs="?", default="examples/hft_strategy.cpp",
                        help="Path to C/C++ source file (default: examples/hft_strategy.cpp)")
    parser.add_argument("--target", default="native",
                        help="Target architecture (native | x86_64 | arm64)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Disable AI agents completely (runs pure deterministic baseline)")
    parser.add_argument("--security-level", choices=["strict", "moderate", "permissive"],
                        default="strict", help="Policy security enforcement level")
    parser.add_argument("--max-iterations", type=int, default=4,
                        help="Maximum AI optimization candidate iterations")
    parser.add_argument("--objective", choices=["performance", "binary_size", "compilation_time", "memory", "balanced"],
                        default="performance", help="Multi-objective Pareto optimization focus")
    parser.add_argument("--web", action="store_true",
                        help="Launch secure dashboard after compilation")
    parser.add_argument("--port", type=int, default=8080,
                        help="Web dashboard port (default: 8080)")
    args = parser.parse_args()

    print("=" * 70)
    print("  SECURE AGENTIC AI COMPILER — ZERO-TRUST DETERMINISTIC ENGINE")
    print("  Priority: CORRECTNESS > SECURITY > REPRODUCIBILITY > PERFORMANCE > AI")
    print("=" * 70)

    policy = PolicyConfig(
        max_agent_iterations=args.max_iterations,
        target_architecture=args.target,
        security_level=args.security_level,
    )

    orchestrator = SecureCompilerOrchestrator(
        policy_config=policy,
        enable_ai_agents=not args.no_ai,
    )

    print(f"\n[1/4] Ingesting & compiling: {args.source}")
    print(f"      Target ISA: {args.target} | AI Enabled: {not args.no_ai} | Policy: {args.security_level} | Objective: {args.objective}\n")

    res = orchestrator.compile(args.source, target_arch=args.target, objective=args.objective)

    sig_str = "✓ SIGNED" if res.signing_result.get("signed") else "✗ UNSIGNED"
    key_id = res.signing_result.get("key_id", "none")
    sig_hex = res.signing_result.get("signature", "")[:16]

    print("=" * 70)
    print(f"  BUILD OUTCOME: {'✓ SUCCESS' if res.success else '✗ FAILED'}")
    print(f"  Build ID:             {res.build_id}")
    print(f"  Selected Strategy:    {res.selected_candidate_id} {'(BASELINE)' if res.is_baseline else '(OPTIMIZED)'}")
    print(f"  Verified Improvement: {res.improvement_pct:.2f}%")
    print(f"  Pass Pipeline:        {', '.join(res.pass_pipeline)}")
    print(f"  Release Signing:      {sig_str} (Key: {key_id}, Sig: {sig_hex}...)")
    print(f"  Replay Manifest:      {res.replay_manifest_path}")
    print(f"  Wall Time:            {res.total_time_ms:.1f} ms")
    print(f"  Audit Log:            {res.audit_log_path}")
    print(f"  Build Summary:        {res.summary_path}")
    print("=" * 70)

    print("\nCandidate Lineage & Evaluation Tree:")
    for c in res.candidate_summary:
        status_symbol = {
            "accepted": "✓ ACCEPTED",
            "rejected": "✗ REJECTED",
            "verified": "✓ VERIFIED",
            "rolled_back": "⟲ ROLLED BACK",
            "pending": "⏳ PENDING",
        }.get(c['status'], c['status'].upper())

        print(f"  • [{c['candidate_id']}] (parent={c['parent_id']}): {status_symbol}")
        print(f"      Passes:      {', '.join(c['passes'])}")
        if c.get("rejection_reason"):
            print(f"      Rejection:   {c['rejection_reason']}")
        elif c.get("improvement_pct", 0) > 0:
            print(f"      Improvement: +{c['improvement_pct']:.2f}%")

    if args.web:
        print(f"\n[WebUI] Launching Secure Dashboard on http://localhost:{args.port}...")
        server = SecureWebUIServer(summary_path=res.summary_path, audit_path=res.audit_log_path, port=args.port)
        server.start()
        server.open_browser(delay=1.0)
        print("[WebUI] Serving dashboard. Press Ctrl+C to exit.")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[WebUI] Dashboard stopped.")


if __name__ == "__main__":
    main()
