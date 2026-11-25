"""
Policy Loader and Cryptographic Integrity Verifier.
Loads the non-AI authoritative policy configuration from disk and verifies
its HMAC-SHA256 signature against the root security enclave key.
The AI is strictly prohibited from mutating policy parameters.
"""

from __future__ import annotations
import json
import hmac
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, List, Set


POLICY_DIR = Path(__file__).parent
CONFIG_PATH = POLICY_DIR / "policy_config.json"
SIGNATURE_PATH = POLICY_DIR / "policy_config.sig"

# System enclave HMAC secret for policy signing
_DEFAULT_POLICY_SIGNING_KEY = b"SECURE_COMPILER_ENCLAVE_ROOT_POLICY_KEY_v2"


class PolicyTamperedError(Exception):
    """Raised when the policy configuration signature is invalid or tampered with."""
    pass


@dataclass(frozen=True)
class GrowthLimits:
    max_ir_growth_pct: float
    max_binary_growth_pct: float


@dataclass(frozen=True)
class BenchmarkLimits:
    min_statistical_margin_pct: float
    min_sigma_factor: float
    warmup_iterations: int
    measurement_iterations: int
    max_acceptable_cv: float


@dataclass(frozen=True)
class ResourceQuotas:
    max_wall_time_sec: float
    max_memory_mb: int
    max_candidate_branches: int
    max_retries_per_unit: int
    max_agent_calls: int
    max_ir_instruction_count: int
    max_functions_count: int
    max_basic_blocks_per_function: int
    max_loop_nesting_depth: int


@dataclass(frozen=True)
class AuthoritativePolicy:
    version: str
    policy_name: str
    security_level: str
    growth_limits: GrowthLimits
    benchmark_limits: BenchmarkLimits
    resource_quotas: ResourceQuotas
    pass_allowlist: Set[str]
    forbidden_passes: Set[str]
    forbidden_intrinsics: Set[str]
    sandbox_rules: Dict[str, Any]

    def is_pass_allowed(self, pass_name: str) -> bool:
        clean = pass_name.strip().lstrip("-")
        if clean in self.forbidden_passes:
            return False
        return clean in self.pass_allowlist

    def filter_pass_pipeline(self, passes: List[str]) -> List[str]:
        return [p for p in passes if self.is_pass_allowed(p)]


def calculate_policy_signature(config_bytes: bytes, key: bytes = _DEFAULT_POLICY_SIGNING_KEY) -> str:
    """Calculates canonical HMAC-SHA256 signature for policy bytes."""
    return hmac.new(key, config_bytes, hashlib.sha256).hexdigest()


def sign_policy_file(
    config_path: Path = CONFIG_PATH,
    sig_path: Path = SIGNATURE_PATH,
    key: bytes = _DEFAULT_POLICY_SIGNING_KEY
) -> str:
    """Signs policy_config.json and writes policy_config.sig."""
    raw = config_path.read_bytes()
    sig = calculate_policy_signature(raw, key)
    sig_path.write_text(sig, encoding="utf-8")
    return sig


def load_authoritative_policy(
    config_path: Path = CONFIG_PATH,
    sig_path: Path = SIGNATURE_PATH,
    key: bytes = _DEFAULT_POLICY_SIGNING_KEY,
    enforce_signature: bool = True
) -> AuthoritativePolicy:
    """
    Loads and validates the authoritative policy.
    Ensures that signature matches before parsing into immutable dataclass.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Policy configuration file not found at {config_path}")

    raw_bytes = config_path.read_bytes()

    if enforce_signature:
        if not sig_path.exists():
            # If signature file doesn't exist yet, sign it initially
            sign_policy_file(config_path, sig_path, key)
        expected_sig = sig_path.read_text(encoding="utf-8").strip()
        calculated_sig = calculate_policy_signature(raw_bytes, key)
        if not hmac.compare_digest(expected_sig, calculated_sig):
            raise PolicyTamperedError("CRITICAL: Authoritative policy signature mismatch! Potential tampering detected.")

    data = json.loads(raw_bytes.decode("utf-8"))

    growth = GrowthLimits(
        max_ir_growth_pct=float(data["growth_limits"]["max_ir_growth_pct"]),
        max_binary_growth_pct=float(data["growth_limits"]["max_binary_growth_pct"])
    )
    bench = BenchmarkLimits(
        min_statistical_margin_pct=float(data["benchmark_limits"]["min_statistical_margin_pct"]),
        min_sigma_factor=float(data["benchmark_limits"]["min_sigma_factor"]),
        warmup_iterations=int(data["benchmark_limits"]["warmup_iterations"]),
        measurement_iterations=int(data["benchmark_limits"]["measurement_iterations"]),
        max_acceptable_cv=float(data["benchmark_limits"]["max_acceptable_cv"])
    )
    quotas = ResourceQuotas(
        max_wall_time_sec=float(data["resource_quotas"]["max_wall_time_sec"]),
        max_memory_mb=int(data["resource_quotas"]["max_memory_mb"]),
        max_candidate_branches=int(data["resource_quotas"]["max_candidate_branches"]),
        max_retries_per_unit=int(data["resource_quotas"]["max_retries_per_unit"]),
        max_agent_calls=int(data["resource_quotas"]["max_agent_calls"]),
        max_ir_instruction_count=int(data["resource_quotas"]["max_ir_instruction_count"]),
        max_functions_count=int(data["resource_quotas"]["max_functions_count"]),
        max_basic_blocks_per_function=int(data["resource_quotas"]["max_basic_blocks_per_function"]),
        max_loop_nesting_depth=int(data["resource_quotas"]["max_loop_nesting_depth"])
    )

    return AuthoritativePolicy(
        version=str(data["version"]),
        policy_name=str(data["policy_name"]),
        security_level=str(data["security_level"]),
        growth_limits=growth,
        benchmark_limits=bench,
        resource_quotas=quotas,
        pass_allowlist=set(data["pass_allowlist"]),
        forbidden_passes=set(data["forbidden_passes"]),
        forbidden_intrinsics=set(data["forbidden_intrinsics"]),
        sandbox_rules=dict(data["sandbox_rules"])
    )
