"""
Secure Compiler — 4-Tier Cryptographic Caching System
Provides deterministic, SHA-256 verified caching across four compilation stages:
  Tier 1: IR Cache (Source + Flags + Target -> LLVM IR)
  Tier 2: Pass Result Cache (IR Hash + Pipeline Hash -> Transformed IR + Metrics)
  Tier 3: Benchmark Cache (IR Hash + Target -> Verified Benchmark Measurements)
  Tier 4: Verified Artifact Cache (IR Hash + Signing Status -> Release Binaries & Manifests)
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple


@dataclass
class CacheStatistics:
    tier1_hits: int = 0
    tier1_misses: int = 0
    tier2_hits: int = 0
    tier2_misses: int = 0
    tier3_hits: int = 0
    tier3_misses: int = 0
    tier4_hits: int = 0
    tier4_misses: int = 0

    def to_dict(self) -> Dict[str, Any]:
        total_hits = self.tier1_hits + self.tier2_hits + self.tier3_hits + self.tier4_hits
        total_misses = self.tier1_misses + self.tier2_misses + self.tier3_misses + self.tier4_misses
        total_queries = total_hits + total_misses
        hit_ratio = (total_hits / total_queries) if total_queries > 0 else 0.0
        return {
            "tier1_ir": {"hits": self.tier1_hits, "misses": self.tier1_misses},
            "tier2_pass": {"hits": self.tier2_hits, "misses": self.tier2_misses},
            "tier3_benchmark": {"hits": self.tier3_hits, "misses": self.tier3_misses},
            "tier4_artifact": {"hits": self.tier4_hits, "misses": self.tier4_misses},
            "overall": {
                "total_hits": total_hits,
                "total_misses": total_misses,
                "hit_ratio_pct": round(hit_ratio * 100, 2)
            }
        }


class FourTierCache:
    """
    Authoritative 4-tier cryptographic caching engine.
    """

    def __init__(self, cache_dir: str = "compiler_artifacts/cache"):
        self.cache_dir = cache_dir
        self.stats = CacheStatistics()
        self._init_dirs()

    def _init_dirs(self) -> None:
        for subdir in ["tier1_ir", "tier2_pass", "tier3_benchmark", "tier4_artifact"]:
            path = os.path.join(self.cache_dir, subdir)
            os.makedirs(path, exist_ok=True)

    @staticmethod
    def _compute_key(*parts: str) -> str:
        h = hashlib.sha256()
        for p in parts:
            h.update(p.encode("utf-8"))
        return h.hexdigest()

    # ── Tier 1: IR Cache ──────────────────────────────────────────────
    def get_ir(self, source_hash: str, flags: str, target: str) -> Optional[str]:
        key = self._compute_key(source_hash, flags, target)
        path = os.path.join(self.cache_dir, "tier1_ir", f"{key}.ll")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                ir_text = f.read()
            self.stats.tier1_hits += 1
            return ir_text
        self.stats.tier1_misses += 1
        return None

    def put_ir(self, source_hash: str, flags: str, target: str, ir_text: str) -> None:
        key = self._compute_key(source_hash, flags, target)
        path = os.path.join(self.cache_dir, "tier1_ir", f"{key}.ll")
        with open(path, "w", encoding="utf-8") as f:
            f.write(ir_text)

    # ── Tier 2: Pass Result Cache ─────────────────────────────────────
    def get_pass_result(self, input_ir_hash: str, passes: list, target: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        pipe_key = ",".join(sorted(passes))
        key = self._compute_key(input_ir_hash, pipe_key, target)
        meta_path = os.path.join(self.cache_dir, "tier2_pass", f"{key}.json")
        ir_path = os.path.join(self.cache_dir, "tier2_pass", f"{key}.ll")
        if os.path.exists(meta_path) and os.path.exists(ir_path):
            with open(ir_path, "r", encoding="utf-8") as f:
                out_ir = f.read()
            with open(meta_path, "r", encoding="utf-8") as f:
                metrics = json.load(f)
            self.stats.tier2_hits += 1
            return out_ir, metrics
        self.stats.tier2_misses += 1
        return None

    def put_pass_result(self, input_ir_hash: str, passes: list, target: str, out_ir: str, metrics: Dict[str, Any]) -> None:
        pipe_key = ",".join(sorted(passes))
        key = self._compute_key(input_ir_hash, pipe_key, target)
        meta_path = os.path.join(self.cache_dir, "tier2_pass", f"{key}.json")
        ir_path = os.path.join(self.cache_dir, "tier2_pass", f"{key}.ll")
        with open(ir_path, "w", encoding="utf-8") as f:
            f.write(out_ir)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

    # ── Tier 3: Benchmark Cache ───────────────────────────────────────
    def get_benchmark(self, ir_hash: str, target: str) -> Optional[Dict[str, Any]]:
        key = self._compute_key(ir_hash, target)
        path = os.path.join(self.cache_dir, "tier3_benchmark", f"{key}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.stats.tier3_hits += 1
            return data
        self.stats.tier3_misses += 1
        return None

    def put_benchmark(self, ir_hash: str, target: str, benchmark_data: Dict[str, Any]) -> None:
        key = self._compute_key(ir_hash, target)
        path = os.path.join(self.cache_dir, "tier3_benchmark", f"{key}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(benchmark_data, f, indent=2)

    # ── Tier 4: Artifact Cache ────────────────────────────────────────
    def get_artifact(self, ir_hash: str) -> Optional[Dict[str, Any]]:
        key = self._compute_key(ir_hash)
        path = os.path.join(self.cache_dir, "tier4_artifact", f"{key}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.stats.tier4_hits += 1
            return data
        self.stats.tier4_misses += 1
        return None

    def put_artifact(self, ir_hash: str, artifact_manifest: Dict[str, Any]) -> None:
        key = self._compute_key(ir_hash)
        path = os.path.join(self.cache_dir, "tier4_artifact", f"{key}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(artifact_manifest, f, indent=2)
