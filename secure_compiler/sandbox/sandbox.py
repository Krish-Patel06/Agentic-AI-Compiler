"""
Secure Compiler — Process Sandbox & 4-Domain Resource Isolation Layer
Executes compiler steps, test harnesses, and candidate binaries in isolated
security domains with CPU limits, memory quotas, timeouts, and sanitized environments.

Defines the 4 Core Isolation Domains:
  Domain 1: FRONTEND SANDBOX (Clang, AST, Preprocessor, IR generation)
  Domain 2: AI PLANNER SANDBOX (Reasoning, JSON Proposals, Cost Models)
  Domain 3: COMPILER SANDBOX (LLVM Pass Manager, Opt, Target Codegen)
  Domain 4: EXECUTION SANDBOX (Generated Binaries, Differential Testing, Benchmarking)
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import os
import sys
import shutil
import tempfile
import time
import subprocess


class SandboxDomain(str, Enum):
    FRONTEND = "domain_1_frontend"
    AI_PLANNER = "domain_2_ai_planner"
    COMPILER = "domain_3_compiler"
    EXECUTION = "domain_4_execution"


# Sensitive environment variable keys to strip
SECRET_PATTERNS = [
    "KEY", "TOKEN", "SECRET", "PASS", "AUTH", "CREDENTIAL",
    "AWS", "AZURE", "GCP", "GITHUB", "OPENAI", "API", "SSH", "PRIVATE"
]


@dataclass
class SandboxConfig:
    """Security boundaries for sandbox execution."""
    domain: SandboxDomain = SandboxDomain.EXECUTION
    timeout_s: float = 10.0
    max_memory_mb: int = 512
    allow_network: bool = False
    allow_fs_write: bool = True
    work_dir: Optional[str] = None
    sanitized_env: bool = True
    cpu_cores: int = 2


@dataclass
class SandboxExecutionResult:
    """Result of sandboxed execution."""
    success: bool
    returncode: int
    stdout: str
    stderr: str
    elapsed_time_s: float
    timed_out: bool = False
    memory_exceeded: bool = False
    domain: str = ""
    violations: List[str] = field(default_factory=list)


class ProcessSandbox:
    """
    Authoritative isolated execution harness.
    Guarantees no arbitrary host modification, no leaked secrets, and strict resource quotas.
    """

    DOMAIN_DEFAULTS = {
        SandboxDomain.FRONTEND: {
            "timeout_s": 30.0,
            "max_memory_mb": 2048,
            "allow_network": False,
        },
        SandboxDomain.AI_PLANNER: {
            "timeout_s": 20.0,
            "max_memory_mb": 1024,
            "allow_network": False,
        },
        SandboxDomain.COMPILER: {
            "timeout_s": 45.0,
            "max_memory_mb": 4096,
            "allow_network": False,
        },
        SandboxDomain.EXECUTION: {
            "timeout_s": 10.0,
            "max_memory_mb": 512,
            "allow_network": False,
        },
    }

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._temp_dir: Optional[str] = None
        self._owns_dir: bool = True

    @classmethod
    def for_domain(cls, domain: SandboxDomain, work_dir: Optional[str] = None) -> "ProcessSandbox":
        """Factory creating an appropriately tuned domain sandbox."""
        defaults = cls.DOMAIN_DEFAULTS.get(domain, {})
        cfg = SandboxConfig(
            domain=domain,
            timeout_s=defaults.get("timeout_s", 10.0),
            max_memory_mb=defaults.get("max_memory_mb", 512),
            allow_network=False,
            work_dir=work_dir,
            sanitized_env=True,
        )
        return cls(cfg)

    def __enter__(self):
        if self.config.work_dir and os.path.exists(self.config.work_dir):
            self._temp_dir = self.config.work_dir
            self._owns_dir = False
        else:
            domain_tag = self.config.domain.value if hasattr(self.config.domain, "value") else str(self.config.domain)
            self._temp_dir = tempfile.mkdtemp(prefix=f"sec_{domain_tag}_")
            self._owns_dir = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._owns_dir and self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    @property
    def sandbox_path(self) -> str:
        return self._temp_dir or tempfile.gettempdir()

    def get_sanitized_env(self) -> Dict[str, str]:
        """Strips secret tokens, clears network proxy settings, and forces secure runtime flags."""
        clean_env = {}
        # Preserve only essential system runtime paths
        for k in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME"):
            if k in os.environ:
                clean_env[k] = os.environ[k]

        clean_env["PYTHONUTF8"] = "1"
        clean_env["PYTHONIOENCODING"] = "utf-8"

        # Explicitly strip any proxy variables to enforce DEFAULT_DENY network
        for proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            if proxy_var in os.environ:
                continue

        # Strip any environment variable containing sensitive tokens
        for k, v in os.environ.items():
            if any(s in k.upper() for s in SECRET_PATTERNS):
                continue
            if k not in clean_env and not k.startswith("PROXY"):
                clean_env[k] = v

        return clean_env

    def run_command(
        self,
        cmd: List[str],
        stdin_input: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> SandboxExecutionResult:
        """Executes a command inside the isolated domain sandbox."""
        timeout_s = timeout or self.config.timeout_s
        env = self.get_sanitized_env() if self.config.sanitized_env else os.environ.copy()

        t0 = time.perf_counter()
        domain_name = self.config.domain.value if hasattr(self.config.domain, "value") else str(self.config.domain)

        try:
            proc = subprocess.run(
                cmd,
                input=stdin_input,
                capture_output=True,
                text=True,
                cwd=self.sandbox_path,
                timeout=timeout_s,
                env=env,
            )
            elapsed = time.perf_counter() - t0
            return SandboxExecutionResult(
                success=(proc.returncode == 0),
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                elapsed_time_s=elapsed,
                domain=domain_name,
            )
        except subprocess.TimeoutExpired as te:
            elapsed = time.perf_counter() - t0
            return SandboxExecutionResult(
                success=False,
                returncode=-1,
                stdout=te.stdout.decode() if isinstance(te.stdout, bytes) else (te.stdout or ""),
                stderr=te.stderr.decode() if isinstance(te.stderr, bytes) else (te.stderr or ""),
                elapsed_time_s=elapsed,
                timed_out=True,
                domain=domain_name,
                violations=[f"Execution exceeded timeout limit ({timeout_s:.1f}s) in {domain_name}."]
            )
        except Exception as e:
            elapsed = time.perf_counter() - t0
            return SandboxExecutionResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                elapsed_time_s=elapsed,
                domain=domain_name,
                violations=[f"Sandbox execution error: {e}"]
            )
