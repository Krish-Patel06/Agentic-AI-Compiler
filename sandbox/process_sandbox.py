"""
Concrete Process Sandbox Implementation with Secret Scrubbing and Workspace Isolation.
Implements Domain 1, 2, 3, and 4 isolation with swappable backend interfaces.
"""

from __future__ import annotations
import os
import sys
import shutil
import tempfile
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from .sandbox_interface import ISandbox, SandboxDomain, SandboxConfig, ExecutionResult


SECRET_PATTERNS = {
    "KEY", "SECRET", "TOKEN", "PASS", "AUTH", "CREDENTIAL", "PRIVATE", "SIGNING"
}


class ProcessSandbox(ISandbox):
    """
    Subprocess-based sandbox with secret-scrubbing and isolated temporary workspaces.
    """

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._temp_dir = tempfile.mkdtemp(prefix=f"sandbox_{self.config.domain.value}_")
        self._cleaned = False

    @property
    def sandbox_path(self) -> str:
        return self._temp_dir

    @classmethod
    def for_domain(cls, domain: SandboxDomain, timeout_sec: float = 30.0) -> ProcessSandbox:
        cfg = SandboxConfig(
            domain=domain,
            timeout_sec=timeout_sec,
            allow_network=False,
            memory_limit_mb=1024
        )
        return cls(cfg)

    def get_sanitized_env(self) -> Dict[str, str]:
        """
        Strips all secrets, API keys, credentials, and tokens from environment variables.
        """
        sanitized = {}
        # Keep basic safe system paths
        safe_keys = {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "USERPROFILE", "LANG", "LC_ALL"}
        for k, v in os.environ.items():
            k_upper = k.upper()
            if any(pattern in k_upper for pattern in SECRET_PATTERNS):
                continue  # Scrub secret
            if k_upper in safe_keys or k.startswith("LLVM_") or k.startswith("CLANG_"):
                sanitized[k] = v

        # Enforce sandbox specific env
        sanitized["SANDBOX_DOMAIN"] = self.config.domain.value
        sanitized["SANDBOX_NETWORK_DENY"] = "1"
        sanitized["TMP"] = self._temp_dir
        sanitized["TEMP"] = self._temp_dir
        sanitized.update(self.config.env_vars)
        return sanitized

    def run_command(
        self,
        cmd: List[str],
        timeout: Optional[float] = None,
        stdin_data: Optional[str] = None
    ) -> ExecutionResult:
        if self._cleaned:
            raise RuntimeError("Cannot execute in a cleaned sandbox.")

        effective_timeout = timeout or self.config.timeout_sec
        env = self.get_sanitized_env()
        t0 = time.perf_counter()

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=self._temp_dir,
                env=env,
                stdin=subprocess.PIPE if stdin_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            stdout, stderr = proc.communicate(input=stdin_data, timeout=effective_timeout)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ExecutionResult(
                command=cmd,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time_ms=elapsed_ms,
                timed_out=False
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ExecutionResult(
                command=cmd,
                exit_code=-1,
                stdout=stdout or "",
                stderr=(stderr or "") + "\n[SANDBOX] Execution timed out.",
                execution_time_ms=elapsed_ms,
                timed_out=True
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ExecutionResult(
                command=cmd,
                exit_code=-1,
                stdout="",
                stderr=f"[SANDBOX ERROR]: {e}",
                execution_time_ms=elapsed_ms,
                timed_out=False
            )

    def cleanup(self) -> None:
        if not self._cleaned:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._cleaned = True
