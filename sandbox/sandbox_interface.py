"""
Abstract Sandbox Interface.
Provides swappable isolation backends (ProcessSandbox, DockerSandbox, BwrapSandbox)
for the four core compiler domains.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from enum import Enum, unique
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@unique
class SandboxDomain(Enum):
    FRONTEND = "frontend"
    AI_PLANNER = "ai_planner"
    COMPILER = "compiler"
    EXECUTION = "execution"


@dataclass
class SandboxConfig:
    domain: SandboxDomain
    timeout_sec: float = 30.0
    memory_limit_mb: int = 1024
    allow_network: bool = False
    read_only_rootfs: bool = True
    non_root_uid: int = 10001
    env_vars: Dict[str, str] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: float
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class ISandbox(ABC):
    """Abstract sandbox contract for isolated process execution."""

    @abstractmethod
    def run_command(
        self,
        cmd: List[str],
        timeout: Optional[float] = None,
        stdin_data: Optional[str] = None
    ) -> ExecutionResult:
        pass

    @abstractmethod
    def cleanup(self) -> None:
        pass

    def __enter__(self) -> ISandbox:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()
