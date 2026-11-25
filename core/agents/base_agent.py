"""
Base Agent Interface.
Supports both deterministic heuristic fallback and optional LLM providers.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseAgent(ABC):
    def __init__(self, name: str, model_id: Optional[str] = None):
        self.name = name
        self.model_id = model_id or "deterministic_heuristic_v2"

    @property
    def is_deterministic(self) -> bool:
        return self.model_id.startswith("deterministic")
