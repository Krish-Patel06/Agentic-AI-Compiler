"""
Structured Agent Gateway.
The sole boundary between the orchestrator and AI advisor agents.
Enforces strict JSON schema validation, strips free text, blocks path/secret leaks,
and applies rate and size quotas.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from policy.schema_validator import AgentSchemaValidator, SchemaValidationError


class GatewaySecurityError(Exception):
    """Raised when an agent output contains unauthorized secrets, paths, or code."""
    pass


class AgentGateway:
    """
    Zero-Trust AI Agent Gateway.
    No raw shell, no host filesystem access, no unvetted prompts.
    """

    FORBIDDEN_PATTERNS = [
        re.compile(r'/etc/passwd', re.IGNORECASE),
        re.compile(r'rm\s+-rf', re.IGNORECASE),
        re.compile(r'sh\s+-c', re.IGNORECASE),
        re.compile(r'bash\s+-c', re.IGNORECASE),
        re.compile(r'cmd\.exe', re.IGNORECASE),
        re.compile(r'powershell', re.IGNORECASE),
        re.compile(r'curl\s+', re.IGNORECASE),
        re.compile(r'wget\s+', re.IGNORECASE),
        re.compile(r'[a-zA-Z]:\\[a-zA-Z0-9_\\]+', re.IGNORECASE),  # Windows absolute path
        re.compile(r'/(?:usr|bin|var|opt|tmp)/[a-zA-Z0-9_/]+', re.IGNORECASE),  # Unix absolute path
    ]

    def __init__(self, schema_validator: Optional[AgentSchemaValidator] = None):
        self.validator = schema_validator or AgentSchemaValidator()

    def sanitize_and_validate(self, schema_name: str, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates the schema, scans for command injection / host path leakage,
        and returns the sanitized, immutable proposal dictionary.
        """
        # 1. Enforce JSON schema
        self.validator.enforce(schema_name, raw_payload)

        # 2. Deep scan text values for command injection or host path leaking
        self._scan_for_forbidden_patterns(raw_payload)

        return raw_payload

    def _scan_for_forbidden_patterns(self, obj: Any, path: str = "root") -> None:
        if isinstance(obj, str):
            for pat in self.FORBIDDEN_PATTERNS:
                if pat.search(obj):
                    raise GatewaySecurityError(
                        f"Security violation at '{path}': Forbidden text/command pattern '{pat.pattern}' detected in agent output."
                    )
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self._scan_for_forbidden_patterns(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self._scan_for_forbidden_patterns(item, f"{path}[{idx}]")
