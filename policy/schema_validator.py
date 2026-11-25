"""
Zero-dependency, authoritative JSON Schema Validator.
Strictly validates agent output payloads against the JSON schemas in /policy/schemas/.
Disallows unexpected properties, raw shell/path injection, and malformed types.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


SCHEMAS_DIR = Path(__file__).parent / "schemas"


class SchemaValidationError(Exception):
    """Raised when an agent proposal or advisory violates the strict JSON schema."""
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or [message]


def _validate_value(val: Any, schema: Dict[str, Any], path: str = "root") -> List[str]:
    errors: List[str] = []

    # Type validation
    expected_type = schema.get("type")
    if expected_type:
        types = [expected_type] if isinstance(expected_type, str) else expected_type
        type_matched = False
        for t in types:
            if t == "object" and isinstance(val, dict):
                type_matched = True
            elif t == "array" and isinstance(val, list):
                type_matched = True
            elif t == "string" and isinstance(val, str):
                type_matched = True
            elif t == "integer" and isinstance(val, int) and not isinstance(val, bool):
                type_matched = True
            elif t == "number" and (isinstance(val, (int, float))) and not isinstance(val, bool):
                type_matched = True
            elif t == "boolean" and isinstance(val, bool):
                type_matched = True
            elif t == "null" and val is None:
                type_matched = True
        if not type_matched:
            errors.append(f"{path}: expected type {expected_type}, got {type(val).__name__}")
            return errors

    # Enum validation
    if "enum" in schema and val not in schema["enum"]:
        errors.append(f"{path}: value {val!r} not in enum {schema['enum']}")

    # String constraints
    if isinstance(val, str):
        if "minLength" in schema and len(val) < schema["minLength"]:
            errors.append(f"{path}: string length {len(val)} < minLength {schema['minLength']}")
        if "maxLength" in schema and len(val) > schema["maxLength"]:
            errors.append(f"{path}: string length {len(val)} > maxLength {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], val):
            errors.append(f"{path}: string {val!r} does not match pattern {schema['pattern']}")

    # Numeric constraints
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        if "minimum" in schema and val < schema["minimum"]:
            errors.append(f"{path}: value {val} < minimum {schema['minimum']}")
        if "maximum" in schema and val > schema["maximum"]:
            errors.append(f"{path}: value {val} > maximum {schema['maximum']}")

    # Array constraints
    if isinstance(val, list):
        if "minItems" in schema and len(val) < schema["minItems"]:
            errors.append(f"{path}: items count {len(val)} < minItems {schema['minItems']}")
        if "maxItems" in schema and len(val) > schema["maxItems"]:
            errors.append(f"{path}: items count {len(val)} > maxItems {schema['maxItems']}")
        if "items" in schema:
            item_schema = schema["items"]
            for idx, item in enumerate(val):
                errors.extend(_validate_value(item, item_schema, f"{path}[{idx}]"))

    # Object constraints
    if isinstance(val, dict):
        if "required" in schema:
            for req in schema["required"]:
                if req not in val:
                    errors.append(f"{path}: missing required property '{req}'")

        if schema.get("additionalProperties") is False:
            allowed_props = set(schema.get("properties", {}).keys())
            for key in val.keys():
                if key not in allowed_props:
                    errors.append(f"{path}: unexpected additional property '{key}' is forbidden")

        if "properties" in schema:
            for key, prop_schema in schema["properties"].items():
                if key in val:
                    errors.extend(_validate_value(val[key], prop_schema, f"{path}.{key}"))

    return errors


class AgentSchemaValidator:
    """Loads schemas from /policy/schemas/ and validates agent payloads."""

    def __init__(self, schemas_dir: Path = SCHEMAS_DIR):
        self.schemas_dir = schemas_dir
        self._schemas: Dict[str, Dict[str, Any]] = {}
        self._load_schemas()

    def _load_schemas(self) -> None:
        if not self.schemas_dir.exists():
            return
        for file in self.schemas_dir.glob("*.json"):
            try:
                self._schemas[file.stem] = json.loads(file.read_text(encoding="utf-8"))
            except Exception:
                pass

    def validate(self, schema_name: str, payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
        if schema_name not in self._schemas:
            schema_file = self.schemas_dir / f"{schema_name}.json"
            if schema_file.exists():
                self._schemas[schema_name] = json.loads(schema_file.read_text(encoding="utf-8"))
            else:
                return False, [f"Schema '{schema_name}' not found"]

        schema = self._schemas[schema_name]
        errors = _validate_value(payload, schema, path="payload")
        return (len(errors) == 0, errors)

    def enforce(self, schema_name: str, payload: Dict[str, Any]) -> None:
        """Enforces schema, raising SchemaValidationError on deviation."""
        valid, errors = self.validate(schema_name, payload)
        if not valid:
            raise SchemaValidationError(
                f"Agent payload failed strict validation for schema '{schema_name}': {'; '.join(errors)}",
                errors=errors
            )
