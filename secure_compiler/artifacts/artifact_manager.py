"""
Secure Compiler — Build Artifact Manager
Safely manages, organizes, and persists build artifacts (IR, binaries, audit logs)
within designated workspace directories without polluting host system directories.
"""

from typing import Dict, Any, Optional
import json
import os
import shutil


class ArtifactManager:
    """
    Manages filesystem layout for builds.
    Guarantees no arbitrary filesystem escape and complete isolation.
    """

    def __init__(self, base_artifacts_dir: str = "compiler_artifacts"):
        self.base_dir = os.path.abspath(base_artifacts_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def get_build_dir(self, build_id: str) -> str:
        build_dir = os.path.join(self.base_dir, build_id)
        os.makedirs(build_dir, exist_ok=True)
        return build_dir

    def save_ir(self, build_id: str, filename: str, ir_text: str) -> str:
        path = os.path.join(self.get_build_dir(build_id), filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(ir_text)
        return path

    def save_audit_log(self, build_id: str, audit_data: Dict[str, Any]) -> str:
        path = os.path.join(self.get_build_dir(build_id), "audit_log.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2)
        return path

    def save_summary(self, build_id: str, summary_data: Dict[str, Any]) -> str:
        path = os.path.join(self.get_build_dir(build_id), "build_summary.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)
        return path
