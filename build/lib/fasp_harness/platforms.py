"""Portable, privacy-minimized runtime facts for FASP ID cards."""

from __future__ import annotations

import os
import platform
import sys
from typing import Any


def os_family() -> str:
    value = platform.system().lower()
    return {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(value, "other")


def runtime_profile() -> dict[str, Any]:
    """Return only non-identifying, capability-relevant runtime information."""
    return {
        "os_family": os_family(),
        "architecture": platform.machine().lower() or "unknown",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "containerized": bool(os.environ.get("container") or os.environ.get("KUBERNETES_SERVICE_HOST")),
        "profiles": ["core-http", "edge-safe"],
    }


def local_model_profile() -> dict[str, Any]:
    """A declarative profile for local model runtimes, including RTX 3050 hosts."""
    return {
        "kind": "local-model-runner",
        "supports": ["plan", "classify", "summarize"],
        "requires_local_policy": True,
        "note": "Suitable for CPU, integrated GPU, or RTX-3050-class edge deployments; model selection is out of protocol scope.",
    }
