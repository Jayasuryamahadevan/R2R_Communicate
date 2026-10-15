"""FASP reference harness: signed discovery, pairing, and safe task transport.

Layered by design (see `fasp_harness.layers`): this software implements
Layers 3 and 4 -- fleet and enterprise coordination. It observes Layer 2,
may request a halt, and has no code path that writes to Layer 1. Hard
real-time local safety belongs to certified equipment outside this process,
and `FASP_INDUSTRIAL_ARCHITECTURE.md` states exactly what is and is not
claimed as a result.
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import FaspHarness, SafeAdapter
    from .layers import Interaction, Layer, LayerGuard, LayerViolation

__all__ = ["FaspHarness", "Interaction", "Layer", "LayerGuard", "LayerViolation", "SafeAdapter"]


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = ".core" if name in {"FaspHarness", "SafeAdapter"} else ".layers"
    value = getattr(import_module(module, __name__), name)
    globals()[name] = value
    return value
