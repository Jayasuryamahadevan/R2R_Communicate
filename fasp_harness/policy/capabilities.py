"""Capability-scope matching shared by every authorization path.

Scopes are names, not arbitrary string prefixes: ``fleet.mission.v1``
matches that capability and its descendants, but never ``fleet.mission.v10``.
An empty scope grants nothing. Callers still decide which operations require a
capability; this module makes the scope rule consistent and fail-closed.
"""

from __future__ import annotations

from collections.abc import Iterable


def matches_scope(capability: str, scope: str) -> bool:
    """Return whether a dot-delimited scope covers one capability name."""
    if not isinstance(capability, str) or not isinstance(scope, str):
        return False
    if not capability or not scope:
        return False

    # A trailing dot is the established spelling for a namespace grant, e.g.
    # ``observe.``. Normalizing it here preserves that spelling while applying
    # segment-aware matching to both it and an exact service scope.
    normalized = scope[:-1] if scope.endswith(".") else scope
    if not normalized:
        return False
    capability_parts = capability.split(".")
    scope_parts = normalized.split(".")
    if any(not part or "*" in part for part in (*capability_parts, *scope_parts)):
        return False
    return capability_parts[: len(scope_parts)] == scope_parts


def allows(capability: str, scopes: Iterable[str]) -> bool:
    """Apply default-deny matching across a peer's or grant's scopes."""
    return any(matches_scope(capability, scope) for scope in scopes)
