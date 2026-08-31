"""Shared UTC timestamp helpers.

Split out of core.py so storage/ (and, later, audit/ and tasks/) can format
and parse FASP timestamps without importing core.py and risking a circular
import (core.py depends on storage/, not the reverse).
"""

from __future__ import annotations

from datetime import UTC, datetime


def now() -> datetime:
    return datetime.now(UTC)


def stamp(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
