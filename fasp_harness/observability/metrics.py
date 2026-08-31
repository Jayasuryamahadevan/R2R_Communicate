"""Minimal stdlib Prometheus text-exposition metrics -- no `prometheus_client`
dependency. Scoped to the handful of counters/gauges that make the
conformance-relevant behaviors (rate limiting, task outcomes, active
streams/reservations) observable to an operator; full tracing or a richer
metrics model would be scope creep for a reference implementation.
"""

from __future__ import annotations

import threading
from typing import Any


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}

    def increment(self, name: str, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + 1

    def render(self, gauges: dict[str, int] | None = None) -> str:
        lines: list[str] = []
        with self._lock:
            counters = dict(self._counters)
        for (name, labels), value in sorted(counters.items()):
            label_text = ",".join(f'{key}="{_escape(value_)}"' for key, value_ in labels)
            lines.append(f"{name}{{{label_text}}} {value}" if label_text else f"{name} {value}")
        for name, value in (gauges or {}).items():
            lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"


def _escape(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')
