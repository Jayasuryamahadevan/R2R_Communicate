"""Optional ROS 1 read-only graph observer bridge."""

from __future__ import annotations

from typing import Any

from .core import FaspError


class ROS1ReadOnlyAdapter:
    def __init__(self) -> None:
        try:
            import rosgraph  # type: ignore[import-not-found]
        except ImportError as exc:
            raise FaspError("capability.unavailable", "ROS 1 Python runtime is not installed on this host.") from exc
        self.master = rosgraph.Master("fasp_observer")

    def capabilities(self) -> list[dict[str, Any]]:
        return [{"id": "observe.ros1.graph.v1", "risk": "observe", "max_runtime_s": 5, "network": "local-ros-master"}]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        if intent.get("capability") != "observe.ros1.graph.v1":
            raise FaspError("capability.unavailable", "ROS 1 bridge only exposes graph observation.")
        publishers, subscribers, services = self.master.getSystemState()
        return {"status": "ok", "publisher_topics": len(publishers), "subscriber_topics": len(subscribers), "services": len(services), "note": "Counts only; topic payloads and robot controls are not exposed."}


def create_adapter() -> ROS1ReadOnlyAdapter:
    return ROS1ReadOnlyAdapter()
