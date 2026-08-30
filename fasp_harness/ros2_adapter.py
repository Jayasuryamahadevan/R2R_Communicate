"""Optional ROS 2 read-only graph observer bridge using rclpy."""

from __future__ import annotations

from typing import Any

from .core import FaspError


class ROS2ReadOnlyAdapter:
    def __init__(self) -> None:
        try:
            import rclpy  # type: ignore[import-not-found]
            from rclpy.node import Node  # type: ignore[import-not-found]
        except ImportError as exc:
            raise FaspError("capability.unavailable", "ROS 2 rclpy runtime is not installed on this host.") from exc
        self.rclpy = rclpy
        if not rclpy.ok():
            rclpy.init()
        self.node: Any = Node("fasp_observer")

    def capabilities(self) -> list[dict[str, Any]]:
        return [{"id": "observe.ros2.graph.v1", "risk": "observe", "max_runtime_s": 5, "network": "local-dds"}]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        if intent.get("capability") != "observe.ros2.graph.v1":
            raise FaspError("capability.unavailable", "ROS 2 bridge only exposes graph observation.")
        return {"status": "ok", "nodes": len(self.node.get_node_names_and_namespaces()), "topics": len(self.node.get_topic_names_and_types()), "services": len(self.node.get_service_names_and_types()), "note": "Counts only; no ROS topics, services, actions, or parameters are invoked."}

    def close(self) -> None:
        self.node.destroy_node()


def create_adapter() -> ROS2ReadOnlyAdapter:
    return ROS2ReadOnlyAdapter()
