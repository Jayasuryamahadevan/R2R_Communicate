"""A safe template for connecting any model runtime to FASP.

Copy this file into your own package and replace only the bounded logic in
handle().  Do not let a model choose a capability or bypass the harness policy.
"""

from __future__ import annotations

from typing import Any

from .core import FaspError


class ExampleModelAdapter:
    def capabilities(self) -> list[dict[str, Any]]:
        return [{"id": "coordinate.plan.v1", "risk": "observe", "max_runtime_s": 20, "network": "none"}]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        if intent.get("capability") != "coordinate.plan.v1":
            raise FaspError("capability.unavailable", "This adapter only plans; it cannot take actions.")
        objective = str(intent.get("objective", ""))[:800]
        # Replace this line with a local model call. The model output is a plan,
        # not an execution request, and cannot grant itself additional authority.
        return {"status": "planned", "plan": f"Review objective and propose a safe bounded plan: {objective}"}


def create_adapter() -> ExampleModelAdapter:
    return ExampleModelAdapter()
