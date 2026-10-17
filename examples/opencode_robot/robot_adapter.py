"""Bounded goal-level MuJoCo robot adapter used by the Docker integration demo.

FASP dispatches a destination. The adapter owns the local simulation loop and
never accepts motor setpoints from the peer.
"""

from __future__ import annotations

import json
import math
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import mujoco

from fasp_harness.protocol.errors import FaspError

MODEL_XML = """
<mujoco model="fasp_point_robot">
  <option timestep="0.01" gravity="0 0 0"/>
  <worldbody>
    <geom name="floor" type="plane" size="2 2 0.1" rgba="0.7 0.7 0.7 1"/>
    <body name="robot" pos="0 0 0.2">
      <joint name="x" type="slide" axis="1 0 0" range="-1.5 1.5" damping="2"/>
      <joint name="y" type="slide" axis="0 1 0" range="-1.5 1.5" damping="2"/>
      <geom name="chassis" type="box" size="0.10 0.08 0.05" mass="1" rgba="0.2 0.4 0.9 1"/>
    </body>
  </worldbody>
  <actuator>
    <motor name="x_drive" joint="x" ctrllimited="true" ctrlrange="-2 2"/>
    <motor name="y_drive" joint="y" ctrllimited="true" ctrlrange="-2 2"/>
  </actuator>
</mujoco>
"""

JOURNAL = Path("/home/fasp/.fasp/robot_actions.jsonl")


class MuJoCoRobotAdapter:
    def __init__(self) -> None:
        self.model = mujoco.MjModel.from_xml_string(MODEL_XML)
        self.data = mujoco.MjData(self.model)
        self.lock = threading.RLock()
        self.goals_completed = 0

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {"id": "observe.robot.pose.v1", "risk": "observe", "layer": 2, "interaction": "observe", "max_runtime_s": 5, "network": "none"},
            {"id": "robot.navigate.sim.v1", "risk": "reversible", "layer": 2, "interaction": "dispatch", "max_runtime_s": 5, "network": "none"},
        ]

    def _pose(self) -> dict[str, Any]:
        return {
            "model": "fasp_point_robot",
            "mujoco_version": mujoco.__version__,
            "sim_time_s": round(float(self.data.time), 3),
            "x_m": round(float(self.data.qpos[0]), 4),
            "y_m": round(float(self.data.qpos[1]), 4),
            "vx_mps": round(float(self.data.qvel[0]), 4),
            "vy_mps": round(float(self.data.qvel[1]), 4),
            "goals_completed": self.goals_completed,
        }

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        capability = intent.get("capability")
        with self.lock:
            if capability == "observe.robot.pose.v1":
                return self._pose()
            if capability != "robot.navigate.sim.v1":
                raise FaspError("capability.unavailable", "This simulation does not expose that capability.")

            try:
                target = json.loads(intent.get("objective", ""))
            except (TypeError, ValueError) as error:
                raise FaspError("schema.invalid", "Goal must be JSON with x_m and y_m.") from error
            if not isinstance(target, dict) or set(target) != {"x_m", "y_m"}:
                raise FaspError("schema.invalid", "Goal must contain only x_m and y_m.")
            coordinates = [target["x_m"], target["y_m"]]
            if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in coordinates):
                raise FaspError("schema.invalid", "Goal coordinates must be finite numbers.")
            x_goal, y_goal = (float(value) for value in coordinates)
            if max(abs(x_goal), abs(y_goal)) > 1.0:
                raise FaspError("policy.out_of_bounds", "Goal is outside the simulation's one-metre working area.")
            distance = math.hypot(x_goal - float(self.data.qpos[0]), y_goal - float(self.data.qpos[1]))
            if distance > 0.5:
                raise FaspError("policy.out_of_bounds", "One goal may move at most 0.5 m from the current pose.")

            reached = False
            for _ in range(500):
                dx = x_goal - float(self.data.qpos[0])
                dy = y_goal - float(self.data.qpos[1])
                if math.hypot(dx, dy) < 0.015 and math.hypot(float(self.data.qvel[0]), float(self.data.qvel[1])) < 0.03:
                    reached = True
                    break
                self.data.ctrl[0] = max(-2.0, min(2.0, 8 * dx - 4 * float(self.data.qvel[0])))
                self.data.ctrl[1] = max(-2.0, min(2.0, 8 * dy - 4 * float(self.data.qvel[1])))
                mujoco.mj_step(self.model, self.data)
            self.data.ctrl[:] = 0
            if not reached:
                raise FaspError("robot.goal_timeout", "Local simulation did not settle at the requested goal.")
            self.goals_completed += 1
            result = self._pose()
            result["goal"] = {"x_m": x_goal, "y_m": y_goal}
            with JOURNAL.open("a", encoding="utf-8") as output:
                output.write(json.dumps({
                    "at": datetime.now(UTC).isoformat(),
                    "idempotency_key": intent.get("idempotency_key"),
                    "goal": result["goal"],
                    "result": result,
                }, separators=(",", ":")) + "\n")
            return result


def factory() -> MuJoCoRobotAdapter:
    return MuJoCoRobotAdapter()
