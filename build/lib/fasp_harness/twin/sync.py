"""Compare the twin against reality, and treat drift as a fault signal.

A twin nobody checks is a simulation with a marketing name. The check is
cheap: keep the prediction, receive the telemetry, measure the gap, and
escalate when the gap stops being noise.

Escalation is deliberately conservative and *bounded*. Divergence means one
of the model, the map, or the vehicle is wrong, and which of the three it
is cannot be determined from the divergence alone -- so the response is to
stop trusting the twin's predictions for that vehicle, raise an incident,
and (only past a hard threshold, and only when configured) request a halt.
Divergence is never treated as a reason to *correct* the vehicle: a
coordinator that starts steering toward its own prediction has quietly
become a control loop over an unreliable link.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..fleet.model import Pose, VehicleState
from ..timestamps import stamp


@dataclass
class DivergenceReport:
    vehicle_id: str
    position_error_m: float
    predicted: dict[str, Any]
    observed: dict[str, Any]
    exceeded: bool
    consecutive_exceedances: int
    at: str = field(default_factory=stamp)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "vehicle_id": self.vehicle_id,
            "position_error_m": round(self.position_error_m, 4),
            "predicted": self.predicted,
            "observed": self.observed,
            "exceeded": self.exceeded,
            "consecutive_exceedances": self.consecutive_exceedances,
            "at": self.at,
            "detail": self.detail,
        }


class TwinSync:
    """Holds predictions, ingests observations, and reports the gap.

    `consecutive_exceedances` rather than a single sample is what makes this
    usable: localisation jitter, a late telemetry frame, and a vehicle
    pausing for a pedestrian all produce one-off spikes. Requiring N in a
    row turns a noisy signal into an actionable one.
    """

    def __init__(
        self,
        *,
        position_tolerance_m: float = 1.0,
        halt_tolerance_m: float = 5.0,
        consecutive_threshold: int = 3,
        on_divergence: Callable[[DivergenceReport], None] | None = None,
        on_halt_required: Callable[[DivergenceReport], None] | None = None,
    ) -> None:
        self.position_tolerance_m = position_tolerance_m
        self.halt_tolerance_m = halt_tolerance_m
        self.consecutive_threshold = consecutive_threshold
        self.on_divergence = on_divergence
        self.on_halt_required = on_halt_required
        self._lock = threading.Lock()
        self._predicted: dict[str, Pose] = {}
        self._streaks: dict[str, int] = {}
        self._history: list[DivergenceReport] = []
        self._trusted: dict[str, bool] = {}

    def predict(self, vehicle_id: str, pose: Pose) -> None:
        with self._lock:
            self._predicted[vehicle_id] = pose

    def trusted(self, vehicle_id: str) -> bool:
        """Whether this vehicle's twin predictions are still believable.

        Preflight consults this: once a vehicle's twin has diverged
        repeatedly, planning against that model is worse than not planning
        at all, because it is confidently wrong.
        """
        with self._lock:
            return self._trusted.get(vehicle_id, True)

    def observe(self, state: VehicleState) -> DivergenceReport | None:
        """Compare one telemetry sample against the standing prediction."""
        if state.pose is None:
            return None
        with self._lock:
            predicted = self._predicted.get(state.vehicle_id)
        if predicted is None or predicted.map_id != state.pose.map_id:
            self.predict(state.vehicle_id, state.pose)
            return None

        error = predicted.distance_to(state.pose)
        exceeded = error > self.position_tolerance_m
        with self._lock:
            streak = self._streaks[state.vehicle_id] = (self._streaks.get(state.vehicle_id, 0) + 1) if exceeded else 0
            if not exceeded:
                self._trusted[state.vehicle_id] = True

        report = DivergenceReport(
            vehicle_id=state.vehicle_id,
            position_error_m=error,
            predicted=predicted.to_dict(),
            observed=state.pose.to_dict(),
            exceeded=exceeded,
            consecutive_exceedances=streak,
            detail=f"Twin predicted {predicted.x:.2f},{predicted.y:.2f}; vehicle reports {state.pose.x:.2f},{state.pose.y:.2f}." if exceeded else "Within tolerance.",
        )
        with self._lock:
            self._history.append(report)
            del self._history[:-512]

        if exceeded and streak >= self.consecutive_threshold:
            with self._lock:
                self._trusted[state.vehicle_id] = False
            if self.on_divergence is not None:
                self.on_divergence(report)
            if error > self.halt_tolerance_m and self.on_halt_required is not None:
                self.on_halt_required(report)
        # Re-anchor on the observation: a twin that keeps predicting from a
        # stale pose reports the same divergence forever and never notices
        # the vehicle recovering.
        self.predict(state.vehicle_id, state.pose)
        return report

    def history(self, vehicle_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            entries = [report for report in self._history if vehicle_id is None or report.vehicle_id == vehicle_id]
        return [report.to_dict() for report in entries[-limit:]]

    def summary(self) -> dict[str, Any]:
        with self._lock:
            history, trusted = list(self._history), dict(self._trusted)
        exceeded = [report for report in history if report.exceeded]
        return {
            "samples": len(history),
            "exceedances": len(exceeded),
            "worst_error_m": round(max((report.position_error_m for report in history), default=0.0), 4),
            "mean_error_m": round(sum(report.position_error_m for report in history) / len(history), 4) if history else 0.0,
            "position_tolerance_m": self.position_tolerance_m,
            "untrusted_vehicles": sorted(vehicle for vehicle, ok in trusted.items() if not ok),
        }
