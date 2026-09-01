"""A digital twin that is actually consulted, and actually checked.

Two failure modes define this area. A "twin" that nobody asks before acting
is a visualisation. A twin that is never compared against the real system
is a simulation. This package is built to be neither:

- `kinematic`  a deterministic vehicle and site model. Same inputs, same
               outputs, no wall clock, no threads -- so a prediction is
               reproducible and a divergence is attributable.
- `preflight`  the twin is asked *before* dispatch: is this mission
               reachable, does it fit the battery, does it cross a static
               obstacle, does it conflict in space-time with a reservation
               already granted. An infeasible mission is refused in
               milliseconds instead of discovered by a robot in an aisle.
- `sync`       the twin is compared *after*: real telemetry against the
               prediction, with a divergence threshold that escalates. A
               twin drifting from reality is itself a fault signal -- it
               usually means the model, the map, or the vehicle is wrong.
"""

from __future__ import annotations

from .kinematic import DifferentialDriveModel, OccupancyGrid, SiteModel, VehicleSim
from .preflight import PreflightResult, preflight_mission
from .sync import DivergenceReport, TwinSync

__all__ = [
    "DifferentialDriveModel",
    "DivergenceReport",
    "OccupancyGrid",
    "PreflightResult",
    "SiteModel",
    "TwinSync",
    "VehicleSim",
    "preflight_mission",
]
