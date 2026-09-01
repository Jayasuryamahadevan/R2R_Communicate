"""Fleet coordination: Layer 3, and the multi-vendor problem it really is.

Nobody runs one brand of vehicle. A live site has AMRs from one supplier,
tuggers from another, a forklift with its own proprietary manager, and a
conveyor that speaks something older than all of them. The failure mode is
predictable -- a coordinator written against vendor A's REST API, then
forked for vendor B -- and it ends with fleet logic duplicated per vendor
and diverging.

So the model here is inverted. `model` defines a vendor-neutral mission and
vehicle vocabulary; `adapter` is the only surface a vendor integration has
to implement; `registry` multiplexes any number of them behind one
namespace, so the scheduler above never learns which vendor a vehicle came
from. Adding a vendor is a new `FleetManagerAdapter`, and nothing else
changes.

Four adapters ship:

- `vda5050`   the VDA 5050 interface (orders, instant actions, state,
              connection, factsheet). The actual industry answer to this
              problem, and the one an integrator is most likely to already
              have on the other side.
- `rest`      a *declaratively configured* HTTP adapter, so a vendor with
              an ordinary REST API is integrated with a config file rather
              than a new module.
- `simulated` a deterministic in-memory fleet, used by the tests, the HIL
              bench, and the digital twin.
- `abb_rws`   a deny-by-default GoFa/OmniCore pilot adapter. It observes RWS
              state and may commit one locally allow-listed command to a
              preloaded RAPID mailbox; it exposes no raw motion or safety API.

Missions here are goal-level by construction (see `model.StepKind`): "go to
node N and pick load L". Trajectories, speeds, and obstacle handling belong
to the vehicle's own autonomy stack at Layer 2, and `fasp_harness.layers`
is what keeps it that way.
"""

from __future__ import annotations

from .abb_rws import AbbRwsPilotAdapter, AbbRwsPilotConfig
from .adapter import FleetManagerAdapter, FleetRegistry
from .model import Mission, MissionState, MissionStep, OperatingMode, Pose, StepKind, VehicleCapabilities, VehicleState
from .simulated import SimulatedFleetManager

__all__ = [
    "AbbRwsPilotAdapter",
    "AbbRwsPilotConfig",
    "FleetManagerAdapter",
    "FleetRegistry",
    "Mission",
    "MissionState",
    "MissionStep",
    "OperatingMode",
    "Pose",
    "SimulatedFleetManager",
    "StepKind",
    "VehicleCapabilities",
    "VehicleState",
]
