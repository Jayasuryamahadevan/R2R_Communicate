"""A conformance twin for the ABB GoFa pilot: what it is, and what it is not.

**What it is.** A controller model that executes the real `FASP_Pilot.mod`
through a RAPID interpreter, behind a Robot Web Services 2.0 endpoint built
from ABB's published OpenAPI specification. The adapter under test talks to it
over a real socket, with real authentication, real session-scoped mastership,
and optionally real TLS. It is strict where a lenient simulator would hide a
bug: RWS 1.0 paths answer 404, unversioned media types answer 406, a write
without the `UAS_RAPID_CURRVALUE` grant or without Edit mastership answers 403,
and eleven endpoints the pilot claims never to call are armed as tripwires that
record any attempt.

**What it is not.** It is not ABB firmware, and it cannot become ABB firmware.
RobotWare's undocumented behaviour is not modelled, no robot moves, no safety
function is exercised, and its timing bounds nothing. The only exact replica of
an OmniCore controller is ABB's own RobotStudio Virtual Controller, which runs
the real RobotWare image; this twin is what you use *before* that, to find
protocol and lifecycle faults cheaply, and it is deliberately loud about the
line between the two -- see `scenarios.NOT_PROVEN`.

    controller  the panel, symbol table, mastership, grants and task lifecycle
    rapid       the interpreter that runs the module file, not a copy of it
    rws         the HTTP surface, its status codes and its refusal order
    server      that surface on a socket, with optional controller TLS
    scenarios   the claims this twin can support, each with the run behind it
"""

from __future__ import annotations

from .controller import GRANT_RAPID_CURRVALUE, TRIPWIRES, OmniCoreTwin
from .rapid import Module, RapidTask, parse_module
from .rws import RwsRequest, RwsResponse, RwsService
from .scenarios import NOT_PROVEN, SCENARIOS, ScenarioResult, bench, run_all
from .server import TwinServer, self_signed_controller_cert

__all__ = [
    "GRANT_RAPID_CURRVALUE",
    "NOT_PROVEN",
    "SCENARIOS",
    "TRIPWIRES",
    "Module",
    "OmniCoreTwin",
    "RapidTask",
    "RwsRequest",
    "RwsResponse",
    "RwsService",
    "ScenarioResult",
    "TwinServer",
    "bench",
    "parse_module",
    "run_all",
    "self_signed_controller_cert",
]
