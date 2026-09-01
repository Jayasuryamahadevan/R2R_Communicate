# ABB GoFa pilot profile

This profile connects FASP to an ABB GoFa CRB 15000 through its OmniCore
controller without turning the network link into a robot motion controller.
It targets RobotWare 7 / Robot Web Services 2.0, the common interface on the
earlier OmniCore GoFa systems. Confirm the installed RobotWare version on the
FlexPendant before commissioning; RobotWare 8 must be checked against its
matching RWS documentation before use.

## Command path

```text
signed FASP mission
        |
        v
local policy + one-command allowlist
        |
        v
ABB RWS writes: mission, command, status, cancel=FALSE
        |
        v
command sequence written last (commit)
        |
        v
preloaded RAPID FASP_PilotMain
        |
        v
one explicit, locally taught routine
```

The adapter never calls RWS endpoints that turn motors on, jog, write joint or
Cartesian targets, upload programs, alter configuration, write safety I/O, or
reset a protective stop. It does not start RAPID remotely. An authorised local
operator puts the controller in the assessed mode, starts the task, and remains
responsible for the existing ABB and mobile-platform safety chain.

The included [`FASP_Pilot.mod`](examples/abb_gofa/FASP_Pilot.mod) accepts only
`pilot_noop`, which waits briefly and completes without motion. It is the first
hardware acceptance test. A trained ABB programmer may add a taught routine
later, but must also add an explicit branch in RAPID and the same command to the
Python-side local allowlist. Network input must never supply a `robtarget`, joint
target, speed, zone, tool, work object, procedure name, or I/O address.

## Important system boundary

The GoFa arm and the LiDAR mobile base are normally two control systems. RWS
reports the arm tool-centre-point in the arm's base coordinate system; that is
not the LiDAR localisation pose. The adapter therefore keeps `robtarget` as
vendor telemetry and deliberately leaves the FASP map pose empty.

The mobile base requires its own supported interface (often VDA 5050, ROS 2, or
a vendor fleet REST API). Do not command the base through this ABB adapter. For
an arm-on-base pilot, the eventual composite gateway must prove that the base is
stationary and locally permitted before accepting an arm routine. Its exact
implementation depends on the base make, model, and safety scanner integration.

## Commissioning sequence

1. Obtain written approval from the college lab owner and identify the GoFa
   model, OmniCore model, RobotWare version, controller name, mobile-base model,
   LiDAR model, and existing risk assessment.
2. Run the complete flow against an ABB RobotStudio virtual controller first.
3. On the real cell, confirm that the E-stop, protective scanner, SafeMove
   configuration, tool, payload, work objects, and speed limits have been
   validated by the responsible integrator. FASP does not validate or replace
   any of them.
4. Create the least-privilege RWS user the installed RobotWare version permits.
   It needs controller/RAPID reads and mailbox-variable updates; do not grant
   safety configuration or I/O privileges. Because ABB privileges may be
   broader than one symbol, also restrict the account by network policy and the
   adapter's fixed endpoint set.
5. Use HTTPS and trust the controller/site CA. Plain HTTP requires the explicit
   `allow_insecure_http` switch and is limited to an isolated lab VLAN.
6. Load `FASP_Pilot.mod` through the authorised ABB workflow. Call
   `FASP_PilotMain` from the locally approved execution task and start it
   locally. FASP intentionally has no endpoint to start the task.
7. Keep `commanding_enabled` false and verify observation first. Poll no faster
   than 2 Hz; this baseline uses ordinary RWS reads rather than subscriptions.
   Run `python -m fasp_harness abb-pilot-check --config abb-node.json --json`.
   Add `--require-command-ready` only during the supervised `pilot_noop` test.
8. Pin the exact controller name, enable only `pilot_noop`, clear the test area,
   station a trained operator at the physical E-stop, and send one mission.
9. Test duplicate delivery, wrong controller identity, manual mode, motors off,
   RAPID stopped, network loss, cancellation, and controller restart. All must
   refuse, fail visibly, or reach one terminal result without unintended motion.

## Python setup

Credentials belong in the process secret store, not in the repository or node
JSON. Direct construction for the first pilot looks like this:

```python
import os

from fasp_harness.fleet import FleetRegistry
from fasp_harness.fleet.abb_rws import AbbRwsPilotAdapter, AbbRwsPilotConfig

config = AbbRwsPilotConfig(
    base_url="https://ABB_CONTROLLER_IP",
    username="fasp-pilot",
    password=os.environ["ABB_RWS_PASSWORD"],
    expected_controller_name="EXACT_NAME_FROM_CTRL_IDENTITY",
    commanding_enabled=False,
    allowed_commands=frozenset({"pilot_noop"}),
)

registry = FleetRegistry()
registry.register(AbbRwsPilotAdapter("abb-lab", config))
state = registry.vehicle_state("abb-lab:gofa")
```

The normal node configuration can construct the same adapter while resolving
the password from its process environment:

```json
{
  "kind": "abb-rws-pilot",
  "fleet": "abb-lab",
  "base_url": "https://ABB_CONTROLLER_IP",
  "username": "fasp-pilot",
  "password_env": "ABB_RWS_PASSWORD",
  "expected_controller_name": "EXACT_NAME_FROM_CTRL_IDENTITY",
  "commanding_enabled": false,
  "allowed_commands": ["pilot_noop"]
}
```

After the observation checks pass, change `commanding_enabled` locally and
restart the FASP process. A valid first mission has exactly one custom step:

```json
{
  "mission_id": "gofa-noop-001",
  "fleet": "abb-lab",
  "vehicle_id": "gofa",
  "steps": [
    {"kind": "custom", "parameters": {"command": "pilot_noop"}}
  ]
}
```

## Acceptance evidence

Keep the RWS/FASP audit record and a video of the cell for each run. Record:

- controller and RobotWare versions, RAPID module digest, local allowlist, and
  operator/test supervisor;
- mission ID, command sequence, acknowledgement sequence, and terminal result;
- FASP and controller timestamps plus observed network interruption;
- confirmation that no motor-on, program-upload, motion-target, I/O, or safety
  endpoint was invoked; and
- the independent mobile-base/LiDAR log when that adapter is added.

Passing `pilot_noop` proves the authenticated command lifecycle and refusal
behaviour. It does not prove safe robot motion, multi-robot coordination, or the
mobile platform integration.
