"""The OmniCore controller state the pilot actually depends on.

This is the model, with no HTTP in it: panel state, the RAPID symbol table,
mastership, user grants, and the task that executes the mailbox module.  Keeping
it transport-free means the same object can be driven directly by a scenario or
served over Robot Web Services, and both see identical behaviour.

Three behaviours here are copied from the real controller because the pilot's
correctness argument leans on them:

- Switching out of AUTO, or dropping motors, **stops program execution**.  A
  mailbox that keeps running through a mode change would let the twin pass a
  test the robot would fail.
- `PERS` values survive a task restart.  That is what makes the module's
  replay refusal meaningful: after a restart it still sees the sequence number
  that was pending when it died.
- Mastership is scoped to a session, not to a user.  Two clients logged in as
  the same account still contend.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...protocol.errors import FaspError
from .rapid import ExecutionReport, Module, RapidTask, parse_module, render

OPERATION_MODES = ("INIT", "AUTO_CH", "MANF_CH", "MANR", "MANF", "AUTO", "UNDEF")
CONTROLLER_STATES = ("init", "motoron", "motoroff", "guardstop", "emergencystop", "emergencystopreset", "sysfail")

#: The grant RobotWare 7 requires to change the current value of RAPID data.
GRANT_RAPID_CURRVALUE = "UAS_RAPID_CURRVALUE"

#: Endpoints the pilot claims never to call.  The twin implements them as
#: tripwires rather than omitting them: an adapter that quietly grew a motor-on
#: call would get a 204 from a controller and a failed assertion from us.
TRIPWIRES = {
    ("POST", "/rw/panel/ctrl-state"): "motor power",
    ("POST", "/rw/panel/ctrl-state/keyless-motoron"): "motor power",
    ("POST", "/rw/panel/opmode"): "operating mode change",
    ("POST", "/rw/rapid/execution/start"): "remote RAPID start",
    ("POST", "/rw/rapid/execution/stop"): "remote RAPID stop",
    ("POST", "/rw/rapid/execution/resetpp"): "program pointer move",
    ("POST", "/rw/motionsystem/jog"): "jogging",
    ("POST", "/rw/motionsystem/position-target"): "Cartesian motion target",
    ("POST", "/rw/motionsystem/position-joint"): "joint motion target",
    ("POST", "/ctrl/safety/reset"): "safety reset",
    ("POST", "/ctrl/safety/config"): "safety configuration",
}


@dataclass
class TripwireHit:
    method: str
    path: str
    capability: str
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method, "path": self.path, "capability": self.capability, "at": self.at}


class OmniCoreTwin:
    """One simulated OmniCore controller running one RAPID mailbox module."""

    def __init__(
        self,
        module_source: str,
        *,
        name: str = "GOFA-TWIN-01",
        controller_type: str = "Virtual Controller",
        task: str = "T_ROB1",
        entry: str = "FASP_PilotMain",
        grants: set[str] | None = None,
        robtarget: dict[str, float] | None = None,
    ) -> None:
        self.module: Module = parse_module(module_source)
        self.name = name
        self.controller_type = controller_type
        self.task = task
        self.entry = entry
        self.grants = set(grants if grants is not None else {GRANT_RAPID_CURRVALUE})
        # ABB's own documented example pose, so a reader recognises the numbers.
        self.robtarget = dict(robtarget or {"x": 515.0, "y": 0.0, "z": 712.0, "q1": 0.7071068, "q2": 0.0, "q3": 0.7071068, "q4": 0.0})

        self._lock = threading.RLock()
        self._opmode = "AUTO"
        self._ctrl_state = "motoroff"
        self._symbols: dict[str, str] = {}
        self._types: dict[str, str] = {}
        self._mastership: dict[str, str | None] = {"edit": None, "motion": None}
        self._rmmp: set[str] = set()
        self._tripwires: list[TripwireHit] = []
        self._task: RapidTask | None = None
        self._thread: threading.Thread | None = None
        self._runs: list[ExecutionReport] = []
        self._load_module_defaults()

    # -- construction ------------------------------------------------------
    @classmethod
    def from_module_file(cls, path: str | Path, **kwargs: Any) -> OmniCoreTwin:
        return cls(Path(path).read_text(encoding="utf-8"), **kwargs)

    def _load_module_defaults(self) -> None:
        """Seed the symbol table from the module's own declared initial values."""

        from .rapid import Literal

        for declaration in self.module.persistents:
            self._types[declaration.name] = declaration.type_name
            if declaration.initial is None:
                self._symbols[declaration.name] = render({"num": 0.0, "string": "", "bool": False}[declaration.type_name])
            elif isinstance(declaration.initial, Literal):
                self._symbols[declaration.name] = render(declaration.initial.value)
            else:
                raise FaspError("schema.invalid", f"PERS {declaration.name} needs a literal initial value the twin can seed.")

    # -- symbol table (also the RapidTask's SymbolStore) --------------------
    def read_symbol(self, name: str) -> str:
        with self._lock:
            if name not in self._symbols:
                raise FaspError("schema.invalid", f"No RAPID symbol {name!r} in module {self.module.name}.")
            return self._symbols[name]

    def write_symbol(self, name: str, text: str) -> None:
        with self._lock:
            if name not in self._symbols:
                raise FaspError("schema.invalid", f"No RAPID symbol {name!r} in module {self.module.name}.")
            self._symbols[name] = text

    def symbol_names(self) -> list[str]:
        with self._lock:
            return sorted(self._symbols)

    def symbols(self) -> dict[str, str]:
        with self._lock:
            return dict(self._symbols)

    def declared_type(self, name: str) -> str | None:
        return self._types.get(name)

    # -- panel -------------------------------------------------------------
    @property
    def operation_mode(self) -> str:
        with self._lock:
            return self._opmode

    @property
    def controller_state(self) -> str:
        with self._lock:
            return self._ctrl_state

    @property
    def execution_state(self) -> str:
        with self._lock:
            return "running" if self._thread is not None and self._thread.is_alive() else "stopped"

    def set_operation_mode(self, mode: str) -> None:
        """Turn the mode selector. Leaving AUTO stops execution, as it does on the robot."""

        if mode not in OPERATION_MODES:
            raise FaspError("schema.invalid", f"{mode!r} is not an OmniCore operating mode.")
        with self._lock:
            self._opmode = mode
            self._rmmp.clear()
        if mode != "AUTO":
            self.stop_task()

    def set_controller_state(self, state: str) -> None:
        """Motors on or off. Dropping motors stops execution."""

        if state not in CONTROLLER_STATES:
            raise FaspError("schema.invalid", f"{state!r} is not an OmniCore controller state.")
        with self._lock:
            self._ctrl_state = state
        if state != "motoron":
            self.stop_task()

    def emergency_stop(self) -> None:
        self.set_controller_state("emergencystop")

    def grant_rmmp(self, session: str) -> None:
        """Simulate an operator confirming remote access on the FlexPendant."""

        with self._lock:
            self._rmmp.add(session)

    def has_rmmp(self, session: str) -> bool:
        with self._lock:
            return session in self._rmmp

    # -- mastership --------------------------------------------------------
    def request_mastership(self, domain: str, session: str) -> bool:
        with self._lock:
            if domain not in self._mastership:
                raise FaspError("schema.invalid", f"No mastership domain {domain!r}.")
            holder = self._mastership[domain]
            if holder is not None and holder != session:
                return False
            self._mastership[domain] = session
            return True

    def release_mastership(self, domain: str, session: str) -> bool:
        with self._lock:
            if self._mastership.get(domain) != session:
                return False
            self._mastership[domain] = None
            return True

    def mastership_holder(self, domain: str) -> str | None:
        with self._lock:
            return self._mastership.get(domain)

    def holds_mastership(self, domain: str, session: str) -> bool:
        return self.mastership_holder(domain) == session

    # -- task lifecycle ----------------------------------------------------
    def start_task(self) -> None:
        """Start the mailbox task, as a local operator does from the pendant.

        Deliberately has no network caller: the twin exposes no endpoint that
        starts RAPID, because the controller the pilot targets is configured so
        that FASP cannot either.
        """

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            if self._ctrl_state != "motoron":
                raise FaspError("capability.unavailable", "Cannot start the RAPID task with motors off.")
            task = RapidTask(self.module, self, self.entry)
            thread = threading.Thread(target=self._run_task, args=(task,), name="fasp-twin-rapid", daemon=True)
            self._task, self._thread = task, thread
        thread.start()
        # The module's preamble runs immediately; wait for it so a caller that
        # starts the task and then reads the mailbox sees a settled state.
        self._await_first_statement()

    def _run_task(self, task: RapidTask) -> None:
        report = task.run()
        with self._lock:
            self._runs.append(report)

    def _await_first_statement(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            task = self._task
            if task is not None and task.report is not None and task.report.statements > 0:
                return
            time.sleep(0.002)

    def stop_task(self) -> None:
        with self._lock:
            task, thread = self._task, self._thread
        if task is not None:
            task.stop()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def restart_controller(self) -> None:
        """Warm restart: the task dies and starts again; PERS values survive."""

        self.stop_task()
        with self._lock:
            was_on = self._ctrl_state == "motoron"
        if was_on:
            self.start_task()

    def task_runs(self) -> list[ExecutionReport]:
        with self._lock:
            return list(self._runs)

    # -- tripwires ---------------------------------------------------------
    def record_tripwire(self, method: str, path: str, capability: str) -> None:
        with self._lock:
            self._tripwires.append(TripwireHit(method, path, capability))

    @property
    def tripwires(self) -> list[TripwireHit]:
        with self._lock:
            return list(self._tripwires)

    # -- reporting ---------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "controller": self.name,
                "controller_type": self.controller_type,
                "module": self.module.name,
                "task": self.task,
                "operation_mode": self._opmode,
                "controller_state": self._ctrl_state,
                "execution_state": self.execution_state,
                "mastership": dict(self._mastership),
                "grants": sorted(self.grants),
                "symbols": dict(self._symbols),
                "tripwires": [hit.to_dict() for hit in self._tripwires],
                "task_runs": len(self._runs),
            }
