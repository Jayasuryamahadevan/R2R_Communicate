"""The question a lab owner actually asks: will this work, and how do you know.

Each scenario drives the real `AbbRwsPilotAdapter` over a real socket against a
twin controller executing the real `FASP_Pilot.mod`, and states the claim it
supports.  A scenario that passes is evidence for exactly its own claim and
nothing broader -- which is why every one of them carries the sentence it is
allowed to justify, and why the suite ends with what it still cannot prove.

Two kinds of scenario are deliberately mixed.  Most drive the adapter and ask
whether the pilot behaves.  A few drive the controller directly, because some
guarantees live in the RAPID module rather than in Python -- the replay refusal
after a restart is the clearest example, and it is unreachable through the
adapter by construction.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...protocol.errors import FaspError
from ..abb_rws import AbbRwsPilotAdapter, AbbRwsPilotConfig, urllib_rws_http
from ..model import Mission, MissionState
from .controller import OmniCoreTwin
from .server import TwinServer

#: The RAPID module the twin executes.  It is package data, not a path into a
#: source checkout: a wheel-installed harness must be able to run the twin, and
#: `tests/test_packaging.py` asserts this copy stays byte-identical to the
#: operator-facing one under `examples/abb_gofa/`.
MODULE_DIR = Path(__file__).resolve().parent / "modules"
MODULE_PATH = MODULE_DIR / "FASP_Pilot.mod"
CONTROLLER_NAME = "GOFA-TWIN-01"


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    ok: bool
    claim: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "claim": self.claim, "detail": self.detail, "evidence": self.evidence}


@dataclass
class Bench:
    """One twin, one server, one adapter, wired and running."""

    controller: OmniCoreTwin
    server: TwinServer
    pilot: AbbRwsPilotAdapter

    def wait_for(self, predicate: Callable[[], bool], *, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.005)
        return predicate()

    def wait_terminal(self, mission_id: str, *, timeout: float = 5.0) -> MissionState:
        self.wait_for(lambda: self.pilot.mission_state(mission_id).terminal, timeout=timeout)
        return self.pilot.mission_state(mission_id)

    def symbol(self, name: str) -> str:
        return self.controller.read_symbol(name)


@contextmanager
def bench(
    *,
    module_path: Path | None = None,
    commanding: bool = True,
    allowed: frozenset[str] = frozenset({"pilot_noop"}),
    expected_name: str | None = CONTROLLER_NAME,
    motors: bool = True,
    start_task: bool = True,
    grants: set[str] | None = None,
    tls: bool = False,
) -> Iterator[Bench]:
    controller = OmniCoreTwin.from_module_file(module_path or MODULE_PATH, name=CONTROLLER_NAME, grants=grants)
    if motors:
        controller.set_controller_state("motoron")
        if start_task:
            controller.start_task()
    server = TwinServer(controller, tls=tls).start()
    try:
        config = AbbRwsPilotConfig(
            base_url=server.base_url,
            username=server.username,
            password=server.password,
            expected_controller_name=expected_name,
            commanding_enabled=commanding,
            allowed_commands=allowed,
            allow_insecure_http=not tls,
            timeout_s=5.0,
        )
        transport = urllib_rws_http(config, ssl_context=server.client_ssl_context())
        yield Bench(controller, server, AbbRwsPilotAdapter("abb-twin", config, http=transport))
    finally:
        controller.stop_task()
        server.stop()


def _mission(mission_id: str, command: str = "pilot_noop") -> Mission:
    return Mission.from_dict(
        {"mission_id": mission_id, "steps": [{"kind": "custom", "parameters": {"command": command}}]},
        requested_by="fasp:system:conformance",
    )


def _writes(server: TwinServer) -> list[tuple[str, str, int]]:
    """Accepted mailbox writes. A refused write is in the log but changed nothing."""

    return [entry for entry in server.service.log if entry[0] == "POST" and entry[1].endswith("/data") and entry[2] == 204]


def _write_attempts(server: TwinServer) -> list[tuple[str, str, int]]:
    return [entry for entry in server.service.log if entry[0] == "POST" and entry[1].endswith("/data")]


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------

def scenario_preflight(_: Any = None) -> ScenarioResult:
    claim = "A commissioned controller reports observation and command readiness without being written to."
    with bench() as it:
        report = it.pilot.pilot_preflight()
        posts = [entry for entry in it.server.service.log if entry[0] == "POST"]
        ok = bool(report["observation_ready"]) and bool(report["ready_for_noop"]) and not posts
        failed = [check["name"] for check in report["checks"] if not check["ok"]]
        return ScenarioResult("preflight", ok, claim,
                              "all checks pass, zero writes" if ok else f"failed: {failed or 'unexpected write'}",
                              {"checks": report["checks"], "writes": len(posts)})


def scenario_noop_lifecycle(_: Any = None) -> ScenarioResult:
    claim = "A signed noop mission reaches RAPID, executes the taught branch, and returns exactly one terminal state."
    with bench() as it:
        vendor = it.pilot.dispatch(_mission("twin-noop-1"), "gofa")
        state = it.wait_terminal("twin-noop-1")
        ok = state is MissionState.COMPLETED and it.symbol("fasp_detail") == '"noop_complete"' and it.symbol("fasp_ack_seq") == "1"
        return ScenarioResult("noop_lifecycle", ok, claim, f"terminal state {state.value}, ack={it.symbol('fasp_ack_seq')}",
                              {"vendor": vendor, "detail": it.symbol("fasp_detail")})


def scenario_commit_ordering(_: Any = None) -> ScenarioResult:
    claim = "The sequence number is committed last, after every payload variable and inside one mastership hold."
    with bench() as it:
        it.pilot.dispatch(_mission("twin-order-1"), "gofa")
        posts = [entry[1] for entry in it.server.service.log if entry[0] == "POST"]
        symbols = [path.rsplit("/", 2)[-2] for _m, path, status in _write_attempts(it.server) for _ in [0]]
        posts = [entry[1] for entry in it.server.service.log if entry[0] == "POST"]
        expected = ["fasp_mission_id", "fasp_command", "fasp_detail", "fasp_result", "fasp_cancel_requested", "fasp_command_seq"]
        bracketed = posts[0].endswith("/rw/mastership/edit/request") and posts[-1].endswith("/rw/mastership/edit/release")
        ok = symbols == expected and bracketed and it.controller.mastership_holder("edit") is None
        return ScenarioResult("commit_ordering", ok, claim,
                              "commit last, mastership taken once and released" if ok else f"order was {symbols}",
                              {"symbol_order": symbols, "first": posts[0], "last": posts[-1]})


def scenario_duplicate_delivery(_: Any = None) -> ScenarioResult:
    claim = "A mission delivered twice is executed once; the retry is answered from controller state."
    with bench() as it:
        it.pilot.dispatch(_mission("twin-dup-1"), "gofa")
        it.wait_terminal("twin-dup-1")
        before = len(_writes(it.server))
        second = it.pilot.dispatch(_mission("twin-dup-1"), "gofa")
        ok = bool(second["idempotent"]) and len(_writes(it.server)) == before and it.symbol("fasp_command_seq") == "1"
        return ScenarioResult("duplicate_delivery", ok, claim,
                              "second delivery wrote nothing" if ok else "the retry wrote to the mailbox",
                              {"writes_before": before, "writes_after": len(_writes(it.server)), "second": second})


def scenario_unknown_command_is_rejected_by_rapid(_: Any = None) -> ScenarioResult:
    claim = "A command the local allowlist permits but RAPID was never taught is refused by the robot, not executed."
    with bench(allowed=frozenset({"pilot_noop", "pilot_home"})) as it:
        it.pilot.dispatch(_mission("twin-untaught-1", "pilot_home"), "gofa")
        state = it.wait_terminal("twin-untaught-1")
        ok = state is MissionState.REJECTED and it.symbol("fasp_detail") == '"command_not_taught"'
        return ScenarioResult("untaught_command", ok, claim, f"{state.value} / {it.symbol('fasp_detail')}", {})


def scenario_allowlist_refuses_offline(_: Any = None) -> ScenarioResult:
    claim = "A command outside the local allowlist is refused before any request reaches the controller."
    with bench() as it:
        with suppress(FaspError):
            it.pilot.dispatch(_mission("twin-deny-1", "pilot_weld"), "gofa")
        ok = it.server.service.log == []
        return ScenarioResult("allowlist_offline_refusal", ok, claim,
                              "no HTTP request was made" if ok else f"{len(it.server.service.log)} requests reached the controller",
                              {"requests": len(it.server.service.log)})


def _refusal(name: str, claim: str, prepare: Callable[[Bench], None], **options: Any) -> ScenarioResult:
    with bench(**options) as it:
        prepare(it)
        code = ""
        try:
            it.pilot.dispatch(_mission(f"twin-{name}"), "gofa")
            refused = False
        except FaspError as error:
            refused, code = True, error.code
        ok = refused and not _writes(it.server) and it.controller.mastership_holder("edit") is None
        return ScenarioResult(name, ok, claim,
                              f"refused with {code}, mailbox untouched" if ok else "the mission was not refused cleanly",
                              {"code": code, "writes": len(_writes(it.server))})


def scenario_manual_mode(_: Any = None) -> ScenarioResult:
    return _refusal("manual_mode", "A controller switched to manual refuses dispatch, and the mailbox is not written.",
                    lambda it: it.controller.set_operation_mode("MANR"))


def scenario_motors_off(_: Any = None) -> ScenarioResult:
    return _refusal("motors_off", "FASP never turns motors on: with motors off the mission is refused.",
                    lambda it: it.controller.set_controller_state("motoroff"))


def scenario_estop(_: Any = None) -> ScenarioResult:
    return _refusal("emergency_stop", "An emergency stop refuses dispatch; FASP has no path to reset it.",
                    lambda it: it.controller.emergency_stop())


def scenario_rapid_stopped(_: Any = None) -> ScenarioResult:
    return _refusal("rapid_stopped", "Without a locally started mailbox task the mission is refused, not queued.",
                    lambda it: it.controller.stop_task())


def scenario_wrong_controller(_: Any = None) -> ScenarioResult:
    return _refusal("wrong_controller", "A configuration pinned to another controller refuses to drive this one.",
                    lambda it: None, expected_name="SOME-OTHER-CELL")


def scenario_no_uas_grant(_: Any = None) -> ScenarioResult:
    return _refusal("missing_uas_grant", "An RWS account without UAS_RAPID_CURRVALUE cannot write the mailbox.",
                    lambda it: None, grants=set())


def scenario_mastership_contention(_: Any = None) -> ScenarioResult:
    claim = "While another client holds Edit mastership the mission is refused rather than half-written."
    with bench() as it:
        it.controller.request_mastership("edit", "robotstudio-session")
        code = ""
        try:
            it.pilot.dispatch(_mission("twin-contended-1"), "gofa")
            refused = False
        except FaspError as error:
            refused, code = True, error.code
        ok = refused and not _writes(it.server) and it.controller.mastership_holder("edit") == "robotstudio-session"
        return ScenarioResult("mastership_contention", ok, claim,
                              f"refused with {code}, the other holder kept mastership" if ok else "contention was not handled",
                              {"code": code, "holder": it.controller.mastership_holder("edit")})


def scenario_mastership_released_on_failure(_: Any = None) -> ScenarioResult:
    claim = "A write that fails mid-block still releases mastership, and the command is never committed."
    with bench() as it:
        it.server.service.fail_write_once = "fasp_result"
        with suppress(FaspError):
            it.pilot.dispatch(_mission("twin-fail-1"), "gofa")
        released = it.controller.mastership_holder("edit") is None
        uncommitted = it.symbol("fasp_command_seq") == "0"
        # And the retry must complete the mission rather than stranding it.
        it.pilot.dispatch(_mission("twin-fail-1"), "gofa")
        state = it.wait_terminal("twin-fail-1")
        ok = released and uncommitted and state is MissionState.COMPLETED
        return ScenarioResult("mastership_released_on_failure", ok, claim,
                              f"released={released}, uncommitted={uncommitted}, retry={state.value}", {})


def scenario_restart_refuses_replay(_: Any = None) -> ScenarioResult:
    claim = "A controller restart with a command still unacknowledged fails it visibly instead of replaying it."
    with bench() as it:
        # Driven at the controller, because the guarantee lives in RAPID: this
        # is the state a power loss between commit and acknowledgement leaves.
        it.controller.stop_task()
        it.controller.write_symbol("fasp_mission_id", '"twin-restart-1"')
        it.controller.write_symbol("fasp_command", '"pilot_noop"')
        it.controller.write_symbol("fasp_command_seq", "7")
        it.controller.start_task()
        it.wait_for(lambda: it.symbol("fasp_ack_seq") == "7")
        ok = it.symbol("fasp_result") == '"FAILED"' and it.symbol("fasp_detail") == '"restart_refused_replay"' and it.symbol("fasp_ack_seq") == "7"
        return ScenarioResult("restart_refuses_replay", ok, claim,
                              f"{it.symbol('fasp_result')} / {it.symbol('fasp_detail')}", {"ack": it.symbol("fasp_ack_seq")})


def scenario_rapid_cancel_branch(_: Any = None) -> ScenarioResult:
    claim = "The taught branch honours a cancel raised before it runs, and reports CANCELLED."
    with bench() as it:
        # Deterministic by construction: the flag is set before the commit, and
        # the module only clears it after a command reaches a terminal state.
        it.controller.write_symbol("fasp_mission_id", '"twin-cancel-1"')
        it.controller.write_symbol("fasp_command", '"pilot_noop"')
        it.controller.write_symbol("fasp_cancel_requested", "TRUE")
        it.controller.write_symbol("fasp_command_seq", "1")
        it.wait_for(lambda: it.symbol("fasp_ack_seq") == "1")
        ok = it.symbol("fasp_result") == '"CANCELLED"' and it.symbol("fasp_cancel_requested") == "FALSE"
        return ScenarioResult("rapid_cancel_branch", ok, claim,
                              f"{it.symbol('fasp_result')}, flag cleared after the branch", {})


def scenario_cancel_is_cooperative(_: Any = None) -> ScenarioResult:
    claim = "Cancel is a cooperative request written to the mailbox; it reaches one terminal state and claims no stop."
    with bench() as it:
        it.pilot.dispatch(_mission("twin-coop-1"), "gofa")
        accepted = it.pilot.cancel("twin-coop-1")
        state = it.wait_terminal("twin-coop-1")
        wrote_flag = any(path.endswith("fasp_cancel_requested/data") for _m, path, _s in _writes(it.server))
        ok = accepted and wrote_flag and state.terminal and not it.controller.tripwires
        return ScenarioResult("cancel_is_cooperative", ok, claim,
                              f"accepted, terminal {state.value}, no stop endpoint touched",
                              {"terminal_state": state.value, "note": "COMPLETED or CANCELLED are both correct: the request races the branch by design"})


def scenario_boundary_tripwires(_: Any = None) -> ScenarioResult:
    claim = "Across a whole mission lifecycle the pilot touches no motor, jog, program-load, safety, or RAPID-start endpoint."
    with bench() as it:
        it.pilot.vehicle_state("gofa")
        it.pilot.dispatch(_mission("twin-boundary-1"), "gofa")
        it.wait_terminal("twin-boundary-1")
        it.pilot.cancel("twin-boundary-1")
        it.pilot.request_stop("gofa", "operator asked")
        hits = it.controller.tripwires
        return ScenarioResult("boundary_tripwires", not hits, claim,
                              "no forbidden endpoint was called" if not hits else f"called: {[hit.capability for hit in hits]}",
                              {"armed": 11, "hits": [hit.to_dict() for hit in hits]})


def scenario_rws_1_0_is_rejected(_: Any = None) -> ScenarioResult:
    claim = "The controller answers RWS 1.0 spellings with 404, so an RWS 1.0 client cannot appear to work."
    with bench() as it:
        base = it.server.base_url
        headers = {"Accept": "application/xhtml+xml;v=2.0"}
        legacy = [
            f"{base}/rw/panel/ctrlstate",
            f"{base}/rw/rapid/symbol/data/RAPID/T_ROB1/FASP_Pilot/fasp_result",
        ]
        statuses = [it.pilot.http("GET", url, headers, None)[0] for url in legacy]
        ok = all(status == 404 for status in statuses)
        return ScenarioResult("rws_1_0_rejected", ok, claim, f"legacy paths answered {statuses}", {"paths": legacy, "statuses": statuses})


def scenario_unversioned_media_type(_: Any = None) -> ScenarioResult:
    claim = "An unversioned Accept header is answered 406, catching a client that negotiates like RWS 1.0."
    with bench() as it:
        url = f"{it.server.base_url}/ctrl/identity"
        unversioned = it.pilot.http("GET", url, {"Accept": "application/xhtml+xml"}, None)[0]
        versioned = it.pilot.http("GET", url, {"Accept": "application/xhtml+xml;v=2.0"}, None)[0]
        ok = unversioned == 406 and versioned == 200
        return ScenarioResult("media_type_versioning", ok, claim, f"unversioned={unversioned}, versioned={versioned}", {})


def scenario_network_loss(_: Any = None) -> ScenarioResult:
    claim = "Losing the controller mid-session surfaces as a transport error, not as a silently dropped mission."
    with bench() as it:
        it.pilot.dispatch(_mission("twin-net-1"), "gofa")
        it.wait_terminal("twin-net-1")
        committed = it.symbol("fasp_command_seq")
        it.server.stop()
        code = ""
        try:
            it.pilot.vehicle_state("gofa")
        except FaspError as error:
            code = error.code
        ok = code == "transport.unreachable" and committed == "1"
        return ScenarioResult("network_loss", ok, claim, f"raised {code or 'nothing'}; mailbox left at seq={committed}", {"code": code})


def scenario_tls_trusted(_: Any = None) -> ScenarioResult:
    claim = "Over HTTPS with the controller's CA trusted, the pilot works with certificate verification left on."
    with bench(tls=True) as it:
        report = it.pilot.pilot_preflight()
        it.pilot.dispatch(_mission("twin-tls-1"), "gofa")
        state = it.wait_terminal("twin-tls-1")
        ok = bool(report["observation_ready"]) and state is MissionState.COMPLETED
        return ScenarioResult("tls_trusted_ca", ok, claim, f"preflight ready, mission {state.value} over TLS", {"scheme": "https"})


def scenario_tls_untrusted(_: Any = None) -> ScenarioResult:
    claim = "An untrusted controller certificate stops the pilot: verification is really on, not decorative."
    controller = OmniCoreTwin.from_module_file(MODULE_PATH, name=CONTROLLER_NAME)
    controller.set_controller_state("motoron")
    controller.start_task()
    server = TwinServer(controller, tls=True).start()
    try:
        config = AbbRwsPilotConfig(base_url=server.base_url, username=server.username, password=server.password,
                                  expected_controller_name=CONTROLLER_NAME, commanding_enabled=True,
                                  allowed_commands=frozenset({"pilot_noop"}))
        pilot = AbbRwsPilotAdapter("abb-twin", config, http=urllib_rws_http(config))  # default trust store
        code = ""
        try:
            pilot.pilot_preflight()
        except FaspError as error:
            code = error.code
        report = pilot.pilot_preflight()
        ok = not report["observation_ready"]
        return ScenarioResult("tls_untrusted_is_refused", ok, claim,
                              "the untrusted certificate was refused" if ok else "an untrusted controller was accepted",
                              {"first_code": code, "checks": report["checks"][:1]})
    finally:
        controller.stop_task()
        server.stop()


def scenario_poll_cost(_: Any = None) -> ScenarioResult:
    claim = "One observation cycle costs a known number of RWS requests, so a poll rate can be chosen deliberately."
    with bench() as it:
        it.pilot.vehicle_state("gofa")  # first call also fetches and caches identity
        baseline = len(it.server.service.log)
        it.pilot.vehicle_state("gofa")
        per_cycle = len(it.server.service.log) - baseline
        preflight_before = len(it.server.service.log)
        it.pilot.pilot_preflight()
        per_preflight = len(it.server.service.log) - preflight_before
        # Seven reads per observation (identity is cached), ten per preflight.
        ok = per_cycle <= 8 and per_preflight <= 11
        return ScenarioResult("poll_cost", ok, claim,
                              f"{per_cycle} requests per vehicle_state, {per_preflight} per preflight",
                              {"per_vehicle_state": per_cycle, "per_preflight": per_preflight,
                               "at_2_hz": per_cycle * 2, "note": "RWS 2.0 subscriptions exist; this baseline polls"})


SCENARIOS: tuple[Callable[[Any], ScenarioResult], ...] = (
    scenario_preflight,
    scenario_noop_lifecycle,
    scenario_commit_ordering,
    scenario_duplicate_delivery,
    scenario_unknown_command_is_rejected_by_rapid,
    scenario_allowlist_refuses_offline,
    scenario_manual_mode,
    scenario_motors_off,
    scenario_estop,
    scenario_rapid_stopped,
    scenario_wrong_controller,
    scenario_no_uas_grant,
    scenario_mastership_contention,
    scenario_mastership_released_on_failure,
    scenario_restart_refuses_replay,
    scenario_rapid_cancel_branch,
    scenario_cancel_is_cooperative,
    scenario_boundary_tripwires,
    scenario_rws_1_0_is_rejected,
    scenario_unversioned_media_type,
    scenario_network_loss,
    scenario_tls_trusted,
    scenario_tls_untrusted,
    scenario_poll_cost,
)

#: What a fully passing run still does not establish.  Stated here rather than
#: in prose someone can skip, because a conformance report that implies more
#: than it proves is the failure mode this whole exercise exists to avoid.
NOT_PROVEN = (
    "This is not ABB firmware. It is a controller built from ABB's published RWS 2.0 specification; RobotWare's undocumented behaviour is not modelled.",
    "No robot moved. `pilot_noop` has no motion, so nothing here is evidence about trajectories, singularities, payload, or tool behaviour.",
    "No safety function was exercised. The E-stop, protective scanner, and SafeMove configuration are outside this software and remain the integrator's responsibility.",
    "Timing is not real-time. The twin runs on a general-purpose OS, so latency figures here do not bound the controller's.",
    "The mobile base is absent entirely. Nothing here says anything about the LiDAR platform or an arm-on-base composite cell.",
)


def run_all(*, include_tls: bool = True) -> list[ScenarioResult]:
    """Run every scenario, isolated, and return results in declaration order."""

    results: list[ScenarioResult] = []
    for scenario in SCENARIOS:
        if not include_tls and "tls" in scenario.__name__:
            continue
        try:
            results.append(scenario(None))
        except Exception as error:  # a scenario that crashes is a failing scenario
            results.append(ScenarioResult(scenario.__name__.removeprefix("scenario_"), False,
                                          "scenario did not complete", f"{type(error).__name__}: {error}"))
    return results
