"""ABB GoFa pilot adapter: RWS wire shape and the safety boundary."""

from __future__ import annotations

import unittest
import urllib.parse
from unittest.mock import patch

from fasp_harness.__main__ import INDUSTRIAL_COMMANDS
from fasp_harness.deployment import NodeConfig, _build_registry
from fasp_harness.fleet.abb_rws import AbbRwsPilotAdapter, AbbRwsPilotConfig, parse_rws_xhtml
from fasp_harness.fleet.model import Mission, MissionState
from fasp_harness.protocol.errors import FaspError


def xhtml(**values: str) -> bytes:
    spans = "".join(f'<span class="{name}">{value}</span>' for name, value in values.items())
    return f'<html xmlns="http://www.w3.org/1999/xhtml"><body><div class="state">{spans}</div></body></html>'.encode()


def rapid_data(value: str) -> bytes:
    """ABB's documented RWS 2.0 symbol-data reply, extra spans and all.

    The surrounding `rap-data-decl-pos` spans are in the real response and are
    included on purpose: the parser must still pick `value` out of them.
    """

    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<html xmlns="http://www.w3.org/1999/xhtml"><body><div class="state">'
        '<a href="" rel="self"></a><ul>'
        f'<li class="rap-data" title="RAPID/T_ROB1/FASP_Pilot"><span class="value">{value}</span></li>'
        '<li class="rap-data-decl-pos" title="decl-pos"><span class="begin-row">9</span>'
        '<span class="begin-column">2</span><span class="end-row">9</span><span class="end-column">34</span></li>'
        "</ul></div></body></html>"
    ).encode()


def symbol_writes(fake: FakeRws) -> list[tuple[str, str]]:
    """(symbol, written value) for each mailbox write, in wire order."""

    return [(url.rsplit("/", 2)[-2], form["value"]) for method, url, form in fake.requests if method == "POST" and url.endswith("/data")]


def posted_paths(fake: FakeRws) -> list[str]:
    return [urllib.parse.urlsplit(url).path for method, url, _form in fake.requests if method == "POST"]


def mission(mission_id: str = "pilot-1", command: str = "pilot_noop") -> Mission:
    return Mission.from_dict(
        {"mission_id": mission_id, "steps": [{"kind": "custom", "parameters": {"command": command}}]},
        requested_by="fasp:system:test",
    )


class FakeRws:
    def __init__(self) -> None:
        self.identity = "GOFA-LAB-01"
        self.opmode = "AUTO"
        self.ctrlstate = "motoron"
        self.execution = "running"
        self.symbols = {
            "fasp_protocol_version": '"1"',
            "fasp_command_seq": "0",
            "fasp_ack_seq": "0",
            "fasp_mission_id": '"none"',
            "fasp_command": '"none"',
            "fasp_result": '"IDLE"',
            "fasp_detail": '"ready"',
            "fasp_cancel_requested": "FALSE",
        }
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.fail_once_on_symbol: str | None = None
        self.mastership_held = False
        self.refuse_mastership = False

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        form = {key: values[-1] for key, values in urllib.parse.parse_qs((body or b"").decode()).items()}
        self.requests.append((method, url, form))
        path = urllib.parse.urlsplit(url).path
        if path == "/ctrl/identity":
            return 200, xhtml(**{"ctrl-name": self.identity, "ctrl-type": "Real Controller"})
        if path == "/rw/panel/opmode":
            return 200, xhtml(opmode=self.opmode)
        if path == "/rw/panel/ctrl-state":
            return 200, xhtml(ctrlstate=self.ctrlstate)
        if path == "/rw/rapid/execution":
            return 200, xhtml(ctrlexecstate=self.execution, cycle="forever")
        if path.endswith("/robtarget"):
            return 200, xhtml(x="515", y="0", z="712", q1="0.7071068", q2="0", q3="0.7071068", q4="0")
        if method == "POST" and path == "/rw/mastership/edit/request":
            if self.refuse_mastership:
                return 403, b""
            self.mastership_held = True
            return 204, b""
        if method == "POST" and path == "/rw/mastership/edit/release":
            self.mastership_held = False
            return 204, b""
        if path.startswith("/rw/rapid/symbol/") and path.endswith("/data"):
            symbol = path.rsplit("/", 2)[-2]
            if method == "POST":
                if not self.mastership_held:
                    # RWS 2.0 defaults `mastership` to explicit; a write from a
                    # client holding nothing is refused, it does not fall back.
                    return 403, b""
                if self.fail_once_on_symbol == symbol:
                    self.fail_once_on_symbol = None
                    return 503, b""
                self.symbols[symbol] = form["value"]
                return 204, b""
            return 200, rapid_data(self.symbols[symbol])
        # Every RWS 1.0 path -- `/rw/panel/ctrlstate`, `/rw/rapid/symbol/data/`,
        # `?action=set` -- lands here, exactly as RobotWare 7 answers it.
        return 404, b""


def adapter(fake: FakeRws, *, enabled: bool = True, allowed: frozenset[str] = frozenset({"pilot_noop"}), expected: str = "GOFA-LAB-01") -> AbbRwsPilotAdapter:
    return AbbRwsPilotAdapter(
        "abb-lab",
        AbbRwsPilotConfig(
            base_url="https://192.0.2.10",
            username="pilot",
            password="secret",
            expected_controller_name=expected,
            commanding_enabled=enabled,
            allowed_commands=allowed,
        ),
        http=fake,
    )


class AbbRwsParsingTests(unittest.TestCase):
    def test_abb_pilot_check_is_routed_to_the_industrial_cli(self) -> None:
        self.assertIn("abb-pilot-check", INDUSTRIAL_COMMANDS)

    def test_official_xhtml_span_shape_is_parsed(self) -> None:
        parsed = parse_rws_xhtml(xhtml(opmode="MANR", ctrlexecstate="stopped"))
        self.assertEqual(parsed, {"opmode": "MANR", "ctrlexecstate": "stopped"})

    def test_malformed_controller_document_is_not_treated_as_state(self) -> None:
        with self.assertRaises(FaspError):
            parse_rws_xhtml(b"<html>")

    def test_https_is_the_default_and_commanding_pins_identity(self) -> None:
        with self.assertRaises(FaspError):
            AbbRwsPilotConfig(base_url="http://192.0.2.10", username="u", password="p")
        with self.assertRaises(FaspError):
            AbbRwsPilotConfig(base_url="https://192.0.2.10", username="u", password="p", commanding_enabled=True)

    def test_node_config_resolves_password_from_environment_only(self) -> None:
        config = NodeConfig(
            fleets=[
                {
                    "kind": "abb-rws-pilot",
                    "fleet": "abb-lab",
                    "base_url": "https://192.0.2.10",
                    "username": "pilot",
                    "password_env": "TEST_ABB_RWS_PASSWORD",
                    "expected_controller_name": "GOFA-LAB-01",
                    "commanding_enabled": True,
                    "allowed_commands": ["pilot_noop"],
                }
            ]
        )
        with patch.dict("os.environ", {"TEST_ABB_RWS_PASSWORD": "environment-secret"}):
            built = _build_registry(config).adapter("abb-lab")
        self.assertIsInstance(built, AbbRwsPilotAdapter)
        self.assertNotIn("environment-secret", repr(built.config))

    def test_node_config_refuses_a_missing_secret(self) -> None:
        config = NodeConfig(
            fleets=[{"kind": "abb-rws-pilot", "fleet": "abb-lab", "base_url": "https://192.0.2.10", "username": "pilot", "password_env": "MISSING_ABB_SECRET"}]
        )
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(FaspError):
            _build_registry(config)


class AbbRwsPilotTests(unittest.TestCase):
    def test_observation_keeps_arm_tcp_out_of_mobile_map_pose(self) -> None:
        fake = FakeRws()
        state = adapter(fake, enabled=False, expected=None).vehicle_state("gofa")
        self.assertIsNone(state.pose)
        self.assertEqual(state.vendor_state["tcp_robtarget_base_mm"]["x"], 515.0)
        self.assertEqual(state.operating_mode.value, "AUTOMATIC")
        self.assertTrue(state.dispatchable()[0])

    def test_observation_only_is_deny_by_default(self) -> None:
        fake = FakeRws()
        with self.assertRaises(FaspError) as raised:
            adapter(fake, enabled=False, expected=None).dispatch(mission(), "gofa")
        self.assertEqual(raised.exception.code, "auth.not_authorized")
        self.assertFalse(any(method == "POST" for method, _url, _form in fake.requests))

    def test_dispatch_commits_sequence_last(self) -> None:
        fake = FakeRws()
        result = adapter(fake).dispatch(mission(), "gofa")
        writes = symbol_writes(fake)
        self.assertEqual([name for name, _value in writes], [
            "fasp_mission_id",
            "fasp_command",
            "fasp_detail",
            "fasp_result",
            "fasp_cancel_requested",
            "fasp_command_seq",
        ])
        self.assertEqual(writes[-1][1], "1")
        self.assertFalse(result["idempotent"])
        self.assertEqual(result["sequence"], 1)

    def test_retry_of_same_mission_does_not_execute_twice(self) -> None:
        fake = FakeRws()
        pilot = adapter(fake)
        pilot.dispatch(mission(), "gofa")
        posts_after_first = sum(method == "POST" for method, _url, _form in fake.requests)
        result = pilot.dispatch(mission(), "gofa")
        self.assertTrue(result["idempotent"])
        self.assertEqual(sum(method == "POST" for method, _url, _form in fake.requests), posts_after_first)

    def test_retry_finishes_a_mailbox_write_that_failed_before_commit(self) -> None:
        fake = FakeRws()
        fake.fail_once_on_symbol = "fasp_result"
        pilot = adapter(fake)
        with self.assertRaises(FaspError):
            pilot.dispatch(mission(), "gofa")
        self.assertEqual(fake.symbols["fasp_command_seq"], "0")

        result = pilot.dispatch(mission(), "gofa")
        self.assertFalse(result["idempotent"])
        self.assertEqual(fake.symbols["fasp_command_seq"], "1")

    def test_only_one_locally_allowlisted_custom_command_is_accepted(self) -> None:
        fake = FakeRws()
        pilot = adapter(fake)
        with self.assertRaises(FaspError):
            pilot.dispatch(mission(command="pilot_home"), "gofa")
        move = Mission.from_dict({"mission_id": "move-1", "steps": [{"kind": "move", "node_id": "A"}]}, requested_by="test")
        with self.assertRaises(FaspError):
            pilot.dispatch(move, "gofa")
        self.assertFalse(any(method == "POST" for method, _url, _form in fake.requests))

    def test_wrong_controller_manual_mode_and_stopped_rapid_are_refused(self) -> None:
        cases = (("identity", "OTHER"), ("opmode", "MANR"), ("execution", "stopped"), ("ctrlstate", "motoroff"))
        for attribute, value in cases:
            with self.subTest(attribute=attribute):
                fake = FakeRws()
                setattr(fake, attribute, value)
                with self.assertRaises(FaspError):
                    adapter(fake).dispatch(mission(), "gofa")
                self.assertFalse(any(method == "POST" for method, _url, _form in fake.requests))

    def test_cancel_is_cooperative_and_never_calls_motor_or_safety_endpoints(self) -> None:
        fake = FakeRws()
        pilot = adapter(fake)
        pilot.dispatch(mission(), "gofa")
        self.assertTrue(pilot.cancel("pilot-1"))
        self.assertEqual(symbol_writes(fake)[-1], ("fasp_cancel_requested", "TRUE"))
        self.assertFalse(any("ctrl-state" in path or "iosystem" in path or "safety" in path for path in posted_paths(fake)))

    def test_terminal_result_maps_to_fasp_state(self) -> None:
        fake = FakeRws()
        fake.symbols["fasp_mission_id"] = '"pilot-1"'
        fake.symbols["fasp_result"] = '"COMPLETED"'
        self.assertEqual(adapter(fake).mission_state("pilot-1"), MissionState.COMPLETED)

    def test_read_only_preflight_reports_mailbox_and_command_readiness(self) -> None:
        report = adapter(FakeRws()).pilot_preflight()
        self.assertTrue(report["observation_ready"])
        self.assertTrue(report["ready_for_noop"])
        self.assertEqual(report["mailbox"]["protocol"], "1")
        self.assertIn("No safety approval", report["safety_claim"])

    def test_preflight_explains_a_manual_controller_without_writing(self) -> None:
        fake = FakeRws()
        fake.opmode = "MANR"
        pilot = adapter(fake)
        report = pilot.pilot_preflight()
        self.assertTrue(report["observation_ready"])
        self.assertFalse(report["ready_for_noop"])
        self.assertEqual(dict((check["name"], check["ok"]) for check in report["checks"])["operation_mode"], False)
        self.assertFalse(any(method == "POST" for method, _url, _form in fake.requests))

    def test_mailbox_uses_the_rws_2_0_symbol_url_and_not_the_rws_1_0_one(self) -> None:
        fake = FakeRws()
        adapter(fake).dispatch(mission(), "gofa")
        paths = [urllib.parse.urlsplit(url).path for _method, url, _form in fake.requests]
        self.assertIn("/rw/rapid/symbol/RAPID/T_ROB1/FASP_Pilot/fasp_command/data", paths)
        self.assertIn("/rw/panel/ctrl-state", paths)
        # RobotWare 7 removed both of these; asking for them is a silent 404.
        self.assertFalse(any("/rw/rapid/symbol/data/" in url or "action=set" in url for _m, url, _f in fake.requests))
        self.assertFalse(any(path == "/rw/panel/ctrlstate" for path in paths))

    def test_a_real_rws_2_0_symbol_document_still_yields_one_value(self) -> None:
        self.assertEqual(parse_rws_xhtml(rapid_data('"IDLE"'))["value"], '"IDLE"')

    def test_writes_are_bracketed_by_edit_mastership(self) -> None:
        fake = FakeRws()
        adapter(fake).dispatch(mission(), "gofa")
        posts = posted_paths(fake)
        self.assertEqual(posts[0], "/rw/mastership/edit/request")
        self.assertEqual(posts[-1], "/rw/mastership/edit/release")
        # Taken once for the whole block, not per write: that is what stops a
        # second RWS client landing a write between the payload and the commit.
        self.assertEqual(posts.count("/rw/mastership/edit/request"), 1)
        self.assertFalse(fake.mastership_held)

    def test_mastership_is_never_taken_before_the_preconditions_pass(self) -> None:
        for attribute, value in (("opmode", "MANR"), ("execution", "stopped")):
            with self.subTest(attribute=attribute):
                fake = FakeRws()
                setattr(fake, attribute, value)
                with self.assertRaises(FaspError):
                    adapter(fake).dispatch(mission(), "gofa")
                self.assertEqual(posted_paths(fake), [])

    def test_mastership_is_released_when_a_write_fails_midway(self) -> None:
        fake = FakeRws()
        fake.fail_once_on_symbol = "fasp_result"
        with self.assertRaises(FaspError):
            adapter(fake).dispatch(mission(), "gofa")
        self.assertFalse(fake.mastership_held)
        self.assertEqual(posted_paths(fake)[-1], "/rw/mastership/edit/release")
        self.assertEqual(fake.symbols["fasp_command_seq"], "0")

    def test_a_controller_that_refuses_mastership_refuses_the_mission(self) -> None:
        fake = FakeRws()
        fake.refuse_mastership = True
        with self.assertRaises(FaspError) as raised:
            adapter(fake).dispatch(mission(), "gofa")
        self.assertEqual(raised.exception.code, "auth.not_authorized")
        self.assertEqual(symbol_writes(fake), [])

    def test_description_never_contains_credentials_or_motion_primitives(self) -> None:
        description = adapter(FakeRws()).describe()
        self.assertNotIn("secret", repr(description))
        self.assertIn("joint or Cartesian motion targets", description["not_provided"])


if __name__ == "__main__":
    unittest.main()
