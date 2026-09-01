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

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        form = {key: values[-1] for key, values in urllib.parse.parse_qs((body or b"").decode()).items()}
        self.requests.append((method, url, form))
        path = urllib.parse.urlsplit(url).path
        query = urllib.parse.urlsplit(url).query
        if path == "/ctrl/identity":
            return 200, xhtml(**{"ctrl-name": self.identity, "ctrl-type": "Real Controller"})
        if path == "/rw/panel/opmode":
            return 200, xhtml(opmode=self.opmode)
        if path == "/rw/panel/ctrlstate":
            return 200, xhtml(ctrlstate=self.ctrlstate)
        if path == "/rw/rapid/execution":
            return 200, xhtml(ctrlexecstate=self.execution, cycle="forever")
        if path.endswith("/robtarget"):
            return 200, xhtml(x="515", y="0", z="712", q1="0.707", q2="0", q3="0.707", q4="0")
        if "/rw/rapid/symbol/data/" in path:
            symbol = path.rsplit("/", 1)[-1]
            if method == "POST" and query == "action=set":
                if self.fail_once_on_symbol == symbol:
                    self.fail_once_on_symbol = None
                    return 503, b""
                self.symbols[symbol] = form["value"]
                return 204, b""
            return 200, xhtml(value=self.symbols[symbol])
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
        writes = [(url.rsplit("/", 1)[-1].split("?", 1)[0], form["value"]) for method, url, form in fake.requests if method == "POST"]
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
        writes = [url for method, url, _form in fake.requests if method == "POST"]
        self.assertTrue(writes[-1].endswith("fasp_cancel_requested?action=set"))
        self.assertFalse(any("ctrlstate" in url or "iosystem" in url or "safety" in url for url in writes))

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

    def test_description_never_contains_credentials_or_motion_primitives(self) -> None:
        description = adapter(FakeRws()).describe()
        self.assertNotIn("secret", repr(description))
        self.assertIn("joint or Cartesian motion targets", description["not_provided"])


if __name__ == "__main__":
    unittest.main()
