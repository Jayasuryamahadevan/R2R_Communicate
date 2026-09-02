"""The twin itself, and the conformance run it exists to support.

Two layers are tested separately on purpose. A twin that is wrong is worse than
no twin, because it manufactures confidence -- so the interpreter, the
controller model and the RWS surface are each pinned here against ABB's
documented behaviour. Only then is the scenario matrix worth running.
"""

from __future__ import annotations

import base64
import unittest

from fasp_harness.__main__ import INDUSTRIAL_COMMANDS
from fasp_harness.fleet.abb_twin import NOT_PROVEN, OmniCoreTwin, RwsRequest, RwsService, TwinServer, parse_module, run_all
from fasp_harness.fleet.abb_twin.rapid import RapidTask, parse_value, render
from fasp_harness.fleet.abb_twin.scenarios import MODULE_PATH
from fasp_harness.protocol.errors import FaspError

AUTH = "Basic " + base64.b64encode(b"fasp-pilot:pilot-secret").decode()
READ = {"authorization": AUTH, "accept": "application/xhtml+xml;v=2.0"}
WRITE = {**READ, "content-type": "application/x-www-form-urlencoded;v=2.0"}
SYMBOL = "/rw/rapid/symbol/RAPID/T_ROB1/FASP_Pilot/{}/data"


def twin(**kwargs: object) -> OmniCoreTwin:
    controller = OmniCoreTwin.from_module_file(MODULE_PATH, **kwargs)  # type: ignore[arg-type]
    controller.set_controller_state("motoron")
    return controller


class RapidInterpreterTests(unittest.TestCase):
    def test_the_shipped_module_parses_and_declares_the_mailbox(self) -> None:
        module = parse_module(MODULE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(module.name, "FASP_Pilot")
        self.assertIn("fasp_pilotmain", module.procedures)
        self.assertEqual(
            [declaration.name for declaration in module.persistents],
            ["fasp_protocol_version", "fasp_command_seq", "fasp_ack_seq", "fasp_mission_id",
             "fasp_command", "fasp_result", "fasp_detail", "fasp_cancel_requested"],
        )

    def test_rapid_text_round_trips_the_way_rws_shows_it(self) -> None:
        self.assertEqual(render(1.0), "1")
        self.assertEqual(render(0.25), "0.25")
        self.assertEqual(render("IDLE"), '"IDLE"')
        self.assertEqual(render(False), "FALSE")
        self.assertEqual(parse_value('"IDLE"'), "IDLE")
        self.assertEqual(parse_value("TRUE"), True)
        self.assertEqual(parse_value("7"), 7.0)

    def test_a_construct_the_interpreter_cannot_run_is_refused_not_skipped(self) -> None:
        # A motion instruction must fail loudly: silently skipping it would let
        # the twin "run" a module that moves a real robot.
        for source in (
            "MODULE M\n  PROC P()\n    MoveJ p10, v100, fine, tool0;\n  ENDPROC\nENDMODULE",
            "MODULE M\n  PERS robtarget p10;\n  PROC P()\n  ENDPROC\nENDMODULE",
            "MODULE M\n  PROC P()\n    IF TRUE THEN\n  ENDPROC\nENDMODULE",
        ):
            with self.subTest(source=source.splitlines()[1].strip()), self.assertRaises(FaspError):
                parse_module(source)

    def test_an_undeclared_assignment_stops_the_task_visibly(self) -> None:
        module = parse_module("MODULE M\n  PERS num a := 0;\n  PROC P()\n    b := 1;\n  ENDPROC\nENDMODULE")
        store = OmniCoreTwin("MODULE M\n  PERS num a := 0;\n  PROC P()\n  ENDPROC\nENDMODULE", entry="P")
        report = RapidTask(module, store, "P").run()
        self.assertIsNotNone(report.error)
        self.assertIn("not declared", str(report.error))

    def test_persistent_writes_go_to_the_controller_not_a_local_copy(self) -> None:
        controller = twin()
        controller.start_task()
        try:
            self.assertEqual(controller.read_symbol("fasp_result"), '"IDLE"')
            self.assertEqual(controller.read_symbol("fasp_detail"), '"ready"')
        finally:
            controller.stop_task()


class ControllerModelTests(unittest.TestCase):
    def test_leaving_auto_or_dropping_motors_stops_execution(self) -> None:
        for action in ("mode", "motors"):
            with self.subTest(action=action):
                controller = twin()
                controller.start_task()
                self.assertEqual(controller.execution_state, "running")
                if action == "mode":
                    controller.set_operation_mode("MANR")
                else:
                    controller.set_controller_state("motoroff")
                self.assertEqual(controller.execution_state, "stopped")

    def test_persistent_values_survive_a_restart_so_replay_refusal_can_work(self) -> None:
        controller = twin()
        controller.start_task()
        controller.write_symbol("fasp_command_seq", "4")
        controller.restart_controller()
        try:
            self.assertEqual(controller.read_symbol("fasp_command_seq"), "4")
            self.assertEqual(controller.read_symbol("fasp_result"), '"FAILED"')
            self.assertEqual(controller.read_symbol("fasp_detail"), '"restart_refused_replay"')
        finally:
            controller.stop_task()

    def test_mastership_is_scoped_to_a_session_not_to_the_account(self) -> None:
        controller = twin()
        self.assertTrue(controller.request_mastership("edit", "session-a"))
        self.assertFalse(controller.request_mastership("edit", "session-b"))
        self.assertFalse(controller.release_mastership("edit", "session-b"))
        self.assertTrue(controller.release_mastership("edit", "session-a"))
        self.assertTrue(controller.request_mastership("edit", "session-b"))

    def test_the_twin_exposes_no_way_for_the_network_to_start_rapid(self) -> None:
        controller = twin()
        service = RwsService(controller)
        for path in ("/rw/rapid/execution/start", "/rw/panel/ctrl-state"):
            with self.subTest(path=path):
                service.handle(RwsRequest("POST", path, {}, WRITE, b""))
        self.assertEqual(controller.execution_state, "stopped")
        self.assertEqual([hit.path for hit in controller.tripwires], ["/rw/rapid/execution/start", "/rw/panel/ctrl-state"])


class RwsSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = twin()
        self.controller.start_task()
        self.service = RwsService(self.controller)
        self.addCleanup(self.controller.stop_task)

    def get(self, path: str, headers: dict[str, str] | None = None, session: str = "s1") -> int:
        return self.service.handle(RwsRequest("GET", path, {}, headers or READ, b"", session)).status

    def post(self, path: str, body: bytes = b"", headers: dict[str, str] | None = None, session: str = "s1", query: dict[str, str] | None = None) -> int:
        return self.service.handle(RwsRequest("POST", path, query or {}, headers or WRITE, body, session)).status

    def test_unauthenticated_requests_are_challenged(self) -> None:
        response = self.service.handle(RwsRequest("GET", "/ctrl/identity", {}, {"accept": "application/xhtml+xml;v=2.0"}))
        self.assertEqual(response.status, 401)
        self.assertIn("Basic", response.headers.get("WWW-Authenticate", ""))

    def test_media_types_must_carry_the_rws_2_0_version(self) -> None:
        self.assertEqual(self.get("/ctrl/identity", {**READ, "accept": "application/xhtml+xml"}), 406)
        self.assertEqual(self.get("/ctrl/identity"), 200)
        self.assertEqual(self.post("/rw/mastership/edit/request", headers={**READ, "content-type": "application/x-www-form-urlencoded"}), 415)

    def test_rws_1_0_spellings_are_not_served(self) -> None:
        for path in ("/rw/panel/ctrlstate", "/rw/rapid/symbol/data/RAPID/T_ROB1/FASP_Pilot/fasp_result"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path), 404)

    def test_symbol_writes_are_refused_in_the_controllers_own_order(self) -> None:
        path, body = SYMBOL.format("fasp_detail"), b"value=%22x%22"
        self.assertEqual(self.post(path, body), 403)  # no mastership
        self.assertEqual(self.post("/rw/mastership/edit/request"), 204)
        self.assertEqual(self.post(path, body), 204)
        # The grant is checked before mastership: removing it refuses a holder.
        self.controller.grants.clear()
        self.assertEqual(self.post(path, body), 403)

    def test_manual_mode_needs_rmmp_before_a_write(self) -> None:
        self.controller.set_operation_mode("MANR")
        self.assertEqual(self.post("/rw/mastership/edit/request"), 403)
        self.controller.grant_rmmp("s1")
        self.assertEqual(self.post("/rw/mastership/edit/request"), 204)
        self.assertEqual(self.post(SYMBOL.format("fasp_detail"), b"value=%22x%22"), 204)

    def test_implicit_mastership_takes_and_releases_around_one_write(self) -> None:
        self.assertEqual(self.post(SYMBOL.format("fasp_detail"), b"value=%22x%22", query={"mastership": "implicit"}), 204)
        self.assertIsNone(self.controller.mastership_holder("edit"))

    def test_unknown_symbols_and_bad_values_are_distinguished(self) -> None:
        self.assertEqual(self.post("/rw/mastership/edit/request"), 204)
        self.assertEqual(self.post(SYMBOL.format("fasp_nonexistent"), b"value=1"), 404)
        self.assertEqual(self.post(SYMBOL.format("fasp_mission_id"), b"value=1"), 400)
        self.assertEqual(self.post(SYMBOL.format("fasp_mission_id"), b"value=%22ok%22"), 204)

    def test_a_second_session_cannot_take_held_mastership(self) -> None:
        self.assertEqual(self.post("/rw/mastership/edit/request", session="s1"), 204)
        self.assertEqual(self.post("/rw/mastership/edit/request", session="s2"), 409)
        self.assertEqual(self.post(SYMBOL.format("fasp_detail"), b"value=%22x%22", session="s2"), 403)


class TwinServerTests(unittest.TestCase):
    def test_tls_mode_serves_a_certificate_a_client_must_be_told_to_trust(self) -> None:
        controller = twin()
        server = TwinServer(controller, tls=True).start()
        self.addCleanup(server.stop)
        self.assertTrue(server.base_url.startswith("https://"))
        self.assertIsNotNone(server.client_ssl_context())
        self.assertIn(b"BEGIN CERTIFICATE", server.ca_pem or b"")


class ConformanceSuiteTests(unittest.TestCase):
    def test_the_commands_are_routed_to_the_industrial_cli(self) -> None:
        self.assertIn("abb-twin", INDUSTRIAL_COMMANDS)
        self.assertIn("abb-conformance", INDUSTRIAL_COMMANDS)

    def test_the_suite_states_what_it_cannot_establish(self) -> None:
        self.assertTrue(any("not ABB firmware" in item for item in NOT_PROVEN))
        self.assertTrue(any("No robot moved" in item for item in NOT_PROVEN))

    def test_every_scenario_passes_against_the_twin(self) -> None:
        results = run_all()
        failed = [f"{item.name}: {item.detail}" for item in results if not item.ok]
        self.assertEqual(failed, [], f"{len(failed)} of {len(results)} scenarios failed")
        self.assertGreaterEqual(len(results), 24)


if __name__ == "__main__":
    unittest.main()
