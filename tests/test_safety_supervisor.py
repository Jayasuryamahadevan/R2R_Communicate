"""The supervisory safety object, and the boundary it refuses to cross."""

from __future__ import annotations

import unittest

from fasp_harness.layers import LayerViolation
from fasp_harness.protocol.errors import FaspError
from fasp_harness.safety.drivers import SafetyStatus, SimulatedSafetyController
from fasp_harness.safety.interlock import LOCAL_OPERATOR, NETWORK_ORIGINS, SafetyFunction, SafetySupervisor


class SafetyStatusTests(unittest.TestCase):
    def test_unknown_state_is_an_unsafe_state(self) -> None:
        self.assertFalse(SafetyStatus.unreachable("dev", "cable cut").safe_to_move)

    def test_every_channel_must_positively_agree(self) -> None:
        base = {"reachable": True, "estop_clear": True, "protective_stop_clear": True, "guards_closed": True, "reset_required": False}
        self.assertTrue(SafetyStatus(**base).safe_to_move)
        for field in ("estop_clear", "protective_stop_clear", "guards_closed"):
            with self.subTest(field=field):
                self.assertFalse(SafetyStatus(**{**base, field: False}).safe_to_move)
        self.assertFalse(SafetyStatus(**{**base, "reset_required": True}).safe_to_move)
        self.assertFalse(SafetyStatus(**{**base, "stale": True}).safe_to_move)


class SimulatedControllerTests(unittest.TestCase):
    def test_releasing_the_button_is_not_a_reset(self) -> None:
        """The classic and dangerous integration bug: treating the button
        coming back up as permission to move again."""
        controller = SimulatedSafetyController()
        controller.press_estop()
        self.assertFalse(controller.read_status().safe_to_move)
        controller.release_estop()
        self.assertFalse(controller.read_status().safe_to_move, "The stop must stay latched after the button is released.")
        self.assertTrue(controller.manual_reset())
        self.assertTrue(controller.read_status().safe_to_move)

    def test_reset_is_refused_while_a_demand_is_present(self) -> None:
        controller = SimulatedSafetyController()
        controller.press_estop()
        self.assertFalse(controller.manual_reset())
        controller.release_estop()
        self.assertTrue(controller.manual_reset())

    def test_it_declares_itself_as_carrying_no_integrity(self) -> None:
        described = SimulatedSafetyController().describe()
        self.assertFalse(described["real_hardware"])
        self.assertIn("no safety integrity", described["integrity_claim"])


class SupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = SimulatedSafetyController()
        self.supervisor = SafetySupervisor(self.controller, stale_after_s=2.0)
        self.supervisor.poll()

    def test_permits_motion_when_everything_is_clear(self) -> None:
        self.supervisor.permit_motion(requested_speed_mps=1.0, reservation_active=True)

    def test_a_halt_latches_and_blocks_dispatch(self) -> None:
        self.supervisor.demand_halt("peer", "operator pressed the panel button", origin="peer")
        self.assertTrue(self.supervisor.latched)
        with self.assertRaises(FaspError) as raised:
            self.supervisor.permit_motion()
        self.assertEqual(raised.exception.code, "safety.estop_active")

    def test_no_network_origin_can_clear_a_halt(self) -> None:
        """The layer boundary, tested from every direction it could be
        crossed. `NETWORK_ORIGINS` is enumerated so a new escalation path
        cannot accidentally become a new clearing path."""
        self.supervisor.demand_halt("peer", "test", origin="peer")
        for origin in sorted(NETWORK_ORIGINS):
            with self.subTest(origin=origin), self.assertRaises(LayerViolation):
                self.supervisor.clear(origin=origin, operator="whoever")
        self.assertTrue(self.supervisor.latched)

    def test_a_local_operator_can_clear_only_once_the_machine_agrees(self) -> None:
        self.controller.press_estop()
        self.supervisor.poll()
        with self.assertRaises(FaspError) as raised:
            self.supervisor.clear(origin=LOCAL_OPERATOR, operator="engineer")
        self.assertEqual(raised.exception.code, "safety.precondition_failed")

        self.controller.release_estop()
        self.controller.manual_reset()
        cleared = self.supervisor.clear(origin=LOCAL_OPERATOR, operator="engineer", note="area checked")
        self.assertEqual(cleared["cleared_by"], "engineer")
        self.assertFalse(self.supervisor.latched)

    def test_an_unreachable_controller_withdraws_permission(self) -> None:
        self.controller.set_unreachable(True)
        self.supervisor.poll()
        with self.assertRaises(FaspError) as raised:
            self.supervisor.permit_motion()
        self.assertEqual(raised.exception.code, "safety.precondition_failed")
        self.assertIn("unreachable", raised.exception.detail)

    def test_a_stale_sample_is_treated_as_unsafe(self) -> None:
        supervisor = SafetySupervisor(self.controller, stale_after_s=0.0)
        supervisor.poll()
        with self.assertRaises(FaspError) as raised:
            supervisor.permit_motion()
        self.assertEqual(raised.exception.code, "safety.precondition_failed")
        self.assertIn("old", raised.exception.detail)

    def test_a_controller_reporting_its_own_demand_latches_the_supervisor(self) -> None:
        """Closes the race where a dispatch decision is made microseconds
        after an observation that should have stopped it."""
        self.controller.set_zone_violated(True)
        self.supervisor.poll()
        self.assertTrue(self.supervisor.latched)

    def test_a_speed_above_the_supervisory_envelope_is_refused(self) -> None:
        supervisor = SafetySupervisor(self.controller, max_speed_mps=1.0)
        supervisor.poll()
        with self.assertRaises(FaspError) as raised:
            supervisor.permit_motion(requested_speed_mps=2.0)
        self.assertEqual(raised.exception.code, "safety.speed_limit")

    def test_a_deployment_with_no_controller_refuses_motion_by_default(self) -> None:
        supervisor = SafetySupervisor(None)
        ok, reason = supervisor.permitted()
        self.assertFalse(ok)
        self.assertIn("no safety controller", reason.lower())

    def test_a_driver_that_raises_becomes_an_unreachable_status(self) -> None:
        class Broken:
            device = "broken"

            def read_status(self):
                raise RuntimeError("bus fault")

            def request_stop(self, reason: str) -> bool:
                return False

            def describe(self) -> dict:
                return {"real_hardware": False}

        supervisor = SafetySupervisor(Broken())
        status = supervisor.poll()
        self.assertFalse(status.reachable)
        self.assertFalse(status.safe_to_move)

    def test_a_halt_is_forwarded_to_the_controller(self) -> None:
        demand = self.supervisor.demand_halt("watchdog", "control plane stalled", origin="watchdog")
        self.assertTrue(demand.forwarded_to_controller)
        self.assertEqual(len(self.controller.stop_requests), 1)

    def test_demand_history_is_bounded(self) -> None:
        for index in range(400):
            self.supervisor.demand_halt("peer", f"demand {index}", origin="peer")
        self.assertEqual(self.supervisor.status()["demand_count"], 400)
        self.assertLessEqual(len(self.supervisor.status()["recent_demands"]), 5)


class SafetyFunctionDeclarationTests(unittest.TestCase):
    def test_a_safety_function_must_be_declared_at_layer_one(self) -> None:
        from fasp_harness.layers import Layer

        with self.assertRaises(LayerViolation):
            SafetyFunction(id="sf-1", description="", integrity_level="PL d", standard="ISO 13849-1", implemented_by="PNOZmulti", layer=Layer.L3_FLEET)

    def test_claiming_this_software_implements_a_safety_function_is_detectable(self) -> None:
        claimed = SafetyFunction(id="sf-1", description="E-stop", integrity_level="PL d", standard="ISO 13849-1", implemented_by="this software")
        real = SafetyFunction(id="sf-2", description="E-stop", integrity_level="PL d", standard="ISO 13849-1", implemented_by="Pilz PNOZ s3")
        self.assertTrue(claimed.implemented_in_software_here)
        self.assertFalse(real.implemented_in_software_here)

    def test_evidence_is_observation_only_and_says_so(self) -> None:
        supervisor = SafetySupervisor(SimulatedSafetyController())
        supervisor.register_function(SafetyFunction(id="sf-estop", description="Category 0 stop", integrity_level="PL d Cat 3", standard="ISO 13849-1", implemented_by="Pilz PNOZ s3", response_time_ms=20.0))
        evidence = supervisor.evidence()
        self.assertTrue(evidence["observed_only"])
        self.assertEqual(evidence["layer"], 1)
        self.assertEqual(len(evidence["declared_functions"]), 1)
        self.assertIn("does not implement", evidence["note"])


if __name__ == "__main__":
    unittest.main()
