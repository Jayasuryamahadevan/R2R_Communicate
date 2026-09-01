"""Multi-vendor fleet coordination: the model, VDA 5050, and the registry."""

from __future__ import annotations

import json
import unittest

from fasp_harness.fleet.adapter import FleetRegistry
from fasp_harness.fleet.model import Mission, MissionState, OperatingMode, Pose, StepKind, VehicleCapabilities, VehicleState
from fasp_harness.fleet.rest import EndpointSpec, FieldMap, RestFleetAdapter
from fasp_harness.fleet.simulated import SimulatedFleetManager
from fasp_harness.fleet.vda5050 import (
    INSTANT_ACTIONS,
    OrderBuilder,
    Vda5050Adapter,
    Vda5050Error,
    mission_state_from,
    parse_factsheet,
    parse_state,
    topic,
)
from fasp_harness.protocol.errors import FaspError


def a_mission(mission_id: str = "m1", steps: list[dict] | None = None, **extra) -> Mission:
    return Mission.from_dict(
        {"mission_id": mission_id, "steps": steps or [{"kind": "move", "node_id": "dock-7"}, {"kind": "pick", "node_id": "dock-7", "parameters": {"load": "tote-42"}}], **extra},
        requested_by="fasp:system:test",
    )


class MissionModelTests(unittest.TestCase):
    def test_a_mission_is_goals_and_never_a_trajectory(self) -> None:
        """The step vocabulary has no member that could express a velocity
        or a wheel command. That is the layer boundary, in a type."""
        self.assertEqual({kind.value for kind in StepKind}, {"move", "pick", "drop", "charge", "dock", "undock", "wait", "custom"})

    def test_a_move_step_needs_somewhere_to_go(self) -> None:
        with self.assertRaises(FaspError):
            Mission.from_dict({"steps": [{"kind": "move"}]}, requested_by="p")

    def test_step_count_is_bounded(self) -> None:
        with self.assertRaises(FaspError):
            Mission.from_dict({"steps": [{"kind": "wait"}] * 500}, requested_by="p")
        with self.assertRaises(FaspError):
            Mission.from_dict({"steps": []}, requested_by="p")

    def test_an_unknown_step_kind_is_rejected(self) -> None:
        with self.assertRaises(FaspError):
            Mission.from_dict({"steps": [{"kind": "detonate"}]}, requested_by="p")

    def test_poses_on_different_maps_cannot_be_compared(self) -> None:
        with self.assertRaises(FaspError):
            Pose(0, 0, map_id="floor1").distance_to(Pose(1, 1, map_id="floor2"))

    def test_only_an_automatic_vehicle_accepts_missions(self) -> None:
        for mode in OperatingMode:
            with self.subTest(mode=mode.value):
                self.assertEqual(mode.accepts_missions, mode is OperatingMode.AUTOMATIC)

    def test_dispatchability_explains_every_refusal(self) -> None:
        base = {
            "vehicle_id": "v1",
            "fleet": "sim",
            "online": True,
            "operating_mode": OperatingMode.AUTOMATIC,
            "pose": Pose(0, 0),
            "battery_ratio": 0.9,
            "charging": False,
            "driving": False,
            "paused": False,
        }
        self.assertTrue(VehicleState(**base).dispatchable()[0])
        for override, expected in (
            ({"online": False}, "offline"),
            ({"operating_mode": OperatingMode.MANUAL}, "MANUAL"),
            ({"safety_estop_active": True}, "emergency stop"),
            ({"protective_field_violated": True}, "protective field"),
            ({"errors": ({"level": "FATAL", "code": "x"},)}, "fatal"),
            ({"current_mission_id": "m9"}, "already running"),
            ({"battery_ratio": 0.05}, "below"),
        ):
            with self.subTest(override=override):
                ok, reason = VehicleState(**{**base, **override}).dispatchable()
                self.assertFalse(ok)
                self.assertIn(expected, reason)

    def test_capabilities_refuse_a_step_the_vehicle_cannot_do(self) -> None:
        tugger = VehicleCapabilities(supported_steps=(StepKind.MOVE,))
        ok, reason = tugger.supports(a_mission())
        self.assertFalse(ok)
        self.assertIn("pick", reason)


class Vda5050Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.published: list[tuple[str, str]] = []
        self.adapter = Vda5050Adapter("acme", lambda subject, payload: self.published.append((subject, payload)), manufacturer="ACME")

    def test_topics_follow_the_standard_and_reject_wildcards(self) -> None:
        self.assertEqual(topic("ACME", "AGV1", "order"), "uagv/v2/ACME/AGV1/order")
        for bad in ("ACME/x", "AC+ME", "#"):
            with self.subTest(bad=bad), self.assertRaises(Vda5050Error):
                topic(bad, "AGV1", "order")

    def test_nodes_are_even_and_edges_odd_and_alternate(self) -> None:
        """A vehicle order-checks on this. Getting it wrong means orders
        rejected mid-aisle."""
        order = OrderBuilder("ACME", "AGV1").build(a_mission(steps=[{"kind": "move", "node_id": "n1"}, {"kind": "move", "node_id": "n2"}, {"kind": "move", "node_id": "n3"}]))
        self.assertEqual([node["sequenceId"] for node in order["nodes"]], [0, 2, 4])
        self.assertEqual([edge["sequenceId"] for edge in order["edges"]], [1, 3])

    def test_base_and_horizon_split_marks_only_the_base_released(self) -> None:
        order = OrderBuilder("ACME", "AGV1").build(
            a_mission(steps=[{"kind": "move", "node_id": f"n{index}"} for index in range(5)]),
            base_nodes=2,
        )
        self.assertEqual([node["released"] for node in order["nodes"]], [True, True, False, False, False])

    def test_a_move_step_carries_no_action(self) -> None:
        order = OrderBuilder("ACME", "AGV1").build(a_mission())
        self.assertEqual(order["nodes"][0]["actions"], [])
        self.assertEqual(order["nodes"][1]["actions"][0]["actionType"], "pick")

    def test_header_ids_increase_monotonically(self) -> None:
        builder = OrderBuilder("ACME", "AGV1")
        ids = [builder.build(a_mission(f"m{index}"))["headerId"] for index in range(5)]
        self.assertEqual(ids, [1, 2, 3, 4, 5])

    def test_an_update_must_keep_the_order_id_and_advance_the_update_id(self) -> None:
        builder = OrderBuilder("ACME", "AGV1")
        mission = a_mission("m1", steps=[{"kind": "move", "node_id": "n1"}, {"kind": "move", "node_id": "n2"}])
        first = builder.build(mission)
        updated = builder.update(first, mission, last_released_node_id="n1")
        self.assertEqual(updated["orderId"], "m1")
        self.assertEqual(updated["orderUpdateId"], 1)
        with self.assertRaises(Vda5050Error):
            builder.update(first, a_mission("m2", steps=[{"kind": "move", "node_id": "n1"}]), last_released_node_id="n1")

    def test_an_update_must_start_at_the_last_released_node(self) -> None:
        builder = OrderBuilder("ACME", "AGV1")
        mission = a_mission("m1", steps=[{"kind": "move", "node_id": "n1"}, {"kind": "move", "node_id": "n2"}])
        first = builder.build(mission)
        with self.assertRaises(Vda5050Error) as raised:
            builder.update(first, mission, last_released_node_id="n2")
        self.assertIn("last released base node", raised.exception.detail)

    def test_only_standard_instant_actions_are_accepted(self) -> None:
        builder = OrderBuilder("ACME", "AGV1")
        for action in sorted(INSTANT_ACTIONS):
            with self.subTest(action=action):
                self.assertEqual(builder.instant_action(action)["actions"][0]["actionType"], action)
        with self.assertRaises(Vda5050Error):
            builder.instant_action("emergencyStop")

    def test_state_maps_onto_the_neutral_model(self) -> None:
        state = parse_state(
            {
                "serialNumber": "AGV1",
                "operatingMode": "AUTOMATIC",
                "driving": True,
                "orderId": "m1",
                "batteryState": {"batteryCharge": 72.0, "charging": False},
                "agvPosition": {"positionInitialized": True, "x": 3.0, "y": 4.0, "theta": 1.2, "mapId": "floor1"},
                "velocity": {"vx": 0.6, "vy": 0.8},
                "safetyState": {"eStop": "NONE", "fieldViolation": False},
                "errors": [{"errorType": "batteryLow", "errorLevel": "WARNING"}],
            },
            fleet="acme",
        )
        self.assertEqual(state.vehicle_id, "AGV1")
        self.assertAlmostEqual(state.battery_ratio, 0.72)
        self.assertAlmostEqual(state.velocity_mps, 1.0)
        self.assertEqual(state.pose.map_id, "floor1")
        self.assertFalse(state.safety_estop_active)
        self.assertEqual(state.fatal_errors, ())

    def test_any_estop_value_but_none_bars_dispatch(self) -> None:
        for value in ("AUTOACK", "MANUAL", "REMOTE"):
            with self.subTest(estop=value):
                state = parse_state({"serialNumber": "AGV1", "safetyState": {"eStop": value}}, fleet="acme")
                self.assertTrue(state.safety_estop_active)
                self.assertFalse(state.dispatchable()[0])

    def test_mission_state_is_derived_from_node_action_and_error_state(self) -> None:
        running = {"orderId": "m1", "nodeStates": [{"nodeId": "n2"}], "actionStates": []}
        self.assertEqual(mission_state_from(running, "m1"), MissionState.RUNNING)
        self.assertEqual(mission_state_from({**running, "paused": True}, "m1"), MissionState.PAUSED)
        self.assertEqual(mission_state_from({"orderId": "m1", "nodeStates": [], "edgeStates": [], "actionStates": [{"actionStatus": "FINISHED"}]}, "m1"), MissionState.COMPLETED)
        self.assertEqual(mission_state_from({"orderId": "m1", "actionStates": [{"actionStatus": "FAILED"}]}, "m1"), MissionState.FAILED)
        self.assertEqual(mission_state_from({"orderId": "m1", "errors": [{"errorLevel": "FATAL"}], "actionStates": []}, "m1"), MissionState.FAILED)

    def test_a_factsheet_teaches_the_coordinator_what_a_vehicle_can_do(self) -> None:
        capabilities = parse_factsheet(
            {
                "manufacturer": "ACME",
                "serialNumber": "AGV1",
                "typeSpecification": {"seriesName": "Tugger200"},
                "physicalParameters": {"speedMax": 1.8, "length": 1.4, "width": 0.7},
                "loadSpecification": {"loadSets": [{"maxWeight": 250.0}]},
                "protocolFeatures": {"agvActions": [{"actionType": "pick"}, {"actionType": "drop"}]},
            },
            fleet="acme",
        )
        self.assertEqual(capabilities.max_speed_mps, 1.8)
        self.assertEqual(capabilities.payload_kg, 250.0)
        self.assertIn(StepKind.PICK, capabilities.supported_steps)
        self.assertIn(StepKind.MOVE, capabilities.supported_steps)

    def test_a_silent_vehicle_is_reported_offline_not_idle(self) -> None:
        adapter = Vda5050Adapter("acme", lambda subject, payload: None, offline_after_s=0.0)
        adapter.on_message("uagv/v2/ACME/AGV1/state", json.dumps({"serialNumber": "AGV1", "operatingMode": "AUTOMATIC"}))
        self.assertFalse(adapter.vehicle_state("AGV1").online)

    def test_a_malformed_message_from_one_vehicle_does_not_break_the_adapter(self) -> None:
        self.adapter.on_message("uagv/v2/ACME/AGV1/state", "{not json")
        self.adapter.on_message("uagv/v2/ACME/AGV2/state", json.dumps({"serialNumber": "AGV2", "operatingMode": "AUTOMATIC"}))
        self.assertEqual([state.vehicle_id for state in self.adapter.list_vehicles()], ["AGV2"])

    def test_a_stop_request_is_a_pause_not_an_emergency_stop(self) -> None:
        """VDA 5050 has no emergency-stop message, deliberately -- and this
        adapter does not invent one."""
        self.adapter.request_stop("AGV1", "aisle blocked")
        subject, payload = self.published[-1]
        self.assertTrue(subject.endswith("/instantActions"))
        self.assertEqual(json.loads(payload)["actions"][0]["actionType"], "startPause")


class RestAdapterTests(unittest.TestCase):
    def test_a_vendor_is_integrated_by_configuration_not_code(self) -> None:
        vendor_state = {
            "robots": [
                {"uuid": "R1", "connected": True, "state": "auto", "charge_pct": 88, "loc": {"px": 2.0, "py": 3.0, "map": "L1"}, "job": None, "faults": []},
            ]
        }

        def http(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, bytes]:
            if url.endswith("/robots"):
                return 200, json.dumps(vendor_state).encode()
            return 200, b"{}"

        adapter = RestFleetAdapter(
            "othervendor",
            EndpointSpec(base_url="https://fleet.example", list_vehicles="/robots"),
            fields=FieldMap(vehicle_list="robots", vehicle_id="uuid", online="connected", operating_mode="state", battery="charge_pct", position_x="loc.px", position_y="loc.py", map_id="loc.map", current_mission="job", errors="faults"),
            http=http,
        )
        (vehicle,) = adapter.list_vehicles()
        self.assertEqual(vehicle.vehicle_id, "R1")
        self.assertEqual(vehicle.operating_mode, OperatingMode.AUTOMATIC)
        self.assertAlmostEqual(vehicle.battery_ratio, 0.88)
        self.assertEqual(vehicle.pose.map_id, "L1")
        self.assertTrue(vehicle.dispatchable()[0])

    def test_an_http_error_is_a_clean_fasp_error(self) -> None:
        adapter = RestFleetAdapter("v", EndpointSpec(base_url="https://fleet.example"), http=lambda *args: (503, b"down"))
        with self.assertRaises(FaspError):
            adapter.list_vehicles()

    def test_an_unknown_vehicle_defaults_to_the_conservative_capability_set(self) -> None:
        adapter = RestFleetAdapter("v", EndpointSpec(base_url="https://fleet.example"), http=lambda *args: (200, b"{}"))
        self.assertEqual(adapter.capabilities("R1").supported_steps, (StepKind.MOVE, StepKind.WAIT))


class RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = FleetRegistry()
        self.acme = SimulatedFleetManager("acme", nodes={"dock-7": Pose(10.0, 0.0)})
        self.acme.add_vehicle("AGV1", battery_ratio=0.9)
        self.other = SimulatedFleetManager("othervendor", nodes={"dock-7": Pose(10.0, 0.0)})
        self.other.add_vehicle("AGV1", battery_ratio=0.4)
        self.registry.register(self.acme)
        self.registry.register(self.other)

    def test_two_vendors_may_use_the_same_vehicle_id_without_colliding(self) -> None:
        addresses = [address for address, _state in self.registry.list_vehicles()]
        self.assertEqual(sorted(addresses), ["acme:AGV1", "othervendor:AGV1"])

    def test_selection_prefers_the_better_vehicle_and_records_every_rejection(self) -> None:
        self.other.vehicle("AGV1").operating_mode = OperatingMode.MANUAL
        chosen, considered = self.registry.select_vehicle(a_mission())
        self.assertEqual(chosen, "acme:AGV1")
        rejected = [entry for entry in considered if not entry["eligible"]]
        self.assertEqual(len(rejected), 1)
        self.assertIn("MANUAL", rejected[0]["reason"])

    def test_a_failing_vendor_degrades_that_fleet_only(self) -> None:
        class Broken:
            fleet = "broken"

            def describe(self) -> dict:
                return {}

            def list_vehicles(self):
                raise RuntimeError("vendor SDK exploded")

        self.registry.register(Broken())
        addresses = [address for address, _state in self.registry.list_vehicles()]
        self.assertEqual(sorted(addresses), ["acme:AGV1", "othervendor:AGV1"])
        self.assertFalse(next(entry for entry in self.registry.health() if entry["fleet"] == "broken")["healthy"])

    def test_a_fleet_wide_stop_request_attempts_every_vehicle(self) -> None:
        outcomes = self.registry.request_stop_all("area evacuation")
        self.assertEqual(sorted(outcomes), ["acme:AGV1", "othervendor:AGV1"])
        self.assertTrue(all(outcomes.values()))
        self.assertTrue(self.acme.vehicle("AGV1").paused)

    def test_a_bad_address_is_rejected(self) -> None:
        with self.assertRaises(FaspError):
            self.registry.vehicle_state("no-colon-here")

    def test_registering_a_fleet_with_a_colon_is_refused(self) -> None:
        manager = SimulatedFleetManager("bad:name")
        with self.assertRaises(FaspError):
            self.registry.register(manager)


class SimulatedFleetTests(unittest.TestCase):
    def test_a_mission_progresses_deterministically(self) -> None:
        manager = SimulatedFleetManager("sim", nodes={"a": Pose(0.0, 0.0), "b": Pose(10.0, 0.0)})
        manager.add_vehicle("v1")
        mission = a_mission("m1", steps=[{"kind": "move", "node_id": "b"}, {"kind": "wait", "parameters": {"duration_s": 2.0}}])
        manager.dispatch(mission, "v1")
        manager.advance(5.0)
        self.assertEqual(manager.mission_state("m1"), MissionState.RUNNING)
        self.assertAlmostEqual(manager.vehicle("v1").pose.x, 5.0)
        manager.advance(10.0)
        self.assertEqual(manager.mission_state("m1"), MissionState.COMPLETED)

    def test_a_paused_vehicle_makes_no_progress_and_the_mission_does_not_fail(self) -> None:
        manager = SimulatedFleetManager("sim", nodes={"b": Pose(10.0, 0.0)})
        manager.add_vehicle("v1")
        manager.dispatch(a_mission("m1", steps=[{"kind": "move", "node_id": "b"}]), "v1")
        manager.request_stop("v1", "person in the aisle")
        manager.advance(30.0)
        self.assertEqual(manager.vehicle("v1").pose.x, 0.0)
        self.assertNotEqual(manager.mission_state("m1"), MissionState.FAILED)

    def test_a_mission_to_an_unknown_node_is_refused_before_dispatch(self) -> None:
        manager = SimulatedFleetManager("sim")
        manager.add_vehicle("v1")
        with self.assertRaises(FaspError):
            manager.dispatch(a_mission("m1", steps=[{"kind": "move", "node_id": "nowhere"}]), "v1")


if __name__ == "__main__":
    unittest.main()
