"""Modbus/TCP, OPC UA, and ROS 2: the field- and supervisory-level buses.

The Modbus tests run against a real socket server so they exercise actual
framing rather than a shared encoder talking to itself.
"""

from __future__ import annotations

import unittest

from fasp_harness.industrial.modbus import (
    ModbusDataStore,
    ModbusError,
    ModbusExceptionResponse,
    ModbusTcpClient,
    ModbusTcpServer,
    SafetyRegisterMap,
    SignalMapping,
    pack_bits,
    unpack_bits,
)
from fasp_harness.industrial.opcua import (
    NodeId,
    OpcUaObserver,
    SimulatedOpcUaClient,
    StatusCode,
    WriteAllowlist,
    WriteRule,
)
from fasp_harness.industrial.ros2 import (
    SENSOR_DATA,
    SUPERVISORY_STATUS,
    CallbackReturn,
    Durability,
    History,
    LifecycleError,
    LifecycleManager,
    LifecycleNode,
    LifecycleState,
    QosProfile,
    Reliability,
    Transition,
    inspect_sros2,
)
from fasp_harness.layers import LayerViolation
from fasp_harness.protocol.errors import FaspError
from fasp_harness.safety.drivers import DEFAULT_SAFETY_SIGNALS, ModbusSafetyController


class ModbusCodecTests(unittest.TestCase):
    def test_bits_pack_least_significant_first(self) -> None:
        self.assertEqual(pack_bits([True, False, True]), bytes([0b101]))
        self.assertEqual(unpack_bits(bytes([0b101]), 3), [True, False, True])

    def test_node_id_round_trip(self) -> None:
        self.assertEqual(str(NodeId.parse("ns=2;s=Device.Temp")), "ns=2;s=Device.Temp")
        self.assertEqual(NodeId.parse("i=85").namespace, 0)
        with self.assertRaises(FaspError):
            NodeId.parse("nonsense")


class ModbusTcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ModbusDataStore(
            discrete_inputs={0: True, 1: True, 2: False, 3: False, 4: False},
            holding_registers={100: 1234, 101: 5678},
            input_registers={0: 42},
            coils={10: False},
        )
        self.server = ModbusTcpServer(self.store).start()
        self.client = ModbusTcpClient("127.0.0.1", self.server.port, timeout_s=2.0)

    def tearDown(self) -> None:
        self.client.close()
        self.server.shutdown()
        self.server.server_close()

    def test_reads_and_writes_over_a_real_socket(self) -> None:
        self.assertEqual(self.client.read_discrete_inputs(0, 5), [True, True, False, False, False])
        self.assertEqual(self.client.read_holding_registers(100, 2), [1234, 5678])
        self.assertEqual(self.client.read_input_registers(0, 1), [42])
        self.client.write_coil(10, True)
        self.assertEqual(self.client.read_coils(10, 1), [True])
        self.client.write_registers(200, [7, 8, 9])
        self.assertEqual(self.client.read_holding_registers(200, 3), [7, 8, 9])

    def test_server_rejects_an_out_of_range_quantity_with_an_exception_response(self) -> None:
        import struct

        from fasp_harness.industrial.modbus import READ_COILS

        with self.assertRaises(ModbusExceptionResponse) as raised:
            self.client._transact(struct.pack(">BHH", READ_COILS, 0, 5000))
        self.assertEqual(raised.exception.exception_code, 0x03)

    def test_a_read_only_coil_is_refused_by_the_device(self) -> None:
        self.store.read_only_coils.add(10)
        with self.assertRaises(ModbusExceptionResponse) as raised:
            self.client.write_coil(10, True)
        self.assertEqual(raised.exception.exception_code, 0x02)

    def test_an_unreachable_device_is_a_clean_error_not_a_traceback(self) -> None:
        client = ModbusTcpClient("127.0.0.1", 1, timeout_s=0.2)
        with self.assertRaises(ModbusError) as raised:
            client.read_discrete_inputs(0, 1)
        self.assertIn("Cannot reach", raised.exception.detail)

    def test_client_validates_before_sending(self) -> None:
        for call in (lambda: self.client.read_coils(0, 0), lambda: self.client.read_holding_registers(0, 500), lambda: self.client.write_register(0, 70000)):
            with self.subTest(), self.assertRaises(ModbusError):
                call()


class SafetyRegisterMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ModbusDataStore(discrete_inputs={0: True, 1: True, 2: False, 3: False, 4: False})
        self.server = ModbusTcpServer(self.store).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_active_low_signals_are_inverted_at_the_map(self) -> None:
        """A safety circuit is wired so a cut wire reads unsafe. Modelling
        that in the map beats inverting it by hand at every call site."""
        controller = ModbusSafetyController("127.0.0.1", self.server.port)
        status = controller.read_status()
        self.assertTrue(status.reachable)
        # discrete input 0/1 are TRUE (circuit closed) and declared
        # active-low, so `estop_channel_a` evaluates to False -> not clear.
        self.assertFalse(status.estop_clear)

        self.store.discrete_inputs.update({0: False, 1: False})
        self.assertTrue(controller.read_status().estop_clear)
        controller.close()

    def test_a_channel_discrepancy_is_reported_as_not_clear(self) -> None:
        self.store.discrete_inputs.update({0: False, 1: True})
        controller = ModbusSafetyController("127.0.0.1", self.server.port)
        status = controller.read_status()
        self.assertFalse(status.estop_clear)
        self.assertIn("discrepancy", status.detail)
        controller.close()

    def test_a_dead_controller_reads_as_completely_unsafe(self) -> None:
        controller = ModbusSafetyController("127.0.0.1", 1, timeout_s=0.2)
        status = controller.read_status()
        self.assertFalse(status.reachable)
        self.assertFalse(status.safe_to_move)
        self.assertTrue(status.reset_required)

    def test_writing_a_safety_relevant_signal_is_structurally_impossible(self) -> None:
        register_map = SafetyRegisterMap(list(DEFAULT_SAFETY_SIGNALS))
        for signal in DEFAULT_SAFETY_SIGNALS:
            with self.subTest(signal=signal.name), self.assertRaises(FaspError) as raised:
                register_map.writable_signal(signal.name)
            self.assertEqual(raised.exception.code, "policy.layer_violation")

    def test_a_non_safety_signal_may_be_written(self) -> None:
        register_map = SafetyRegisterMap([SignalMapping("indicator_lamp", "coil", 20, safety_relevant=False)])
        self.assertEqual(register_map.writable_signal("indicator_lamp").address, 20)


class OpcUaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = SimulatedOpcUaClient()
        self.client.connect()
        self.client.add_device("Palletiser1", {"Ready": True, "Cycles": 42, "SetpointRpm": 120.0}, writable=("SetpointRpm",))

    def test_browse_walks_the_address_space(self) -> None:
        objects = self.client.browse("ns=0;i=85")
        self.assertIn("DeviceSet", [child["browse_name"] for child in objects])
        devices = self.client.browse("ns=2;s=DeviceSet")
        self.assertIn("Palletiser1", [child["browse_name"] for child in devices])

    def test_reads_carry_status_and_a_source_timestamp(self) -> None:
        (value,) = self.client.read(["ns=2;s=Palletiser1.Cycles"])
        self.assertEqual(value.value, 42)
        self.assertTrue(value.status.good)
        self.assertTrue(value.source_timestamp)

    def test_an_unknown_node_is_a_bad_status_not_an_exception(self) -> None:
        (value,) = self.client.read(["ns=2;s=Nope"])
        self.assertEqual(value.status, StatusCode.BAD_NODE_ID_UNKNOWN)

    def test_writes_are_deny_by_default(self) -> None:
        with self.assertRaises(FaspError) as raised:
            self.client.write("ns=2;s=Palletiser1.SetpointRpm", 150.0)
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_an_allowlisted_write_succeeds_and_is_recorded(self) -> None:
        self.client.allowlist.allow(WriteRule("ns=2;s=Palletiser1.SetpointRpm", "MES sets the line rate", minimum=0.0, maximum=200.0))
        self.assertEqual(self.client.write("ns=2;s=Palletiser1.SetpointRpm", 150.0), StatusCode.GOOD)
        self.assertEqual(self.client.write_log[-1]["reason"], "MES sets the line rate")

    def test_an_out_of_range_write_is_refused_by_the_rule(self) -> None:
        self.client.allowlist.allow(WriteRule("ns=2;s=Palletiser1.SetpointRpm", "line rate", minimum=0.0, maximum=200.0))
        with self.assertRaises(FaspError):
            self.client.write("ns=2;s=Palletiser1.SetpointRpm", 900.0)

    def test_a_layer1_node_cannot_be_added_to_the_allowlist(self) -> None:
        allowlist = WriteAllowlist()
        for node_id in ("ns=3;s=Cell.estop.reset", "ns=3;s=Line.safety.zone.mute", "ns=3;s=Axis1.motor.command"):
            with self.subTest(node=node_id), self.assertRaises(LayerViolation):
                allowlist.allow(WriteRule(node_id, "operator asked for it"))

    def test_subscriptions_deliver_and_unsubscribe(self) -> None:
        received = []
        unsubscribe = self.client.subscribe("ns=2;s=Palletiser1.Ready", received.append)
        self.client.set_value("ns=2;s=Palletiser1.Ready", False)
        self.assertEqual(len(received), 1)
        unsubscribe()
        self.client.set_value("ns=2;s=Palletiser1.Ready", True)
        self.assertEqual(len(received), 1)

    def test_the_observer_adapter_exposes_only_declared_names(self) -> None:
        observer = OpcUaObserver(self.client, nodes={"ready": "ns=2;s=Palletiser1.Ready"})
        for capability in observer.capabilities():
            self.assertEqual(capability["interaction"], "observe")
        result = observer.handle({"capability": "observe.opcua.read.v1", "parameters": {"names": ["ready"]}})
        self.assertTrue(result["values"]["ready"]["good"])
        with self.assertRaises(FaspError) as raised:
            observer.handle({"capability": "observe.opcua.read.v1", "parameters": {"names": ["secret"]}})
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_a_disconnected_client_refuses_to_read(self) -> None:
        client = SimulatedOpcUaClient()
        with self.assertRaises(FaspError):
            client.read(["ns=0;i=2259"])


class Ros2LifecycleTests(unittest.TestCase):
    def test_the_standard_bring_up_path(self) -> None:
        node = LifecycleNode("navigation")
        self.assertEqual(node.state, LifecycleState.UNCONFIGURED)
        self.assertFalse(node.publishing)
        node.trigger(Transition.CONFIGURE)
        self.assertEqual(node.state, LifecycleState.INACTIVE)
        self.assertFalse(node.publishing, "An inactive managed node must not publish.")
        node.trigger(Transition.ACTIVATE)
        self.assertEqual(node.state, LifecycleState.ACTIVE)
        self.assertTrue(node.publishing)
        node.trigger(Transition.DEACTIVATE)
        self.assertEqual(node.state, LifecycleState.INACTIVE)
        node.trigger(Transition.SHUTDOWN)
        self.assertEqual(node.state, LifecycleState.FINALIZED)

    def test_an_invalid_transition_is_refused_with_the_available_ones(self) -> None:
        node = LifecycleNode("perception")
        with self.assertRaises(LifecycleError) as raised:
            node.trigger(Transition.ACTIVATE)
        self.assertIn("configure", raised.exception.detail)

    def test_failure_returns_to_the_previous_state_while_error_processes(self) -> None:
        """FAILURE and ERROR are different: "I could not" versus "I am in an
        unknown state". Conflating them is how a node ends up active after
        a failed configure."""
        failing = LifecycleNode("f", callbacks={Transition.CONFIGURE: lambda state: CallbackReturn.FAILURE})
        failing.trigger(Transition.CONFIGURE)
        self.assertEqual(failing.state, LifecycleState.UNCONFIGURED)

        erroring = LifecycleNode("e", callbacks={Transition.CONFIGURE: lambda state: CallbackReturn.ERROR})
        erroring.trigger(Transition.CONFIGURE)
        self.assertEqual(erroring.state, LifecycleState.UNCONFIGURED)
        self.assertEqual(erroring.history[-1].result, CallbackReturn.ERROR)

    def test_a_raising_callback_is_an_error_not_a_crash(self) -> None:
        def explode(state: LifecycleState) -> CallbackReturn:
            raise RuntimeError("driver missing")

        node = LifecycleNode("x", callbacks={Transition.CONFIGURE: explode})
        node.trigger(Transition.CONFIGURE)
        self.assertEqual(node.state, LifecycleState.UNCONFIGURED)
        self.assertIn("callback raised", node.history[-1].detail)

    def test_error_handling_that_itself_fails_is_terminal(self) -> None:
        node = LifecycleNode("x", callbacks={Transition.CONFIGURE: lambda state: CallbackReturn.ERROR})
        node.on_error = lambda state: CallbackReturn.FAILURE
        node.trigger(Transition.CONFIGURE)
        self.assertEqual(node.state, LifecycleState.FINALIZED)

    def test_the_manager_stops_at_the_first_node_that_will_not_come_up(self) -> None:
        manager = LifecycleManager()
        manager.add(LifecycleNode("perception"))
        manager.add(LifecycleNode("navigation", callbacks={Transition.ACTIVATE: lambda state: CallbackReturn.FAILURE}))
        manager.add(LifecycleNode("missions"))
        ok, report = manager.bring_up()
        self.assertFalse(ok)
        self.assertEqual([entry["node"] for entry in report], ["perception", "navigation"])
        self.assertFalse(manager.all_active())


class Ros2QosTests(unittest.TestCase):
    def test_reliable_subscriber_cannot_receive_a_best_effort_publisher(self) -> None:
        ok, problems = QosProfile(reliability=Reliability.RELIABLE).compatible_with(SENSOR_DATA)
        self.assertFalse(ok)
        self.assertIn("RELIABLE", problems[0])

    def test_best_effort_subscriber_accepts_a_reliable_publisher(self) -> None:
        ok, _ = QosProfile(reliability=Reliability.BEST_EFFORT).compatible_with(QosProfile(reliability=Reliability.RELIABLE))
        self.assertTrue(ok)

    def test_transient_local_request_needs_a_transient_local_offer(self) -> None:
        ok, problems = SUPERVISORY_STATUS.compatible_with(QosProfile(durability=Durability.VOLATILE))
        self.assertFalse(ok)
        self.assertTrue(any("late joiners" in problem for problem in problems))

    def test_every_incompatibility_is_reported_not_just_the_first(self) -> None:
        requested = QosProfile(reliability=Reliability.RELIABLE, durability=Durability.TRANSIENT_LOCAL, deadline_s=0.1, lease_duration_s=1.0)
        offered = QosProfile(reliability=Reliability.BEST_EFFORT, durability=Durability.VOLATILE, deadline_s=5.0, lease_duration_s=10.0)
        ok, problems = requested.compatible_with(offered)
        self.assertFalse(ok)
        self.assertGreaterEqual(len(problems), 4)

    def test_supervisory_status_matches_itself(self) -> None:
        ok, problems = SUPERVISORY_STATUS.compatible_with(SUPERVISORY_STATUS)
        self.assertTrue(ok, problems)
        self.assertEqual(SUPERVISORY_STATUS.history, History.KEEP_LAST)


class Sros2PostureTests(unittest.TestCase):
    def test_security_off_is_a_critical_finding(self) -> None:
        posture = inspect_sros2({"ROS_SECURITY_ENABLE": "false"})
        self.assertFalse(posture.enabled)
        self.assertFalse(posture.acceptable_for_production)
        self.assertTrue(any(finding.severity == "critical" for finding in posture.findings))
        with self.assertRaises(FaspError):
            posture.require_enforcing()

    def test_permit_strategy_is_critical_because_it_looks_secure(self) -> None:
        """`Permit` is the configuration most often found in the field: a
        node with no security material runs unauthenticated rather than
        failing to start."""
        posture = inspect_sros2({"ROS_SECURITY_ENABLE": "true", "ROS_SECURITY_STRATEGY": "Permit", "ROS_SECURITY_KEYSTORE": "/tmp/keystore"})
        self.assertTrue(posture.enabled)
        self.assertFalse(posture.enforcing)
        self.assertTrue(any(finding.control == "sros2.strategy" and finding.severity == "critical" for finding in posture.findings))

    def test_a_complete_keystore_and_enforce_is_acceptable(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            keystore = os.path.join(directory, "keystore")
            for part in ("public", "private", "enclaves/robot1"):
                os.makedirs(os.path.join(keystore, part), exist_ok=True)
            os.chmod(os.path.join(keystore, "private"), 0o700)
            for artefact in ("cert.pem", "key.pem", "permissions.p7s", "governance.p7s"):
                open(os.path.join(keystore, "enclaves", "robot1", artefact), "w").close()
            posture = inspect_sros2(
                {"ROS_SECURITY_ENABLE": "true", "ROS_SECURITY_STRATEGY": "Enforce", "ROS_SECURITY_KEYSTORE": keystore, "ROS_SECURITY_ENCLAVE_OVERRIDE": "/robot1", "ROS_DOMAIN_ID": "7"}
            )
            self.assertTrue(posture.acceptable_for_production, [finding.detail for finding in posture.findings])
            posture.require_enforcing()

    def test_world_readable_private_material_is_critical(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            keystore = os.path.join(directory, "keystore")
            for part in ("public", "private", "enclaves"):
                os.makedirs(os.path.join(keystore, part), exist_ok=True)
            os.chmod(os.path.join(keystore, "private"), 0o755)
            posture = inspect_sros2({"ROS_SECURITY_ENABLE": "true", "ROS_SECURITY_STRATEGY": "Enforce", "ROS_SECURITY_KEYSTORE": keystore})
            self.assertTrue(any(finding.control == "sros2.keystore_permissions" for finding in posture.findings))


if __name__ == "__main__":
    unittest.main()
