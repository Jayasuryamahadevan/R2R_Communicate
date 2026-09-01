"""Index: each stated industrial gap -> what closes it, and what still doesn't.

The brief for this work was a list of thirteen things the repository lacked.
This file is the answer sheet, and it is executable: every module named here
must import, every test module named here must exist, and every claim marked
`PARTIAL` or `NOT_CLOSED` stays visible rather than quietly disappearing once
something adjacent was built.

That last part is the point. The dishonest way to close a gap list is to
implement something nearby and tick the box. `STATUS` below distinguishes:

    CLOSED       implemented here, exercised by the named tests
    PARTIAL      the software side is implemented; the remainder needs
                 hardware, a vendor, or an organisation -- named explicitly
    NOT_CLOSED   cannot be closed by software at all, and is not claimed
"""

from __future__ import annotations

import importlib
import unittest

CLOSED = "closed"
PARTIAL = "partial"
NOT_CLOSED = "not_closed"

# gap -> (status, modules, tests, what remains)
INDUSTRIAL_INDEX: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], str]] = {
    "real-time deterministic scheduling": (
        PARTIAL,
        ("fasp_harness.realtime.scheduler", "fasp_harness.realtime.watchdog", "fasp_harness.realtime.capability"),
        ("test_realtime",),
        "Drift-free periodic execution with deadlines, overrun policies, measured jitter, and fail-safe watchdogs -- for the management plane. "
        "Hard real-time is NOT provided and is structurally refused (`hard_realtime` is a constant False): CPython has a GIL and a stop-the-world "
        "collector. Layer 1 control loops belong on a certified controller or an RTOS, outside this process.",
    ),
    "safety certification": (
        NOT_CLOSED,
        ("fasp_harness.safety.case", "fasp_harness.safety.reference_case"),
        ("test_safety_case",),
        "A machine-checkable safety case with executable evidence is provided, and it reports its own gaps. Certification itself requires an "
        "accredited body assessing a specific installation; no software can produce it, and `SafetyCaseReport.certifiable` is always False.",
    ),
    "PLC/industrial safety-controller integration": (
        CLOSED,
        ("fasp_harness.industrial.modbus", "fasp_harness.safety.drivers", "fasp_harness.safety.interlock"),
        ("test_industrial_protocols", "test_safety_supervisor"),
        "Modbus/TCP client and server, a vendor-neutral driver interface, two-channel E-stop evaluation with discrepancy detection, latching, "
        "and a structural refusal to write any safety-relevant address.",
    ),
    "OPC UA integration": (
        CLOSED,
        ("fasp_harness.industrial.opcua",),
        ("test_industrial_protocols",),
        "Client abstraction, deterministic address-space simulator, optional `asyncua` binding, deny-by-default write allowlist with range "
        "checks, and a refusal to allowlist any node naming a Layer 1 function.",
    ),
    "ROS 2/DDS production-grade security and lifecycle": (
        CLOSED,
        ("fasp_harness.industrial.ros2",),
        ("test_industrial_protocols",),
        "The managed-node lifecycle state machine including the error path, DDS Requested-vs-Offered QoS compatibility, and an SROS 2 posture "
        "check that treats `Permit` as critical and can refuse to run unauthenticated.",
    ),
    "multi-vendor fleet-manager adapters": (
        CLOSED,
        ("fasp_harness.fleet.adapter", "fasp_harness.fleet.vda5050", "fasp_harness.fleet.rest", "fasp_harness.fleet.simulated"),
        ("test_fleet",),
        "A vendor-neutral mission/vehicle model, a registry multiplexing any number of vendors behind one address space, a VDA 5050 adapter "
        "with the order-sequencing and update rules enforced, and a declaratively configured REST adapter for everything else.",
    ),
    "industrial edge deployment/HA": (
        CLOSED,
        ("fasp_harness.edge.lease", "fasp_harness.edge.health", "fasp_harness.deployment"),
        ("test_edge_ha",),
        "Leader election with fencing tokens that refuse a superseded coordinator at the moment of effect, plus four distinct probes so a "
        "standby is not restarted for being a standby. Cross-machine consensus is explicitly out of scope and `describe()` says so.",
    ),
    "offline mesh/network-resilience validation": (
        CLOSED,
        ("fasp_harness.edge.outbox", "fasp_harness.resilience.faults", "fasp_harness.resilience.mesh"),
        ("test_edge_ha", "test_resilience"),
        "Durable store-and-forward with per-destination ordering, capped backoff and dead lettering; a seeded virtual-time network with loss, "
        "duplication, reordering, corruption and asymmetric partitions; store-carry-forward relaying validated across a 60s hard partition.",
    ),
    "hardware-in-the-loop testing": (
        PARTIAL,
        ("fasp_harness.hil.bench", "fasp_harness.hil.scenario"),
        ("test_hil",),
        "A bench that measures response times against declared deadlines and emits hash-chained, signable evidence, with five standard safety "
        "scenarios. It runs against a simulator in CI; a *timing claim about a machine* requires the same scenarios on that machine's hardware, "
        "which is why every report records `real_hardware`.",
    ),
    "digital-twin simulation integration": (
        CLOSED,
        ("fasp_harness.twin.kinematic", "fasp_harness.twin.preflight", "fasp_harness.twin.sync"),
        ("test_twin", "test_mission_pipeline"),
        "The twin is consulted before dispatch (reachability, energy, obstacles, deadline, space-time conflict) and compared against reality "
        "after, with divergence withdrawing trust in its own predictions. A higher-fidelity simulator plugs in behind the same interface.",
    ),
    "industrial cybersecurity certification/workflows": (
        PARTIAL,
        ("fasp_harness.security.iec62443", "fasp_harness.security.posture", "fasp_harness.security.sbom"),
        ("test_security_workflow",),
        "An IEC 62443-3-3 register evaluated against the running configuration, a 62443-3-2 zone/conduit model, a startup gate that refuses an "
        "insecure deployment, and a CycloneDX SBOM. Certification remains an accredited third-party activity covering organisational processes.",
    ),
    "a safety case and independent validation": (
        PARTIAL,
        ("fasp_harness.safety.case", "fasp_harness.safety.reference_case"),
        ("test_safety_case",),
        "The safety case is built and runnable, and every claim is bound to executed evidence. Independent validation is present in the argument "
        "as an explicitly UNDEVELOPED claim (G9) rather than omitted -- it requires a competent body assessing a specific installation.",
    ),
    "the layered architecture itself": (
        CLOSED,
        ("fasp_harness.layers",),
        ("test_layers", "test_mission_pipeline"),
        "Layer 1 is observable and unwritable from FASP, enforced at adapter registration and again on the dispatch path, with a semantic deny "
        "list so a mislabelled capability cannot launder a Layer 1 function through a higher layer.",
    ),
}


class IndustrialConformanceIndexTests(unittest.TestCase):
    def test_every_named_module_imports(self) -> None:
        for gap, (_status, modules, _tests, _remaining) in INDUSTRIAL_INDEX.items():
            for module in modules:
                with self.subTest(gap=gap, module=module):
                    importlib.import_module(module)

    def test_every_named_test_module_exists(self) -> None:
        for gap, (_status, _modules, tests, _remaining) in INDUSTRIAL_INDEX.items():
            for test_module in tests:
                with self.subTest(gap=gap, tests=test_module):
                    importlib.import_module(test_module)

    def test_every_gap_states_what_remains(self) -> None:
        """A gap closed without saying what it did not close is the failure
        mode this index exists to prevent."""
        for gap, (status, _modules, _tests, remaining) in INDUSTRIAL_INDEX.items():
            with self.subTest(gap=gap):
                self.assertIn(status, {CLOSED, PARTIAL, NOT_CLOSED})
                self.assertGreater(len(remaining), 80, f"{gap} needs a real description of scope and limits")

    def test_the_honest_claims_are_still_honest(self) -> None:
        """Certification and hard real-time must never be marked CLOSED."""
        self.assertEqual(INDUSTRIAL_INDEX["safety certification"][0], NOT_CLOSED)
        self.assertEqual(INDUSTRIAL_INDEX["real-time deterministic scheduling"][0], PARTIAL)
        self.assertEqual(INDUSTRIAL_INDEX["hardware-in-the-loop testing"][0], PARTIAL)
        self.assertEqual(INDUSTRIAL_INDEX["a safety case and independent validation"][0], PARTIAL)

    def test_the_original_thirteen_gaps_are_all_indexed(self) -> None:
        stated = {
            "real-time deterministic scheduling",
            "safety certification",
            "PLC/industrial safety-controller integration",
            "OPC UA integration",
            "ROS 2/DDS production-grade security and lifecycle",
            "multi-vendor fleet-manager adapters",
            "industrial edge deployment/HA",
            "offline mesh/network-resilience validation",
            "hardware-in-the-loop testing",
            "digital-twin simulation integration",
            "industrial cybersecurity certification/workflows",
            "a safety case and independent validation",
        }
        self.assertTrue(stated.issubset(set(INDUSTRIAL_INDEX)), sorted(stated - set(INDUSTRIAL_INDEX)))


if __name__ == "__main__":
    unittest.main()
