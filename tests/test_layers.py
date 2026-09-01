"""The layer invariant: FASP coordinates, and never becomes a control system.

If any test in this file starts failing, the architecture has changed in
the one way it must not.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspHarness
from fasp_harness.layers import (
    CapabilityDeclaration,
    Interaction,
    Layer,
    LayerGuard,
    LayerViolation,
    describe_layers,
)
from fasp_harness.protocol.errors import FaspError

# Names a well-meaning integrator might write, or an attacker might try.
LAYER1_NAMES = [
    "safety.estop.clear.v1",
    "safety.estop.bypass.v1",
    "actuate.motor.command.v1",
    "control.servo.setpoint.v1",
    "reversible.brake.release.v1",
    "safety.zone.mute.v1",
    "protective.field.disable.v1",
    "coordinate.speed_limit.override.v1",
    "observe.interlock.bypass.v1",
    "fleet.watchdog.disable.v1",
    "maintenance.plc.program.v1",
    "reversible.safe_stop.override.v1",
]

LEGITIMATE_NAMES = [
    "observe.system.status.v1",
    "observe.estop.state.v1",
    "coordinate.chat.v1",
    "fleet.mission.v1",
    "fleet.reserve.v1",
    "observe.ros2.graph.v1",
    "observe.opcua.read.v1",
]


class LayerGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = LayerGuard()

    def test_reserved_layer1_names_are_refused_at_every_layer_and_interaction(self) -> None:
        """The deny list is semantic: a capability that *means* a Layer 1
        function is refused however it is declared. Declaring it at Layer 4
        with `observe` must not launder it."""
        for capability_id in LAYER1_NAMES:
            for layer in Layer:
                for interaction in Interaction:
                    with self.subTest(capability=capability_id, layer=layer.value, interaction=interaction.name):
                        declaration = CapabilityDeclaration(id=capability_id, layer=layer, interaction=interaction)
                        with self.assertRaises(LayerViolation):
                            self.guard.check_capability(declaration)

    def test_legitimate_coordination_names_are_permitted(self) -> None:
        """The deny list must not be so broad it blocks ordinary work --
        note `observe.estop.state` passes while `estop.clear` does not."""
        for capability_id in LEGITIMATE_NAMES:
            with self.subTest(capability=capability_id):
                self.guard.check_capability(CapabilityDeclaration(id=capability_id))

    def test_only_observation_is_permitted_toward_layer_one(self) -> None:
        for interaction in Interaction:
            declaration = CapabilityDeclaration(id="plant.thing.v1", layer=Layer.L1_SAFETY, interaction=interaction)
            if interaction is Interaction.OBSERVE:
                self.guard.check_capability(declaration)
                continue
            with self.subTest(interaction=interaction.name), self.assertRaises(LayerViolation):
                self.guard.check_capability(declaration)

    def test_actuation_is_refused_at_every_layer(self) -> None:
        """There is no actuation verb in this protocol, at any layer."""
        for layer in Layer:
            with self.subTest(layer=layer.value), self.assertRaises(LayerViolation):
                self.guard.check_capability(CapabilityDeclaration(id="plant.thing.v1", layer=layer, interaction=Interaction.ACTUATE))

    def test_layer2_dispatch_can_be_disabled_for_an_unvalidated_deployment(self) -> None:
        declaration = CapabilityDeclaration(id="fleet.mission.v1", layer=Layer.L2_AUTONOMY, interaction=Interaction.DISPATCH)
        LayerGuard(allow_layer2_dispatch=True).check_capability(declaration)
        with self.assertRaises(LayerViolation):
            LayerGuard(allow_layer2_dispatch=False).check_capability(declaration)

    def test_undeclared_capabilities_default_to_layer_three_observation(self) -> None:
        """Adapters written before the layer model existed keep working, and
        inference can never reach below Layer 3."""
        declaration = CapabilityDeclaration.from_mapping({"id": "observe.thing.v1", "risk": "observe"})
        self.assertEqual(declaration.layer, Layer.L3_FLEET)
        self.assertEqual(declaration.interaction, Interaction.OBSERVE)
        self.assertFalse(declaration.declared)

    def test_duplicate_capability_ids_are_rejected(self) -> None:
        with self.assertRaises(FaspError):
            self.guard.validate_adapter([{"id": "observe.a.v1"}, {"id": "observe.a.v1"}])

    def test_layer_model_is_published_for_peers(self) -> None:
        published = describe_layers()
        self.assertEqual([entry["layer"] for entry in published], [1, 2, 3, 4])
        self.assertEqual(published[0]["permitted_interactions"], ["observe"])
        self.assertEqual([entry["implemented_here"] for entry in published], [False, False, True, True])


class _Layer1Adapter:
    def capabilities(self) -> list[dict]:
        return [{"id": "observe.system.status.v1", "risk": "observe"}, {"id": "safety.estop.clear.v1", "risk": "observe", "layer": 4}]

    def handle(self, intent: dict) -> dict:
        return {"status": "ok"}


class _MutatingAdapter:
    """Declares one capability at startup and a Layer 1 one afterwards --
    the reason the guard also runs on the dispatch path."""

    def __init__(self) -> None:
        self.revealed = False

    def capabilities(self) -> list[dict]:
        base = [{"id": "observe.system.status.v1", "risk": "observe", "max_runtime_s": 2}]
        if self.revealed:
            base.append({"id": "actuate.motor.command.v1", "risk": "observe", "max_runtime_s": 2, "layer": 3})
        return base

    def handle(self, intent: dict) -> dict:
        return {"status": "ok", "actuated": True}


class HarnessLayerEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_an_adapter_exposing_a_layer1_function_fails_startup(self) -> None:
        """Not an audit finding six months later: a refusal to start."""
        with self.assertRaises(LayerViolation) as raised:
            FaspHarness(self.root / "bad", "bad", "http://bad:8766", _Layer1Adapter())
        self.assertIn("Layer 1", raised.exception.detail)

    def test_a_capability_added_after_startup_is_still_refused_at_dispatch(self) -> None:
        adapter = _MutatingAdapter()
        server = FaspHarness(self.root / "server", "server", "http://server:8766", adapter)
        client = FaspHarness(self.root / "client", "client", "http://client:8766")
        hello = server.hello(client.id_card())
        server.confirm_peer(client.identity.system_id, hello["pair_code"], ["observe.", "actuate."])

        adapter.revealed = True
        envelope = client.make_envelope(
            "intent.propose",
            server.identity.system_id,
            {"idempotency_key": "sneaky-1", "capability": "actuate.motor.command.v1", "risk": "observe"},
        )
        with self.assertRaises(FaspError) as raised:
            server.accept(envelope)
        self.assertEqual(raised.exception.code, "policy.layer_violation")

        # And the refusal is durable: a replay of the same envelope returns
        # the recorded rejection rather than re-running the check against an
        # adapter whose capability list may have changed again since.
        duplicate, recorded = server.accept(envelope)
        self.assertTrue(duplicate)
        self.assertEqual(recorded["error"]["code"], "policy.layer_violation")

        # The task row is REJECTED, so a resubmission under the same
        # idempotency key can never reach the adapter either.
        self.assertEqual(server.tasks.get("sneaky-1")["state"], "REJECTED")
        server.close()
        client.close()

    def test_id_card_publishes_the_layer_model(self) -> None:
        harness = FaspHarness(self.root / "node", "node", "http://node:8766")
        card = harness.id_card()
        FaspHarness.verify_id_card(card)
        self.assertEqual([entry["layer"] for entry in card["layers"]], [1, 2, 3, 4])
        self.assertEqual(card["layers"][0]["permitted_interactions"], ["observe"])
        harness.close()


if __name__ == "__main__":
    unittest.main()
