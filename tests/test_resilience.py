"""Network resilience, proved on a deterministic adversarial network."""

from __future__ import annotations

import unittest

from fasp_harness.resilience.faults import LinkProfile, SimulatedNetwork
from fasp_harness.resilience.mesh import MeshNode, run_partition_scenario


class SimulatedNetworkTests(unittest.TestCase):
    def test_the_same_seed_produces_the_same_run(self) -> None:
        """Determinism is the point: a resilience bug found here comes with
        a seed that reproduces it exactly."""

        def run(seed: int) -> list[tuple[float, str]]:
            received: list[tuple[float, str]] = []
            network = SimulatedNetwork(seed=seed)
            network.set_default(LinkProfile.industrial_wifi())
            network.on_receive("b", lambda source, payload, corrupted: received.append((network.now_ms, payload)))
            for index in range(200):
                network.send("a", "b", f"m{index}")
                network.advance(1.0)
            network.drain()
            return received

        self.assertEqual(run(11), run(11))
        self.assertNotEqual(run(11), run(12))

    def test_a_partition_drops_everything_and_healing_does_not_undrop_it(self) -> None:
        received: list[str] = []
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile.perfect())
        network.on_receive("b", lambda source, payload, corrupted: received.append(payload))
        network.partition(["a"], ["b"])
        network.send("a", "b", "during-partition")
        network.drain()
        self.assertEqual(received, [])
        network.heal()
        network.drain()
        self.assertEqual(received, [], "Healing a partition must not resurrect frames that were dropped by it.")
        network.send("a", "b", "after-heal")
        network.drain()
        self.assertEqual(received, ["after-heal"])

    def test_an_asymmetric_partition_only_cuts_one_direction(self) -> None:
        """The nastier case: A believes it is talking to B, and B hears
        nothing, so A's timeouts never fire."""
        to_a: list[str] = []
        to_b: list[str] = []
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile.perfect())
        network.on_receive("a", lambda source, payload, corrupted: to_a.append(payload))
        network.on_receive("b", lambda source, payload, corrupted: to_b.append(payload))
        network.partition(["a"], ["b"], symmetric=False)
        network.send("a", "b", "a->b")
        network.send("b", "a", "b->a")
        network.drain()
        self.assertEqual(to_b, [])
        self.assertEqual(to_a, ["b->a"])

    def test_loss_duplication_and_corruption_are_all_observable(self) -> None:
        received: list[tuple[str, bool]] = []
        network = SimulatedNetwork(seed=5)
        network.set_default(LinkProfile(loss_ratio=0.3, duplicate_ratio=0.3, corrupt_ratio=0.3, latency_ms=(1.0, 2.0)))
        network.on_receive("b", lambda source, payload, corrupted: received.append((payload, corrupted)))
        for index in range(300):
            network.send("a", "b", f"m{index}")
        network.drain()
        report = network.report
        self.assertEqual(report.sent, 300)
        self.assertGreater(report.dropped_loss, 0)
        self.assertGreater(report.duplicated, 0)
        self.assertGreater(report.corrupted, 0)
        self.assertTrue(any(corrupted for _payload, corrupted in received))

    def test_a_bounded_link_drops_when_its_queue_is_full(self) -> None:
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile(latency_ms=(100.0, 100.0), max_in_flight=5))
        network.on_receive("b", lambda source, payload, corrupted: None)
        for index in range(50):
            network.send("a", "b", index)
        self.assertGreater(network.report.dropped_queue_full, 0)

    def test_virtual_time_never_moves_backwards(self) -> None:
        network = SimulatedNetwork(seed=1)
        network.advance(1000.0)
        self.assertEqual(network.now_ms, 1000.0)
        network.advance_to(500.0)
        self.assertEqual(network.now_ms, 1000.0)


class MeshTests(unittest.TestCase):
    def test_carrying_delivers_across_a_hard_partition(self) -> None:
        report = run_partition_scenario(seed=3, messages=12)
        self.assertEqual(report.delivered_during_partition, 0, "The scenario must actually exercise a partition.")
        self.assertEqual(report.delivered, 12)
        self.assertEqual(report.duplicate_deliveries, 0)
        self.assertTrue(report.complete)

    def test_the_result_holds_across_seeds(self) -> None:
        for seed in (1, 2, 3, 4, 5):
            with self.subTest(seed=seed):
                report = run_partition_scenario(seed=seed, messages=8)
                self.assertTrue(report.complete, report.to_dict())

    def test_duplicate_arrivals_are_suppressed_by_message_id(self) -> None:
        """Multi-path flooding means duplicates are guaranteed. `message_id`
        is what makes them harmless -- the same gate the protocol already
        uses for replay."""
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile.perfect())
        delivered: list[str] = []
        sink = MeshNode("sink", network, on_deliver=lambda envelope: delivered.append(envelope.message_id))
        left = MeshNode("left", network, neighbours=["sink"])
        right = MeshNode("right", network, neighbours=["sink"])
        source = MeshNode("source", network, neighbours=["left", "right"])
        for node in (sink, left, right):
            node.add_neighbour("source")
        source.send("sink", "m1", {"payload": True})
        network.drain(on_tick=lambda now: [node.tick(now) for node in (source, left, right, sink)])
        self.assertEqual(delivered, ["m1"])
        self.assertGreater(sink.stats.duplicates_suppressed, 0)

    def test_a_corrupted_frame_is_rejected_not_propagated(self) -> None:
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile(corrupt_ratio=1.0, latency_ms=(1.0, 1.0)))
        delivered: list[str] = []
        sink = MeshNode("sink", network, on_deliver=lambda envelope: delivered.append(envelope.message_id))
        source = MeshNode("source", network, neighbours=["sink"])
        sink.add_neighbour("source")
        source.send("sink", "m1", {})
        network.drain()
        self.assertEqual(delivered, [])
        self.assertGreater(sink.stats.corrupted_rejected, 0)

    def test_hop_limit_bounds_the_flood(self) -> None:
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile.perfect())
        chain = [f"n{index}" for index in range(8)]
        nodes = {}
        delivered: list[str] = []
        for index, node_id in enumerate(chain):
            neighbours = [neighbour for neighbour in (chain[index - 1] if index else None, chain[index + 1] if index + 1 < len(chain) else None) if neighbour]
            nodes[node_id] = MeshNode(node_id, network, neighbours=neighbours, on_deliver=lambda envelope: delivered.append(envelope.message_id))
        nodes[chain[0]].send(chain[-1], "m1", {}, hop_limit=2)
        network.drain(on_tick=lambda now: [node.tick(now) for node in nodes.values()])
        self.assertEqual(delivered, [], "A hop limit of 2 must not reach the far end of an 8-node chain.")
        self.assertTrue(any(node.stats.hop_limited for node in nodes.values()))

    def test_an_expired_message_is_dropped_rather_than_delivered_uselessly_late(self) -> None:
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile.perfect())
        delivered: list[str] = []
        sink = MeshNode("sink", network, on_deliver=lambda envelope: delivered.append(envelope.message_id))
        relay = MeshNode("relay", network, neighbours=[])
        source = MeshNode("source", network, neighbours=["relay"])
        relay.add_neighbour("source")
        source.send("sink", "m1", {}, ttl_ms=100.0)
        network.run(duration_ms=5_000, tick_ms=50.0, on_tick=lambda now: [node.tick(now) for node in (source, relay, sink)])
        self.assertEqual(delivered, [])
        self.assertGreater(relay.stats.expired + source.stats.expired, 0)

    def test_carry_capacity_is_bounded(self) -> None:
        network = SimulatedNetwork(seed=1)
        network.set_default(LinkProfile.perfect())
        node = MeshNode("carrier", network, neighbours=[], carry_capacity=5)
        for index in range(20):
            node.send("elsewhere", f"m{index}", {})
        self.assertGreater(node.stats.dropped_capacity, 0)


if __name__ == "__main__":
    unittest.main()
