"""The hardware-in-the-loop bench and the evidence it produces."""

from __future__ import annotations

import unittest

from fasp_harness.hil.bench import HilBench, SimulatedSafetyDut
from fasp_harness.hil.scenario import Scenario, Step, moving_permitted, standard_safety_scenarios, stopped


class BenchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.device = SimulatedSafetyDut(stale_after_s=0.3)
        self.device.reset()
        self.bench = HilBench(self.device, poll_interval_ms=1.0)

    def test_every_standard_safety_scenario_passes(self) -> None:
        for scenario in standard_safety_scenarios():
            with self.subTest(scenario=scenario.name):
                self.device.reset()
                report = self.bench.run(scenario)
                self.assertTrue(report.passed, report.render_text())
                self.assertLessEqual(report.worst_latency_ms, max(step.deadline_ms for step in scenario.steps))

    def test_a_simulated_run_is_labelled_as_such(self) -> None:
        """A green CI run must never be presentable as a hardware
        qualification."""
        report = self.bench.run(standard_safety_scenarios()[0])
        self.assertFalse(report.real_hardware)
        self.assertIn("Simulated runs demonstrate logic", report.to_dict()["note"])

    def test_the_evidence_chain_verifies_and_detects_tampering(self) -> None:
        report = self.bench.run(standard_safety_scenarios()[1])
        ok, index = report.verify_chain()
        self.assertTrue(ok)
        self.assertIsNone(index)

        report.results[0].latency_ms = 0.0001
        ok, index = report.verify_chain()
        self.assertFalse(ok, "An edited measurement must invalidate the chain.")
        self.assertEqual(index, 0)

    def test_an_expectation_that_never_holds_fails_at_its_deadline(self) -> None:
        scenario = Scenario(name="impossible", steps=(Step("never", lambda sample: False, deadline_ms=20.0),))
        report = self.bench.run(scenario)
        self.assertFalse(report.passed)
        self.assertIsNone(report.results[0].latency_ms)
        self.assertIn("never held", report.results[0].detail)

    def test_a_failed_critical_step_aborts_the_scenario(self) -> None:
        """Continuing past a failed safety expectation measures a system in
        a state the scenario never intended."""
        scenario = Scenario(
            name="abort",
            steps=(
                Step("fails", lambda sample: False, deadline_ms=10.0, critical=True),
                Step("never-runs", lambda sample: True, deadline_ms=10.0),
            ),
        )
        report = self.bench.run(scenario)
        self.assertEqual(len(report.results), 1)

    def test_a_raising_stimulus_is_a_failed_step_not_a_crashed_bench(self) -> None:
        def explode(device) -> None:
            raise RuntimeError("bench cable unplugged")

        report = self.bench.run(Scenario(name="boom", steps=(Step("stimulus-fails", lambda sample: True, explode, deadline_ms=10.0),)))
        self.assertFalse(report.passed)
        self.assertIn("stimulus raised", report.results[0].detail)

    def test_setup_and_teardown_run_around_the_scenario(self) -> None:
        events: list[str] = []
        scenario = Scenario(
            name="lifecycle",
            steps=(Step("ok", lambda sample: True, deadline_ms=50.0),),
            setup=lambda device: events.append("setup"),
            teardown=lambda device: events.append("teardown"),
        )
        self.bench.run(scenario)
        self.assertEqual(events, ["setup", "teardown"])

    def test_teardown_runs_even_when_a_step_fails(self) -> None:
        events: list[str] = []
        scenario = Scenario(name="x", steps=(Step("fails", lambda sample: False, deadline_ms=5.0),), teardown=lambda device: events.append("teardown"))
        self.bench.run(scenario)
        self.assertEqual(events, ["teardown"])

    def test_the_bench_measures_a_real_actuation_delay(self) -> None:
        """A device with a modelled delay must not measure as instantaneous:
        if it did, the bench would be measuring itself."""
        slow = SimulatedSafetyDut(stale_after_s=0.3)
        slow.controller.stop_delay_s = 0.05
        slow.reset()
        scenario = Scenario(
            name="delayed",
            steps=(
                Step("baseline", moving_permitted, lambda device: device.apply({"reset": True}), deadline_ms=1000.0),
                Step("halt-observed", stopped, lambda device: device.apply({"network_halt": "measured"}), deadline_ms=1000.0),
            ),
        )
        report = HilBench(slow, poll_interval_ms=1.0).run(scenario)
        self.assertTrue(report.passed, report.render_text())
        self.assertGreaterEqual(report.results[-1].latency_ms, 50.0)

    def test_a_signed_report_carries_a_verifiable_head(self) -> None:
        import tempfile
        from pathlib import Path

        from fasp_harness.crypto.envelope import verify
        from fasp_harness.crypto.identity import Identity

        with tempfile.TemporaryDirectory() as directory:
            identity = Identity.load_or_create(Path(directory) / "identity.json")
            report = HilBench(self.device, poll_interval_ms=1.0, identity=identity).run(standard_safety_scenarios()[0])
            self.assertIsNotNone(report.signature)
            verify(report.signature, identity.public_b64)
            self.assertEqual(report.signature["head"], report.results[-1].row_hash)

    def test_the_device_records_that_it_refused_a_network_clear(self) -> None:
        self.bench.run(next(item for item in standard_safety_scenarios() if item.name == "network-halt-request"))
        self.assertGreater(self.device.rejected_network_clears, 0)


if __name__ == "__main__":
    unittest.main()
