"""The safety case engine, and the reference argument built on it."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspHarness
from fasp_harness.safety.case import CERTIFICATION_NOTE, Claim, Evidence, EvidenceResult, SafetyCase, Verdict
from fasp_harness.safety.drivers import SimulatedSafetyController
from fasp_harness.safety.interlock import SafetySupervisor
from fasp_harness.safety.reference_case import ATTEMPTED_LAYER1_CAPABILITIES, build_reference_case
from fasp_harness.security.posture import DeploymentConfig, SecurityProfile


def passing(detail: str = "ok") -> Evidence:
    return Evidence("E-ok", detail, "test", lambda: EvidenceResult.supported(detail))


class SafetyCaseEngineTests(unittest.TestCase):
    def test_a_claim_is_supported_only_when_its_evidence_passes(self) -> None:
        case = SafetyCase("t", "G1")
        case.add_evidence(passing())
        case.claim(Claim("G1", "It works.", evidence=("E-ok",)))
        self.assertIs(case.verify().root_verdict, Verdict.SUPPORTED)

    def test_failing_evidence_propagates_to_the_root(self) -> None:
        case = SafetyCase("t", "G1")
        case.add_evidence(Evidence("E-bad", "d", "test", lambda: EvidenceResult.failed("measured 900ms against a 250ms budget")))
        case.claim(Claim("G1", "Root.", sub_claims=("G2",)))
        case.claim(Claim("G2", "Child.", evidence=("E-bad",)))
        report = case.verify()
        self.assertIs(report.root_verdict, Verdict.NOT_SUPPORTED)
        self.assertEqual(len(report.failures), 2)

    def test_evidence_that_raises_is_inconclusive_never_passing(self) -> None:
        """An assessor must see a broken check as an unmet claim; a crash
        must never be mistaken for either success or a clean failure."""

        def explode() -> EvidenceResult:
            raise RuntimeError("the bench is unplugged")

        case = SafetyCase("t", "G1")
        case.add_evidence(Evidence("E-boom", "d", "test", explode))
        case.claim(Claim("G1", "Root.", evidence=("E-boom",)))
        report = case.verify()
        self.assertIs(report.root_verdict, Verdict.INCONCLUSIVE)
        self.assertIn("raised", report.outcomes[0].evidence[0][1].detail)

    def test_a_delegated_claim_is_recorded_not_claimed_and_not_a_failure(self) -> None:
        case = SafetyCase("t", "G1")
        case.claim(Claim("G1", "Root.", sub_claims=("G2",), evidence=()))
        case.claim(Claim("G2", "Layer 1.", delegated_to="the machine builder's certified controller"))
        report = case.verify()
        self.assertIs(report.root_verdict, Verdict.SUPPORTED)
        self.assertEqual(len(report.delegated), 1)
        self.assertEqual(report.failures, [])

    def test_an_undeveloped_claim_is_visible_in_the_verdict(self) -> None:
        case = SafetyCase("t", "G1")
        case.claim(Claim("G1", "Root.", sub_claims=("G2",)))
        case.claim(Claim("G2", "Independent validation.", undeveloped=True, rationale="requires a competent body"))
        report = case.verify()
        self.assertEqual(len(report.undeveloped), 1)
        self.assertIn("undeveloped", report.verdict)

    def test_a_claim_with_neither_evidence_nor_children_is_undeveloped(self) -> None:
        case = SafetyCase("t", "G1")
        case.claim(Claim("G1", "Trust me."))
        self.assertIs(case.verify().root_verdict, Verdict.UNDEVELOPED)

    def test_structural_problems_are_found_without_running_anything(self) -> None:
        ran: list[int] = []
        case = SafetyCase("t", "G1")
        case.add_evidence(Evidence("E1", "d", "test", lambda: (ran.append(1), EvidenceResult.supported("x"))[1]))
        case.claim(Claim("G1", "Root.", sub_claims=("G-missing",), evidence=("E1", "E-missing")))
        problems = case.validate()
        self.assertEqual(len(problems), 2)
        report = case.verify()
        self.assertIs(report.root_verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(ran, [], "A structurally broken case must not execute evidence.")

    def test_a_cycle_is_detected(self) -> None:
        case = SafetyCase("t", "G1")
        case.claim(Claim("G1", "A.", sub_claims=("G2",)))
        case.claim(Claim("G2", "B.", sub_claims=("G1",)))
        self.assertTrue(any("cycle" in problem for problem in case.validate()))

    def test_shared_evidence_runs_exactly_once(self) -> None:
        runs: list[int] = []

        def counted() -> EvidenceResult:
            runs.append(1)
            return EvidenceResult.supported("ok")

        case = SafetyCase("t", "G1")
        case.add_evidence(Evidence("E1", "d", "test", counted))
        case.claim(Claim("G1", "Root.", sub_claims=("G2", "G3")))
        case.claim(Claim("G2", "A.", evidence=("E1",)))
        case.claim(Claim("G3", "B.", evidence=("E1",)))
        case.verify()
        self.assertEqual(len(runs), 1, "The report must not contain two answers to the same question.")

    def test_the_report_can_never_call_itself_certifiable(self) -> None:
        case = SafetyCase("t", "G1")
        case.add_evidence(passing())
        case.claim(Claim("G1", "Everything is fine.", evidence=("E-ok",)))
        report = case.verify()
        self.assertFalse(report.certifiable)
        self.assertIn("not a certificate", CERTIFICATION_NOTE)
        self.assertIn("not a certificate", report.render_text())
        self.assertIn("not independently assessed", report.verdict)

    def test_the_argument_serialises_for_review(self) -> None:
        case = SafetyCase("t", "G1")
        case.add_evidence(passing())
        case.claim(Claim("G1", "It works.", evidence=("E-ok",)))
        self.assertIn("G1", case.to_json())


class ReferenceCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_the_argument_is_structurally_sound(self) -> None:
        self.assertEqual(build_reference_case().validate(), [])

    def test_without_a_configured_system_the_posture_claims_do_not_hold(self) -> None:
        """The case must fail honestly when it has nothing to check."""
        report = build_reference_case().verify()
        failed = {outcome.claim.id for outcome in report.failures}
        self.assertIn("G8", failed)
        self.assertIn("G1", failed)

    def test_with_a_running_system_every_technical_claim_holds(self) -> None:
        harness = FaspHarness(self.root / "node", "node", "http://node:8766")
        supervisor = SafetySupervisor(SimulatedSafetyController())
        config = DeploymentConfig(profile=SecurityProfile.DEVELOPMENT, state_dir=self.root / "node")
        report = build_reference_case(harness=harness, config=config, supervisor=supervisor).verify()

        # G15's evidence rightly fails on a simulated controller, so G8
        # fails: that is the case working, not the case broken.
        failed = {outcome.claim.id for outcome in report.failures}
        self.assertEqual(failed, {"G1", "G8"}, report.render_text())
        for claim_id in ("G3", "G4", "G5", "G6", "G7"):
            with self.subTest(claim=claim_id):
                outcome = next(item for item in report.outcomes if item.claim.id == claim_id)
                self.assertIs(outcome.verdict, Verdict.SUPPORTED, outcome.detail)
        harness.close()

    def test_layer1_claims_are_delegated_and_validation_is_undeveloped(self) -> None:
        report = build_reference_case().verify()
        delegated = {outcome.claim.id for outcome in report.delegated}
        self.assertEqual(delegated, {"G2", "G10"})
        self.assertEqual({outcome.claim.id for outcome in report.undeveloped}, {"G9"})
        g9 = next(outcome for outcome in report.outcomes if outcome.claim.id == "G9")
        self.assertIn("competent body", g9.detail)

    def test_the_attempted_layer1_capabilities_are_a_real_list(self) -> None:
        self.assertGreaterEqual(len(ATTEMPTED_LAYER1_CAPABILITIES), 8)
        from fasp_harness.layers import LayerGuard

        for capability_id in ATTEMPTED_LAYER1_CAPABILITIES:
            with self.subTest(capability=capability_id):
                self.assertIsNotNone(LayerGuard.reserved_reason(capability_id))


if __name__ == "__main__":
    unittest.main()
