"""Security as a workflow: posture enforcement, 62443 register, SBOM."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fasp_harness.protocol.errors import FaspError
from fasp_harness.security.iec62443 import (
    Conduit,
    ControlStatus,
    SecurityLevel,
    SystemContext,
    Zone,
    ZoneModel,
    assess,
    default_register,
    reference_zone_model,
)
from fasp_harness.security.posture import DeploymentConfig, SecurityProfile, evaluate_posture
from fasp_harness.security.sbom import generate_sbom


class PostureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp.name)
        (self.state_dir / "identity.json").write_text("{}")
        (self.state_dir / "admin_token").write_text("token")
        os.chmod(self.state_dir / "identity.json", 0o600)
        os.chmod(self.state_dir / "admin_token", 0o600)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def config(self, **overrides) -> DeploymentConfig:
        return DeploymentConfig(state_dir=self.state_dir, **overrides)

    def test_development_on_loopback_is_acceptable(self) -> None:
        report = evaluate_posture(self.config(profile=SecurityProfile.DEVELOPMENT))
        self.assertTrue(report.acceptable, report.render_text())

    def test_plain_http_on_a_public_interface_blocks_a_hardened_profile(self) -> None:
        report = evaluate_posture(self.config(profile=SecurityProfile.HARDENED, host="0.0.0.0", insecure_http=True))
        self.assertFalse(report.acceptable)
        self.assertIn("transport.tls", [finding.control for finding in report.blocking])
        with self.assertRaises(FaspError) as raised:
            report.enforce()
        self.assertEqual(raised.exception.code, "policy.insecure_configuration")

    def test_production_additionally_requires_mutual_tls(self) -> None:
        certificates = {"tls_cert": self.state_dir / "cert.pem", "tls_key": self.state_dir / "key.pem"}
        hardened = evaluate_posture(self.config(profile=SecurityProfile.HARDENED, host="0.0.0.0", **certificates))
        self.assertTrue(hardened.acceptable, hardened.render_text())

        production = evaluate_posture(self.config(profile=SecurityProfile.PRODUCTION, host="0.0.0.0", **certificates))
        self.assertFalse(production.acceptable)
        self.assertIn("transport.mtls", [finding.control for finding in production.blocking])

        secured = evaluate_posture(self.config(profile=SecurityProfile.PRODUCTION, host="0.0.0.0", audit_verified=True, artifact_encryption=True, tls_client_ca=self.state_dir / "ca.pem", **certificates))
        self.assertTrue(secured.acceptable, secured.render_text())

    def test_world_readable_private_material_blocks_everything_above_development(self) -> None:
        os.chmod(self.state_dir / "identity.json", 0o644)
        report = evaluate_posture(self.config(profile=SecurityProfile.HARDENED, host="127.0.0.1"))
        self.assertFalse(report.acceptable)
        self.assertIn("secrets.permissions", [finding.control for finding in report.blocking])

    def test_disabled_rate_limiting_is_blocking(self) -> None:
        report = evaluate_posture(self.config(profile=SecurityProfile.HARDENED, rate_limit_per_peer=0.0))
        self.assertIn("availability.rate_limits", [finding.control for finding in report.blocking])

    def test_a_simulated_safety_controller_blocks_a_real_deployment(self) -> None:
        """The check nobody wants to fail in production and everyone fails
        in CI -- which is exactly why it must be a gate, not a note."""
        from fasp_harness.safety.drivers import SimulatedSafetyController

        report = evaluate_posture(self.config(profile=SecurityProfile.HARDENED, safety_controller=SimulatedSafetyController().describe()))
        self.assertFalse(report.acceptable)
        self.assertIn("safety.controller", [finding.control for finding in report.blocking])

    def test_a_broken_audit_chain_is_critical(self) -> None:
        report = evaluate_posture(self.config(profile=SecurityProfile.HARDENED, audit_verified=False))
        self.assertIn("audit.integrity", [finding.control for finding in report.blocking])

    def test_an_unenforcing_ros2_domain_is_reported(self) -> None:
        from fasp_harness.industrial.ros2 import inspect_sros2

        report = evaluate_posture(self.config(profile=SecurityProfile.HARDENED, ros2_enabled=True, ros2_posture=inspect_sros2({"ROS_SECURITY_ENABLE": "false"})))
        self.assertTrue(any(finding.control.startswith("ros2.") for finding in report.blocking))

    def test_every_finding_carries_a_remediation(self) -> None:
        report = evaluate_posture(self.config(profile=SecurityProfile.PRODUCTION, host="0.0.0.0"))
        for finding in report.findings:
            with self.subTest(control=finding.control):
                self.assertTrue(finding.remediation, f"{finding.control} has no remediation")


class Iec62443Tests(unittest.TestCase):
    def test_the_register_covers_every_foundational_requirement(self) -> None:
        covered = {control.fr.name for control in default_register()}
        self.assertEqual(covered, {"FR1", "FR2", "FR3", "FR4", "FR5", "FR6", "FR7"})

    def test_assessment_runs_without_a_running_system_and_says_so(self) -> None:
        assessment = assess(SystemContext())
        manual = [control for control, result in assessment.results if result.status is ControlStatus.MANUAL]
        self.assertTrue(manual)
        self.assertIn("not a certification", assessment.to_dict()["disclaimer"])

    def test_the_roll_up_is_the_minimum_and_names_the_limiting_control(self) -> None:
        """A system with nine met controls and one gap is protected to the
        level of the gap. Averaging is how that fact gets lost."""
        assessment = assess(SystemContext(config=DeploymentConfig(profile=SecurityProfile.DEVELOPMENT)))
        for requirement, detail in assessment.demonstrated.items():
            with self.subTest(fr=requirement):
                self.assertIn("limited_by", detail)
                self.assertGreaterEqual(detail["sl"], 0)
                if detail["status"] != "met":
                    self.assertEqual(detail["sl"], 0 if detail["status"] in {"manual", "not_met"} else detail["sl"])

    def test_a_control_whose_check_raises_is_unmet_never_a_pass(self) -> None:
        from fasp_harness.security.iec62443 import Control, FoundationalRequirement

        def explode(context: SystemContext):
            raise RuntimeError("nope")

        control = Control("SR X", FoundationalRequirement.FR1, "broken", SecurityLevel.SL2, explode)
        self.assertIs(control.run(SystemContext()).status, ControlStatus.NOT_MET)

    def test_disabled_rate_limiting_fails_the_denial_of_service_control(self) -> None:
        assessment = assess(SystemContext(config=DeploymentConfig(rate_limit_per_peer=0.0)))
        result = next(result for control, result in assessment.results if control.id == "SR 7.1")
        self.assertIs(result.status, ControlStatus.NOT_MET)

    def test_the_reference_zone_model_is_internally_consistent(self) -> None:
        self.assertEqual(reference_zone_model().validate(), [])

    def test_a_conduit_weaker_than_the_zone_it_reaches_is_a_problem(self) -> None:
        """The conduit is the weakest point of the higher zone."""
        model = ZoneModel(
            zones=[Zone("safety", SecurityLevel.SL3), Zone("office", SecurityLevel.SL1)],
            conduits=[Conduit("weak", "safety", "office", ("http",), SecurityLevel.SL1)],
        )
        problems = model.validate()
        self.assertEqual(len(problems), 1)
        self.assertIn("weakest point", problems[0])

    def test_a_conduit_to_an_undefined_zone_is_a_problem(self) -> None:
        model = ZoneModel(zones=[Zone("a", SecurityLevel.SL1)], conduits=[Conduit("c", "a", "ghost", ("x",), SecurityLevel.SL1)])
        self.assertTrue(any("undefined zone" in problem for problem in model.validate()))

    def test_the_safety_zone_has_no_writable_inbound_conduit(self) -> None:
        model = reference_zone_model()
        inbound = [conduit for conduit in model.conduits if conduit.destination == "safety"]
        self.assertEqual(inbound, [], "Nothing may write into the safety zone.")
        outbound = next(conduit for conduit in model.conduits if conduit.source == "safety")
        self.assertIn("read-only", " ".join(outbound.protocols + outbound.controls).lower())


class SbomTests(unittest.TestCase):
    def test_it_produces_a_valid_cyclonedx_document(self) -> None:
        document = generate_sbom()
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.5")
        self.assertTrue(document["components"])
        for component in document["components"]:
            self.assertTrue(component["purl"].startswith("pkg:pypi/"))
            self.assertTrue(component["hashes"])

    def test_components_are_deterministically_ordered(self) -> None:
        first, second = generate_sbom()["components"], generate_sbom()["components"]
        self.assertEqual(first, second)
        self.assertEqual([component["bom-ref"] for component in first], sorted(component["bom-ref"] for component in first))

    def test_it_reports_the_runtime_it_describes(self) -> None:
        properties = {entry["name"]: entry["value"] for entry in generate_sbom()["metadata"]["properties"]}
        self.assertIn("fasp:python", properties)
        self.assertIn("fasp:platform", properties)


if __name__ == "__main__":
    unittest.main()
