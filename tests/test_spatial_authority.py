"""Delegated authority: expiry without messages, volumes that bound the
envelope rather than the point, and a Layer 1 boundary that no signature
crosses.

The symmetry tests matter as much as the refusals: a delegation design
that only works in one direction is a master/slave design wearing
different words.
"""

from __future__ import annotations

import unittest

from fasp_harness.protocol.errors import FaspError
from fasp_harness.spatial.authority import MAX_DELEGATION_MS, SpatialDelegation, Volume
from fasp_harness.spatial.clock import TimeInterval
from fasp_harness.spatial.guard import Envelope, GuardPolicy, Morphology, envelope_for
from fasp_harness.spatial.linalg import identity, mat_scale
from fasp_harness.spatial.state import Aerial, GroundVehicle, StateReport

TIGHT = mat_scale(identity(6), 0.01)
SITE = Volume("site", [-20.0, -20.0, -5.0], [20.0, 20.0, 15.0])


def _ground_envelope(position: list[float], *, robot_id: str = "ugv-1", now_ms: float = 0.0, frame: str = "site") -> Envelope:
    report = StateReport(robot_id, frame, position, [1.5, 0.0, 0.0], TIGHT, TimeInterval(0.0, 5.0), GroundVehicle(), 2.0)
    return envelope_for(report, GuardPolicy(), now_ms, morphology=Morphology.GROUND, body_radius_m=0.4)


def _air_envelope(position: list[float], *, robot_id: str = "uav-1") -> Envelope:
    report = StateReport(robot_id, "site", position, [1.5, 0.0, 0.0], TIGHT, TimeInterval(0.0, 5.0), Aerial(), 12.0)
    return envelope_for(report, GuardPolicy(), 0.0, morphology=Morphology.AIR, body_radius_m=0.5)


def _delegation(**overrides: object) -> SpatialDelegation:
    defaults: dict[str, object] = {
        "holder": "uav-1",
        "subject": "ugv-1",
        "capability": "fleet.waypoint.append",
        "volume": SITE,
        "not_before_ms": 0.0,
        "not_after_ms": 30_000.0,
        "max_speed_mps": 2.0,
        "morphologies": frozenset({Morphology.GROUND}),
    }
    defaults.update(overrides)
    return SpatialDelegation(**defaults)  # type: ignore[arg-type]


class VolumeTests(unittest.TestCase):
    def test_a_sphere_must_fit_entirely_not_merely_its_centre(self) -> None:
        """Authorising on the point estimate authorises exactly the case
        where the robot turned out not to be at that point."""
        self.assertTrue(SITE.contains_point([19.9, 0.0, 0.0]))
        self.assertFalse(SITE.contains_sphere([19.9, 0.0, 0.0], 1.0))
        self.assertTrue(SITE.contains_sphere([0.0, 0.0, 0.0], 1.0))

    def test_clearance_reports_how_far_outside_a_refusal_was(self) -> None:
        self.assertAlmostEqual(SITE.clearance_m([19.0, 0.0, 0.0], 0.5), 0.5, places=9)
        self.assertAlmostEqual(SITE.clearance_m([19.0, 0.0, 0.0], 2.0), -1.0, places=9)

    def test_a_degenerate_volume_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            Volume("site", [0.0, 0.0, 0.0], [0.0, 5.0, 5.0])

    def test_a_volume_must_name_its_frame(self) -> None:
        with self.assertRaises(FaspError):
            Volume("", [-1.0, -1.0, -1.0], [1.0, 1.0, 1.0])

    def test_round_trips_through_a_mapping(self) -> None:
        self.assertEqual(Volume.from_mapping(SITE.to_dict()), SITE)


class ConstructionTests(unittest.TestCase):
    def test_a_layer_one_capability_cannot_be_delegated_at_any_scope(self) -> None:
        """No signature, scope or duration reaches an e-stop. A drone may
        propose a route; the ground robot's own safety layer remains the
        only thing that decides whether wheels turn."""
        for capability in ("safety.estop.clear", "protective.zone.mute", "wheel.velocity", "brake.release"):
            with self.assertRaises(FaspError, msg=capability) as caught:
                _delegation(capability=capability)
            self.assertEqual(caught.exception.code, "policy.layer_violation")

    def test_a_coordination_capability_is_accepted(self) -> None:
        self.assertEqual(_delegation().capability, "fleet.waypoint.append")

    def test_a_delegation_may_not_outlast_the_shared_lease_bound(self) -> None:
        with self.assertRaises(FaspError):
            _delegation(not_after_ms=MAX_DELEGATION_MS + 1.0)

    def test_a_delegation_must_expire_after_it_begins(self) -> None:
        with self.assertRaises(FaspError):
            _delegation(not_before_ms=10_000.0, not_after_ms=5_000.0)

    def test_a_system_cannot_delegate_to_itself(self) -> None:
        with self.assertRaises(FaspError):
            _delegation(holder="ugv-1", subject="ugv-1")

    def test_an_uncapped_speed_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            _delegation(max_speed_mps=0.0)

    def test_a_delegation_covering_no_morphology_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            _delegation(morphologies=frozenset())


class AuthorisationTests(unittest.TestCase):
    def test_permits_an_envelope_well_inside_the_volume(self) -> None:
        verdict = _delegation().authorise(_ground_envelope([0.0, 0.0, 0.0]), 1_000.0)
        self.assertTrue(verdict.permitted)
        self.assertGreater(verdict.clearance_m, 0.0)
        self.assertAlmostEqual(verdict.remaining_ms, 29_000.0, places=6)

    def test_refuses_when_the_envelope_protrudes_even_though_the_point_is_inside(self) -> None:
        verdict = _delegation().authorise(_ground_envelope([19.5, 0.0, 0.0]), 1_000.0)
        self.assertFalse(verdict.permitted)
        self.assertIn("protrudes", verdict.reason)

    def test_expiry_needs_no_revocation_message(self) -> None:
        """The failure this exists for is the link dropping while a
        delegation is outstanding. There is no message to lose, because
        expiry needs none: a clock is enough where a network is not."""
        delegation = _delegation()
        envelope = _ground_envelope([0.0, 0.0, 0.0])
        self.assertTrue(delegation.authorise(envelope, 29_999.0).permitted)
        self.assertFalse(delegation.authorise(envelope, 30_000.0).permitted)
        self.assertEqual(delegation.authorise(envelope, 30_001.0).remaining_ms, 0.0)

    def test_a_delegation_that_has_not_begun_is_refused(self) -> None:
        verdict = _delegation(not_before_ms=5_000.0, not_after_ms=35_000.0).authorise(_ground_envelope([0.0, 0.0, 0.0]), 1_000.0)
        self.assertFalse(verdict.permitted)
        self.assertIn("not begun", verdict.reason)

    def test_a_stale_report_silently_shrinks_the_authority_it_supports(self) -> None:
        """Nothing was revoked. The envelope simply grew until it no longer
        fitted the delegated volume, which is graceful degradation rather
        than a cliff."""
        delegation = _delegation()
        self.assertTrue(delegation.authorise(_ground_envelope([0.0, 0.0, 0.0], now_ms=0.0), 1_000.0).permitted)
        self.assertFalse(delegation.authorise(_ground_envelope([0.0, 0.0, 0.0], now_ms=8_000.0), 1_000.0).permitted)

    def test_a_delegation_over_one_robot_does_not_authorise_another(self) -> None:
        verdict = _delegation().authorise(_ground_envelope([0.0, 0.0, 0.0], robot_id="ugv-2"), 1_000.0)
        self.assertFalse(verdict.permitted)
        self.assertIn("ugv-2", verdict.reason)

    def test_a_frame_mismatch_is_refused_rather_than_assumed_away(self) -> None:
        verdict = _delegation().authorise(_ground_envelope([0.0, 0.0, 0.0], frame="uav/enu"), 1_000.0)
        self.assertFalse(verdict.permitted)
        self.assertIn("frame", verdict.reason)

    def test_a_delegation_for_ground_does_not_cover_an_aerial_platform(self) -> None:
        verdict = _delegation(holder="ugv-1", subject="uav-1").authorise(_air_envelope([0.0, 0.0, 5.0]), 1_000.0)
        self.assertFalse(verdict.permitted)
        self.assertIn("air", verdict.reason)

    def test_a_speed_above_the_delegated_cap_is_refused(self) -> None:
        verdict = _delegation().authorise(_ground_envelope([0.0, 0.0, 0.0]), 1_000.0, requested_speed_mps=5.0)
        self.assertFalse(verdict.permitted)
        self.assertIn("exceeds the delegated cap", verdict.reason)

    def test_a_speed_within_the_cap_is_permitted(self) -> None:
        self.assertTrue(_delegation().authorise(_ground_envelope([0.0, 0.0, 0.0]), 1_000.0, requested_speed_mps=1.0).permitted)


class SymmetryTests(unittest.TestCase):
    def test_authority_runs_in_both_directions_with_the_same_construct(self) -> None:
        """Holder and subject are names, not roles. The drone commanding
        the ground robot and the ground robot commanding the drone are one
        mechanism with the fields swapped."""
        drone_over_ground = _delegation()
        ground_over_drone = _delegation(
            holder="ugv-1",
            subject="uav-1",
            max_speed_mps=12.0,
            morphologies=frozenset({Morphology.AIR}),
        )
        self.assertTrue(drone_over_ground.authorise(_ground_envelope([0.0, 0.0, 0.0]), 1_000.0).permitted)
        self.assertTrue(ground_over_drone.authorise(_air_envelope([0.0, 0.0, 5.0]), 1_000.0).permitted)

    def test_holding_authority_over_a_peer_does_not_confer_it_in_reverse(self) -> None:
        verdict = _delegation().authorise(_air_envelope([0.0, 0.0, 5.0]), 1_000.0)
        self.assertFalse(verdict.permitted)


class GrantIntegrationTests(unittest.TestCase):
    def test_round_trips_through_the_existing_grant_constraints_field(self) -> None:
        """Carried inside the existing grant rather than as a parallel
        credential, so signature, revocation and audit apply unchanged."""
        delegation = _delegation()
        constraints = delegation.to_constraints()
        self.assertIn("spatial_delegation", constraints)
        self.assertEqual(SpatialDelegation.from_constraints(constraints), delegation)

    def test_constraints_without_a_delegation_are_refused(self) -> None:
        with self.assertRaises(FaspError):
            SpatialDelegation.from_constraints({"purpose": "unrelated"})

    def test_a_malformed_delegation_payload_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            SpatialDelegation.from_constraints({"spatial_delegation": {"holder": "uav-1"}})

    def test_an_unknown_morphology_is_refused(self) -> None:
        broken = _delegation().to_constraints()
        broken["spatial_delegation"]["morphologies"] = ["orbital"]
        with self.assertRaises(FaspError):
            SpatialDelegation.from_constraints(broken)

    def test_a_layer_one_capability_smuggled_through_constraints_is_still_refused(self) -> None:
        """The deny list runs on deserialisation too, so a peer cannot post
        a delegation the local API would have rejected."""
        smuggled = _delegation().to_constraints()
        smuggled["spatial_delegation"]["capability"] = "safety.estop.clear"
        with self.assertRaises(FaspError) as caught:
            SpatialDelegation.from_constraints(smuggled)
        self.assertEqual(caught.exception.code, "policy.layer_violation")


if __name__ == "__main__":
    unittest.main()
