"""Spatial coordination between machines that share no clock and no frame.

The problem this package exists for is the air-ground one: a drone and a
ground vehicle that must agree about where each other are, when, and who
may act. Nothing about that is solved by putting them on the same network.
Two robots on one flawless link still disagree about the time, still hold
incompatible coordinate frames, and still act on information that was true
when it was sent and is not now.

Four message types, and each is one honest answer:

    TimeSync    `clock.py`      when, to within a stated bound
    StateReport `state.py`      where and how fast, with covariance
    FrameLink   `frames.py`     how two frames relate, and how stale that is
    Grant       `authority.py`  who may act, where, until when

They compose in one direction. A `TimeInterval` from a clock exchange
bounds the stamp on a `StateReport`; propagating that report turns the
timing bound into position uncertainty; expressing it through a
`FrameLink` adds the frame's own error; `guard.py` turns the result into a
radius at a stated residual risk; and `authority.py` asks whether that
radius fits inside what was actually delegated.

The invariant running through all of it is that no value crosses a machine
boundary without its uncertainty attached. A timestamp is an interval. A
pose is a mean and a covariance. A frame relationship carries a drift rate
and decays. A separation verdict quotes the risk it was decided at. This
is not conservatism for its own sake -- it is the only way a coordination
decision made from stale, remote, imprecise data can state what it is
actually worth.

Layer discipline is unchanged and enforced (`fasp_harness/layers.py`).
Everything here is Layer 3 coordination: it decides what a machine is
*permitted* to do, never what it does. There is no actuation verb in this
package, delegated authority cannot name a Layer 1 function, and a guard
band that closes is a coordination refusal -- the machine's own protective
stop is a different mechanism, upstream of anything here, and remains the
thing that actually keeps people safe.
"""

from __future__ import annotations

from .authority import MAX_DELEGATION_MS, Authorisation, SpatialDelegation, Volume
from .clock import (
    COMMODITY_CRYSTAL_PPM,
    GNSS_DISCIPLINED_PPM,
    TCXO_PPM,
    ClockEstimate,
    ClockTracker,
    Exchange,
    TimeInterval,
)
from .frames import DriftRate, FrameGraph, FrameLink, Rigid3, align_frames
from .guard import (
    Envelope,
    GuardPolicy,
    Morphology,
    Separation,
    check_separation,
    coverage_factor,
    envelope_for,
)
from .state import Aerial, ConstantVelocity, GroundVehicle, MotionModel, StateReport

__all__ = [
    # when
    "TimeInterval",
    "Exchange",
    "ClockTracker",
    "ClockEstimate",
    "COMMODITY_CRYSTAL_PPM",
    "TCXO_PPM",
    "GNSS_DISCIPLINED_PPM",
    # where two frames stand
    "Rigid3",
    "DriftRate",
    "FrameLink",
    "FrameGraph",
    "align_frames",
    # where a robot is
    "StateReport",
    "MotionModel",
    "ConstantVelocity",
    "GroundVehicle",
    "Aerial",
    # whether to proceed
    "Morphology",
    "GuardPolicy",
    "Envelope",
    "Separation",
    "envelope_for",
    "check_separation",
    "coverage_factor",
    # who may act
    "Volume",
    "SpatialDelegation",
    "Authorisation",
    "MAX_DELEGATION_MS",
]
