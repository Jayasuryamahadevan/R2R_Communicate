"""Two-way time transfer: what "at the same moment" means between machines.

Two robots cannot compare positions until they agree about when. This is
not a detail that can be deferred -- a ground vehicle and a drone closing
at a combined 5 m/s are 5 cm apart per millisecond of clock disagreement,
so a 200 ms unnoticed offset is a metre of phantom clearance in a
calculation that reads as exact.

The mechanism is the one NTP and PTP both use, reduced to its core. Four
timestamps per exchange:

    t1  requester sends          (local clock)
    t2  responder receives       (remote clock)
    t3  responder sends          (remote clock)
    t4  requester receives       (local clock)

    offset      theta = ((t2 - t1) + (t3 - t4)) / 2
    round trip  delta = (t4 - t1) - (t3 - t2)

theta is exact only if the two path directions took equal time. They did
not. What survives is the bound: the true offset lies within delta/2 of
theta, because all of the asymmetry a path can hide is bounded by the trip
it took. So this module never returns an offset -- it returns a
`TimeInterval`, and every consumer is forced to carry the width.

Two things this does that a naive implementation does not:

1. **Min-filtering.** On a shared radio the round trip is dominated by
   queueing, not distance, so the samples are a long right tail over a
   floor. The minimum-RTT sample in a window is the least-queued one and
   therefore the tightest bound; averaging instead pulls the estimate into
   the tail. Samples are bucketed in time and the minimum of each bucket
   is kept, which filters queueing while preserving the spread a skew fit
   needs.

2. **Refusing to assume zero drift.** Two clocks do not merely differ,
   they diverge. `C(t) = (1 + alpha) t + beta`, and a commodity crystal is
   specified at +/-50 ppm -- 180 ms per hour. Until enough samples exist
   to *measure* alpha, this module assumes the datasheet worst case rather
   than zero, so a tracker that has just started is honestly imprecise
   instead of confidently wrong.

`ClockEstimate.resync_interval_s()` inverts the same arithmetic: given the
tolerance a caller needs to hold, it says how often the exchange must run.
At 50 ppm, holding one millisecond means resyncing every twenty seconds.
"""

from __future__ import annotations

import math
from bisect import insort
from collections.abc import Sequence
from dataclasses import dataclass

from ..protocol.errors import FaspError

__all__ = [
    "TimeInterval",
    "Exchange",
    "ClockEstimate",
    "ClockTracker",
    "COMMODITY_CRYSTAL_PPM",
    "TCXO_PPM",
    "GNSS_DISCIPLINED_PPM",
]

# Free-running crystal oscillators, as specified rather than as hoped. The
# default is the commodity part, because assuming the good one and getting
# the cheap one is the failure that shows up as unexplained drift in the
# field rather than as an error at startup.
COMMODITY_CRYSTAL_PPM = 50.0
TCXO_PPM = 2.0
GNSS_DISCIPLINED_PPM = 0.01

# A round trip longer than this is not a measurement, it is an outage. Kept
# generous: a three-hop mesh under load genuinely takes hundreds of ms.
MAX_PLAUSIBLE_ROUND_TRIP_MS = 5_000.0


@dataclass(frozen=True)
class TimeInterval:
    """An instant known only to within a half-width.

    This type exists so that "when" cannot be passed around as a bare
    number. Every timestamp crossing a machine boundary in this package is
    one of these, and the width is the accumulated cost of the clock
    transfer plus the drift since it happened.
    """

    center_ms: float
    half_width_ms: float

    def __post_init__(self) -> None:
        if not math.isfinite(self.center_ms) or not math.isfinite(self.half_width_ms):
            raise FaspError("schema.invalid", "A time interval must be finite.")
        if self.half_width_ms < 0.0:
            raise FaspError("schema.invalid", "A time interval cannot have negative width.")

    @property
    def earliest_ms(self) -> float:
        return self.center_ms - self.half_width_ms

    @property
    def latest_ms(self) -> float:
        return self.center_ms + self.half_width_ms

    def widened_by(self, extra_ms: float) -> TimeInterval:
        return TimeInterval(self.center_ms, self.half_width_ms + max(extra_ms, 0.0))

    def shifted_by(self, delta_ms: float) -> TimeInterval:
        return TimeInterval(self.center_ms + delta_ms, self.half_width_ms)

    def contains(self, instant_ms: float) -> bool:
        return self.earliest_ms <= instant_ms <= self.latest_ms

    def overlaps(self, other: TimeInterval) -> bool:
        """True unless the two intervals are provably disjoint.

        Deliberately inclusive at the endpoints: two intervals that merely
        touch are not evidence of separation, and this predicate is used to
        decide whether two machines might have been somewhere at the same
        time.
        """
        return self.earliest_ms <= other.latest_ms and other.earliest_ms <= self.latest_ms

    def to_dict(self) -> dict[str, float]:
        return {"center_ms": self.center_ms, "half_width_ms": self.half_width_ms}

    @classmethod
    def from_mapping(cls, payload: dict[str, object]) -> TimeInterval:
        center, half_width = payload.get("center_ms"), payload.get("half_width_ms")
        if not isinstance(center, int | float) or not isinstance(half_width, int | float):
            raise FaspError("schema.invalid", "A time interval needs numeric center_ms and half_width_ms.")
        return cls(float(center), float(half_width))


@dataclass(frozen=True)
class Exchange:
    """One four-timestamp round trip.

    `t1`/`t4` are read from the local clock, `t2`/`t3` from the remote's.
    Both sides must use a monotonic source: a wall-clock step landing
    between t1 and t4 produces an offset that is wrong by the size of the
    step and looks entirely reasonable.
    """

    t1_ms: float
    t2_ms: float
    t3_ms: float
    t4_ms: float

    def __post_init__(self) -> None:
        values = (self.t1_ms, self.t2_ms, self.t3_ms, self.t4_ms)
        if not all(math.isfinite(value) for value in values):
            raise FaspError("schema.invalid", "Time transfer timestamps must be finite.")
        if self.t4_ms < self.t1_ms:
            raise FaspError("schema.invalid", "Local receive precedes local send; the local clock stepped mid-exchange.")
        if self.t3_ms < self.t2_ms:
            raise FaspError("schema.invalid", "Remote send precedes remote receive; the remote clock stepped mid-exchange.")
        if self.round_trip_ms < 0.0:
            raise FaspError("schema.invalid", "Round trip is negative; the exchange is not physically realisable.")
        if self.round_trip_ms > MAX_PLAUSIBLE_ROUND_TRIP_MS:
            raise FaspError("schema.invalid", "Round trip exceeds the plausible bound; treat this as an outage, not a measurement.")

    @property
    def offset_ms(self) -> float:
        """theta: how far the remote clock leads the local one."""
        return ((self.t2_ms - self.t1_ms) + (self.t3_ms - self.t4_ms)) / 2.0

    @property
    def round_trip_ms(self) -> float:
        """delta: elapsed time on the wire, with the remote's dwell removed."""
        return (self.t4_ms - self.t1_ms) - (self.t3_ms - self.t2_ms)

    @property
    def uncertainty_ms(self) -> float:
        """delta/2 -- the whole of the asymmetry the path could be hiding."""
        return self.round_trip_ms / 2.0

    def as_interval(self) -> TimeInterval:
        return TimeInterval(self.offset_ms, self.uncertainty_ms)

    def to_dict(self) -> dict[str, float]:
        return {"t1_ms": self.t1_ms, "t2_ms": self.t2_ms, "t3_ms": self.t3_ms, "t4_ms": self.t4_ms}


@dataclass(frozen=True)
class ClockEstimate:
    """A fitted relationship between two clocks, with its own error bars.

    `skew_measured` is the field that matters operationally. When it is
    False the skew figure is an assumed datasheet bound rather than an
    observation, and `uncertainty_at()` grows at that assumed rate -- which
    is the correct behaviour for a tracker that has only just started, and
    the reason a fresh tracker reports wide intervals instead of confident
    ones.
    """

    offset_ms: float
    skew_ppm: float
    skew_uncertainty_ppm: float
    skew_measured: bool
    base_uncertainty_ms: float
    reference_local_ms: float
    best_round_trip_ms: float
    samples: int

    def offset_at(self, local_ms: float) -> float:
        """Projected offset, carrying the fitted drift forward."""
        return self.offset_ms + self.skew_ppm * 1e-6 * (local_ms - self.reference_local_ms)

    def uncertainty_at(self, local_ms: float) -> float:
        """Half-width at a local instant: transfer error plus accumulated drift."""
        elapsed_ms = abs(local_ms - self.reference_local_ms)
        return self.base_uncertainty_ms + self.skew_uncertainty_ppm * 1e-6 * elapsed_ms

    def to_remote(self, local_ms: float) -> TimeInterval:
        """Convert a local instant into the remote clock's frame."""
        return TimeInterval(local_ms + self.offset_at(local_ms), self.uncertainty_at(local_ms))

    def to_local(self, remote_ms: float) -> TimeInterval:
        """Convert a remote instant into the local clock's frame.

        The offset is evaluated at the remote instant rather than solved
        for exactly. Over the seconds-to-minutes horizon this package
        operates on, the difference is `skew * offset`, which at 50 ppm and
        a one-second offset is 50 microseconds -- orders below the transfer
        error it sits inside.
        """
        return TimeInterval(remote_ms - self.offset_at(remote_ms), self.uncertainty_at(remote_ms))

    def resync_interval_s(self, tolerance_ms: float) -> float:
        """How often the exchange must run to hold `tolerance_ms`.

        Inverts the drift arithmetic. Returns 0.0 when the transfer error
        alone already exceeds the tolerance -- no resync rate can buy
        precision the link cannot deliver, and the caller needs to know
        that rather than receive an impossible schedule.
        """
        headroom_ms = tolerance_ms - self.base_uncertainty_ms
        if headroom_ms <= 0.0:
            return 0.0
        rate_ms_per_s = max(self.skew_uncertainty_ppm, 1e-9) * 1e-6 * 1000.0
        return headroom_ms / rate_ms_per_s

    def to_dict(self) -> dict[str, float | bool | int]:
        return {
            "offset_ms": self.offset_ms,
            "skew_ppm": self.skew_ppm,
            "skew_uncertainty_ppm": self.skew_uncertainty_ppm,
            "skew_measured": self.skew_measured,
            "base_uncertainty_ms": self.base_uncertainty_ms,
            "reference_local_ms": self.reference_local_ms,
            "best_round_trip_ms": self.best_round_trip_ms,
            "samples": self.samples,
        }


class ClockTracker:
    """Maintains a `ClockEstimate` for one peer from a stream of exchanges.

    Not thread-safe by design: one tracker belongs to one peer session, and
    a lock here would imply it is shared, which would then hide the more
    interesting question of which session's samples these are.
    """

    def __init__(
        self,
        *,
        window_ms: float = 60_000.0,
        buckets: int = 8,
        assumed_skew_ppm: float = COMMODITY_CRYSTAL_PPM,
        min_samples_for_skew: int = 4,
        min_span_ms: float = 5_000.0,
    ) -> None:
        if window_ms <= 0.0 or buckets < 2:
            raise ValueError("ClockTracker needs a positive window and at least two buckets.")
        self.window_ms = window_ms
        self.buckets = buckets
        self.assumed_skew_ppm = assumed_skew_ppm
        self.min_samples_for_skew = max(min_samples_for_skew, 3)
        self.min_span_ms = min_span_ms
        self._samples: list[tuple[float, Exchange]] = []

    def observe(self, exchange: Exchange) -> None:
        """Record one exchange, keyed by the local time it completed."""
        insort(self._samples, (exchange.t4_ms, exchange), key=lambda item: item[0])
        horizon = self._samples[-1][0] - self.window_ms
        self._samples = [item for item in self._samples if item[0] >= horizon]

    @property
    def sample_count(self) -> int:
        return len(self._samples)

    def filtered_samples(self) -> list[tuple[float, Exchange]]:
        """One least-queued sample per time bucket.

        Bucketing rather than a single global minimum is what makes the
        skew fit possible: a global minimum is one point, and one point has
        no slope. Each bucket contributes its cleanest observation, so the
        regression sees both a filtered signal and the time spread it needs.
        """
        if not self._samples:
            return []
        start = self._samples[0][0]
        span = max(self._samples[-1][0] - start, 1e-9)
        best: dict[int, tuple[float, Exchange]] = {}
        for local_ms, exchange in self._samples:
            index = min(int((local_ms - start) / span * self.buckets), self.buckets - 1)
            incumbent = best.get(index)
            if incumbent is None or exchange.round_trip_ms < incumbent[1].round_trip_ms:
                best[index] = (local_ms, exchange)
        return [best[index] for index in sorted(best)]

    def estimate(self) -> ClockEstimate:
        """Fit offset and skew over the filtered samples.

        With too few points, or too short a span, the slope is not
        identifiable -- so it is not claimed. The estimate falls back to
        the assumed crystal bound, flags `skew_measured=False`, and lets
        the interval widen at the datasheet rate.
        """
        filtered = self.filtered_samples()
        if not filtered:
            raise FaspError("capability.unavailable", "No time transfer has completed with this peer yet.")

        times = [local_ms for local_ms, _ in filtered]
        offsets = [exchange.offset_ms for _, exchange in filtered]
        best_round_trip = min(exchange.round_trip_ms for _, exchange in filtered)
        reference = times[-1]
        transfer_error = best_round_trip / 2.0
        span_ms = times[-1] - times[0]

        if len(filtered) < self.min_samples_for_skew or span_ms < self.min_span_ms:
            # Not enough leverage to separate drift from noise. Report the
            # most recent offset and let the assumed crystal bound widen it.
            return ClockEstimate(
                offset_ms=offsets[-1],
                skew_ppm=0.0,
                skew_uncertainty_ppm=self.assumed_skew_ppm,
                skew_measured=False,
                base_uncertainty_ms=transfer_error,
                reference_local_ms=reference,
                best_round_trip_ms=best_round_trip,
                samples=len(filtered),
            )

        slope_ms_per_ms, intercept, residual_spread, slope_error = _least_squares(times, offsets, reference)
        skew_ppm = slope_ms_per_ms * 1e6
        skew_uncertainty_ppm = max(slope_error * 1e6, 0.0)
        return ClockEstimate(
            offset_ms=intercept,
            skew_ppm=skew_ppm,
            skew_uncertainty_ppm=min(max(skew_uncertainty_ppm, 1e-3), self.assumed_skew_ppm),
            skew_measured=True,
            # The residual spread is real disagreement between filtered
            # samples; taking the larger of it and the transfer bound keeps
            # the interval honest when the link is noisier than one round
            # trip suggests.
            base_uncertainty_ms=max(transfer_error, residual_spread),
            reference_local_ms=reference,
            best_round_trip_ms=best_round_trip,
            samples=len(filtered),
        )


def _least_squares(times: Sequence[float], offsets: Sequence[float], reference: float) -> tuple[float, float, float, float]:
    """Ordinary least squares of offset against time, centred on `reference`.

    Returns `(slope, value_at_reference, residual_std, slope_std_error)`.
    Centring on the reference instant rather than on zero keeps the
    intercept meaningful and the normal equations well conditioned --
    monotonic clocks can be large numbers, and regressing against them raw
    loses precision in the intercept for no reason.
    """
    count = len(times)
    centred = [time_ms - reference for time_ms in times]
    mean_x = math.fsum(centred) / count
    mean_y = math.fsum(offsets) / count
    variance_x = math.fsum((x - mean_x) ** 2 for x in centred)
    if variance_x <= 0.0:
        return 0.0, mean_y, 0.0, 0.0
    covariance = math.fsum((x - mean_x) * (y - mean_y) for x, y in zip(centred, offsets, strict=True))
    slope = covariance / variance_x
    intercept_at_mean = mean_y - slope * mean_x
    residuals = [y - (slope * x + intercept_at_mean) for x, y in zip(centred, offsets, strict=True)]
    degrees_of_freedom = max(count - 2, 1)
    residual_variance = math.fsum(residual * residual for residual in residuals) / degrees_of_freedom
    residual_std = math.sqrt(max(residual_variance, 0.0))
    slope_std_error = math.sqrt(max(residual_variance / variance_x, 0.0))
    return slope, intercept_at_mean, residual_std, slope_std_error
