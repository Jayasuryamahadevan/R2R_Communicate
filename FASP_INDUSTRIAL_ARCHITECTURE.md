# FASP industrial architecture: what is claimed, and what is not

This document is the honest counterpart to the feature list. It states the
layer model the implementation enforces, what each previously-missing
capability now does, and — with equal prominence — what it still does not.

The one-line version: **FASP is a coordination protocol at Layers 3 and 4.
It observes Layer 2, may request a halt, and has no code path that writes
to Layer 1.** Everything below follows from that.

## 1. The layer model

| Layer | Owns | Runs on | FASP may |
|---|---|---|---|
| **1** hard real-time local safety | E-stop, safety-rated protective fields, speed/force limiting, safety PLC logic, motor control | certified safety hardware and/or an RTOS, **outside this process** | **observe only** |
| **2** local autonomy | navigation, perception, obstacle avoidance, route following | the vehicle | observe, request a halt, coordinate, dispatch a *goal* |
| **3** fleet coordination | mission assignment, zone reservation, charging, scheduling | **this software** | everything above, plus configure |
| **4** enterprise / cloud | WMS, MES, ERP, digital twin, analytics, human approvals | **this software** + plant systems | everything above |

Two rules make this real rather than aspirational, both in
[`fasp_harness/layers.py`](fasp_harness/layers.py):

1. **`PERMITTED_INTERACTIONS`** — toward Layer 1 the only permitted verb is
   `OBSERVE`. The `ACTUATE` interaction appears in the permitted set of *no*
   layer: this protocol has no actuation verb at all.
2. **`RESERVED_L1_FUNCTIONS`** — a semantic deny list. Rule 1 trusts a
   capability's declared layer, and a declaration is exactly what a mistake
   gets wrong. So a capability whose *meaning* is a Layer 1 function
   (`estop.clear`, `motor.command`, `safety.zone.mute`, `interlock.bypass`,
   `speed_limit.override`, …) is refused regardless of the layer, risk
   class, or grants attached to it.

Enforcement runs twice: at construction, before a socket is bound — an
adapter exposing a Layer 1 function **fails startup** — and again on the
dispatch path, because an adapter may compute its capability list per call.

There is no `safety.clear` message kind. Clearing a halt requires a local
operator at the machine, and the underlying controller must independently
report that its own demands are gone and its manual reset has been done
(`SafetySupervisor.clear`). `python -m fasp_harness layers` prints what
this build enforces.

## 2. Capability status

Every row is exercised by the tests named in
[`tests/test_industrial_conformance.py`](tests/test_industrial_conformance.py),
which is itself executable and refuses to let a `PARTIAL` quietly become a
`CLOSED`.

### Real-time deterministic scheduling — **partial, by physics**

`fasp_harness/realtime/` provides a drift-free periodic executor
(releases computed from an absolute origin, so a slow cycle is absorbed
once instead of inherited forever), explicit per-cycle deadlines, three
defined overrun policies (`SKIP`, `CATCH_UP`, `FAIL_SAFE`), bounded-memory
latency histograms, and fail-safe deadline watchdogs that latch.

It does **not** provide hard real-time, and cannot: CPython has a global
interpreter lock and a stop-the-world garbage collector.
`probe_realtime_capability()` reports `hard_realtime` as a *constant*
`False` with the reasons attached — not computed, so no refactor can
accidentally make it true — and the best label it can return is `firm`,
only when a PREEMPT_RT kernel, `SCHED_FIFO` availability, and isolated CPUs
all agree. Hard real-time control loops belong on a certified controller or
an RTOS, outside this process. That is the architecture, not a limitation
to be worked around.

### Safety certification — **not closed, and not claimable**

`fasp_harness/safety/case.py` implements a Goal Structuring Notation safety
case where every leaf is a *callable*, so the verdict is recomputed from
executed evidence each time it is asked for and cannot drift from the
system. `reference_case.py` is this coordinator's actual argument.

Two verdicts a paper case usually elides are first-class here:
`DELEGATED` (this claim is Layer 1's, discharged by certified equipment and
named), and `UNDEVELOPED` (not argued at all — independent validation, G9,
is left visibly open). `SafetyCaseReport.certifiable` is always `False`:
certification is a judgement an accredited body makes about a specific
installation, and no amount of passing evidence produces it.

`python -m fasp_harness safety-case --config …` exits non-zero when a claim
that should be supported is not.

### PLC / safety-controller integration — **closed**

`fasp_harness/industrial/modbus.py` is a dependency-free Modbus/TCP client
*and* server (the tests run over a real socket). `safety/drivers.py` adds a
vendor-neutral `SafetyControllerDriver` interface with two implementations:
Modbus for real hardware, and a deterministic simulator for CI and offline
benching that declares itself as carrying no safety integrity.

Two-channel E-stop inputs are compared, and a persistent A/B discrepancy is
reported as *not clear* rather than resolved by believing either channel.
Signals default to `safety_relevant=True`, and `SafetyRegisterMap`
refuses to produce a write path for any such signal — so wiring "clear the
E-stop" to a network handler is an exception at configuration time, not an
oversight away.

### OPC UA — **closed**

`fasp_harness/industrial/opcua.py`: a client abstraction, a deterministic
address-space simulator structured like a real server, and an optional
`asyncua` binding that raises `capability.unavailable` rather than
degrading when the library is absent.

Reads are unrestricted. Writes require a `WriteAllowlist` — an explicit set
of node ids with a recorded reason and engineering range per rule, **empty
by default**, and refusing any node whose id names a Layer 1 function. The
FASP-facing `OpcUaObserver` exposes observation capabilities only; there is
no write capability a network peer can propose.

### ROS 2 / DDS security and lifecycle — **closed**

`fasp_harness/industrial/ros2.py`, with no `rclpy` import, so it is testable
on a machine with no ROS:

- the **managed-node lifecycle** state machine including transition states
  and the error path (`FAILURE` returns to the previous state; `ERROR`
  routes through `errorprocessing`; error handling that itself fails is
  terminal). `publishing` is true only while `ACTIVE`.
- **QoS compatibility** implementing the real Requested-vs-Offered rules,
  reporting *every* incompatibility. DDS silently fails to connect
  mismatched endpoints; this turns that into an answer.
- **SROS 2 posture**: `ROS_SECURITY_STRATEGY=Permit` is a *critical*
  finding, because it is the configuration that looks secure and is not —
  a node without security material runs unauthenticated instead of failing
  to start. Keystore layout, enclave artefacts, and private-material
  permissions are inspected; `require_enforcing()` refuses a production
  profile on an unauthenticated domain.

### Multi-vendor fleet managers — **closed**

`fasp_harness/fleet/` inverts the usual shape. `model.py` is the neutral
vocabulary (borrowing VDA 5050's own terms where they exist, so the common
adapter is a rename rather than a lossy translation); `adapter.py` is the
only surface a vendor implements; `FleetRegistry` multiplexes any number
behind `fleet:vehicle_id`, so two vendors may both call a robot `AGV-01`
and the scheduler never branches on vendor. A vendor whose manager is down
degrades to *that fleet* being unavailable.

Four adapters ship: **VDA 5050** (orders with the node/edge sequencing
rule, base/horizon split, and update rules enforced — building these wrong
is how a vehicle rejects an order mid-aisle); a **declaratively configured
REST** adapter, so most HTTP vendors need a config file rather than a
module (the mapping language is dotted paths, with no expression
evaluation, so a bad config can read the wrong field and nothing worse);
an **ABB GoFa/OmniCore pilot** adapter which observes Robot Web Services and
can commit one locally allow-listed command to a preloaded RAPID mailbox while
exposing no motor-power, raw-motion, program-upload, or safety endpoint; and a
deterministic **simulator**.

Missions are goal-level by construction: `StepKind` has no member that
could express a trajectory, a velocity, or a wheel command.

### Industrial edge deployment / HA — **closed, with a stated boundary**

`fasp_harness/edge/lease.py` implements leader election with **fencing
tokens**. The hard part of hot standby is not electing a leader; it is the
old leader that lost the network for ninety seconds and has not noticed.
Timeouts cannot fix that, because the two nodes' clocks disagree about
exactly the interval in question. A monotonic fence, checked at the moment
of effect, makes a superseded coordinator's dispatch *fail* rather than
merely being improbable.

The boundary is stated in `describe()`: this is correct for active/standby
processes sharing one database, which covers the common industrial-edge
appliance pattern. It is **not** cross-machine consensus and is not a
substitute for Raft.

`edge/health.py` separates the four questions an orchestrator actually asks
— startup, liveness, readiness, drain — because a hot standby is alive,
must not be restarted, and must not be given work, which one boolean cannot
express.

### Offline mesh / network resilience — **closed**

`edge/outbox.py` makes a partition a *delay* rather than a *loss*: durable
store-and-forward, per-destination ordering (so a cancel cannot overtake
the order it cancels) with independent progress across destinations, capped
exponential backoff with full jitter, dead-lettering instead of retrying
forever, absolute expiry, and a depth cap.

`resilience/faults.py` is a seeded, virtual-time network with loss,
duplication, reordering, corruption, finite queues, and **asymmetric**
partitions. Same seed, same interleaving, every run — so a resilience
failure is a reproducible test rather than an anecdote.

`resilience/mesh.py` adds store-carry-forward relaying for nodes with no
end-to-end path. It is acceptable precisely because it requires no trust: a
relay carries an opaque signed envelope, cannot forge or replay to effect
(`message_id` already gates the receiver's durable dedup), and can only do
what the network could do anyway — drop or delay. The validated result:
across a 60-second hard partition with 8% loss, **zero** messages cross
during the outage, **all** are delivered after healing, with **zero**
duplicate deliveries, on every seed tested.

### Hardware-in-the-loop — **partial: the bench is real, the device in CI is not**

`fasp_harness/hil/` applies a stimulus, polls until the expectation holds,
and measures from *before* the stimulus — so the poll interval is
measurement granularity (reported) rather than a systematic offset. Reports
are hash-chained and signable, and the safety case consumes them directly,
so a response-time claim cannot drift from its measurement.

Five standard scenarios ship, each for a known field failure: E-stop
response time; latching (releasing the button is not a reset); reset
refused while a demand is present; an unreachable controller withdrawing
permission; and a network halt being honoured while a network *clear* is
refused. The same scenarios run against a simulator in CI and real hardware
on a bench — `HilReport.real_hardware` records which, so a green CI run can
never be presented as a hardware qualification. **A timing claim about a
machine requires these scenarios on that machine.**

### Digital twin — **closed**

The two failure modes here are a twin nobody consults (a visualisation) and
a twin nobody checks (a simulation). `fasp_harness/twin/` is neither:
`preflight.py` is consulted *before* dispatch (reachability, energy against
a reserve, static obstacles along the route, deadline, and space-time
conflict with reservations already granted), and `sync.py` compares
prediction against telemetry *after*, requiring N consecutive exceedances
so localisation jitter is not mistaken for a fault.

Divergence withdraws trust in the twin's own predictions for that vehicle
rather than correcting the vehicle — a coordinator steering toward its own
prediction over an unreliable link has quietly become a control loop. The
kinematic model is deliberately simple; a vendor simulator, Gazebo, or
Isaac plugs in behind the same interface. What matters is that the
integration is real.

### Industrial cybersecurity workflow — **partial**

`security/iec62443.py` is a control register mapped to the seven
foundational requirements, each control **evaluated against the running
configuration**. The roll-up per FR is the *minimum* across its controls,
never the mean — a system with nine met controls and one gap is protected
to the level of the gap — and the report names the limiting control, which
turns a bad number into a task. Controls requiring evidence this software
cannot produce about itself are marked `MANUAL` and named, not omitted.
The 62443-3-2 zone/conduit model is included; note that the safety zone has
no inbound conduit at all.

`security/posture.py` is a startup gate, not advice: `production` requires
mutual TLS, an enforcing ROS 2 domain, 0600 private material, a verified
audit chain, and refuses a simulated safety controller. Every finding
carries a remediation, because a gate that says what is wrong without
saying what to do is a gate people disable. `security/sbom.py` emits
CycloneDX 1.5 from the installed distributions.

Certification remains an accredited third-party activity covering
organisational processes as much as software.

### Safety case and independent validation — **partial, by definition**

The case is built, runnable, and honest about itself. Independent
validation is present as claim **G9**, marked `UNDEVELOPED`, with the
rationale that it requires a competent body assessing a specific
installation. A safety case that omits the claim it cannot support is worse
than one that shows the gap.

## 3. The path a mission takes

Implemented in [`fasp_harness/fleet/service.py`](fasp_harness/fleet/service.py).
The order is the design:

1. **record durably** — before anything external happens, so a crash
   mid-dispatch leaves a mission to reconcile rather than a robot nobody is
   tracking;
2. **safety gate** — a latched halt stops dispatch at the top, once, not in
   seven places further down;
3. **leadership** — a fenced lease, checked again at the moment of effect;
4. **vehicle selection** — across every vendor, with a reason recorded for
   each rejection ("no vehicle available" is the least actionable message a
   fleet system emits);
5. **twin preflight** — simulate before dispatching;
6. **space-time reservation** — for the *predicted* windows, not the whole
   route for the whole mission, which would serialise the fleet;
7. **dispatch** — goal-level, to the vendor adapter;
8. **reconcile** — the vendor is the authority on what a vehicle is doing.

## 4. What a deployment must still supply

- A **certified Layer 1 safety controller** for every machine with physical
  actuation, assessed to the risk of its application. The simulator in this
  repository carries no safety integrity, and the production posture check
  and safety case both refuse it.
- **Independent validation** of the safety argument for the specific
  installation.
- **Site risk assessment, commissioning, and validation** by competent
  persons.
- **Real hardware HIL runs** for any timing claim about a machine.
- Hardware-backed keys, an external authorization issuer, encrypted storage
  at rest, and network segmentation enforced in the network — the zone
  model here describes it; it does not implement it.
