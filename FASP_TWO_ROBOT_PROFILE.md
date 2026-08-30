# FASP Two-Robot Coordination Profile 1.0

## Scenario

Two autonomous indoor mobile robots share a warehouse inspection floor.

- **Atlas** carries bins from staging to packing.
- **Nova** performs aisle inspection and returns to a charging dock.
- Both run local localization, obstacle detection, speed limits, and emergency
  stop circuits. Neither robot can delegate those controls to the network.
- A FASP traffic witness holds short-lived space-time reservations. It may be a
  third robot, a fleet server, or a high-availability local controller.

The goal is not merely to exchange chat messages. The systems must coordinate
intent, avoid the same narrow aisle at the same time, stream useful state under
lossy Wi-Fi, survive a peer failure, and avoid turning diagnostics into unsafe
remote driving.

## 1. Identity and admission

At commissioning, each robot has a hardware-backed or locally protected FASP
Ed25519 identity and a signed ID card. Its card advertises only runtime facts
and capabilities, for example:

```json
{
  "display_name": "atlas",
  "runtime": {"os_family": "linux", "architecture": "aarch64"},
  "capabilities": [
    {"id": "observe.robot.state.v1", "risk": "observe"},
    {"id": "fleet.reserve.v1", "risk": "bounded-actuate"},
    {"id": "observe.robot.map_delta.v1", "risk": "observe"}
  ],
  "limitations": ["No remote motor command capability", "Local E-stop mandatory"]
}
```

Discovery is limited to the operator-approved fleet VLAN and FASP port. A
discovered card is only a self-signed candidate. A technician or fleet issuer
compares the pairing code and grants narrowly scoped permissions:

```text
atlas → traffic-witness: fleet.reserve., observe.
nova  → traffic-witness: fleet.reserve., observe.
operator-console → robots: observe.
```

No robot treats proximity on Wi-Fi, a ROS topic name, or a peer’s model output
as permission to control motors.

## 2. Communication architecture

```text
                 reliable signed control
 Atlas  ─────────────────────────────────> Traffic witness <──────────────────────────────── Nova
   │                                              │                                         │
   │ latest pose / health                          │ reservation grants                      │ latest pose / health
   └──────────────> operator/fleet observability  └──────────────────> operator/fleet observability

 local planner → local safety gate → motor controller        local planner → local safety gate → motor controller
```

The control plane is FASP: paired identity, grants, task lifecycle,
reservations, cancellations, and safety status. It remains reliable and signed.
The data plane carries explicit streams. A stream has a content type, rate,
latency/reliability choice, lease, retention policy, and bounded resource
window.

ROS 2/DDS remains the local robot middleware. FASP does not replace DDS-Security
or SROS2; it coordinates systems across a fleet boundary. ROS 2 security already
separates identity authentication, access control, and cryptographic protection,
which remains enabled beneath this profile. [ROS 2 DDS-Security integration](https://design.ros2.org/articles/ros2_dds_security.html)

## 3. Streams and QoS

| Data | FASP delivery | Rate / expiry | ROS 2 QoS guidance | Reason |
|---|---|---|---|---|
| pose, velocity, battery health | `latest` | 5–20 Hz, lifespan 500 ms | best-effort, keep-last 1, volatile | newest value matters; old pose is dangerous/noisy |
| route reservation / release | reliable control | immediate, lease-bound | reliable, volatile | no loss or stale replay |
| mission state | reliable control | event-driven | reliable, volatile | duplicate-safe state transition |
| map delta / inspection result | reliable stream | bounded chunks | reliable, depth based on memory | data must be complete and checksummed |
| camera preview | latest via WebRTC/QUIC | 5–15 FPS | sensor-data QoS locally | inspect only; never a control source |
| lidar/point cloud preview | latest, aggregated | 1–5 Hz | sensor-data QoS locally | bound CPU/network; raw scan only if granted |
| emergency stop | local hardwired + local safety topic | immediate | independent of FASP | network delivery cannot be the only stop path |

ROS 2 exposes reliability, durability, deadline, lifespan, and liveliness QoS
policies; its documentation specifically notes that lossy wireless links may
need best-effort while other paths need reliable delivery. [ROS 2 QoS settings](https://docs.ros.org/en/humble/Concepts/Intermediate/About-Quality-of-Service-Settings.html)

Every FASP stream includes `sent_monotonic_ns`, sequence, checksum, credit
window, and deadline. A UI displays stale pose as stale; it never extrapolates a
missing live feed as fact.

## 4. Reservation protocol

Before entering the shared narrow aisle, Atlas sends a signed request to the
traffic witness:

```json
{
  "kind": "reservation.request",
  "payload": {
    "reservation_id": "atlas-aisle-3-018f",
    "lease_ms": 30000,
    "segments": [
      {"cell": "aisle-3/cell-17", "start_ms": 1788126000000, "end_ms": 1788126004000},
      {"cell": "aisle-3/cell-18", "start_ms": 1788126004000, "end_ms": 1788126008000}
    ]
  }
}
```

The witness rejects any overlap in the same cell and time interval. Nova sees a
conflict and receives `reservation.reject` with a safe retry time; it replans or
waits. A reservation expires quickly and must be released when unused. It is a
coordination aid, not a collision-avoidance system.

This mirrors the core fleet-traffic idea used by OpenRMF: detect an upcoming
schedule conflict and negotiate a resolution rather than allowing both routes to
proceed. [OpenRMF traffic scheduling](https://openrmf.readthedocs.io/_/downloads/en/latest/pdf/)

## 5. Local safety dominance

Even with a valid reservation, each robot checks locally before motion:

```text
E-stop clear
AND obstacle-free path
AND healthy localization
AND active unexpired reservation
AND requested speed ≤ local speed envelope
```

Any false condition prevents or stops motion. A remote peer cannot set any of
these values. If Wi-Fi fails while moving, the robot follows its certified local
fail-safe policy—typically decelerate and stop before leaving its confirmed safe
envelope—then reacquires a reservation before entering shared space again.

For ROS 2 deployments, use lifecycle-managed nodes: a FASP gateway should only
advertise control-adjacent state while the local robot stack is in its approved
active state. [ROS 2 managed node lifecycle](https://docs.ros.org/en/rolling/p/lifecycle/)

## 6. A complete interaction

1. Atlas and Nova boot. They validate local safety hardware and publish only
   `starting`; no route is active.
2. Both authenticate to the traffic witness and publish a short, latest-only
   health/pose stream. The stream lease is five seconds and must renew.
3. Atlas receives a bin mission. Its local planner proposes a route and asks the
   witness for aisle reservations—not permission to move motors.
4. The witness grants Atlas’s cells. Nova asks for overlapping cells, receives a
   conflict response, and locally selects an alternate wait point.
5. Atlas enters the aisle only after local safety checks. It sends current pose
   as a best-effort/latest stream and reservation progress as reliable control.
6. A pallet blocks the aisle. Atlas’s local perception stack stops it. Atlas
   releases remaining cells and emits a reliable `task.progress` event.
7. Nova receives the release, obtains a new reservation, checks local safety,
   and proceeds. Neither robot needed a human to manually relay messages.
8. If the witness fails, both leases expire. Both robots stop/replan locally;
   they do not assume the previous grant is still valid.

## 7. Failure handling

| Failure | Required behaviour |
|---|---|
| Wi-Fi loss | expire streams/reservations; local safe stop or local approved fallback; no blind continuation into shared space |
| packet loss | latest pose drops old frames; reliable map/control retransmits within credit window |
| stale pose | mark stale after lifespan; do not use for collision decision |
| duplicate reservation request | return existing grant/rejection without allocating a second route |
| conflicting reservation | reject with retry time; never silently override another robot |
| FASP gateway crash | lifecycle transitions inactive; robot safety controller remains local |
| compromised peer key | revoke peer, block grants, isolate its FASP traffic; local E-stop remains available |
| operator console crash | robots continue only under existing local safe policy and expiring leases |

## 8. Harness support in this repository

The reference harness implements `/fleet/reserve` and `/fleet/release` with a
durable, conservative cell/time `ReservationBook`, plus `LocalSafetyGate` tests
for E-stop, obstacle, localization, reservation, and speed prerequisites. It
also implements the generic streaming endpoints from
[FASP_MESSAGING_STREAMING.md](FASP_MESSAGING_STREAMING.md).

It is not a certified fleet manager or motion controller. Before deployment on
a real robot, integrate it with the robot vendor’s safety architecture, SROS2
strict enforcement, validated map/time synchronization, hardware E-stop,
collision avoidance, and an independent safety review.
