# FASP Runtime Profiles

FASP is model-, hardware-, and operating-system-independent. These profiles
define how a Windows workstation, Linux server, Raspberry Pi, phone gateway,
or robot host keeps the same identity, authority, and lifecycle semantics.

## Common baseline

Every profile implements signed identity cards, pairing, replay protection,
idempotency, scoped capability policy, leases, and safe terminal states. An ID
card may report OS family and architecture but MUST NOT expose serial numbers,
MAC addresses, IMEI, user names, host names, or home paths.

## `edge-safe`

For Windows, Linux, macOS, Raspberry Pi OS, and embedded Linux. The included
Python core is portable across these systems.

- Use HTTPS/TLS 1.3 in production. Plain HTTP requires explicit
  `--insecure-http` and is only appropriate for isolated development LANs.
- Keep `.fasp` state on encrypted local storage and supervise the process with
  a native service manager: systemd, Windows Service/Task Scheduler, launchd,
  or a container supervisor.
- Model adapters receive only policy-validated intents and never choose their
  own capability or grant.

## `edge-rtx3050`

For RTX-3050-class GPU laptops/workstations and any local inference runtime.
The GPU is an execution resource, never a trust boundary.

- Run FASP and the model runner as separate local processes.
- Bind model APIs to loopback; expose only the FASP endpoint to peers.
- Limit GPU memory, request time, output size, and concurrency. An out-of-memory
  condition reports `resource.exhausted`; it does not trigger an unbounded retry.
- Keep credentialed tools, physical control, and broad shell access outside the
  model process. A separate local capability implementation must authorize them.

## `ros1-observer`

`fasp_harness.ros1_adapter:create_adapter` works on a ROS 1 host and exposes
only aggregate graph observation. It does not publish, call services, alter
parameters, or actuate a robot.

## `ros2-observer`

`fasp_harness.ros2_adapter:create_adapter` works on a host with `rclpy` and
exposes only aggregate ROS 2/DDS graph observation. It does not publish, invoke
services/actions, change lifecycle nodes, or bypass DDS-Security/SROS2.

Use DDS-Security/SROS2 below FASP for local robotics authentication, access
control, and encryption. Keep speed/force limits, collision avoidance,
geofencing, watchdogs, and emergency stops local to the robot controller.

## `mobile-gateway`

The OS companion owns permissions. A Termux/PRoot/container process MUST report
that a sensor is unavailable when it cannot read it, even if hardware exists.
Sensor access defaults to one-time, purpose-bound aggregation; continuous
streaming needs explicit rate, duration, retention, recipient, and stop rules.

## `constrained-gateway`

Microcontrollers and low-power robots can use CBOR/COSE or serial framing behind
a gateway. The gateway preserves device identity and cannot obtain actuator
authority merely because it can communicate with the device.
