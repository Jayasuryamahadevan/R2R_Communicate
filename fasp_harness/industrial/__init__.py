"""Field- and supervisory-level industrial protocols.

Three integrations live here, and they share one shape: a small, honest,
dependency-free implementation of the wire protocol, a *simulator* that
speaks the same protocol so every path is exercised offline and in CI, and
an optional binding to the heavyweight vendor library when one is present.

- `modbus`  Modbus/TCP client and server. The lingua franca of safety PLC
            status I/O -- almost every safety controller can expose its
            state on it, which makes it the realistic way for a Layer 3
            coordinator to *see* Layer 1 without touching it.
- `opcua`   OPC UA client abstraction, an address-space simulator, and an
            optional `asyncua` backend. The supervisory/MES boundary.
- `ros2`    The ROS 2 managed-node lifecycle state machine, DDS QoS
            compatibility, and an SROS 2 security posture check that can
            refuse to run unauthenticated.

Nothing in this package writes to a safety function. `modbus` will refuse
to write a register an operator has marked safety-relevant, and the OPC UA
client writes only to an explicit allowlist. See `fasp_harness.layers`.
"""

from __future__ import annotations
