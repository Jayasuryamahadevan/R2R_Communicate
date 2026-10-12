# Communication options and one canonical FASP path

This is a catalog of useful communication families, grouped by what an
adapter has to do. A physical link, an IP protocol, and a broker can be
stacked; they are not competing implementations of the same layer. Adding
every protocol to the FASP core would duplicate authorization, framing, and
storage. Each source instead terminates at a small adapter and enters the
same signed FASP path.

## The canonical form

| Need | Canonical FASP form | Lifetime |
|:--|:--|:--|
| One event, request, command, receipt, or small result | One signed envelope, at most 64 KiB; `kind` selects its schema and handler | One packet |
| Repeated telemetry, audio blocks, video frames, or any continuous feed | Signed `stream.open`, ordered bounded `stream.packet` envelopes, and `stream.close`; reliable or latest delivery is chosen per stream | Finite lease |
| A large result needed once | Immutable content-addressed artifact in the local store; send its digest and reference in a signed packet | Explicit retention |

Every envelope carries sender, recipient, message ID, expiry, nonce, payload,
and Ed25519 signature over [RFC 8785 canonical JSON](https://www.rfc-editor.org/rfc/rfc8785).
The wire bearer may chunk or frame that JSON, but it does not change its
meaning. A stream is a sequence of packets under one bounded contract, not
an unrelated message format. The reference harness stores artifacts produced
by local adapters and supports authorized fetch; it does not expose a generic
remote blob upload endpoint.

```text
device / process / broker / file / network
    → source adapter: authenticate, parse, validate, attach provenance
    → packet OR stream.open → stream.packet* → stream.close
    → one signed-envelope verifier and policy/dispatch path
    → optional local artifact reference for large one-time data
```

An already signed FASP envelope is verified as received. A gateway for an
unsigned device must validate the device-specific data and sign a *new*
envelope with the gateway's identity. It must preserve the original source
as provenance and cannot pretend the device itself is a paired FASP peer.
Transport encryption protects the link; the receiver's pairing, grants,
capability rules, replay journal, and stream policy still decide admission.

The implementation has one bounded JSON decoder and one envelope dispatcher
for HTTP, WebSocket, and Bluetooth. Duplicate JSON keys, non-finite values,
oversized integers, invalid UTF-8, and overlarge frames are rejected before
dispatch. Stream packetization yields chunks as needed, with a 4 MiB frame
limit; it does not allocate a list of all chunks. Reassembly permits at most
eight incomplete frames per consumer by default. These are memory and
ambiguity controls, not a claim that every protocol below is implemented.

## Ways to reach that path

**Native** means this repository implements the bearer. **IP carrier** means
the operating system provides a routable IP link for the native HTTPS or
WebSocket bearer. **Adapter** means a gateway or protocol-specific bridge is
needed; listing one does not imply it is implemented.

| Family | Common choices | FASP entry | Status |
|:--|:--|:--|:--|
| Local process | function calls, Unix sockets, named pipes, shared memory, file drop | local adapter creates packet or stream | Adapter |
| Wired IP | Ethernet copper/fiber, industrial Ethernet/TSN, USB Ethernet | HTTPS or WebSocket | IP carrier |
| Wireless IP | Wi-Fi, cellular 4G/5G, private LTE, Thread/6LoWPAN, IP VPN | HTTPS or WebSocket | IP carrier |
| Bluetooth Classic | RFCOMM, Bluetooth PAN/IP | signed packet or stream packet | Native RFCOMM; PAN is an IP carrier |
| Bluetooth LE | LE L2CAP credit based channels, GATT | signed packet or stream packet | Native L2CAP; GATT needs an adapter |
| Direct serial and device buses | USB CDC, UART/RS-232/RS-485, SPI, I²C, CAN/CAN FD/CANopen | adapter frames and signs packets | Adapter |
| Constrained and low power radio | Zigbee/802.15.4, LoRaWAN, NFC, satellite/mesh gateways | gateway validates and signs packets | Adapter |
| Web request/response | HTTP REST, HTTP/2 or HTTP/3, Server-Sent Events, CoAP | packet; SSE/CoAP observe become stream packets | Native HTTPS REST; others need adapter |
| Persistent IP sessions | WebSocket, raw TCP/TLS, UDP/DTLS, QUIC, WebTransport | packet or leased stream | Native WebSocket; others need adapter |
| RPC and media | gRPC unary/streaming, WebRTC data channel/media | packet or leased stream | Adapter |
| Message brokers and logs | MQTT/MQTT-SN, AMQP, NATS/JetStream, Kafka, ZeroMQ | broker consumer validates, deduplicates, signs packets | Adapter |
| Robot and industrial middleware | DDS/RTPS, ROS 2, OPC UA client/server or PubSub, Modbus TCP/RTU | schema-aware gateway creates packet or stream | Adapter |
| One-time object transfer | filesystem, object store, HTTP download | local artifact and signed reference | Native local artifact storage; remote upload needs a profile |

The groupings come from the standards and maintainers' own descriptions:
[HTTP](https://www.rfc-editor.org/rfc/rfc9110),
[WebSocket](https://www.rfc-editor.org/rfc/rfc6455),
[QUIC](https://www.rfc-editor.org/rfc/rfc9000),
[WebRTC](https://www.w3.org/TR/webrtc/),
[gRPC](https://grpc.io/docs/what-is-grpc/core-concepts/),
[CoAP](https://www.rfc-editor.org/rfc/rfc7252),
[Bluetooth L2CAP](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-62/out/en/host/logical-link-control-and-adaptation-protocol-specification.html),
[USB CDC](https://www.usb.org/defined-class-codes),
[Thread](https://threadgroup.org/portals/0/documents/resources/Thread_Technical_Overview.pdf),
[MQTT](https://mqtt.org/mqtt-specification/),
[AMQP](https://www.amqp.org/resources/specifications.html),
[NATS](https://docs.nats.io/concepts/jetstream),
[Kafka](https://kafka.apache.org/documentation/),
[DDS](https://www.omg.org/spec/DDS/),
[ROS 2 middleware](https://docs.ros.org/en/ros2_documentation/kilted/Concepts/Intermediate/About-Different-Middleware-Vendors.html),
[OPC UA PubSub](https://reference.opcfoundation.org/specs/OPC-10000-14/full),
[Modbus](https://www.modbus.org/modbus-specifications), and
[LoRaWAN](https://resources.lora-alliance.org/home/lorawan-specification-v1-0-3).

## Selection rule

Use HTTPS for reliable control and low-rate packets on any IP carrier.
Use WebSocket when a paired peer needs lower-latency bidirectional push.
Use Bluetooth when IP is unavailable and both hosts support the radio
profile. Use a gateway for fieldbuses, broker ecosystems, and devices that
cannot sign FASP envelopes. Route sustained data through a leased stream;
send the control that opens or closes it as a reliable packet. Store a large
one-time value only when an authorized receiver needs to fetch it later.

Benchmarks must name their workload, hardware, and delivery mode. The
repository's HIL bench measures safety scenarios against a real controller;
it is not a transport throughput target. `benchmarks/canonical.py` measures
local JSON normalization and stream packetization, without claiming network
or radio performance. A deployed system should record p50/p95/p99 latency,
throughput, loss, CPU, memory, and durable-queue depth under its actual link
and adapter load before setting an SLO.
