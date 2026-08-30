# FASP Messaging and Live Streaming Profile 1.0

This profile adds durable messaging and live data transport to FASP. It carries
any data type—structured events, text, telemetry, images, audio chunks, video
metadata, point clouds, files, and robot state—without pretending that every
data type needs identical reliability or latency guarantees.

## 1. Two planes, two guarantees

| Plane | Use | Guarantee | Examples |
|---|---|---|---|
| **Control** | identity, pairing, grants, task state, stream open/close, safety halt | signed, authenticated, ordered by causation, durably acknowledged | `intent.propose`, `stream.open`, `task.cancel` |
| **Data** | bounded live samples after a stream is authorized | selected per stream: `reliable` or `latest` | sensor values, JPEG frames, audio blocks, robot telemetry |

Control MUST never be sent as an unacknowledged live frame. A safety halt,
authorization change, task cancellation, and stream close always use the FASP
control envelope and take precedence over queued data.

## 2. Stream lifecycle

```text
OPEN_REQUEST → OPEN → ACTIVE → {DRAINING → CLOSED | EXPIRED | FAILED}
                         └────→ PAUSED (backpressure or local safety)
```

1. Sender sends signed `stream.open` with capability, purpose, content type,
   maximum packet size, delivery mode, rate/duration/retention limits, and
   lease expiry.
2. Receiver validates paired identity, grant/capability prefix, local policy,
   resource limits, and data contract. It returns the accepted window and
   stream ID.
3. Sender emits signed `stream.packet` envelopes for the HTTP baseline, or
   packet frames bound to the authenticated session for a realtime profile.
4. Receiver sends `stream.ack` credit updates. It may pause or close the stream
   at any time for policy, resource, safety, or expiry reasons.
5. Sender sends signed `stream.close`; receiver returns `stream.closed`.

Every stream has a finite lease. Loss of renewal MUST stop collection and close
the producer locally. A stream is never an implied right to keep sensing.

## 3. Open contract

```json
{
  "stream_id": "optional-uuid",
  "capability": "observe.environment.temperature.v1",
  "purpose": "Show one room temperature chart to the paired operator.",
  "content_type": "application/json",
  "delivery": "reliable",
  "max_payload_bytes": 40960,
  "window": 32,
  "max_rate_hz": 2,
  "duration_s": 300,
  "retention_packets": 32,
  "retention": "bounded-local",
  "stop_condition": "lease expiry or explicit close"
}
```

`delivery` is exactly one of:

- **`reliable`** — each sequence must arrive in order. The sender retransmits
  only missing packets inside the receiver’s credit window. Use for commands,
  measurements, logs, and files.
- **`latest`** — old samples may be dropped in favour of the newest one. Use
  for video previews, high-rate IMU data, and visualization. It MUST NOT carry
  safety commands, financial events, or task lifecycle state.

## 4. Packet frame

The HTTP baseline transports this object inside a signed `stream.packet` FASP
envelope. For WebSocket, QUIC, MQTT, DDS, or serial profiles, the same fields
are encoded in the session frame.

```json
{
  "stream_id": "stream-uuid",
  "epoch": 0,
  "sequence": 41,
  "sent_monotonic_ns": 123456789,
  "content_type": "application/json",
  "frame_id": "frame-uuid",
  "fragment_index": 0,
  "fragment_count": 1,
  "payload": "base64url-bytes",
  "checksum": "sha-256:hex"
}
```

- `epoch` changes only after explicit resume/rekey; consumers discard packets
  from a retired epoch.
- `sequence` starts at zero for an epoch and is never reused.
- `sent_monotonic_ns` enables local jitter/age estimates; it is not wall-clock
  evidence or a security timestamp.
- `frame_id` plus fragments permit bounded reassembly of any byte payload.
- `checksum` detects corruption independently of transport encryption.

The reference harness caps raw payloads at 40 KiB so base64 and signed-envelope
metadata remain below the 64 KiB control limit. Larger artifacts use chunked
frames or the artifact-transfer profile.

## 5. Packet management and backpressure

The receiver returns:

```json
{
  "type": "stream.ack",
  "stream_id": "stream-uuid",
  "epoch": 0,
  "ack_sequence": 41,
  "credit": 32,
  "duplicate": false
}
```

For `reliable` streams, a sender MUST NOT send sequence `n + credit` before
the receiver has acknowledged `n`. If it does, the receiver returns
`stream.backpressure`; the sender backs off and retransmits only the required
gap. Duplicate packets are safe and acknowledged without reprocessing.

For `latest` streams, the receiver may discard any queued old packet and report
the latest accepted sequence. Producers SHOULD lower rate/quality before
increasing queue depth. Consumers MUST expose discontinuity rather than
fabricate a continuous signal.

Reassembly is bounded by frame count and byte limit; malformed, overlarge,
out-of-window, expired, checksum-failed, or stale-epoch frames are rejected.

## 6. Transport profiles

| Profile | Recommended use | Data path |
|---|---|---|
| `http-baseline` | telemetry, text, images, low-rate streams | signed POST packets + pull/ack endpoints |
| `websocket-session` | interactive dashboards, bidirectional medium-rate data | TLS WebSocket after signed control session |
| `quic-datagram` | latest-only high-rate telemetry | authenticated QUIC session; ordered control remains reliable |
| `webrtc-media` | audio/video to a user interface | FASP control opens stream; WebRTC carries media; no task control in media channel |
| `mqtt-dds-bridge` | IoT/ROS 2 environments | topic ACLs plus end-to-end FASP identity and capability checks |
| `serial-cbor` | microcontrollers and robots | CBOR/COSE frames, fixed windows, local watchdog |

The included harness implements `http-baseline`. Realtime transports MUST bind
their session to the paired FASP identities, stream ID, epoch, capability grant,
and expiry. A relay/broker is never an authorization authority.

## 7. Data classes and safety

| Data class | Default profile | Extra rule |
|---|---|---|
| task/control | reliable control only | never send as `latest` |
| scalar telemetry | reliable or latest | schema and units required |
| image/video | latest | bounded resolution/FPS; no identity inference by default |
| audio | WebRTC/media | explicit recording/retention grant required |
| sensor inference | reliable aggregate | report uncertainty; do not send raw data unless granted |
| file/artifact | reliable chunks | digest, size, retention, resumable manifest |
| robot state | latest or reliable by field | local safety controller remains authoritative |
| robot command | control only | separate capability, grant, plan/commit, and safety interlock |

No stream may transmit personal identifiers, credentials, raw audio/video,
location, biometric data, contacts, or network scans without a narrowly scoped
grant that explicitly names those fields, recipient, purpose, duration, and
retention. For basic proximity or environment tasks, transmit a one-time
aggregate result or `unknown`, not continuous raw sensor data.

## 8. HTTP baseline endpoints

| Endpoint | Signed envelope kind | Result |
|---|---|---|
| `POST /stream/open` | `stream.open` | accepted stream configuration |
| `POST /stream/packet` | `stream.packet` | `stream.ack` or backpressure/error |
| `POST /stream/pull` | `stream.pull` | bounded retained packet set |
| `POST /stream/close` | `stream.close` | terminal `stream.closed` |

All endpoints require a paired peer and authorized capability prefix. HTTP is
appropriate for low/medium-rate data and correctness testing. Use TLS 1.3 in
production. The server refuses non-loopback plain HTTP unless the operator
explicitly passes `--insecure-http` for an isolated development LAN.

## 9. Failure semantics

- `stream.backpressure`: sender exceeded credit; slow down or wait for ack.
- `stream.out_of_order`: reliable sender must retransmit the expected sequence.
- `stream.checksum_mismatch`: discard frame; retransmit only for reliable mode.
- `stream.invalid_fragment`: discard entire frame and record a bounded audit
  event.
- `stream.not_open`: do not retry; open/renew a valid stream first.
- `lease.expired`: producer MUST stop local collection immediately.
- `resource.exhausted`: receiver MUST protect memory/storage; producer lowers
  rate, payload size, retention, or quality only if policy permits.

## 10. Implementation checklist

1. Define a schema and units for every content type.
2. Start with `reliable`, small packets, short duration, and bounded retention.
3. Add `latest` only after the UI handles gaps and stale data visibly.
4. Measure end-to-end latency, jitter, loss, queue depth, and memory under
   network loss; do not infer quality from a happy-path test.
5. Add a realtime profile only after identity/session binding and stream expiry
   are independently tested.
6. Keep robot safety and emergency stops local and independent of this layer.
