# Lightweight operation and low-latency observations

FASP has two explicit delivery paths. The default retains durable coordination
semantics. The optional volatile path handles short-lived live observations
without per-message SQLite writes. Both authenticate and authorize requests.
This is a Python coordination implementation, not a wire-compatible NATS
server or an implementation of JetStream replication/consumer semantics.

## Delivery guarantees

| Property | Default durable path | Explicit volatile path |
|---|---|---|
| Request kinds | Existing protocol kinds | Only `heartbeat` and memory-stream `stream.packet` |
| Identity/signature | Paired Ed25519 identity and signature on every request | Same checks on every request |
| Current authority | Fresh pairing, revocation and domain/grant checks | Same checks; public-key decoding alone is cached |
| Request/response journal | SQLite | Bounded process-local replay window |
| Restart | Durable state survives, subject to SQLite/adapter guarantees | Requests for the old receiver instance are rejected |
| Live packet storage | Existing stream contract and retention | Zero packet retention; sequence/rate state in memory |
| Reconnection | Task status and retained-stream pull where supported | Missed observations are lost; use a fresh stream after receiver restart |
| Completion meaning | Existing task lifecycle | Heartbeat/packet acceptance, never durable delivery or device completion |
| Eligible work | Tasks, grants, stream control, safety and other defined kinds | Observations only; tasks and control operations are refused |

The design takes the useful separation from NATS Core (live messages without
replay) and JetStream (persistence, replay and acknowledgements). FASP's
per-message Ed25519 signatures, policy checks and device coordination do
different work, so raw broker figures are not interchangeable performance
claims. The local SQLite implementation has no Raft replication, JetStream
consumer cursors or broker-level exactly-once claim.

## What changed on the critical path

- Validate the full JSON structure, but canonicalize the signed content only
  once. Reuse those freshly computed bytes for verification. The record-size
  check includes the signature block exactly; boundary tests cover 65,536
  and 65,537 bytes.
- Fetch current peer scopes, expiry, key selector and revocation in one
  SQLite read. Avoid Python decoding of an entire discovery card. This
  lookup is deliberately not cached, including changes by another connection.
- Cache at most 256 decoded immutable public keys. Signature results,
  permissions, grants and peer approval are never cached by this optimization.
- Store a durable heartbeat and its response in one transaction, preserving
  existing replay behavior while eliminating a second write transaction.
- Load package exports lazily. Ordinary CLI help and agent operations no
  longer import the ASGI server, fleet service and twin implementation just
  to parse a command. Dependencies and existing package exports remain available.
- Serialize each pushed JSON frame once and share that immutable text across
  its target connections. Bound pending sends by count, bytes and timeout.

There is no change to WAL's `synchronous=NORMAL` setting, no disabled signing,
and no removal of the audit/grant/task lifecycle to improve a benchmark.
NORMAL is not a per-acknowledgement power-loss durability guarantee.

## Using the volatile profile

First obtain and verify the receiver's signed `/profile`, compare it with the
approved pairing identity, and require both `fasp.required-features.v1` and
`fasp.volatile.v1` in `protocol_support.features`. The Python CLI's delivery
helper checks required features against the live pinned profile. A legacy
receiver may ignore unknown fields, so never infer support merely because
it accepts an ordinary FASP envelope.

The signed card contains `instance_id`, a fresh random identifier for this
receiver process. Given an existing sender and verified receiver card:

```python
from fasp_harness.protocol.contracts import check_peer_features

check_peer_features(receiver_card, ["fasp.volatile.v1"])
request = sender.make_envelope(
    "heartbeat", receiver_card["system_id"], {},
    delivery="volatile", receiver_instance=receiver_card["instance_id"],
)
```

Send that signed request over a persistent authenticated WebSocket at
`/fasp/v1/channel`. The generated lifetime is one second; receivers allow at
most five seconds of total lifetime and five seconds remaining. A wrong
instance, expired request, unsupported feature or ineligible kind fails
closed. After a receiver restart, refresh the verified profile and open a
new memory stream. Do not replay the previous instance's packets.

Use persistent connections for high-rate traffic. Launching a CLI process,
fetching a profile and establishing TLS for each sample adds costs far above
the receiver's message-processing time. Keep the CLI/outbox for enrollment,
control and durable work. An async producer can send serialized SDK envelopes
through its already-open TLS connection.

The TypeScript bridge accepts the same choice:

```ts
client.buildEnvelope("heartbeat", receiverId, {}, {
  delivery: "volatile", receiverInstance: verifiedCard.instance_id,
});
```

### Live telemetry streams

The receiver must explicitly permit `storage_modes: ["memory"]` (or both
`disk` and `memory`) in the existing local stream-sharing rule. The default
rule only permits disk storage. The source also needs its ordinary peer
scope and stream grant. A grant can narrow `storage_modes` further.

Open the stream through the **durable** control path with these additions
to the existing purpose/fields/rate/lease/recipient/grant contract:

```json
{
  "storage": "memory",
  "delivery": "latest",
  "retention_packets": 0
}
```

Python and TypeScript envelope builders automatically mark memory stream
opening with the required volatile feature. Each subsequent packet uses
`delivery: volatile` on the **envelope**, with the receiver instance and
short expiry. This differs from the stream payload's `delivery: latest`.
Reliable streams and retained packets cannot select memory storage.

Valid live packets still check the accepted fields, payload/checksum,
sequence, rate, lease, current local sharing policy and grants. Only their
sequence/rate bookkeeping moves to memory. Consent is rechecked before
forwarding; pushes identify storage mode, forwarder instance and expiry.
Consumers must discard expired live data. There is no retained packet pull
for this mode. `stream.open`, close, grants and pairings remain durable.

## Resource bounds and slow consumers

| Resource | Default bound |
|---|---|
| Volatile replay entries | 4,096, indexed by message ID and signed-content digest |
| Volatile expiry | Generated 1 s; accepted maximum 5 s |
| Concurrent memory streams | 128; expired entries reclaimed when opening another stream |
| Volatile per-peer rate | 1,000/s, burst 256; separate from durable work budget |
| Registered push connections | 128 total, four per peer |
| Pending pushes | 16 per connection, aggregate 8 MiB of encoded-frame reservations |
| Send wait | One second, including waiting behind another push |

An unexpired replay entry is never evicted to admit new work; a full window
returns `resource.exhausted`. Replay storage contains digests and small
heartbeat/ack responses, not sample payloads. A new receiver instance blocks
replay after its memory is lost. These guarantees require one owner process
per FASP node, as the existing SQLite deployment already does.

Saturated push queues drop new pushes; a stalled or failing connection is
unregistered. Reservations remain charged until its pending sends finish,
including after disconnection, so connection churn cannot bypass the byte
budget. Durable consumers can poll their retained state; live observations
can be lost. Already-scheduled/in-transit observations are not retractable.
Watch `fasp_push_dropped_total` and `fasp_push_pending_bytes` on the protected
metrics endpoint. Do not treat acceptance as evidence of subscriber delivery.

Server rate knobs are `--volatile-rate-limit-per-peer` and
`--volatile-rate-limit-burst`. Pre-authentication HTTP/IP limits still apply;
the WebSocket path applies them to connection establishment and checks the
signed per-peer budget on every frame. Larger payloads and long expiry
windows consume more CPU/capacity; avoid setting every limit to its maximum.

## Measurements and reproduction

The committed [raw results](benchmarks/results/2026-10-15-linux-x86_64.json)
include five alternating fresh-process runs against baseline `fc6ac9a` on
one x86-64 Linux host, using the same Python and dependencies. Each local
run has 3,000 samples. Separate persistent TLS 1.3/mTLS loopback runs have
1,000 measured round trips per available mode, after 20 warm-up messages.
The table summarizes the median of the five per-run statistics, not pooled
samples or independent measurements on five machines.

<!-- performance-results:start -->
| Receiver-only processing (ms) | Baseline p50 / p95 / p99 | Updated p50 / p95 / p99 |
|---|---|---|
| Fresh durable heartbeat | 0.266 / 0.396 / 0.589 | 0.211 / 0.321 / 0.515 |
| Duplicate durable heartbeat | 0.240 / 0.374 / 0.506 | 0.204 / 0.312 / 0.451 |
| Volatile heartbeat (different guarantee) | Unavailable | 0.191 / 0.287 / 0.439 |

| Persistent TLS/mTLS RTT (ms) | Baseline p50 / p95 / p99 | Updated p50 / p95 / p99 |
|---|---|---|
| Durable heartbeat | 0.731 / 0.955 / 1.180 | 0.666 / 0.890 / 1.223 |
| Volatile heartbeat | Unavailable | 0.642 / 0.898 / 1.242 |

| Fresh process activity | Baseline startup / peak RSS | Updated startup / peak RSS |
|---|---|---|
| Package import | 65.5 ms / 27.1 MiB | 2.0 ms / 12.1 MiB |
| CLI help | 140.0 ms / 36.8 MiB | 50.6 ms / 25.3 MiB |
| Node initialize and close | 71.8 ms / 30.1 MiB | 54.1 ms / 29.3 MiB |

Durable receiver p50 falls by 20.6%; CLI-help startup falls by 63.8% and
its peak RSS by 31.3%. The initialized-node RSS reduction is only 2.8%.
The volatile mode removes writes, but its median-of-run network p99 is
**higher** than the updated durable mode in this sample (1.242 vs 1.223 ms).
These results support reduced processing/startup cost, not a tail-latency SLO.
<!-- performance-results:end -->

The receiver-only microbenchmark excludes sockets, TLS, signing and device
effects. The WebSocket benchmark includes framing, transport, server checks
and response handling; its client/server share one process and host. It
excludes pairing, handshake, sender signing, robots, WAN behavior, overload,
long endurance and broker replication. Rate limits are increased only in
the isolated benchmark. Both paths retain signature verification. All valid
volatile runs assert **zero SQLite row changes** during sample processing.

Performance fluctuates with host load, scheduling and storage. Tail latency
does not become a guaranteed SLO from these runs. Startup/import RSS measures
the named process activity, not memory under an arbitrary fleet or queue
load. The package still includes optional feature source files and five
runtime dependencies; this is not a tiny native single-binary server.

```sh
git worktree add --detach /tmp/fasp-baseline fc6ac9a
uv run --locked python -m benchmarks.compare \
  --baseline /tmp/fasp-baseline --runs 5 --iterations 3000 --channel
uv run --locked python -m benchmarks.channel --iterations 1000
```

CI exercises actual TLS/mTLS round trips and zero-write volatile delivery on
Python 3.11–3.13. It does not enforce noisy absolute latency thresholds.
NATS parity would require a separate, equivalent workload on measured NATS
Core and JetStream configurations, with security/delivery guarantees held
explicit. A compact binary/session-authenticated data profile or native
implementation would require its own negotiated protocol and security
review; neither is claimed by this change.

Primary references: [Core NATS](https://docs.nats.io/learn/core-nats/),
[JetStream](https://docs.nats.io/concepts/jetstream),
[NATS resource sizing](https://docs.nats.io/running-a-nats-service/environment),
[SQLite WAL](https://www.sqlite.org/wal.html).
