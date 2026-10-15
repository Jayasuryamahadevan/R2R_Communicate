# Concurrent communication and access lifetimes

This extends the [lightweight delivery profiles](PERFORMANCE.md) with bounded
request admission, separate execution capacity, authenticated channel lifetimes
and a corrected reconnecting TypeScript client. It does not establish hard
real-time behavior, broker replication or physical safety certification.

## Admission and isolation

The HTTP envelope/receipt routes and WebSocket frames use the same dispatcher.
It reserves capacity before submitting a handler and refuses excess work with
`transport.overloaded`; rejected requests have not entered the protocol inbox
or dispatched device work. There is no application queue waiting for an
execution slot. TCP, ASGI framing and the separate durable task store retain
their own bounds and behavior.

| Ingress lane | Request kinds | Default concurrent handlers |
|---|---|---|
| Observation | `heartbeat`, `stream.packet` | 4 |
| Control | `task.status`, `task.cancel`, `stream.close`, `reservation.release`, `receipt.processed`, `safety.halt`, `safety.status`, `mission.status`, `mission.cancel` | 4 |
| Work | All other kinds | 8 |

Each claimed peer can occupy at most two handlers per lane. Claims only
partition capacity: signatures, pairing and authorization are still checked
inside every admitted handler. Spoofing another identity does not authorize a
request or create an unbounded map. HTTP and WebSocket share these budgets.

Each lane has its own bounded executor, independent of Starlette's shared
worker capacity. Cancelling or disconnecting a caller does **not** release its
reservation until the synchronous handler exits. This prevents reconnect churn
from creating hidden in-flight work. Request context variables survive the
offload. Shutdown drains ingress before closing protocol storage.

These are handler counts, not the entire process's thread count. The local
adapter executor and other ASGI operations have separate capacity. A blocked
SQLite transaction, CPU contention, a device driver or the network can still
delay an admitted control request. Network `safety.halt` is a request to local
safety infrastructure; local protective stops must remain independent.

### Overload and uncertain results

HTTP returns 503 with `Retry-After: 1`; a channel returns a correlated
`protocol.error`. Retry with bounded exponential backoff and jitter, preserving
the signed request/message ID while it remains valid. Refresh an expired
request according to its delivery profile. Overload rejections are counted
rather than logged individually, avoiding a log flood on this path.

After a connection failure or timeout, an already-admitted durable request may
have taken effect. Reconcile by its original message/task identity. A timeout
is not cancellation or proof of non-execution. Durable outbox/recovery and
`task.status` remain necessary for important work.

## Channel bounds and identity

| Resource | Default |
|---|---|
| Total WebSocket sessions, including unauthenticated/closing sessions | 128 |
| Completed first authenticated exchange | 5 seconds |
| Consecutive invalid decoded envelope frames | 8 |
| Reply/push send deadline, including writer wait | 1 second |
| HTTP request body deadline | 10 seconds |
| HTTP request/frame size | 64 KiB |
| CLI Uvicorn connection/task concurrency limit | 256 |

Start each channel with a signed heartbeat addressed to the **receiver**. Its
reply registers push delivery. The initial deadline includes that exchange;
starting with long-running work can time out while admitted work continues.
A socket stays bound to its first successful peer identity. A subsequent frame
claiming another identity is rejected **before dispatch**, then closes with
1008. Use another connection for another identity. Invalid JSON closes with
1007; oversized frames use 1009; saturation/slow consumers use 1013. A retryable
ingress overload does not consume the invalid-frame allowance.

Replies and errors include `in_reply_to` when the decoded request supplies a
bounded message ID. This field correlates transport replies; it is not a
signature, authorization proof, persistent receipt or proof of subscriber
processing. Unsolicited `task.push` / `stream.push` remain distinct messages.
Direct replies, pushes and close use the same writer lock, preventing
concurrent writes to a WebSocket.

The existing push count/byte limits remain in force. A failed or stalled push
unregisters and closes its connection. Operator revocation disconnects a peer's
registered channels. Before enqueueing a push, current pairing, expiry and
revocation are read again; this also notices changes made by another database
connection. Stream-specific consent/grants are still checked before forwarding.
A revocation cannot retract bytes already transmitted or a write in progress.

CLI controls: `--ingress-work-workers`, `--ingress-control-workers`,
`--ingress-observation-workers`, `--ingress-per-peer`, `--max-channels`,
`--channel-auth-timeout`, `--body-timeout`, `--max-connections`. Invalid limits
fail before node state is created. Embedded applications can pass a validated
`TransportLimits` to `create_app`/`build_asgi_app`; configure their ASGI server's
connection limit separately. Use one process per node; these limits and the
volatile replay/session state are process-local.

Protected `/metrics` includes `fasp_ingress_active{lane=...}`,
`fasp_ingress_rejected_total{lane=...}`, `fasp_channel_sessions`,
`fasp_channel_rejected_total{reason=...}` and `fasp_channel_errors_total{code=...}`,
plus existing push counters. Peer IDs are not metric labels.

## TypeScript bridge

The first handshake and every reconnect address the remote system ID rather
than the client's own ID. `openChannel` accepts the approved receiver ID as its
fourth argument, or uses the ID verified by a preceding `hello` on this client.
The convenience identity map is capped at 256 URLs; persist operator-approved
pairing identities in the host application.

```ts
const channel = await client.openChannel(
  receiverUrl, onMessage, onStatusChange, approvedRemoteSystemId,
);
channel.send(client.buildEnvelope("heartbeat", approvedRemoteSystemId, {}));
```

Before connecting/reconnecting, the helper fetches and verifies the signed
profile against that expected identity. A changed identity stops reconnection
and surfaces `auth.identity_mismatch`. A registration heartbeat must be
acknowledged before queued envelopes are flushed. Connect/registration waits
are bounded; closing during reconnect prevents later connections from being
kept open. Explicit close clears timers and queued messages; sending afterward
fails clearly.

Outgoing records are limited to 64 KiB. The reconnect queue has both 50-record
and 1 MiB bounds; native socket buffering has a 256 KiB admission budget.
Expired queued records are discarded with `channel.expired`. Live/volatile
envelopes are never buffered offline: send fails with `channel.offline` so the
producer can refresh the receiver profile/session and send a fresh observation.

`send()` only accepts a record into local transport state. It does not await a
server acknowledgement, and the reconnect queue is RAM-only. The helper does
not automatically resend frames whose acknowledgements were lost. Use the
persistent outbox/reconciliation path for durable delivery requirements.

HTTPS certificate verification and the signed profile's identity check serve
different purposes; both are required remotely. The Node helper uses the host's
global fetch/WebSocket implementations and does not provision mTLS credentials.
Configure and test the host's TLS/client-certificate transport before using it
against production nodes. Python CLI mTLS and the TLS/mTLS server smoke tests
remain separate validated paths.

## Evidence and limitations

[Raw saturation runs](benchmarks/results/2026-10-15-ingress-isolation.json)
compare five alternating fresh-process runs against `500d206`. The same peer
submits 48 concurrent signed slow intents. A timer releases the held adapter
250 ms after the heartbeat probe begins. This is local ASGI/TestClient traffic,
without TCP/TLS; it tests admission/isolation rather than broker throughput.

<!-- saturation-results:start -->
| Local ASGI saturation result | Before (`500d206`) | Updated |
|---|---|---|
| Heartbeat elapsed (median) | 281.61 ms | 1.35 ms |
| Accepted slow requests (each run) | 48 | 2 |
| Retryable overload responses (each run) | 0 | 46 |
| Heartbeat completed before adapter release | 0 / 5 runs | 5 / 5 runs |
<!-- saturation-results:end -->

This improvement intentionally includes load shedding and per-peer fairness:
it does not accept the same number of slow requests. Rejected work must be
retried. The result is not evidence of higher completed-work throughput or a
guaranteed latency bound under arbitrary load.

[Raw TLS comparison](benchmarks/results/2026-10-15-isolated-transport.json)
uses the same interpreter/dependencies, five alternating fresh-process runs,
1,000 persistent TLS 1.3/mTLS loopback round trips per mode/run, and 3,000 local
CPU samples. Results summarize the median of each run's percentile. Network
measurements exclude handshake, sender signing, WAN and device effects; they
include verification, framing, storage/dispatch and response handling.

<!-- transport-results:start -->
| Persistent TLS/mTLS heartbeat RTT (ms) | Before p50 / p95 / p99 | Updated p50 / p95 / p99 |
|---|---|---|
| Durable | 0.735 / 1.114 / 2.156 | 0.715 / 0.989 / 1.497 |
| Volatile | 0.675 / 0.950 / 1.379 | 0.655 / 0.884 / 1.283 |
<!-- transport-results:end -->

Tests exercise admission without effects on overload, control/observation
isolation, caller cancellation, fairness, shared writers, authentication/body
deadlines, identity changes, revocation and external expiry updates. The actual
TypeScript SDK is type-stripped with Node's built-in API: a real loopback ASGI
integration proves pairing/registration/correlated exchange, while socket fault
injection tests reconnect, stale observations, queue bytes and changed identities.
Python TLS/mTLS smoke tests separately exercise encrypted transport. CI covers
Python 3.11–3.13 and Node 22, and records saturation evidence without enforcing
noisy absolute performance thresholds.

Reproduce with test extras installed:

```sh
git worktree add --detach /tmp/fasp-transport-baseline 500d206
uv run --locked --extra test python -m benchmarks.saturation \
  --baseline /tmp/fasp-transport-baseline --runs 5
uv run --locked --extra test python -m benchmarks.compare \
  --baseline /tmp/fasp-transport-baseline --runs 5 --iterations 3000 --channel
```

References: [Uvicorn concurrency limits](https://www.uvicorn.org/settings/#resource-limits),
[Starlette's shared thread pool](https://www.starlette.io/threadpool/).
