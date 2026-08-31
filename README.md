# FASP Harness

This repository contains a runnable reference harness for the **Federated
Autonomous Systems Protocol** in [FASP_PROTOCOL.md](FASP_PROTOCOL.md). It is a
model-agnostic coordination layer for two or more autonomous systems: models,
phones, laptops, Raspberry Pis, robots, or gateways.

The harness does **not** execute arbitrary instructions received over the
network. A model is attached through a local adapter with declared capabilities;
the harness authenticates the peer, verifies its authorization scope, journals
idempotency, and only then invokes that adapter.

## Architecture

- **Transport**: Starlette + uvicorn (ASGI). HTTP/1.1 parsing, TLS/ALPN, and
  chunked transfer-encoding are handled by an audited library rather than a
  hand-rolled `http.server` -- see `fasp_harness/transport/`.
- **Durable state**: SQLite (WAL mode), one `fasp.db` per system under its
  state directory, schema-versioned migrations in
  `fasp_harness/storage/migrations/`. The Ed25519 private key and the local
  admin token stay outside the database as separate 0600 files.
- **Crypto**: Ed25519 signing (`fasp_harness/crypto/`) over RFC 8785 (JSON
  Canonicalization Scheme) bytes, via the `rfc8785` package (Trail of Bits),
  verified against the official test vectors in `tests/vendor_vectors/`.
- **Authorization**: pairing-time capability prefixes (coarse) plus optional,
  time-limited, revocable grants (fine; `fasp_harness/policy/grants.py`) --
  a grant only ever narrows what pairing already scoped, never widens it.
- **Task lifecycle**: the full `PROPOSED -> RUNNING -> {COMPLETED | FAILED |
  CANCELLED}` state machine (`fasp_harness/tasks` logic lives in
  `core.py` + `storage/tasks_repo.py`), with real cancellation racing and a
  startup sweep that resolves any task stuck `RUNNING` by a prior crash to a
  safe terminal state instead of replaying it.
- **Bounded work queue**: `adapter.handle()` runs on a fixed-size
  `ThreadPoolExecutor`, not inline per request -- a real wall-clock timeout on
  the capability's own `max_runtime_s`, a hard concurrency bound, and durable
  backpressure (`resource.exhausted` once `max_inflight_tasks` -- backed by
  the `tasks` table itself, not an in-memory counter -- is reached).
- **Live channel**: an optional `/fasp/v1/channel` websocket
  (`fasp_harness/transport/http_app.py`, `fasp_harness/channels.py`) carries
  the identical signed-envelope protocol over a persistent connection, used
  to push a late task result or a subscribed stream's new packets the moment
  they're ready -- always a latency optimization on top of the durable state,
  never a replacement for `task.status`/`stream.pull` polling.
- **Audit**: a tamper-evident, hash-chained append-only log
  (`fasp_harness/audit/chain.py`) of every grant/task/revocation/pairing
  decision, verifiable end to end with `AuditChain.verify()`.
- **Artifacts**: large results are stored content-addressed on disk
  (`fasp_harness/artifacts/`) and referenced by digest instead of inflating a
  signed envelope past its 64 KiB cap.
- **Hardening**: mutual TLS (optional), a two-layer token-bucket rate limiter
  (per-source-IP ahead of authentication, per-peer after signature
  verification), and a non-constant-time-free admin-token comparison.
- **Observability**: structured JSON logs with a redaction filter for known
  secret field names, and a `/metrics` endpoint in Prometheus text format.

## What is implemented

- Ed25519 system identity and signed system profile
- explicit local-CIDR active discovery of `/.well-known/fasp/id-card.json`
- pending -> human-confirmed pairing with an expiry, plus explicit peer
  revocation and re-pairing; scanning never grants authority
- signed pairing, task, inbox, receipt, artifact, streaming, fleet-reservation,
  and safety/incident/heartbeat workflows over one generic envelope ingress,
  with universal message_id replay dedup across every kind, not only tasks
- durable (SQLite) inbox/replay cache, full task-lifecycle state machine,
  content-addressed artifacts, and a hash-chained audit log
- a bounded adapter work queue: intent.propose runs on a fixed-size worker
  pool with a real wall-clock timeout and durable backpressure
  (`resource.exhausted` once too many tasks are in flight), plus `task.status`
  to poll an intent whose synchronous wait already timed out
- an optional `/fasp/v1/channel` websocket carrying the identical
  signed-envelope protocol over a persistent connection, so a completed task
  or a live stream packet can be pushed to a connected peer instead of polled
- capability-prefix policy, optional scoped grants, and a safe default adapter
- bounded, opt-in model adapter interface, with optional `cancel()` hook
- portable runtime profiles for Windows, Linux, macOS, Raspberry Pi, Android
  gateways, RTX-3050-class local inference, ROS 1, and ROS 2
- generic live-stream packet management with reliable/latest modes, sequence
  windows, fragmentation, integrity checks, acknowledgements, backpressure,
  and an opt-in `stream.subscribe` push channel on top of durable `stream.pull`
- mutual TLS, per-IP and per-peer rate limiting, and an artifact storage cap

## HTTP endpoints

| Endpoint | Method | Access | Purpose |
|---|---:|---|---|
| `/profile` (+ `/.well-known/fasp/id-card.json` alias) | GET | public | signed system profile |
| `/health` | GET | public | liveness only |
| `/metrics` | GET | local admin token | Prometheus text exposition |
| `/peers` | GET | local admin token | inspect pairing state |
| `/pair/hello` | POST | public signed card | create/update a pending pairing record |
| `/pair/confirm` | POST | local admin token | turn a matching pending record into a paired peer |
| `/pair/revoke` | POST | local admin token | immediately reject a peer regardless of pairing state |
| `/grants/issue` | POST | local admin token | issue a time-limited, capability-scoped grant to a paired peer |
| `/grants/revoke` | POST | local admin token | revoke a previously issued grant |
| `/fasp/v1/envelopes` | POST | paired signed envelope | generic ingress; dispatches on the envelope's `kind` |
| `/fasp/v1/receipts` | POST | paired signed `receipt.processed` | alias into the same dispatch, per FASP_PROTOCOL.md ss13 |
| `/fasp/v1/channel` | WS | paired signed envelope, per frame | the same dispatch over a persistent connection, plus push delivery |

`/fasp/v1/envelopes` dispatches `intent.propose`/`task.cancel`/`artifact.fetch`
through the idempotent task pipeline (response wrapped in `receipt.delivered`),
and `task.status`, `inbox.pull`, `receipt.processed`,
`stream.open/packet/pull/subscribe/unsubscribe/close`,
`reservation.request/release`, `safety.halt/status`, `incident.report`, and
`heartbeat` through their own dedicated handlers, returning each one's own
response shape directly. An unrecognized `kind` is rejected with
`protocol.unsupported_kind`, never silently accepted. Every kind shares one
message_id replay-dedup gate: a retried envelope (same `message_id`) always
returns its original recorded response rather than being processed again.

`intent.propose` never falsely claims a model has understood or completed the
requested work: the delivery receipt and the task result are always distinct.
A slow capability's synchronous wait is capped at its own declared
`max_runtime_s`; past that, the caller gets `task.progress` immediately and
either polls `task.status` or -- if connected over `/fasp/v1/channel` -- is
pushed the eventual `task.push` result the moment it completes.

## Quick start

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[test,dev]"

ruff check fasp_harness tests
python3 -m unittest discover -s tests -v
python3 -m fasp_harness serve \
  --host 0.0.0.0 --port 8766 \
  --public-url http://192.168.0.22:8766 \
  --name laptop-agent --state-dir .fasp/laptop --insecure-http
```

(Any PEP 517-compatible installer works; `uv` is just fast. The runtime
dependencies are `cryptography`, `starlette`, `uvicorn`, and `rfc8785`.)
`.github/workflows/ci.yml` runs the same lint and test suite on every
push and pull request, across Python 3.11-3.13.

Or run it in a container:

```bash
docker build -t fasp-harness .
docker run -p 8766:8766 -v fasp-state:/home/fasp/.fasp fasp-harness
```

The server prints its system ID, public profile URL, and the path to its
private admin token. Do not expose the admin token or identity private key.

Run a second instance on a phone, Pi, or other host using its own state folder
and public URL.

### Rate limiting and mTLS

```bash
python3 -m fasp_harness serve --state-dir .fasp/laptop --public-url https://192.168.0.22:8766 \
  --tls-cert cert.pem --tls-key key.pem --tls-client-ca client-ca.pem \
  --rate-limit-per-peer 10 --rate-limit-burst 20 \
  --ip-rate-limit-per-second 20 --ip-rate-limit-burst 40
```

`--tls-client-ca` requires and verifies client certificates (mutual TLS) --
this is transport hardening only, never a substitute for the envelope-level
peer authorization that still runs on every request regardless.

## Active discovery: explicit and limited

Discovery only probes one fixed FASP path on one explicitly supplied CIDR and
port. It is capped at 1,024 hosts unless `--allow-large` is given. It stores
**self-signed discovered cards**, not trusted peers.

```bash
python3 -m fasp_harness discover \
  --cidr 192.168.0.0/24 --port 8766 --state-dir .fasp/laptop
```

Before scanning, obtain authorization for that network. Do not use this tool on
networks you do not own or administer.

## Pairing workflow

1. Fetch or discover the other endpoint's signed system profile.
2. POST that profile's `id_card` to its `/pair/hello` endpoint. The reply
   supplies a short pair code and its own profile.
3. Compare the same pair code on both trusted local displays or an out-of-band
   channel.
4. On each endpoint, call `/pair/confirm` with the local admin token, peer ID,
   and pair code. Choose allowed capability prefixes, for example
   `observe.` and `coordinate.`. A pairing expires after 90 days by default.
5. Only now send signed task envelopes. If a key is ever suspected compromised,
   call `/pair/revoke` -- the peer is rejected immediately regardless of its
   prior pairing state, until a fresh `/pair/hello` + `/pair/confirm` re-pairs it.

The reference uses trust-on-first-use only for the *pending* record. A human or
organization issuer confirms the public key before any task authority exists.

## Scoped, time-limited grants

Pairing-time capability prefixes are the base authorization. A grant narrows
that further for a specific window: issue one with the local admin token,
then reference it from an `intent.propose` payload's `grant: {"id": ...}` field.

```bash
curl -s -X POST http://host:8766/grants/issue -H "X-FASP-Admin-Token: $TOKEN" -d '{
  "subject_peer": "fasp:system:...", "capability_prefixes": ["reversible."],
  "duration_seconds": 3600, "purpose": "one staging deploy"
}'
```

A grant can never authorize more than the peer's pairing prefixes already
allow -- it is purely an additional, independently expiring/revocable
requirement layered on top.

## Connect any model safely

An adapter needs two required methods, plus an optional `cancel` hook for
long-running work:

```python
class MyAdapter:
    def capabilities(self) -> list[dict]: ...
    def handle(self, intent: dict) -> dict: ...
    def cancel(self, idempotency_key: str) -> bool: ...  # optional
```

Use [fasp_harness/example_adapter.py](fasp_harness/example_adapter.py) as the
template, then start with a local import path:

```bash
python3 -m fasp_harness serve --adapter my_package.adapter:create_adapter
```

The adapter should return planning, analysis, or other bounded outputs. It must
not use peer text as permission for shell commands, network calls, account
changes, destructive actions, continuous sensing, or physical actuation. Those
require separately declared capabilities and local approval gates.

## Example `intent.propose` payload

The actual request is a FASP-signed envelope. Its payload is:

```json
{
  "intent_id": "status-001",
  "idempotency_key": "laptop-status-001",
  "capability": "observe.system.status.v1",
  "objective": "Return a non-sensitive service health summary.",
  "constraints": {"network": "none", "retain": "none"},
  "risk": "observe"
}
```

The harness rejects unknown peers, invalid signatures, expired requests, replay,
unpaired/revoked/expired peers, unauthorized capability prefixes, missing or
invalid grants, unknown capabilities, and risk classes above
`observe`/`reversible` before the adapter runs -- and persists a rejection so a
resubmission of the same `idempotency_key` returns the identical outcome
instead of re-running the checks.

## Coding-agent bridges: self-describing, MCP-capable, any host

A FASP peer already knows who it is -- a signed identity, capability-
scoped pairing, a profile from the moment it joins. A general-purpose
coding agent typically doesn't: nothing about it is signed, versioned,
or self-describing across restarts. [`bridge_core/`](bridge_core/) is
the one host-agnostic implementation (Ed25519 over a minimal RFC 8785
subset, `node:crypto` only) of the
[Agent ID Card](https://github.com/Jayasuryamahadevan/agent-id-card)
identity layer that fixes that -- curious about its own environment on
first run, hash-chained rather than a static credential, and kept
honest over time as the agent's actual capabilities change.

Two bridges load it today, unmodified, as a thin host-specific adapter:

- [`pi_bridge/`](pi_bridge/) -- a [pi](https://github.com/earendil-works/pi)
  extension that also adds a generic MCP client (pi ships without one by
  design) and generic incoming/outgoing webhook connectivity.
- [`opencode_bridge/`](opencode_bridge/) -- an
  [OpenCode](https://github.com/anomalyco/opencode) plugin that also
  defaults OpenCode Zen as the primary model provider (only when the
  user hasn't already chosen one), and relies on OpenCode's own native
  MCP client rather than duplicating one.

A third host needs only its own thin adapter importing the same nine
`bridge_core` files -- see [`bridge_core/README.md`](bridge_core/README.md)
for why that single shared core, rather than one copy per host, is the
actual answer to "hardware- and software-agnostic": it has been run, for
real, against two independent, unrelated agents on this same machine,
and for a host with no Node at all,
[`agent-id-card`'s `NO_PYTHON.md`](https://github.com/Jayasuryamahadevan/agent-id-card/blob/main/NO_PYTHON.md)
gives the same crypto in OpenSSL, or libsodium instead.

## Production hardening

This harness is a reference baseline, not a safety-certified robot controller.
Already covered: TLS 1.3 with optional mutual TLS, RFC 8785 canonicalization
(verified against the official test vectors), rate limiting at the
application layer, a durable audit trail, and grant-based revocation. Still
your responsibility for a real deployment: an RFC 8785 implementation in every
other language your peers use, hardware-backed keys where available, a real
external authorization issuer, encrypted artifact storage at rest, rate
limiting/WAF at a reverse proxy in front of this one, and local safety
controllers/emergency stops for every physical actuator -- `safety.halt` here
can only ever be *requested* over the network, never used to clear one. See
[FASP_PROTOCOL.md](FASP_PROTOCOL.md) for the complete protocol.
See [FASP_RUNTIME_PROFILES.md](FASP_RUNTIME_PROFILES.md) for cross-platform
deployment profiles and [FASP_MESSAGING_STREAMING.md](FASP_MESSAGING_STREAMING.md)
for the packet-management and live-streaming profile.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
