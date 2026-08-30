# FASP Harness

This repository contains a runnable reference harness for the **Federated
Autonomous Systems Protocol** in [FASP_PROTOCOL.md](FASP_PROTOCOL.md). It is a
model-agnostic coordination layer for two or more autonomous systems: models,
phones, laptops, Raspberry Pis, robots, or gateways.

The harness does **not** execute arbitrary instructions received over the
network. A model is attached through a local adapter with declared capabilities;
the harness authenticates the peer, verifies its authorization scope, journals
idempotency, and only then invokes that adapter.

## What is implemented

- Ed25519 system identity and signed public ID card
- explicit local-CIDR active discovery of `/.well-known/fasp/id-card.json`
- pending → human-confirmed pairing; scanning never grants authority
- signed `/hello`, `/send`, `/task`, `/inbox`, and `/receipt` workflows
- durable inbox, replay cache, idempotency journal, task result cache, and
  processed receipts
- capability-prefix policy and safe default adapter
- bounded, opt-in model adapter interface
- portable runtime profiles for Windows, Linux, macOS, Raspberry Pi, Android
  gateways, RTX-3050-class local inference, ROS 1, and ROS 2
- generic live-stream packet management with reliable/latest modes, sequence
  windows, fragmentation, integrity checks, acknowledgements, and backpressure

## Standard HTTP endpoints

| Endpoint | Method | Access | Purpose |
|---|---:|---|---|
| `/.well-known/fasp/id-card.json` | GET | public | signed discovery card |
| `/id_card` | GET | public | alias for the signed card |
| `/capabilities` | GET | public | advertised, non-secret capabilities |
| `/health` | GET | public | liveness only |
| `/hello` | POST | public signed card | create/update a pending pairing record |
| `/pair/confirm` | POST | local admin token | turn a matching pending record into a paired peer |
| `/send` | POST | paired signed envelope | deliver a general FASP envelope |
| `/task` | POST | paired signed envelope | deliver an `intent.propose` envelope |
| `/inbox` | POST | paired signed `inbox.pull` | retrieve durable inbox entries |
| `/receipt` | POST | paired signed `receipt.processed` | confirm application processing |
| `/stream/open` | POST | paired signed `stream.open` | negotiate a bounded live stream |
| `/stream/packet` | POST | paired signed `stream.packet` | submit a sequenced, checksummed data packet |
| `/stream/pull` | POST | paired signed `stream.pull` | retrieve bounded retained packets |
| `/stream/close` | POST | paired signed `stream.close` | close and safe-stop a stream |
| `/peers` | GET | local admin token | inspect pairing state |

`/send` returns `receipt.delivered`; it does not falsely claim that a model has
understood or completed the requested work. Task execution returns an explicit
terminal `task.result` or `task.fail` response.

## Quick start

The only Python dependency is `cryptography`, which provides Ed25519.

```bash
python3 -m unittest discover -s tests -v
python3 -m fasp_harness serve \
  --host 0.0.0.0 --port 8766 \
  --public-url http://192.168.0.22:8766 \
  --name laptop-agent --state-dir .fasp/laptop --insecure-http
```

The server prints its system ID, public ID-card URL, and the path to its private
admin token. Do not expose the admin token or identity private key.

Run a second instance on a phone, Pi, or other host using its own state folder
and public URL.

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

1. Fetch or discover the other endpoint’s signed ID card.
2. POST that card to its `/hello` endpoint. The reply supplies a short pair
   code and its own ID card.
3. Compare the same pair code on both trusted local displays or an out-of-band
   channel.
4. On each endpoint, call `/pair/confirm` with the local admin token, peer ID,
   and pair code. Choose allowed capability prefixes, for example
   `observe.` and `coordinate.`.
5. Only now send signed task envelopes.

The reference uses trust-on-first-use only for the *pending* record. A human or
organization issuer confirms the public key before any task authority exists.

## Connect any model safely

An adapter needs only two methods:

```python
class MyAdapter:
    def capabilities(self) -> list[dict]: ...
    def handle(self, intent: dict) -> dict: ...
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
unpaired peers, unauthorized capability prefixes, unknown capabilities, and
risk classes above `observe`/`reversible` before the adapter runs.

## Production hardening

This harness is a reference baseline, not a safety-certified robot controller.
For real deployment, use HTTPS with mutual TLS, an RFC 8785 implementation in
every language, hardware-backed keys where available, a real authorization
issuer and revocation service, encrypted artifact storage, rate limiting at the
reverse proxy, and local safety controllers/emergency stops for every physical
actuator. See [FASP_PROTOCOL.md](FASP_PROTOCOL.md) for the complete protocol.
See [FASP_RUNTIME_PROFILES.md](FASP_RUNTIME_PROFILES.md) for cross-platform
deployment profiles and [FASP_MESSAGING_STREAMING.md](FASP_MESSAGING_STREAMING.md)
for the packet-management and live-streaming profile.
