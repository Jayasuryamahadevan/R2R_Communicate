# FASP CLI for AI agents and reliable coordination

The installed `fasp` command is a JSON-first interface for two *separately
owned* agents or nodes. It uses the existing Ed25519-signed FASP v1 wire
protocol; it is NOT a model-hosting service, unauthenticated peer-to-peer
chat system, or universal NAT traversal layer.

## Install

From the repository:

```bash
python -m pip install -e .
fasp --help
```

If your shell cannot find the installed script, use
`python -m fasp_harness init|register|...` instead. The existing
`python -m fasp_harness serve` entrypoint remains compatible, and
`fasp serve` is also supported.

## Two-node setup

Run on **machine A**:

```bash
fasp init --name agent-a --base-url https://agent-a.internal:8766 --state-dir ~/.fasp-a
fasp serve --name agent-a --state-dir ~/.fasp-a --host 0.0.0.0 --port 8766 \
  --public-url https://agent-a.internal:8766 \
  --tls-cert /run/secrets/a.crt --tls-key /run/secrets/a.key \
  --tls-client-ca /run/secrets/mesh-ca.crt
```

Run on **machine B**, in another terminal:

```bash
fasp init --name agent-b --base-url https://agent-b.internal:8766 --state-dir ~/.fasp-b
fasp serve --name agent-b --state-dir ~/.fasp-b --host 0.0.0.0 --port 8766 \
  --public-url https://agent-b.internal:8766 \
  --tls-cert /run/secrets/b.crt --tls-key /run/secrets/b.key \
  --tls-client-ca /run/secrets/mesh-ca.crt
```

These commands are deployment **examples**: use real hostnames, certificates,
appropriately protected keys and a restricted network. mTLS is enforced only
when `--tls-client-ca` is provided. For physical/production deployment follow
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) and its fail-closed gates.

From machine A, request pairing (specify client credentials when required):

```bash
fasp register https://agent-b.internal:8766 --state-dir ~/.fasp-a \
  --ca-cert /run/secrets/mesh-ca.crt \
  --client-cert /run/secrets/a.crt --client-key /run/secrets/a.key
```

From machine B, request pairing with A:

```bash
fasp register https://agent-a.internal:8766 --state-dir ~/.fasp-b \
  --ca-cert /run/secrets/mesh-ca.crt \
  --client-cert /run/secrets/b.crt --client-key /run/secrets/b.key
```

Both JSON replies contain the *same* pairing fingerprint. Operators must
compare that fingerprint **out of band** and verify the expected public-key
identities before approving either side. Registration itself does not grant
access. Approval is local to the machine owning the state directory.

On **both** machines, using the other machine's exact `fasp:system:...` ID
and the checked fingerprint:

```bash
fasp approve 'fasp:system:PEER_ID' --code PAIRING_CODE \
  --scope observe. --scope coordinate. --state-dir ~/.fasp-a
```

Use `~/.fasp-b` and the opposite peer ID on B. `--scope` can be repeated;
the scope is a receiver-side authorization boundary, not just metadata.
`fasp peers --state-dir ~/.fasp-a` shows paired identities and endpoints.

### AI-to-AI communication

With the default safe test adapter on machine B:

```bash
fasp communicate 'fasp:system:BOB_ID' \
  --message 'Summarize the current work plan' \
  --capability coordinate.chat.v1 \
  --idempotency-key task-001 \
  --state-dir ~/.fasp-a \
  --ca-cert /run/secrets/mesh-ca.crt \
  --client-cert /run/secrets/a.crt --client-key /run/secrets/a.key
```

The default adapter only echoes the provided objective: it does NOT invoke
an LLM or run arbitrary agent code. To connect a real model or agent, launch
the receiving node with a reviewed local adapter using `--adapter
your_package:factory`. Each permitted capability must be declared with an
authoritative risk classification and enforced by the receiver. For eligible
stateless adapters `--process-adapter` provides a killable subprocess but
not OS security sandboxing.

### Surviving a network interruption

The CLI writes a signed envelope to a local SQLite outbox *before* attempting
the network. Requests receive an independent `message_id` and tasks may have
an explicit stable `idempotency_key`.

```bash
# Queue without requiring the remote node to be online:
fasp communicate 'fasp:system:BOB_ID' --message 'Status?' \
  --queue-only --state-dir ~/.fasp-a

# Run a supervised delivery loop, e.g. under systemd:
fasp drain --watch --interval 2 --state-dir ~/.fasp-a \
  --ca-cert /run/secrets/mesh-ca.crt \
  --client-cert /run/secrets/a.crt --client-key /run/secrets/a.key

# Inspect response and attempt state by returned message ID:
fasp outbox MESSAGE_ID --state-dir ~/.fasp-a

# Check a durable remote task by the application idempotency key:
fasp task-status 'fasp:system:BOB_ID' task-001 --state-dir ~/.fasp-a \
  --ca-cert /run/secrets/mesh-ca.crt \
  --client-cert /run/secrets/a.crt --client-key /run/secrets/a.key
```

Only one CLI delivery owner is allowed per local state directory. The
receiver deduplicates signed `message_id` and, for intentions, the stable
task idempotency key. The original immutable signed envelope is retried
with bounded exponential backoff. A successful HTTP response with an
intention receipt must match the submitted message ID; the response is
persisted in the outbox for later agent access.

**Expiry is deliberate.** The current FASP core signs envelopes for about
**two minutes**. Queued requests that remain offline past this bound are
dead-lettered, not re-signed behind the user's back. For longer-duration
outages, a higher-level scheduler must obtain fresh authorization and create
a new signed message; never replay a stale safety-sensitive instruction.
This is bounded *at-least-once transport delivery with receiver deduplication*,
not a guarantee of exactly-once physical effects. An accepted task may
still fail or be cancelled after network delivery.

A `fasp` command emits one JSON document to stdout; errors are JSON on
stderr. Exit codes: `0` delivered/accepted or deliberately queued;
`2` invalid CLI/policy/configuration; `3` queued after transport
failure; `4` permanently rejected/dead-lettered.

## Lower-level signed messages

For protocol messages other than `intent.propose`, supply a JSON object
from a file or standard input:

```bash
printf '{}' | fasp send 'fasp:system:BOB_ID' --kind heartbeat \
  --payload-file - --state-dir ~/.fasp-a
```

Only kinds handled by FASP's built-in dispatch table are accepted. Generic
network requests never bypass the receiver's scopes, grants, risk
classification or layer guard. Raw messages and peer responses can contain
private information; store CLI output with appropriate permissions.

## Current boundaries

- Requires pre-existing IP/DNS/TLS reachability; does not itself create
  libp2p circuits, NAT hole punching or a relay mesh.
- Requires two-sided operator approval, rather than hidden auto-enrollment.
- Certificates and CA roots remain operator responsibilities; TLS server
  verification is on by default, with no insecure-skip-verification switch.
- `--insecure-http` exists only for isolated *development* LANs. Remote
  HTTP is otherwise refused. Be aware even signed JSON is not encrypted.
- Calls use the sender's local identity and receiver's capability policy.
  Remote tool execution is never free-form; the receiver must install an
  allowed adapter first.
