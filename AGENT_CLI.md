# FASP CLI for AI agents and reliable coordination

The installed `fasp` command is a CLI and JSON interface for two *separately
owned* agents or nodes. It uses the existing Ed25519-signed FASP v1 wire
protocol; it is NOT a model-hosting service, unauthenticated peer-to-peer
chat system, or universal NAT traversal layer.

## Install

From the repository:

```bash
./install.sh
.venv/bin/fasp --help
```

If your shell cannot find the installed script, use
`python -m fasp_harness init|register|...` instead. The existing
`python -m fasp_harness serve` entrypoint remains compatible, and
`fasp serve` is also supported.

## MCP hosts

Install the optional [official Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk), then initialize a node:

```bash
./install.sh --with-mcp
.venv/bin/fasp init --name my-node --state-dir ~/.fasp-agent
```

Add this local stdio server to your MCP host's configuration (replace both
absolute paths). The host launches it on demand; no MCP port is opened:

```json
{
  "mcpServers": {
    "fasp": {
      "command": "/absolute/path/to/R2R_Communicate/.venv/bin/fasp",
      "args": ["mcp", "--state-dir", "/absolute/path/to/private/fasp-state"]
    }
  }
}
```

Use the host's equivalent server configuration format if it differs. The
server exposes `identity`, `peers`, `outbox`, `communicate`,
`queue_intent`, and `drain`. `communicate` signs, queues and attempts delivery
once; its result says `sent`, `pending`, or `dead` and includes the saved
response when available. `sent` confirms delivery, not completion of the
remote task. `queue_intent` persists without contacting the peer, and `drain`
attempts one bounded delivery batch. For automatic retries, supervise `fasp drain --watch`
separately. Pair and approve peers with the CLI before asking the MCP host
to send work. An MCP host with access to the private state directory can
use this node's identity, so give that host the same local trust level as
the `fasp` CLI. Keep each node's state on persistent storage and use a
different state directory for each identity.

The MCP tools also expose `routes` and `speak` for named task routing. `connect`
accepts an optional `name`, such as `agent.researcher`; `communicate` and
`queue_intent` accept either that local name or a system ID. Names are local
address-book entries and confer no trust or capability.

The MCP extra is installed only when requested. For a minimal runtime,
`./install.sh` installs only the five FASP dependencies. The optional Node
bridges are installed with `./install.sh --with-bridges` and require Node 20+.


## Human-friendly device management (CLI and MCP)

The CLI name is `fasp` (commands use a space, e.g. `fasp scan`). The MCP server named `FASP` exposes tools named `scan`, `inspect`, `connect`, `approve`, `disconnect`, `capabilities`, and `ping`, in addition to the existing identity, peers, communicate, queue_intent, drain, and outbox tools. Depending on the MCP host, these appear as `FASP.scan` or similarly qualified tool names.

**Scope:** discovery scans for **FASP-enabled nodes**, not arbitrary Bluetooth, USB, CAN, MQTT, Modbus, cameras or smart-home appliances. Such devices require an explicit reviewed gateway/adapter that provides FASP identity, capabilities and consent boundaries. No network scan can safely turn an unknown device into an authorized robot controller.

Initialize a distinct identity on each node, persist each state directory, and start each node's network listener with correctly configured TLS and a reachable advertised URL. A representative commissioning flow:

```bash
# Use a CIDR you control. By default, scanning requires HTTPS and validates TLS.
fasp scan --cidr 192.168.10.0/24 --port 8766 \
  --scheme https --ca-cert /etc/fasp/ca.pem --state-dir ~/.fasp-agent

# Read-only live signed-card verification. Scan results are cached by system ID.
fasp inspect 'fasp:system:EXACT_DISCOVERED_ID' \
  --ca-cert /etc/fasp/ca.pem --state-dir ~/.fasp-agent

# Starts pending mutual pairing, never grants authority.
fasp connect 'fasp:system:EXACT_DISCOVERED_ID' \
  --ca-cert /etc/fasp/ca.pem --state-dir ~/.fasp-agent

# Verify the printed 12-character pairing fingerprint through an independent
# trusted channel; complete the reverse connect and approve ON BOTH nodes.
fasp approve 'fasp:system:PEER_ID' --code 'VERIFIED_CODE' \
  --scope observe. --scope coordinate. --state-dir ~/.fasp-agent

fasp devices --state-dir ~/.fasp-agent
fasp capabilities 'fasp:system:PEER_ID' --ca-cert /etc/fasp/ca.pem --state-dir ~/.fasp-agent
fasp ping 'fasp:system:PEER_ID' --ca-cert /etc/fasp/ca.pem --state-dir ~/.fasp-agent
fasp communicate 'fasp:system:PEER_ID' --capability coordinate.chat.v1 \
  --message 'Inspect target' --ca-cert /etc/fasp/ca.pem --state-dir ~/.fasp-agent

# Local revocation; the other node must manage its own trust state.
fasp disconnect 'fasp:system:PEER_ID' --reason 'Device retired' --state-dir ~/.fasp-agent
fasp status --state-dir ~/.fasp-agent
```

For isolated loopback testing, use `fasp scan --cidr 127.0.0.0/30 --scheme http`. For non-loopback cleartext HTTP, `--insecure-http` is required for development, and is unsuitable for production. Discovery is restricted to explicitly supplied private/local CIDRs, refuses more than 1,024 hosts without CLI-only `--allow-large` (hard cap 65,536), limits workers to 32, and never automatically connects or authorizes. All data returned from an unknown node is an untrusted self-signed claim until its actual key is independently verified. The client verifies the key again when connecting, and refuses a mismatched pinned key or discovery identity. Direct public HTTPS endpoints can be inspected/connected by explicit URL without public-range scanning.

TLS client certificates are supported during scanning as well as direct connection using `--client-cert` and `--client-key`. The optional local stdio MCP server inherits its configured TLS credentials. **MCP tools execute with the authority of the host process that can access the local identity and state.** Restrict that filesystem access, require human approval for the `approve` and `disconnect` actions, and never expose stdio MCP as an unauthenticated network server. A `connect` operation by itself does not grant a capability; an approved scope does not bypass local adapter risk classifications or hardware safety.

## Two-node setup

### Local names and text tasks

After connecting and approving a peer on both nodes, you can address it with
a memorable local name. You can also supply `--as agent.researcher` to
`connect`, `register`, or `radio-register` to save the name during pairing;
the peer still stays pending until both operators approve it.

```bash
fasp route add agent.researcher 'fasp:system:PEER_ID'
fasp route list
fasp say agent.researcher 'Hello'
fasp speak agent.researcher.summarize --message 'Summarize this report' \
  --idempotency-key report-001
fasp tasks
fasp task-status agent.researcher report-001
fasp task-cancel agent.researcher report-001
fasp route remove agent.researcher
```

`speak` selects the longest registered name at the start of the task path,
then includes the complete `task_path` and remaining `task_name` in the signed
intent payload. For example, `agent.researcher.summarize` routes through
`agent.researcher` and carries `summarize` as the task name. The receiving
adapter sees these fields and decides how to handle the task. The default
adapter only echoes the text. Names cannot be rebound to a different peer
without explicitly removing the old binding. The durable outbox records each
task before sending and `tasks` lists recent outgoing intents.

Terminal output is readable by default; pipes and command substitution get
one JSON object per command. Use `--human` or `--json` anywhere in the command
to force a format. Set `FASP_STATE_DIR` to use the same private state directory
for `fasp`, `fasp serve`, and `fasp mcp` without repeating `--state-dir`.

Network commands still need the appropriate `--ca-cert` and optional mTLS
flags. A pending or revoked name cannot send tasks.

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

For Linux Bluetooth Classic or BLE, use `fasp radio-register ADDRESS
--mode classic|ble` on both nodes, compare the same FASP fingerprint and
approve both sides. Use `--transport radio` on `communicate`, `send`,
`task-status`, or `drain`. The full setup and Python/BlueZ requirements are
in [CONNECTIVITY.md](CONNECTIVITY.md).

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

In `--watch` mode, the drain command emits JSON when a delivery is sent,
retried, or dead-lettered; idle polls stay silent.

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

When stdout is piped, a `fasp` command emits one JSON document to stdout;
errors are JSON on stderr. Terminal output is readable unless `--json` is
supplied. Exit codes: `0` delivered/accepted or deliberately queued;
`2` invalid CLI/policy/configuration; `3` queued after transport
failure; `4` permanently rejected/dead-lettered.

## Outbound relay across NAT

Both nodes can connect *outbound* to one reachable HTTPS relay. The relay
stores bounded, short-lived ciphertext; it has no adapter, peer grant, or
decryption key. Each frame has an Ed25519 signature and uses an ephemeral
X25519 key plus ChaCha20-Poly1305 for end-to-end encryption. The original
FASP envelope remains signed and subject to the receiving node's policy.
At least one relay must have a public address; this does not perform NAT
hole punching.

On the relay host, provision separate tokens for the two known system IDs
and run the hub with a valid TLS certificate:

```bash
fasp relay-authorize 'fasp:system:ALICE_ID' --output /secure/alice.token --state-dir /var/lib/fasp-relay
fasp relay-authorize 'fasp:system:BOB_ID' --output /secure/bob.token --state-dir /var/lib/fasp-relay
fasp relay-serve --host 0.0.0.0 --port 8877 --tls-cert /secure/relay.crt \
  --tls-key /secure/relay.key --state-dir /var/lib/fasp-relay
```

Transfer each token privately to its matching node. Exchange the nodes'
signed ID-card files through an independent trusted channel; compare the
displayed system IDs and pairing code before approving **on both nodes**:

```bash
fasp id --json --state-dir ~/.fasp-a > alice-card.json
# Transfer alice-card.json to B and bob-card.json to A.
fasp import-card bob-card.json --as agent.researcher --state-dir ~/.fasp-a
fasp approve agent.researcher --code VERIFIED_CODE --scope coordinate. --state-dir ~/.fasp-a
fasp relay-config https://relay.example.com:8877 --token-file /secure/alice.token --state-dir ~/.fasp-a
```

Repeat the import, approval, and relay configuration on B. Run `fasp serve
--relay-worker` on B so inbound relay requests use its configured adapter and
policy. A standalone node can use `fasp relay-worker --watch --adapter
your_package:factory`. Then A can send and retry in the ordinary outbox:

```bash
fasp speak agent.researcher.summarize --message 'Summarize this' --transport relay --state-dir ~/.fasp-a
fasp drain --watch --transport relay --state-dir ~/.fasp-a
```

For multiple relay hops, provision a relay-role token on the *next* hub and
add a static route for the destination ID on each preceding hub:

```bash
fasp relay-authorize relay-west --role relay --output /secure/west.token --state-dir /var/lib/next-hub
fasp relay-route 'fasp:system:BOB_ID' https://next-hub.example.com:8877 \
  --account relay-west --token-file /secure/west.token --state-dir /var/lib/current-hub
```

Configure reverse routes for responses. A chain is capped at four hubs;
loops, expired frames, unauthorized accounts, and full mailboxes fail
closed. Relay storage is capped per destination and globally. The sender's
outbox retries a temporarily unavailable hop using the original signed
message. Delivery still expires with the signed envelope, so long outages
need a new authorized request. Use `--ca-cert` on send/drain, `--relay-ca-cert`
on `serve`, or `--ca-cert` on `relay-route` for a private relay CA.

## Reconcile an interrupted external task

After a crash or expired execution lease, a task is `unknown`: the node
cannot infer whether a robot, vendor API, or other external system acted.
It never reruns that effect automatically. Adapters that perform external
effects should implement a read-only `reconcile(idempotency_key, intent)`
hook that queries the external system by the same stable key. It may return
`{"status":"completed","output":...}`, `{"status":"failed","error":
{"code":"...","detail":"..."}}`, or any other result to leave the task
unknown. A vendor's "not found" answer must remain unknown unless that vendor
can prove the operation never ran. `fasp serve` checks unknown tasks periodically when this hook exists.
An operator can also request a local check:

```bash
fasp task-reconcile task-001 --adapter your_package:factory --state-dir ~/.fasp-b
```

The requesting peer sees `task.unknown` from `task-status` until verified.
Use a new task key only after the external system has been checked; a repeated
key returns the saved state without repeating the effect.

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

- Direct IP links require pre-existing IP/DNS/TLS reachability; Bluetooth links
  require paired Linux/BlueZ radios and the matching RFCOMM channel or LE_PSM.
  Relay transport requires at least one reachable HTTPS hub and static routes
  for multiple hubs. It does not create NAT hole punching or libp2p circuits.
- Requires two-sided operator approval, rather than hidden auto-enrollment.
- Certificates and CA roots remain operator responsibilities; TLS server
  verification is on by default, with no insecure-skip-verification switch.
- `--insecure-http` exists only for isolated *development* LANs. Remote
  HTTP is otherwise refused. Be aware even signed JSON is not encrypted.
- Calls use the sender's local identity and receiver's capability policy.
  Remote tool execution is never free-form; the receiver must install an
  allowed adapter first.
