# Federated Autonomous Systems Protocol (FASP) 1.0

**Status:** draft protocol and reference implementation; not an independently validated standard

**Audience:** autonomous AI agents, phones, laptops, embedded systems, robots,
industrial controllers, gateways, and their human operators.

The implemented JSON/Ed25519 contract is defined precisely in
[WIRE_PROFILE.md](WIRE_PROFILE.md) and its [portable schema](spec/fasp-wire-v1.schema.json).
Sections describing other transports, remote grants, or physical conformance
are design requirements, not claims that this harness implements them. The
opt-in encrypted HTTPS mailbox relay is described in the CLI guide. The signed ID card lists accepted request kinds; configured
capabilities and local policy determine which operations are available.

FASP is a secure coordination protocol for *independent autonomous systems*.
It answers a different question from a model-to-tool API: how can two systems
discover one another, establish scoped trust, exchange work, expose progress,
handle loss and cancellation, and safely interact with the physical world?

It does not require a particular model, operating system, transport, cloud,
vendor, or hardware class. A Raspberry Pi sensor node and a cloud agent can use
the same protocol, while a mobile phone may participate through a gateway.

## 1. Normative language and design goals

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative. They follow BCP 14 usage.

FASP is designed around seven non-negotiable goals:

1. **Explicit authority.** A message is not permission. Authority is scoped,
   time-limited, and independently verified.
2. **Safe autonomy.** A peer can act on clearly allowed, bounded work without
   silently escalating to network, account, destructive, or physical actions.
3. **Truthful state.** “Sent”, “delivered”, “processed”, “running”, and
   “complete” have distinct meanings.
4. **Resilience.** Duplicates, restarts, partitions, delayed cancellation, and
   offline devices are normal conditions, not exceptional ones.
5. **Physical-world caution.** A network message cannot bypass an emergency
   stop, local safety controller, or human approval requirement.
6. **Privacy by construction.** Systems exchange the minimum information and
   never turn incidental sensing into ambient surveillance.
7. **Transport independence.** The same message model works over HTTPS,
   WebSocket, MQTT, DDS, serial, or a store-and-forward relay.

## 2. System model

### 2.1 Roles

One implementation may hold more than one role.

| Role | Responsibility |
|---|---|
| **Principal** | A human, organization, policy engine, or safety controller that grants authority. |
| **System** | An autonomous endpoint with a stable cryptographic identity. |
| **Coordinator** | Plans or delegates work; it has no implicit authority over another system. |
| **Executor** | Decides whether it can safely carry out an accepted intent. |
| **Gateway** | Bridges constrained or local hardware to FASP without becoming that hardware’s identity. |
| **Witness** | Optional audit, approval, or safety authority. |
| **Relay** | Store-and-forward transport only; it is not trusted to authorize or interpret work. |

The reference deployment groups these roles into a node, a local control
function, and an optional store-and-forward relay. They may be co-located;
they are not required to be separate services. The harness includes an
opt-in HTTPS mailbox relay with end-to-end encrypted frames, paired identities,
bounded storage, and static routes across at most four hubs. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the deployment model and implementation
status.

### 2.2 Terms

- **Intent:** a requested outcome with explicit scope, limits, and success
  criteria. It is never raw shell text.
- **Capability:** a named operation an executor advertises, including its risk
  class and required authority.
- **Grant:** a signed, expiring permission to use one or more capabilities.
- **Lease:** a renewable right to keep a task active or a data stream open.
- **Receipt:** evidence of a transport or application state transition.
- **Artifact:** immutable output referenced by digest and metadata.
- **Safety envelope:** local limits that remain enforced even when a remote
  request is authenticated.

## 3. Trust and identity

### 3.1 No network-based trust

Being on the same Wi-Fi, VPN, subnet, mDNS domain, or USB cable MUST NOT grant
authority. Each system MUST authenticate the specific peer and MUST authorize
the requested capability for that peer and grant. This follows the resource-
centric, rather than network-location-centric, model of zero trust.

### 3.2 System identity

Each system MUST have a long-term asymmetric signing key. FASP 1.0 requires
support for **Ed25519** and permits a hardware-backed or attested key where the
platform provides one. A system identity is:

```text
fasp:system:<base64url-no-padding(SHA-256(raw-32-byte-public-key))>
```

The public key, key identifier, and identity are bound in a signed System
Profile. A hostname, IP address, device model, serial number, MAC address, or
phone number MUST NOT be used as an identity.

### 3.3 Pairing ceremony

New peers MUST be paired through an out-of-band confirmation such as a QR code,
short authentication string shown on both devices, physical cable, or an
organization-approved issuer. Pairing records MUST contain:

```json
{
  "peer_id": "fasp:system:…",
  "public_key": "base64url…",
  "trust_tier": "local-paired",
  "allowed_capability_prefixes": ["observe.", "coordinate."],
  "expires_at": "2026-09-30T12:00:00Z",
  "revocation_ref": "https://issuer.example/revocations/…"
}
```

Pairing MUST require a human or an existing trusted issuer for any capability
outside the `observe.` scope. A system MUST expose a local, recoverable
revocation path.
Capability prefixes MUST match complete dot-delimited segments: `fleet.mission.v1`
covers that name and descendants, but not `fleet.mission.v10`. `*` has no
wildcard meaning, and an empty scope grants nothing.

### 3.4 Channel and message protection

- Routable networks MUST use TLS 1.3 or a transport with equivalent
  authenticated encryption. LAN deployments SHOULD use mutual TLS.
- Every baseline envelope MUST use an Ed25519 signature over its RFC 8785
  canonical JSON content. HTTP Message Signatures are not a substitute in
  this implementation. A future CBOR/COSE profile requires its own specified
  encoding, negotiation and conformance vectors.
- Receivers MUST check signature, peer identity, audience, expiry, nonce,
  replay window, schema version, and local authority (including a grant when
  required) before executing payload content.
- Bearer secrets MAY bootstrap a local pairing flow but MUST NOT be the sole
  production identity or be placed in a task, transcript, screenshot, or
  source repository.

## 4. Discovery and System Profile

Discovery answers “who could do this?”; it never authorizes a request. A
profile may be fetched through HTTPS, a paired registry, QR payload, Bluetooth
handoff, mDNS hint, or a local file.

Every profile MUST be signed and contain:

```json
{
  "fasp": "fasp/1.0",
  "type": "id_card",
  "system_id": "fasp:system:7Q…",
  "display_name": "mobile-observer",
  "public_key": "base64url-raw-Ed25519-public-key",
  "endpoints": {"profile":"https://peer.example/profile","envelopes":"https://peer.example/fasp/v1/envelopes"},
  "capabilities": [{
    "id": "observe.environment.proximity.v1",
    "risk": "observe",
    "inputs_schema": "https://…/schemas/proximity-request.json",
    "outputs_schema": "https://…/schemas/proximity-result.json",
    "limits": {"max_duration_s": 5, "continuous": false},
    "required_grant": "observe.environment"
  }],
  "key_id": "2026-01",
  "issued_at": "2026-08-31T00:00:00Z",
  "expires_at": "2026-09-30T00:00:00Z"
}
```

Profiles MUST disclose limitations that affect correctness, such as “sensor API
unavailable inside container” or “camera access disabled”. They MUST NOT claim
a capability merely because hardware exists.

This example is illustrative, with abbreviated keys and identities. Fields
such as capability input/output schemas describe domain profiles; this
harness does not automatically fetch or execute remote schemas. Legacy
client-only cards may use null endpoint values and omit issued_at/key_id.
New harness cards include a signed `key_id` and `protocol_support` metadata.

## 5. Universal envelope

FASP messages are UTF-8 JSON for the baseline profile. Maximum inline payload
size is 64 KiB; larger data MUST be an artifact reference.

```json
{
  "fasp": "fasp/1.0",
  "kind": "intent.propose",
  "message_id": "018f…",
  "conversation_id": "018f…",
  "causation_id": "018f…",
  "from": "fasp:system:laptop…",
  "to": "fasp:system:phone…",
  "issued_at": "2026-08-31T12:00:00.000Z",
  "expires_at": "2026-08-31T12:02:00.000Z",
  "sequence": 42,
  "nonce": "base64url-96-bits",
  "grant": {"id": "grant-…", "digest": "sha-256:…"},
  "payload": {},
  "signature": {"alg": "Ed25519", "kid": "2026-01", "value": "base64url…"}
}
```

`message_id` MUST be globally unique. `conversation_id` groups a collaboration;
`causation_id` names the message that caused this one. The baseline generates
UUIDs and accepts bounded opaque ID strings for compatibility. `sequence`
is an optional domain field; only the stream profile enforces sequence
ordering. Task grants belong in `payload.grant`, not an assumed global grant.

The signature covers every field except `signature`. Accepted message IDs
are durably bound to the authenticated sender and exact signed record.
Duplicates return the prior outcome; conflicting reuse is rejected. The
signed nonce is not a separate uniqueness index in this implementation.
Expiration is checked before replay lookup. Durable journal retention and
disk quotas remain deployment responsibilities; there is no automatic
inbox/audit compactor. A queue-capacity refusal before work creation may be
retried with the same signed envelope within its expiry.

## 6. Message families

| Family | Purpose |
|---|---|
| `session.hello`, `session.ready`, `session.close` | Authenticated session establishment. |
| `profile.request`, `profile.publish` | Capability/profile exchange. |
| `intent.propose`, `intent.accept`, `intent.reject` | Request and bounded commitment. |
| `task.progress`, `task.result`, `task.fail`, `task.unknown` | Execution lifecycle, including an interrupted effect awaiting verification. |
| `task.cancel`, `task.cancelled`, `task.too_late` | Explicit cancellation race handling. |
| `receipt.delivered`, `receipt.processed` | Transport versus application acknowledgement. |
| `presence.update`, `typing.update`, `heartbeat` | Ephemeral liveness only. |
| `grant.request`, `grant.issue`, `grant.revoke` | Delegated authority. |
| `stream.open`, `stream.sample`, `stream.close` | Bounded telemetry. |
| `safety.halt`, `safety.status`, `incident.report` | Safety response and evidence. |

Unknown `kind` values MUST be rejected with `protocol.unsupported_kind`, not
silently ignored when a response channel exists.

The table includes proposed message families. Implemented signed request
kinds come from `FaspHarness.DISPATCH` and the ID card's
`protocol_support.accepted_kinds`. Responses generally use `type`, not
`kind`. Do not infer implementation of `session.*`, `presence.*`, remote
`grant.*` or `intent.commit` from this vocabulary table.

## 7. Work lifecycle and exactly-once effects

### 7.1 Intent schema

An intent is outcome-oriented and MUST include an idempotency key, deadline,
desired result, constraints, and risk declaration.

```json
{
  "intent_id": "inspect-storage-018f",
  "capability": "observe.storage.summary.v1",
  "idempotency_key": "work:phone:storage:2026-08-31T12:00Z",
  "objective": "Return total, used, and free storage rounded to 0.1 GiB.",
  "constraints": {"max_runtime_s": 15, "network": "none", "retain": "none"},
  "success_criteria": ["schema-valid result", "no file paths or identifiers"],
  "risk": "observe",
  "deadline": "2026-08-31T12:01:00Z"
}
```

The executor MUST persist an intent journal before action. The journal maps the
idempotency key to `accepted`, `running`, `completed`, `failed`, or `cancelled`
and to the final result digest. A duplicate intent returns the original result
or current state; it MUST NOT repeat an external or physical side effect.

### 7.2 State machine

```text
queued → running → {succeeded | failed | cancelled}
```

- A work item is recorded as `queued` before its effect can begin. `running`
  means the executor has started it; domain progress such as `preflight` or
  `assigned` is carried separately in `phase`.
- An executor MUST acknowledge an accepted intent within the requested or
  advertised acknowledgement window.
- Long work MUST publish progress with a lease renewal before the lease ends.
- `task.result`, `task.fail`, and `task.cancelled` are terminal and immutable.
- Queued work may be cancelled before execution starts. Running work becomes
  `cancelled` only after the executor confirms the stop. If work has completed
  or the executor cannot stop it, the caller receives `task.too_late` with the
  current outcome. A cancellation request alone does not change a running
  item into a cancelled one.
- A running intent whose lease expires after a restart becomes `unknown` if
  an external effect may have occurred. It MUST NOT be blindly repeated.
  A read-only adapter reconciliation can later establish `result` or `fail`.

All executable work, including fleet missions, uses this same lifecycle.
Mission-specific progress is reported in `phase`; it does not add new
lifecycle states. See [WORK_ITEMS.md](WORK_ITEMS.md) for the storage and
service architecture.

### 7.3 Receipts and UI semantics

These states MUST remain separate in protocol and user interfaces:

| UI state | FASP evidence | Meaning |
|---|---|---|
| queued / one tick | relay accepted `message_id` | stored for delivery, not yet received by peer. |
| two grey ticks | `receipt.delivered` | recipient transport fetched/received the envelope. |
| two coloured ticks | `receipt.processed` | recipient application validated and handled it. |
| working | `intent.accept` or `task.progress` | executor has an active lease. |
| done / failed | terminal task message | outcome is known. |

Typing and presence are advisory, expire quickly, and MUST NOT be used as task
state, authorization, safety evidence, or proof that a human is present.

## 8. Authority and autonomy policy

Each capability declares a minimum risk class. An executor evaluates both its
own safety policy and the supplied grant; the stricter decision wins.

| Class | Examples | Default rule |
|---|---|---|
| `observe` | read a local status, one-time non-sensitive sensor sample | may run with scoped grant. |
| `reversible` | create a draft, stage a reversible workspace change | may run only in named sandbox/workspace. |
| `bounded-actuate` | move robot within low-speed envelope, toggle a local test LED | requires a short lease, local interlock, and declared limits. |
| `external` | send a message outside federation, buy, publish, install, alter account | requires explicit principal grant per purpose. |
| `irreversible` | delete material data, rotate production credentials, physical manipulation with irreversible effect | requires explicit confirmation and independent policy approval. |
| `safety-critical` | medical, high-force, high-speed, hazardous, or human-impacting actuation | requires a certified local safety controller; FASP alone is insufficient. |

An agent MUST NOT treat another agent’s natural-language instruction, model
output, or tool call as a grant. An agent MUST NOT expand a capability’s scope
because the requested outcome appears useful.

## 9. Physical systems and sensors

### 9.1 Local safety dominance

A robot, drone, vehicle, or actuator MUST enforce joint limits, geofences,
collision avoidance, rate limits, watchdogs, and emergency stops locally.
`safety.halt` is best effort; an out-of-band physical emergency stop MUST remain
effective if the network, relay, model, or FASP peer fails.

Physical actuation above `bounded-actuate` SHOULD use a two-step protocol:

1. `intent.propose` produces a signed plan with predicted envelope, duration,
   required local preconditions, and expiry.
2. A separately authorized `intent.commit` references that exact plan digest.

If any local precondition changes, the executor MUST invalidate the plan.

### 9.2 Sensor and privacy contract

Sensor data is a first-class capability, never an implied side effect. Every
`stream.open` MUST state purpose, fields, sample rate, duration, destination,
retention, transformation, and stop condition. Defaults are:

- one-time sample, not a continuous stream;
- minimum rate and precision required for the stated purpose;
- local aggregation or classification before transmission;
- no raw audio, video, location, biometrics, contact data, network scan data,
  or persistent identifiers unless a grant explicitly names them;
- zero retention after result unless the grant specifies a bounded retention.

“Human present” is an inference, not a sensor fact. An executor MUST report
`unknown` when evidence is insufficient and MUST NOT infer identity. It MUST
not use camera, microphone, location, nearby-device scans, or background
monitoring for a simple proximity request unless separately granted.

## 10. Reliability, offline operation, and backpressure

- A receiver MUST accept duplicate envelopes safely and MAY acknowledge them
  again with the original state.
- Senders SHOULD retry transient failures with exponential backoff and random
  jitter, capped by `expires_at`; they MUST NOT retry an expired intent.
- A device that polls MUST persist its cursor only after it has durably handled
  the message and emitted a receipt/result. This prevents lost work on restart.
- A relay MUST support bounded retention and per-recipient acknowledgement
  (a cursor or explicit frame ack). It MUST NOT claim application processing
  merely because it stored a message. Expired frames are removed; the sender's
  durable outbox records retries and dead letters.
- Every stream and task MUST have a deadline or renewable lease. On expiry,
  a live executor MUST safe-stop and close the stream. After an interrupted
  external task, it MUST report an unknown outcome until verified.
- Receivers MUST apply size, rate, depth, CPU, memory, and storage limits before
  expensive parsing or model invocation.
- Clock uncertainty MUST be represented. If clocks differ beyond the configured
  skew, the systems MUST re-establish time or use short relative leases.

## 11. Artifacts, data provenance, and audit

Large results are immutable artifacts:

```json
{
  "artifact_id": "artifact-018f",
  "media_type": "application/json",
  "digest": "sha-256:…",
  "size_bytes": 1248,
  "created_by": "fasp:system:phone…",
  "retention_until": "2026-08-31T13:00:00Z",
  "access_grant": "grant-…"
}
```

Executors SHOULD maintain an append-only, tamper-evident local audit chain of
grant decisions, intent transitions, safety events, and artifact digests. Audit
records SHOULD exclude task payloads and sensitive raw data by default.

## 12. Failure and security handling

Baseline errors are `task.fail` or `protocol.error` records with machine-readable
codes, protected in transit by TLS. General response records are not yet
signed envelopes and cannot serve as independent third-party receipts.
Implementations MUST NOT place secrets, stack traces, raw private logs,
or identifiers in errors.

Required codes include:

```text
auth.invalid_signature        auth.grant_expired
auth.not_authorized           replay.detected
protocol.unsupported_version  protocol.unsupported_kind
schema.invalid                resource.exhausted
capability.unavailable        policy.requires_confirmation
lease.expired                 safety.precondition_failed
task.cancelled                task.too_late
privacy.data_minimization     transport.unreachable
```

On suspected key compromise, a system MUST stop accepting grants bound to that
key, issue `incident.report` to paired principals where possible, rotate keys,
and require re-pairing. A relay compromise MUST be assumed capable of delay,
replay, deletion, and traffic analysis; signatures and end-to-end encryption
are still required.

## 13. Minimal transport profiles

### HTTPS profile

`POST /fasp/v1/envelopes` accepts a signed envelope and returns its application
response (wrapped in `receipt.delivered` for intent/cancel/artifact requests).
The node ingress remains direct. The separate HTTPS relay hub carries opaque
encrypted frames and is configured through the CLI. A signed `inbox.pull` request
returns a mirror of that peer's own previously submitted messages; there is
no `GET /fasp/v1/inbox` route or general peer-to-peer mailbox in this build.
`POST /fasp/v1/receipts` reports delivered/processed states. `GET /profile`
returns the signed System Profile. HTTPS deployments SHOULD use HTTP/2+ and
TLS 1.3.

### Encrypted relay profile

The opt-in relay uses outbound HTTPS from each node to a reachable hub.
`POST /relay/v1/messages` accepts `{ "frame": ..., "path": [...] }`;
`GET /relay/v1/messages?limit=16` returns `{ "frames": [{ "id": ..., "frame": ... }] }`;
`POST /relay/v1/ack` accepts `{ "id": ... }` after durable handling.
Requests carry `Authorization: Bearer <token>` and
`X-FASP-Relay-Account: <account>`. A client token is bound to exactly one
system ID; relay-role tokens are provisioned for trusted next hubs.

A frame contains `version=1`, `from`, `to`, `message_id`, `kind` (`request`
or `response`), `expires_at`, `ephemeral_key`, `nonce`, `ciphertext`, and an
Ed25519 `signature` over the frame. The recipient X25519 public key is in
its pinned, signed ID card. Each frame uses a fresh ephemeral X25519 key;
HKDF-SHA256 derives a 32-byte ChaCha20-Poly1305 key with the UTF-8 string
`fasp-relay-v1|from|to|message_id|kind|expires_at` as both HKDF `info` and
AEAD associated data. `nonce` is 12 random bytes. Binary fields are
unpadded base64url. Request plaintext is `{ "envelope": <signed FASP
envelope> }`; response plaintext is `{ "receipt": <delivery receipt> }`.
The recipient verifies the outer signature and authenticated ciphertext,
then applies normal FASP signature, pairing, replay, and capability checks
to the inner envelope.

The hub stores at most 128 frames per destination and 4096 total, removes
expired frames, and never treats storage as execution. Static forwarding
uses a bounded `path` of at most four hubs to detect loops. Each hop
authenticates to the next over HTTPS; the ciphertext and its signature do
not change. The sender's outbox retries unavailable hops until the signed
envelope expires. Return routes must be configured independently.

### Pub/sub profile

MQTT or DDS topic names MUST include the recipient identity and conversation
scope. Broker ACLs are defense in depth only; end-to-end signatures, grants,
and replay handling remain mandatory. This mirrors the useful separation in
robotics middleware between authentication, access control, and cryptographic
protection.

### Constrained-device profile

A constrained node MAY use CBOR/COSE, a gateway, and store-and-forward serial
transport. The gateway MUST preserve the node’s end identity and MUST NOT
silently turn a gateway credential into authority to actuate the node.

## 14. Reference interaction

1. A laptop and phone pair by QR code and verify the same six-word fingerprint.
2. The phone publishes `observe.environment.proximity.v1` with a five-second
   maximum and `continuous: false`.
3. A human principal issues a five-minute grant for one one-time, aggregate
   proximity check.
4. The laptop sends an `intent.propose` with `idempotency_key`, no camera/mic/
   location fields, and `retain: none`.
5. The phone validates key, grant, capability, limits, and local API access.
   If its sensor API is unavailable in PRoot, it returns `capability.unavailable`
   rather than pretending hardware access exists.
6. If executable, the phone returns `intent.accept`, takes one bounded sample,
   sends an aggregate result (`likely_near`, `likely_not_near`, or `unknown`),
   emits `task.result`, deletes the raw sample, and closes the lease.
7. If cancellation arrives before sampling, it emits `task.cancelled`. If it
   arrives after the one-time result is committed, it emits `task.too_late` and
   identifies the already-completed result—without re-sampling.

## 15. Conformance requirements

An implementation may claim **FASP 1.0 Core** only if it passes all of these:

1. Rejects an unsigned, expired, wrong-audience, malformed, or replayed envelope.
2. Rejects a validly signed request lacking local capability authority or a
   matching grant when its risk or sharing policy requires one. Pairing scopes
   can authorize the baseline's low-risk observe/chat operations.
3. Demonstrates idempotent duplicate intent handling without repeating effect.
4. Distinguishes relay receipt, recipient delivery, application processing, and
   terminal completion in its API and UI.
5. Survives restart without skipping an accepted message or replaying a completed
   effect.
6. Expires a task/stream lease into a safe terminal state.
7. Implements cancellation-before-effect and cancellation-too-late cases.
8. Enforces message, queue, rate, and artifact limits.
9. Redacts secrets and restricted identifiers from telemetry, errors, and audit.
10. Demonstrates key revocation and re-pairing.

**FASP 1.0 Physical** additionally requires local safety-envelope enforcement,
independent emergency stop, and a test proving loss of the coordinator cannot
continue unsafe movement. **FASP 1.0 Sensor** additionally requires purpose,
minimization, duration, retention, and stop-condition checks.

## 16. Lessons incorporated from the laptop–phone deployment

| Observed failure mode | FASP control |
|---|---|
| Same Wi-Fi was treated as sufficient trust. | Paired cryptographic identities and scoped grants. |
| Polling did not wake an agent by itself. | Explicit subscription/polling requirement plus durable cursor. |
| Old messages triggered new replies. | Expiry, conversation state, idempotency journal, and terminal-state handling. |
| “Received” was ambiguous. | Separate relay, delivery, processing, progress, and completion receipts. |
| Cancellation raced with work. | Explicit `cancelled` versus `too_late` terminal outcomes. |
| A PRoot environment advertised hardware it could not read. | Capability requires verified runtime availability and limitation disclosure. |
| A shared secret appeared in operational instructions. | Pairing secrets are bootstrap-only; production messages are signed and grants are scoped. |
| Background autonomy risked arbitrary workspace changes. | Capability classes, safety policy, and confirmation gates. |
| Chat typing/read UI was confused with execution state. | Presence is advisory only; task state has signed lifecycle evidence. |
| Sensor request could drift into surveillance. | Purpose-bound, time-bound, minimized sensor contract with explicit prohibited fields. |

## 17. Research basis and interoperability posture

FASP intentionally does not copy another agent protocol’s object model. It
borrows only broadly proven design principles: explicit capability discovery and
terminal task states; zero-trust resource protection; canonical signed messages;
and robotics-style separation of authentication, authorization, cryptography,
and local safety.

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/)
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [ROS 2 DDS-Security integration](https://design.ros2.org/articles/ros2_dds_security.html)
- [A2A specification, consulted for ecosystem interoperability only](https://google-a2a.github.io/A2A/specification/)

## 18. Implementation order

Build in this order:

1. Ed25519 identity, pairing, profile validation, canonical signing, and replay
   cache.
2. Envelope parser with size limits and the shared work-item lifecycle
   ([WORK_ITEMS.md](WORK_ITEMS.md)).
3. Scoped grants, risk classes, receipts, durable inbox cursor, retries, and
   cancellation semantics.
4. Artifact references, audit chain, revocation, and operator UI state mapping.
5. Device gateways, sensor contracts, local safety controller integration, and
   physical conformance tests.

Do not deploy physical actuation or continuous sensing before steps 1–4 are
independently tested.

## 19. Reference harness profiles

The companion `fasp_harness` implementation provides a portable HTTP baseline,
signed ID-card discovery, explicit pairing, durable task handling, and bounded
stream packets. Its cross-platform deployment constraints are specified in
[FASP Runtime Profiles](FASP_RUNTIME_PROFILES.md); packet, realtime-transport,
and live-data requirements are specified in [FASP Messaging and Live Streaming
Profile](FASP_MESSAGING_STREAMING.md). These profiles are normative companions
for the reference harness and do not weaken the local-safety requirements above.
