# FASP JSON/Ed25519 wire profile v1

Status: implemented reference profile, `fasp-json-ed25519-v1`. This document
defines the interoperable baseline of this repository. The broader protocol
proposal does not imply implementation of every proposed feature or bearer.

## Scope and structure

The same authenticated request enters the harness through HTTP, WebSocket,
the optional radio bearer, or an in-process call. The layers have separate
responsibilities:

| Module | Responsibility |
|---|---|
| `transport/canonical.py` | Bounded UTF-8 JSON parsing, duplicate-key rejection, bearer-independent dispatch and response translation |
| `protocol/contracts.py` | Types, structural limits, version, lifetime and required-feature rules |
| `protocol/schemas.py` | Portable JSON Schema and shared OpenAPI structural definitions |
| `crypto/` | RFC 8785 serialization, canonical base64url, Ed25519, durable identity |
| `core.py` | Authentication, pairing, local authorization, domain dispatch |
| `storage/work_items_repo.py` | Transactional admission, idempotency and work state |
| Local adapter | Domain semantics, device permissions, effect idempotency, cancellation |

The public schema is available at `GET /schemas/fasp-wire-v1.json` and in
[`spec/fasp-wire-v1.schema.json`](spec/fasp-wire-v1.schema.json). OpenAPI uses
the same definitions at `GET /openapi.json`. Regenerate the committed schema:

```sh
python -m fasp_harness.protocol.schemas > spec/fasp-wire-v1.schema.json
```

Schema validation alone does not establish a valid signature, matching
identity, active pairing, unexpired permission, or executable capability.

## Identity and signatures

The identity is `fasp:system:` followed by unpadded base64url of SHA-256 over
the **raw 32-byte Ed25519 public key**. The suffix has 43 characters. Do not
hash a PEM string, DER wrapper, hostname or base64 text. The old proposal's
base32 spelling was inconsistent with both implemented clients and is corrected.

The signature block contains `alg: Ed25519`, `kid` and `value`. Canonicalize
the entire record after removing only its top-level `signature` property.
Do not remove unknown extension fields. Sign those bytes, then encode the
64-byte signature as unpadded base64url. Reject padding, whitespace,
nonalphabet characters and nonzero unused pad bits.

New harness ID cards include a **signed** `key_id` that must match
`signature.kid`. Received envelopes must select the paired card's key ID.
A discovery refresh cannot change a paired key selector or remove its
signed binding. Key rotation requires an explicit enrollment design; there
is no transparent rotation or hardware attestation in this release.

Self-signature proves key possession, not who owns the device. Pairing still
requires an out-of-band identity/fingerprint check. TLS/mTLS protects network
traffic; signatures do not encrypt payloads.

## JSON and time rules

| Property | Baseline rule |
|---|---|
| Protocol discriminator | Exactly `fasp/1.0` |
| Record | JSON object; HTTP/radio/WebSocket payloads must be UTF-8 |
| Record size | At most 65,536 raw ingress bytes and 65,536 canonical bytes |
| Nesting | Root depth 0, maximum depth 32; object keys count as child nodes |
| Structure | At most 8,192 nodes, including object keys |
| Strings | Unicode scalar values; no lone surrogates; preserve normalization |
| Numbers | Finite IEEE 754 values; integral values must be within ±(2^53−1), regardless of exponent notation |
| Large counters/precise decimals | Encode as strings in a domain-specific schema |
| Duplicate object keys | Reject, including inside nested values |
| Message/nonce/conversation IDs | Nonempty opaque strings, at most 128 characters; generated message IDs are UUIDs |
| Envelope payload | JSON object |
| Timestamps | RFC 3339 with `T`, seconds and explicit `Z` or numeric offset; up to six fractional digits |
| Lifetime | `expires_at` strictly after `issued_at`; expired requests rejected before replay lookup |
| Clock tolerance | At most 60 seconds of future issuance |

Envelope `issued_at` is required. Legacy ID cards can omit it; cards that
provide it receive the same ordering/future checks. New harness cards always
include it. JSON Schema expresses structural rules; Unicode, byte size,
depth, canonical encodings and cross-field rules are runtime checks.

The TypeScript FASP bridge uses `bridge_core/fasp_canonical.mjs`, with
ECMAScript number serialization and UTF-16 key ordering. Its separate Agent
ID Card encoder is intentionally unaffected. Python–Node tests verify the
actual FASP encoder with fractions, exponent notation, control characters,
Tamil text, supplementary Unicode, key ordering, identities and signatures.

## Versioning and extensions

Signed harness cards advertise `protocol_support`: profile name, versions,
signature/canonicalization, accepted request kinds, supported features and
structural limits. These are implementation facts, not grants. A recognized
request kind can still fail with `capability.unavailable` because the local
fleet, sensor or safety adapter is not configured.

Unknown protocol versions fail with `protocol.unsupported_version`; there
is no silent downgrade. Unknown optional fields are preserved in the signed
record. Optional metadata must not change authorization or execution rules.

An extension that changes required behavior must name that behavior in the
signed `required_features` array. Unknown required names fail with
`protocol.unsupported_feature`. The implemented feature names are
`fasp.required-features.v1`, indicating enforcement of this mechanism, and
`fasp.volatile.v1` for explicitly memory-only observations. A
future feature must have a specification, validator, handlers and tests
before being added to the advertised feature set.

**Compatibility:** old implementations may ignore required_features. A sender
must first verify a peer card advertising this mechanism before relying on
it. Peers without protocol_support can use the legacy baseline only; they
must not receive requests relying on mandatory extensions. This is explicit
feature discovery, not a completed general session-negotiation protocol.

The endpoint map permits null values for client-only participants. Signed
endpoint URLs are advertisements, not permission to connect to arbitrary
addresses. Maintain URL/source restrictions and verify the identity reached.

### Explicit volatile observations

The default remains durable. The optional `fasp.volatile.v1` feature permits
only heartbeat and memory-stream packet envelopes to request `delivery:
volatile`. Such requests must name the receiver's signed profile
`instance_id` in `receiver_instance` and use a short expiry (generated 1 s,
maximum total/remaining 5 s). They still require signatures and current
pairing/domain authority. A bounded in-memory replay window replaces the
SQLite inbox for these eligible observations; old-instance replay is refused.
Memory stream contracts require local policy opt-in, latest delivery and
zero retention. Stream controls stay durable. See [PERFORMANCE.md](PERFORMANCE.md)
for exact limits, loss/restart semantics, client examples and measurements.

## Admission, replay and errors

Verify structure, lifetime, audience, paired key, signature and peer rate
before journaling or executing work. Check the request kind and relevant
payload types, then apply the domain's authorization and semantic checks.

An accepted message ID is bound to its authenticated sender and signed
record. Exact duplicates return the stored result; conflicting reuse fails.
Task idempotency separately binds the work key to the original peer/payload.
Global work keys currently reject collisions across peers rather than
creating independent per-peer namespaces. Select globally unique keys.

Capacity checks and work insertion occur inside one SQLite write
transaction, including across independent database connections. A duplicate
work result remains readable at capacity. An admission refusal before work
creation releases its unprocessed inbox reservation so the **same signed
message** may succeed after capacity recovers. Other recorded outcomes
remain immutable. Retrying never extends signed expiry.

HTTP errors use 400 for malformed/version/feature errors, 401 for auth
failures, 404 for unsupported kinds/unavailable capabilities, 413 for size
limits, 429 for exhausted admission/rate capacity and 503 for an outcome
not yet available. Replaying a cached error preserves its HTTP error status
and does not turn it into a successful delivery receipt.

Responses are generally ordinary JSON records protected by TLS, not signed
request envelopes. Stream pushes have signatures; general task push/result
records do not yet provide independently verifiable response provenance.
Do not put a terminating untrusted relay between peers and assume response
integrity or end-to-end confidentiality.

## Resource and interoperability limits

The limiter tracks at most 4,096 identities/addresses. At capacity it only
evicts an idle bucket that could have fully refilled; otherwise new keys
are denied. Identity churn cannot evict an exhausted peer to reset its quota.
Pending pairing records are capped at 256; a new unknown hello removes
pending entries last seen over 15 minutes ago. Confirmed peer records are
preserved. The task default is 256 active intents and eight adapter threads.

These bounds do not imply bounded total disk use. Inbox, task, receipt and
audit history need monitored volume quotas and an agreed retention/backup
strategy. There is no general durable journal compactor. Python thread
timeouts do not terminate device effects; use the supported process adapter
where appropriate and independent local device safety.

Universal participation requires an implementation of this wire profile or
a reviewed gateway. It does not automatically add arbitrary USB, BLE, MQTT,
DDS, Modbus, Android or proprietary-device support. Domain adapters must
agree on units, frames, timestamps, schemas, privacy and effect semantics.
The protocol itself needs no language model.
