# FASP interoperability: one wire protocol, many runtimes

**Status:** FASP 1.0 JSON/Ed25519 is implemented. The repository includes a dependency-free Node.js client, Python↔Node interoperability tests, and vendor/gateway adapters. This is **not** a claim of arbitrary-device plug-and-play or production safety certification.

## Keep the wire contract, not a Python dependency

The common contract is [`fasp-json-ed25519-v1`](WIRE_PROFILE.md). Every interoperable client must implement the *protocol*, not the Python class hierarchy:

- `fasp:system:` + unpadded Base64URL of SHA-256 over the raw 32-byte Ed25519 public key.
- RFC 8785 canonical UTF-8 JSON, Ed25519 signatures covering every envelope field except the top-level `signature`.
- Explicit receiver, unique message identity, nonce, expiry, required-feature handling, and bounded structure.
- Peer pairing, locally enforced capability scopes, revocation, idempotency, and truthful task outcomes.
- Defined capabilities, units, coordinate frames, cancellation semantics, and reconciliation for each *domain* adapter.

The [public JSON Schema](spec/fasp-wire-v1.schema.json) is useful but insufficient on its own: schema validation does not establish signature validity, pairing, or authorization.

| Environment | Recommended deployment |
|---|---|
| Python host | Existing `fasp_harness` reference node |
| Node.js 22+ without Python | `interop/fasp-peer.mjs`, using Node built-ins only |
| C, C++, Rust, or another host language | Implement the published profile and pass independent conformance tests |
| Closed vendor controller / industrial PLC | Run a FASP gateway on a separate authorized host; retain its vendor API |
| MCU / RTOS | Native bounded client where feasible, otherwise use its existing protocol through a gateway |

Hardware agnosticism is a property of the **protocol**, not a promise that one executable runs everywhere. Devices without a usable programming or communication interface need vendor cooperation.

## A small independent Node client

`interop/fasp-peer.mjs` is a client-only implementation, not a second FASP server. Its two files (`fasp-peer.mjs` and `fasp-canonical.mjs`) require no Python, package manager, WASM engine, or third-party Node dependency. The TypeScript bridge retains its self-contained canonicalizer for isolated deployments. The portable client carries the same small encoder as a second file; CI compares both files byte for byte to prevent implementation drift.

```sh
node interop/fasp-peer.mjs init --state ./peer-identity.json
node interop/fasp-peer.mjs card --state ./peer-identity.json
node interop/fasp-peer.mjs pair --state ./peer-identity.json --url https://robot.example.com:8766
```

The pairing command verifies the returned signed card and `hello.ready` response. It prints a fingerprint and leaves the relationship **pending**. Compare that fingerprint through a trusted independent channel and use the receiving node's local operator CLI to approve only the necessary scopes. It never auto-approves a remote identity.

Do not publish `peer-identity.json`: it contains the Ed25519 private-key seed. The client refuses HTTP except on loopback.

Obtain the receiver's *operator-verified* signed ID card and save it as `robot-card.json`. This must be an intentionally pinned peer identity, not an unverified trust-on-first-use operation.

```sh
node interop/fasp-peer.mjs verify-card --file robot-card.json
node interop/fasp-peer.mjs send --state ./peer-identity.json --url https://robot.example.com:8766 --peer-card robot-card.json --kind heartbeat --payload '{}'
```

`send` verifies that the live `/profile` still represents the pinned peer before sending the signed request. The general HTTP reply is **not independently signed** by the current Python reference implementation; do not treat it as detached end-to-end evidence. Use TLS to protect the direct connection. Work accepted by a remote device still needs authoritative status and reconciliation.

`envelope` emits a signed request without a network connection:

```sh
node interop/fasp-peer.mjs envelope --state ./peer-identity.json --to 'fasp:system:<real-ID>' --kind heartbeat --payload '{}'
```

## Legacy devices and gateways

An unsigned legacy device cannot be made cryptographically self-authenticating by assigning it a FASP-looking name. An authorized gateway must validate the device's native input, sign a **new** FASP message as the gateway, and preserve the original device's provenance. The gateway has responsibility for local vendor credentials, rate limits, permitted operations, and effect reconciliation. Only high-level robot goals cross this boundary; safety PLCs, motor loops, and emergency stops remain independently controlled.

Existing ROS 1/2 observers only expose read-only graph counts. The VDA 5050 and REST fleet adapters are reference integrations, not universal implementations for every manufacturer or software version.

## Reproduce conformance evidence

```sh
node --test interop/fasp-peer.test.mjs
python -m unittest tests.test_portable_peer -v
```

The cross-runtime test constructs a real Python receiver, verifies a Node-created ID card, accepts and deduplicates a Node-signed request, rejects tampering, and uses Node to verify a Python-signed card. CI exercises these tests. This demonstrates a specific, reproducible Python↔Node wire boundary, **not** fully certified physical-world interoperability or a complete native C/C++/Rust SDK.

Avoid introducing an incompatible language or new envelope for hardware portability. If constrained hardware warrants CBOR/COSE or another binary representation, define a separately versioned, explicitly signed profile and prove it with independent vectors. A transformed payload does not retain the original JSON signature unless the original signed bytes are preserved.

WASM, Zenoh, MQTT, and DDS may be useful *optional* adapters or carriers. None is required by the base FASP wire contract.
