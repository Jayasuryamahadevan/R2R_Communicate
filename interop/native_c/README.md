# Minimal C11 FASP peer (proof of native wire interoperability)

This is a deliberately **small** independent C signing library and CLI for the **existing** FASP 1.0 JSON/Ed25519 wire profile. It does not require Python, Node.js, WASM, an application JSON library, or a FASP C server. It requires POSIX/C11 and **OpenSSL libcrypto** with Ed25519 support. It is not intended for microcontrollers without POSIX/OpenSSL or for deployment as a full robotic runtime.

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic interop/native_c/fasp_peer.c interop/native_c/fasp_wire.c -o fasp-c-peer -lcrypto
./fasp-c-peer init ./native.key
./fasp-c-peer id ./native.key
./fasp-c-peer card ./native.key
./fasp-c-peer heartbeat ./native.key 'fasp:system:<ACTUAL_RECEIVER_ID>'
```

The command-line interface remains compatible with the original lowercase-hex seed file format and retains the `init`, `id`, `card`, and `heartbeat` commands. The reusable `fasp_wire.h` + `fasp_wire.c` signing API can be linked into C or C++ projects without the POSIX command-line wrapper. The API takes caller-owned key bytes, timestamps and output buffers; it performs no network or file I/O. All secret-key, clock, randomness, storage and transport concerns remain the host application's responsibility.\n\nThe `card` command emits a signed client-only identity card with null network endpoints. This identity can be introduced to a FASP Python node through its existing explicit out-of-band pairing process. The `heartbeat` command emits a signed request that a receiver can verify and journal, **not** a network request; the operator or application must deliver it over an authorized supported transport. It does not enroll the peer, grant permissions, or execute robot actions.

For auditability this example signs *only* two fixed ASCII-only message templates: a client-only identity card and an empty-payload heartbeat. Those templates are already in RFC 8785 key order. **Do not add arbitrary JSON payloads by concatenating strings:** doing so would bypass JCS number formatting, Unicode ordering, escaping and structural validation. A full C SDK needs a verified RFC 8785 implementation and the complete authorization, replay, and task-lifecycle requirements in [../../WIRE_PROFILE.md](../../WIRE_PROFILE.md). Use a gateway for closed/RTOS devices that cannot execute this implementation.

The 32-byte Ed25519 seed is persisted as lowercase hex in an exclusive, owner-only file. **Never commit, log, or share that file.** The program refuses to overwrite it and refuses to read group/world-readable key files. It does not provide private-key hardware protection. For production use, an appropriate key-management implementation is required.

Conformance: `python -m unittest tests.test_native_c_peer -v` compiles the CLI and C library and verifies its signed card and heartbeat against the **real Python receiver**; it also asks the independent Node verifier to validate the C-signed card. These tests prove a concrete native wire interoperability boundary—not universal hardware support or production device safety.

A public, deterministic [identity test vector](../vectors/identity-v1.json) is verified by the C and Node suites against the shared SHA-256/Ed25519 identity contract. Never use the published seed in production.

## Standalone C/C++ linking check

The independent `api_smoke.cpp` client includes `fasp_wire.h`, links a separately compiled C object, checks fixed-schema card and heartbeat signing, refuses an invalid destination and insufficient output buffer, and verifies secret-memory clearing:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -c interop/native_c/fasp_wire.c -o /tmp/fasp_wire.o
c++ -std=c++17 -O2 -Wall -Wextra -Werror -pedantic interop/native_c/api_smoke.cpp /tmp/fasp_wire.o -lcrypto -o /tmp/fasp-api-smoke
/tmp/fasp-api-smoke
```

This is a **small native wire signer**, not a complete C/C++ SDK or safety-certified controller. There is no networking, pairing approval, native JSON decoder, arbitrary intent execution, or background agent in the C library.
