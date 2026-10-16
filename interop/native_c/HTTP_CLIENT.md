# Native C transport client (optional)

This companion to the existing native C signer makes **real HTTP(S) requests** to a FASP 1.0 Python node without Python, Node.js, or WASM on the client. It is intentionally a **separate executable**: the `fasp_wire.c` signing library stays free of sockets, `libcurl`, and JSON dependencies.

Requires C11, `libcurl`, `json-c`, OpenSSL and a suitable system TLS trust store. Build on a Linux/POSIX host:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
  interop/native_c/fasp_http.c -o fasp-c-http \
  $(pkg-config --cflags --libs libcurl json-c openssl)

cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
  interop/native_c/fasp_peer.c interop/native_c/fasp_wire.c \
  -lcrypto -o fasp-c-peer
```

A receiving FASP node must first explicitly **pair and approve** the C client's signed ID card through the normal operator workflow. No command in this example self-enrolls or grants authority.

For isolated loopback development only:

```sh
./fasp-c-http profile http://127.0.0.1:8766 'fasp:system:<receiver-id>'
./fasp-c-peer heartbeat ./native.key 'fasp:system:<receiver-id>' | \
  ./fasp-c-http send http://127.0.0.1:8766 'fasp:system:<receiver-id>'
```

`profile` prints the receiver's advertised `protocol_support` information; it is **not an authorization grant**. `send` first obtains the profile and checks that its declared system ID agrees with the expected ID and its public-key hash, then submits the signed envelope and reports the JSON response or an error. Responses are transport-authenticated, **not independently FASP-signed**.

For remote servers, **HTTPS and a pre-verified TLS SPKI pin are mandatory**. Configure system CA trust or a private CA (`--ca`) and obtain the actual certificate's SPKI pin from a **trusted operator channel**, not by blindly accepting whatever a first connection returns:

```sh
./fasp-c-http profile https://robot.example:8766 'fasp:system:<receiver-id>' \
  --pin 'sha256//<44-character-base64-SPKI-hash>' --ca ./trusted-ca.pem
```

**Security boundary:** The C transport checks the ID/public-key relationship and validates the TLS server certificate and pinned TLS key, but it **does not perform RFC 8785 canonicalization and Ed25519 verification of the remote FASP identity card**. A copied FASP public key plus a rogue TLS server is not independently detected unless the endpoint's SPKI was correctly pinned. This is why an independently verified TLS pin is mandatory remotely. Use the full Python or Node identity-card verifier where end-to-end signed-card verification is required. Neither TLS nor the system ID check grants remote permissions.

Other bounds: HTTP is allowed only for `localhost`/`127.0.0.1`/`::1`, redirects are not followed, requests have timeouts, profiles and replies are size-capped, non-2xx responses fail, and the submitted envelope must target the expected receiver. This tool is a host-level gateway transport, **not** a microcontroller runtime, complete C FASP SDK, or safety controller. Large streams, retries, mission execution, and native key management are intentionally outside this command.

Run the live interoperability tests with `python -m unittest tests.test_native_http_peer -v`; CI builds the C client and runs the tests against an actual locally served Python FASP node, including TLS pinning and rejection cases.