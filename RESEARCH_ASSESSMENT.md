# Feasibility, production gaps and research assessment

Assessment date: 2026-10-15. Reviewed starting point:
`033d177b5f41f2ac64333e95dd0a9507b03d38a1`. The 615 existing tests passed
before changes. Passing them did not reveal all ingress or concurrency flaws.

## Verdict

**Feasible:** a common coordination layer for devices, services and agents
with independent identities, local authority, typed adapters and durable work
state. A Python reference node with CLI/MCP access already demonstrates
important parts of this design. Models can plan work above this layer;
authentication, authorization, transport and journals do not require AI.

**Not established:** arbitrary-device plug-and-play, high-assurance production
readiness, research novelty, hard real-time behavior, or safety certification.
This change strengthens a reference implementation. A software change cannot
establish hardware safety or independent scientific evidence.

The useful universal boundary is a stable **identity/authority/work contract**
over defined transports. Device drivers and domain meanings still require
adapters. A camera/radar workflow additionally needs calibrated coordinate
frames, synchronized time with uncertainty, a target-ID contract, an agreed
capture capability, privacy permissions, failure handling and a local motion
controller. Discovery alone cannot provide those semantics.

## Confirmed defects addressed

| Finding | Repair | Evidence |
|---|---|---|
| Nonobject signatures, wrong DB-key types and naive timestamps raised unhandled exceptions | Transport-independent structural, type and lifetime validation | `tests/test_wire_contracts.py` |
| Escaped lone surrogates and deep structures reached later processing | Unicode scalar, nesting and node-count limits at parser and direct API | Same tests, including WebSocket ingress |
| Permissive base64 decoder accepted alternate spellings; key selectors were not checked | Canonical base64url, paired key-ID check, signed card key_id and downgrade protection | Same tests |
| Queue count and task insertion could race | One BEGIN IMMEDIATE admission/insert transaction | `tests/test_admission_boundaries.py`: 16 simultaneous requests, two DB connections, capacity 3 |
| Capacity check ran before duplicate work lookup | Resolve existing identity before applying admission cap | Completed result available at saturation and after restart |
| Queue refusal was cached forever for the retried message | Explicit pre-effect admission error releases only its unprocessed reservation | Same signed request succeeds after capacity frees; later duplicate returns prior result |
| Replayed cached errors could become HTTP 200 receipts | Shared bearer response translation rethrows stored protocol errors | HTTP first/replayed rejection parity test |
| IP/peer bucket map and pending pairing records grew without a count bound | Capped limiter with quota-preserving eviction; capped pending records and stale-pending cleanup | Churn and pending-expiry tests |
| A corrupt stored system ID could be advertised with a different private key | Verify the derived identity when loading local key state | Local identity corruption test |
| Spec used base32, a different version discriminator and a nonexistent inbox route | Align implemented wire profile, shared schemas, supported-kind discovery and explicit extension requirements | Portable schema and OpenAPI parity tests |
| TypeScript FASP used an integer-only canonicalizer for a protocol carrying sensor fractions | Dedicated FASP JCS encoder; independent Python–Node signatures and bytes | `tests/test_wire_interop.py` |

## Architecture direction

Preserve one shared protocol core and small bearer adapters. Move new
validation into protocol contracts, not extra HTTP/CLI/MCP-specific rules.
Storage owns atomic transitions; local adapters own actual device effects.
Keep fleet/spatial/safety extensions optional and avoid requiring them for a
phone or cloud agent that only needs basic work exchange.

Before adding more transports, define stable domain capability profiles with
input/output schemas, units, error semantics, version compatibility, privacy
and cancellation guarantees. A schema URL alone is not a trusted validator;
pin reviewed schemas locally. Support a second independently written peer
before claiming broad implementation interoperability.

The current monolithic dispatch service can be split gradually by domain,
retaining one authentication/replay entry point. Moving every handler into
a new framework would add regression risk without proving a better protocol.

## Remaining production release gates

| Priority | Gap | Acceptance evidence |
|---|---|---|
| P0 for exposed deployment | Independent security review of all request families, optional TypeScript clients, enrollment and device adapters | Reproducible findings closed; external penetration test; dependency and release-artifact review |
| P0 for sustained operation | Growing durable inbox/work/audit/receipt history; expensive full-chain readiness checks and unpaginated inbox reads | Retention design that preserves replay/idempotency and audit anchors, quotas, pagination and disk-full recovery tests at realistic history sizes |
| P0 for physical use | Safe response to process stalls, stale state and network loss | Hardware hazard analysis, independent E-stop, measured stop behavior and device-side idempotency; simulation cannot replace these |
| P1 | General responses lack envelope signatures and end-to-end encryption | Versioned response envelopes with request/audience binding; replay tests; reviewed encryption design if relays are required |
| P1 | Generic capability payload/output schemas and cross-vendor semantics are adapter-specific | Two independent implementations using the same reviewed domain profile, including units/frame/time/error tests |
| P1 | Key rotation, organization enrollment, attestation and cross-NAT connectivity are incomplete | Rotation/revocation exercises and explicitly chosen gateway/issuer/network topology |
| P1 | Thread timeouts and restart recovery do not prove external effects stopped | Killable isolated adapters or device acknowledgement/reconciliation; power-cut and uncertain-effect tests |
| P1 | Optional client and bearer paths need their own end-to-end validation | Cross-platform client/server tests, reconnect/revocation tests, real radio and certificate rotation exercises |
| P2 | Single-node SQLite architecture, not an active-active replicated control plane | Separate consensus/storage design if genuinely required; never use a shared SQLite volume as multi-node consensus |

These are release gates, not assertions that a breach or safety incident has
occurred. Deploy a constrained supervised pilot only after its applicable
gates are satisfied; measure the environment you actually intend to use.

## Research contribution and comparison

Signing, discovery, pub/sub, permissions and task states individually do not
establish novelty. ROS 2 already separates authentication, access control and
cryptographic protection through DDS Security. Zenoh already provides
pub/sub, query and storage abstractions. FASP needs a measurable contribution
above those primitives, rather than a claim to replace all of them.

| Candidate contribution | Falsifiable evaluation |
|---|---|
| Authority preservation across heterogeneous device gateways | Show that each bridge preserves end identity, capability scope, revocation and effect ownership under malicious and faulty peers |
| Recovery of cooperative work on intermittent edge networks | Compare completion rate, duplicate effects, uncertain outcomes and recovery time under controlled partitions and process crashes |
| Explicit temporal/spatial uncertainty improves coordination | Compare conflicts, safe refusals, throughput and stop behavior against an otherwise equivalent coordinator without uncertainty handling |
| Lower integration effort for a defined class of devices | Have independent developers implement the same workflow through FASP and a specified alternative; measure code changes, setup time and errors |

Choose one primary claim. A paper requires a prior-art review, an exact model
and threat assumptions, repeatable methodology, independent baselines,
multiple runs with uncertainty, negative cases and reproducible data. The
present review is not a novelty search, a proof of security, or evidence of
publication acceptance.

## Reproducible evaluation plan

1. Freeze the commit, wire profile, local policy and adapter versions. Record
   CPU, memory, storage, operating system, crypto library and certificates.
2. Use at least laptop/VM, Raspberry Pi and Android/gateway participants.
   Separate genuine devices from simulated processes in every result.
3. Compare equivalent workflows: ordinary HTTPS JSON; signed HTTPS JSON;
   full FASP; and a ROS 2/DDS or Zenoh integration where that workload fits.
   Keep hardware, payloads, policy, encryption and delivery guarantees explicit.
4. Vary peer counts (2/10/50), record sizes (256 B/4 KiB/16 KiB), rates,
   network delays, reordering, disconnect duration and clock offsets.
   Report refusal/backpressure as a result, not as missing samples.
5. Inject crashes before journal insert, after insert, before external effect,
   after effect and before completion commit. Distinguish no effect,
   successful effect, duplicate effect and uncertain outcome. Do not infer
   exactly-once physical effects from a message-dedup test.
6. Measure p50/p95/p99 latency, throughput, CPU/RSS, database growth, bandwidth,
   revocation delay, recovery time, completion rate and duplicate/uncertain
   effects. Repeat runs; report confidence intervals and all failures.
7. Publish scripts, deterministic fixtures, raw data, configuration and analysis.
   Use independent replicas of the experiment rather than repeated requests
   inside one run as if they were independent experiments.

Start with the local microbenchmark:

```sh
uv sync --locked --extra test --extra dev
uv run --locked --extra test --extra dev python -m unittest discover -s tests
uv run --locked python -m benchmarks.protocol --iterations 300 --payload-bytes 256 > protocol-benchmark.json
```

It records its environment, a hash of the Python source, encoded size and
per-operation latency samples summarized by percentiles. It measures local
decode/canonicalization/sign/verify and SQLite-backed heartbeat handling,
including replay and invalid-signature rejection. It excludes sockets,
TLS, models, devices, concurrency, energy, endurance and external effects.
The SQLite mode is WAL with synchronous=NORMAL; this is not power-loss
durability evidence. At least hundreds of samples across several independent
runs are needed before interpreting tail latency as an operational target.

One development-container run (300 requests, 855-byte records, Python
3.12.14, x86-64 Linux, cryptography 50.0.1, SQLite 3.53.1) measured local fresh
heartbeat acceptance at p50 **0.283 ms**, p95 **0.473 ms**, p99 **0.560 ms**.
These are illustrative measurements on this host, not robot/network SLOs,
capacity claims or a comparison proving superiority.

## Primary sources

- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 3339: Date and Time on the Internet](https://www.rfc-editor.org/rfc/rfc3339.html)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [ROS 2 DDS-Security integration](https://design.ros2.org/articles/ros2_dds_security.html)
- [ROS 2 QoS design](https://design.ros2.org/articles/qos.html)
- [Zenoh abstractions](https://zenoh.io/docs/manual/abstractions/)
- [SQLite write transactions](https://www.sqlite.org/lang_transaction.html)
- [SQLite WAL limitations](https://www.sqlite.org/wal.html)
