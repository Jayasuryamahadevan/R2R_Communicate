# FASP production architecture and acceptance gates

**Current status: production-oriented reference software, not independently
penetration-tested or safety-certified.** CI passing, even with hundreds of
tests, does not establish field reliability or compliance.

## System architecture and trust boundaries

    Enterprise or peer service (allowlisted, authenticated)
                         |
        Site firewall / network ACL / restricted TLS ingress
                         |
     +---------------- FASP node -----------------+
     | Dedicated OS identity and private state   |
     | TLS 1.3 + mTLS and signed Ed25519 envelopes|
     | Explicit pairing, scoped grants, revocation|
     | Persistent inbox, work state, audit records|
     | Per-peer artifact access, hash verification|
     | Local encrypted volume, SQLite WAL         |
     +--------------------+-----------------------+
                          |
        Reviewed, resource-limited local adapter
                          |
       Autonomous robot / fleet vendor controller
                          |
     Certified LOCAL safety system (never remote-writable)

The node owns coordination, not physical safety. The safety controller,
protective zones, braking, motor loops and local emergency-stop path remain
independent of FASP. A network fault must not remove the local safety response.

### Trust assumptions

- One FASP node corresponds to one independent identity and durable state
  directory. Never clone an identity or share a writable SQLite database
  across machines.
- Signed FASP envelopes authenticate origin and detect modification.
  They are not end-to-end encrypted on their own. TLS/mTLS protects network
  hops; any terminating reverse proxy may inspect the payload.
- Local receiving-node policy governs all peer requests. A trusted pairing
  is not an unrestricted authorization. Artifact download now also checks
  the producing peer's authorization record.
- Adapters must enforce their own narrow schemas, external idempotency and
  device-specific confirmation for physical effects. FASP's task receipt
  never proves a robot has finished moving.
- IP networking is direct HTTPS/WebSocket. Opt-in Linux Bluetooth Classic
  and BLE L2CAP listeners require authenticated BlueZ link pairing, the
  matching channel/PSM, and hardware validation. They use the same signed
  envelope authorization boundary. The stock container has no radio device
  access. Cross-NAT routing, automated
  organizational enrollment and a multi-hop end-to-end ciphertext relay
  are not present. The Compose stack supervises the CLI's signed outbox
  drain; the generic node outbox has no network router. The resilience
  mesh module is simulation, not a real routing plane.
- Durable SQLite WAL is intentionally per node, on local storage. It is not
  a distributed active-active database and must not be put on NFS/SMB.

## What the hardened build enforces

1. Pairing-bound Ed25519 signatures, local scoped grants and revocation.
2. Capabilities checked at adapter startup and every dispatch; remote
   payloads cannot downgrade the adapter's authoritative risk class.
3. Idempotency identity scoped to the original peer and original payload.
4. Response replay tied to the exact authenticated signed envelope.
5. Per-peer authorization for artifact retrieval, with digest validation.
6. Limited HTTP/WebSocket messages and per-IP and per-peer rate limiting.
7. Startup posture checks against actual listener TLS/mTLS settings, not
   merely the advertised URL; configured security profile retained.
8. Audit-chain integrity checked against the opened database before loops
   or sockets start; the service refuses hardened startup if corrupted.
9. Outbox inflight recovery for a single-owner restarted node, with retries
   bounded by signed message expiry, dead letters and durable ordering.
10. Online WAL-aware snapshot backup API for database contents.

These are guards implemented in code, not a third-party audit attestation.

## Secure deployment example

The provided `deploy/production/compose.yaml` uses a dedicated non-root UID,
read-only image filesystem, no-new-privileges, removed Linux capabilities,
persistent state, TLS secret mounts and bounded container resources. It
initializes one durable identity, starts the HTTPS listener, probes `/readyz`
through mTLS with hostname verification, then starts a supervised `fasp drain
--watch` process for the same state directory. The service binds to HOST
loopback for an upstream restricted ingress. The image installs hash-checked
runtime packages from `requirements-prod.txt`, exported from `uv.lock`.
Regenerate that file with `uv export --locked --no-dev --no-emit-project
--format requirements-txt --offline --output-file requirements-prod.txt`
whenever the lockfile changes; CI checks that it is in sync.

Set up the deployment before starting it:

1. Copy `deploy/production/.env.example` to `deploy/production/.env`. Set
   `FASP_NODE_NAME` and `FASP_PUBLIC_URL`. The URL must resolve for peers and
   its DNS name must appear in the server certificate's subject alternative
   names. Keep these values stable for a persisted identity; `fasp-init`
   refuses a silent config change.
2. Create `deploy/production/secrets/` outside version control with
   `tls.crt` and `tls.key` for the server, `client.crt` and `client.key` for
   this node's outbound mTLS connections, and `mesh-ca.crt` containing the
   issuing CA for trusted nodes. Ensure container UID 10001 can traverse the
   directory and read these files. Restrict private key access to that UID;
   never commit the keys. The client certificate needs client authentication
   use, and the server certificate needs server authentication use.
3. Validate the rendered Compose configuration, build, and start:

       cd deploy/production
       docker compose config --quiet
       docker compose build
       docker compose up -d
       docker compose ps

`fasp-init` should exit successfully, `fasp` should become healthy, and
`fasp-drain` should stay running. Inspect `docker compose logs fasp
fasp-drain` if any condition fails. The shared `fasp-state` volume contains
the identity and SQLite database; preserve it through routine updates.
The drain process retries only the CLI's signed outbox, within each
envelope's roughly two-minute expiry. Inspect dead letters with `fasp
outbox` and obtain a fresh authorized message after expiry.

For remote access place the node behind a firewall-controlled TLS-aware
ingress, or an authenticated private network. Test certificate rotation,
revocation, source restrictions and denied requests before attaching a
device. No example deployment is approved for physical actuation by default.

A manually launched process can use:

    python -m fasp_harness serve
      --config /etc/fasp/node.json
      --host 0.0.0.0 --port 8766
      --public-url https://node.example.internal:8766
      --state-dir /var/lib/fasp
      --tls-cert /run/secrets/tls.crt
      --tls-key /run/secrets/tls.key
      --tls-client-ca /run/secrets/mesh-ca.crt
      --security-profile production

This command is shown across lines for readability; use shell continuations
or one actual command line. The profile validates config choices, not vendor
certification, encrypted-disk status or real hardware testing. Do not use
the deliberately insecure HTTP development switch on exposed interfaces.

## State backup and recovery

Use the online SQLite backup interface; copying only fasp.db while WAL is
active can silently omit committed data.

    from pathlib import Path
    from fasp_harness.storage.db import Database
    db = Database(Path("/var/lib/fasp/fasp.db"))
    db.backup(Path("/secure-backups/fasp-snapshot.db"))

The snapshot deliberately excludes identity.json, admin_token, artifacts,
TLS keys, and local vendor configuration. Back those up separately with
appropriate encryption and access controls. Restore to ONE isolated
replacement identity, never allow a clone to run concurrently with the
original, and rehearse complete restores and schema upgrades.

Outbox recovery requeues uncertain inflight records when build_node opens
the database. A prior send may already have reached the receiver; the
receiver's message-ID replay protection prevents repeated application
through FASP, but arbitrary external device effects still require adapter
idempotency. The Compose `fasp-drain` service supervises delivery for
messages created by the agent CLI. A standalone deployment must run its
own `fasp drain --watch` worker; the lower-level generic outbox still
requires an application-supplied sender.

## Agent command-line integration

`fasp register` performs a signed two-party handshake but **does not
approve a peer**. `fasp approve` requires an out-of-band checked
fingerprint. `fasp communicate` and `fasp drain` persist and retry
signed messages; they cannot extend the original two-minute envelope
expiry or guarantee exactly-once external device effects. Use mTLS,
protected persistent state, and a supervised drain loop. See
[AGENT_CLI.md](AGENT_CLI.md) for commands and boundaries.

## Operations and site acceptance checklist

- Threat model: record data sensitivity, identity lifetimes, dangerous
  capabilities, operators, vendors and trust boundaries.
- SLOs: specify measured p50/p95/p99 latency, max task age, recovery-time
  target, backup frequency, disk limits and maximum clock uncertainty.
- Fault injection: terminate the node at each state transition; simulate
  partitions, duplicates, reordering, corrupted messages, disk full,
  clock drift, cert expiration and concurrent conflicting requests.
- Security: fuzz signed envelopes, configuration and packet validators;
  test untrusted peers, replay and grants; rotate keys and review logging
  for secret exposure; scan dependencies and sign release artifacts.
- Observability: protected Prometheus scrape and alerts for audit failure,
  readiness, queue depth, dead letters, stale safety observations, vendor
  status and failed authorization. Export durable security events off-node.
- Sandbox: put adapter processes behind OS resource limits, allowlisted
  outbound network, filesystem/secret isolation and a supervisor capable
  of terminating hung jobs. The in-process Python worker timeout alone
  does not terminate a misbehaving thread. For stateless adapters the new
  optional --process-adapter CLI mode starts a killable subprocess for each
  execution; it is NOT an OS sandbox or a device safety controller.
- Robotics: physically verify independent E-stop, brake, protective
  fields, safe speed, local autonomy and hazard analysis. Validate ROS 2
  security enclaves if ROS 2 is enabled. Simulation-only evidence is NOT
  hardware certification.
- Release: pin exact artifact digests, test built-wheel installation,
  restore backups, evaluate mixed-version protocol compatibility,
  commission independent security review and require an operator's
  written site-specific go/no-go acceptance.

## Optional process-supervised adapters

For a stateless local model/analysis adapter, add both of these flags to
the FASP serve command:

    --adapter my_package.adapter:create_adapter --process-adapter

In this mode the server invokes a dedicated subprocess for capability
discovery and each subsequent adapter call. The process supervisor can
terminate a timed-out or cancelled invocation; its STDOUT is treated as
a bounded JSON protocol, and child stderr is never returned to a peer.

Use this only for independently replayable, stateless adapter functions.
Do not apply it to device adapters that own persistent hardware sessions
or expect state to survive across invocations. Process separation does
not automatically remove inherited environment variables, permit fewer
system calls, restrict filesystem access or block unauthorized network
access: configure those using separate service accounts, secure container
runtime restrictions, network policies and resource cgroups. No remote
model text should choose the local adapter import path.

### Unfinished release blockers (no code-only shortcut)

Independent security audit, real-hardware safety assessment, full multi-host
endurance testing, supervised out-of-process adapters, site-proven drain
behavior across partitions, and production-grade cross-NAT transport if
that network topology is required. A central multi-node active-active control
plane would require a separately designed state/consensus architecture;
do NOT deploy multiple writer replicas over a shared SQLite volume.

## Primary technical references

- NIST SP 800-82 Rev. 3, Operational Technology Security:
  https://www.nist.gov/publications/guide-operational-technology-ot-security
- NIST SP 800-218, Secure Software Development Framework:
  https://csrc.nist.gov/pubs/sp/800/218/final
- OWASP Application Security Verification Standard 5.0:
  https://github.com/OWASP/ASVS/tree/master/5.0
- OWASP API Security Top 10, resource consumption:
  https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/
- SQLite WAL design and limitations:
  https://www.sqlite.org/wal.html
- SQLite Online Backup API:
  https://www.sqlite.org/backup.html
- ISO 3691-4:2023, driverless industrial trucks:
  https://www.iso.org/standard/83545.html
- ROS 2 DDS-Security and enclaves:
  https://design.ros2.org/articles/ros2_dds_security
