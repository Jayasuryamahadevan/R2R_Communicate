# Agent ID Card for pi

Gives `pi` a real, cryptographic identity for the workspace it's
running in, following the [Agent ID Card (AIC)](https://github.com/Jayasuryamahadevan/agent-id-card)
format: a hash-chained lineage of signed "epochs" rather than a single
static credential, with three privilege-gated disclosure tiers (public /
detailed / sensitive) and a cheap, frequent renewal heartbeat instead of
a revocation list.

## What it does

On the first `session_start` in a workspace with no existing `.aic/`
directory, this extension is curious about its surroundings before
doing anything else:

- OS, CPU, accelerator + driver version, available dev tools (all via
  Node built-ins and best-effort `child_process` probes -- every check
  degrades to `"unknown"` rather than throwing).
- pi's own current toolset (`pi.getAllTools()`), which becomes the
  card's declared capabilities.
- Whether it's running as root, inside a container/CI, with network
  access -- and states plainly, in the card's `known_limitations`, what
  it cannot do.

It then generates a genesis epoch, signs it with a freshly generated
Ed25519 key (Node's built-in `node:crypto`, no external dependency), and
persists everything under `.aic/`: `identity.json` (the private key,
0600), `chain.json`, `detail.json`, `sensitive.json`, `renewal.json`,
plus two append-only, hash-chained JSON Lines logs --
`action_log.jsonl` (every tool call) and `experience.jsonl` (capability/
limitation drift discovered over time).

`/aic-status` prints and verifies the current card. `/aic-reconcile`
diffs `pi`'s live toolset and any recorded experience against the card's
declared capabilities, and mints a `capability_update` epoch if anything
has actually changed -- so the card keeps matching reality instead of
freezing at whatever was true the first time `pi` ran here.

## Why this matters for an agent, specifically

Most identity formats (X.509, most Verifiable Credentials) assume one
long-lived credential blessed by one authority, revoked (if ever) via an
external denylist. An agent like `pi` is closer to the opposite: it's
re-run constantly, its toolset and the environment under it can change
between runs, and there usually isn't a single certificate authority in
the loop at all. AIC is built around exactly that -- see the linked
repo's `SPEC.md` (§1) for the full reasoning, and `HARNESS_BOOTSTRAP.md`
for the general bootstrap procedure this extension implements
concretely for `pi`.

## Usage

```bash
pi --extension examples/extensions/agent-id-card/index.ts
# or, for auto-discovery on every project:
cp -r agent-id-card ~/.pi/agent/extensions/
```

## Interoperability

This extension implements AIC's crypto (Ed25519 over a minimal RFC 8785
canonicalization subset -- see the upstream repo's `NO_PYTHON.md`) using
only Node's built-in `node:crypto`. A bundle produced here was verified,
while writing this extension, against the upstream repo's Python
reference implementation's `verify_bundle()` -- genuine cross-language
interoperability, not merely a shared file format in name.

## Files

| File | Purpose |
|---|---|
| `crypto.ts` | Ed25519 signing + the minimal canonicalizer, `node:crypto` only |
| `epoch.ts` | Tier 1 identity content, hash-chained across epochs |
| `tiers.ts` | Tier 2 (detailed) / Tier 3 (sensitive) content, digest-committed by the epoch |
| `renewal.ts` | The liveness heartbeat |
| `log.ts` | The generic append-only, hash-chained JSON Lines log |
| `provenance.ts` | Honest runtime/environment introspection |
| `harness.ts` | Ties identity, the action log, and experience-driven reconciliation together |
| `index.ts` | The actual pi extension: wires the above into `session_start`/`tool_call`/`tool_result` and two commands |
