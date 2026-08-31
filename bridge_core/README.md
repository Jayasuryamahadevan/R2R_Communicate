# bridge_core

The one, host-agnostic implementation of the
[Agent ID Card](https://github.com/Jayasuryamahadevan/agent-id-card)
identity layer, shared by every bridge in this repository
([`pi_bridge/`](../pi_bridge/), [`opencode_bridge/`](../opencode_bridge/),
and whatever comes next). Nothing in this directory imports from, or
knows about, any specific host agent -- that's the whole point: nine
files, importable by any Node/TypeScript host, that don't change no
matter which one loads them.

## Why this exists as its own directory

Both bridges started as separate copies of the same nine files. That
worked, until it didn't: a real bug (a floating-point field that a
minimal RFC 8785 canonicalizer can't sign) was fixed once, then had to
be found and fixed a second time in the other copy, because nothing
forced the two to stay identical. Two copies of anything that's
supposed to be identical will drift. `bridge_core/` removes the
question entirely -- there is exactly one copy, and every host imports
it directly (`../../bridge_core/harness.js`, etc.), so a fix applied
here is a fix everywhere at once.

That's also the concrete, checked answer to "hardware and software
agnostic, adapts to whatever the system is": this core has been run,
for real, against a real Node process on this actual machine (real
CPU/GPU/OS, not fixtures) under two independent, unrelated host
agents, producing byte-identical, cross-verified signed output both
times. Adding a third host means writing a third thin
`index.ts`-equivalent that imports these same nine files -- not
forking, not re-deriving the crypto, not risking a second copy of the
float bug. And for a system with no Node at all,
[`agent-id-card`'s `NO_PYTHON.md`](https://github.com/Jayasuryamahadevan/agent-id-card/blob/main/NO_PYTHON.md)
gives the same guarantee one level down: the wire format itself (Ed25519
over a documented RFC 8785 subset) is provably reproducible in OpenSSL,
Node, or libsodium, so "whatever language" the target system actually
runs is never a reason this can't work there too -- only a reason for
which of those three paths a new host's thin adapter takes.

## Files

| File | Purpose |
|---|---|
| `crypto.ts` | Ed25519 signing + the minimal canonicalizer, `node:crypto` only |
| `epoch.ts` | Tier 1 (public) identity content, hash-chained across epochs |
| `tiers.ts` | Tier 2 (detailed) / Tier 3 (sensitive) content, digest-committed by the epoch |
| `renewal.ts` | The liveness heartbeat |
| `log.ts` | The generic append-only, hash-chained JSON Lines log |
| `provenance.ts` | Honest runtime/environment introspection (integers only -- see the note in the file on why) |
| `harness.ts` | Ties identity, the action log, and experience-driven reconciliation together |
| `webhooks.ts` | Generic incoming/outgoing webhook connectivity, `node:http` + `fetch` only |
| `timestamps.ts` | The one timestamp format used everywhere here |

No `package.json` here on purpose: this directory has zero dependencies
of its own (Node built-ins only). Each bridge's own `package.json` adds
whatever ITS host needs (`@modelcontextprotocol/sdk` for `pi_bridge`,
`@opencode-ai/plugin` for `opencode_bridge`) without this core ever
needing to know that.
