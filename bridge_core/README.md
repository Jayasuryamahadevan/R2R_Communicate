# bridge_core

The one, host-agnostic implementation of the
[Agent ID Card](https://github.com/Jayasuryamahadevan/agent-id-card)
identity layer, shared by every bridge in this repository
([`pi_bridge/`](../pi_bridge/), [`opencode_bridge/`](../opencode_bridge/),
and whatever comes next). Nothing in this directory imports from, or
knows about, any specific host agent -- that's the whole point: twelve
files, importable by any Node/TypeScript host, that don't change no
matter which one loads them.

## Why this exists as its own directory

Both bridges started as separate copies of the same files. That
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
`index.ts`-equivalent that imports these same files -- not forking, not
re-deriving the crypto, not risking a second copy of the float bug. And
for a system with no Node at all,
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
| `provenance.ts` | Honest runtime/environment introspection (integers only -- see the note in the file on why); accelerator detection checks NVIDIA, AMD/ROCm, and Apple Silicon in turn, and CPU architecture (arm64/x64/...) is always recorded |
| `harness.ts` | Ties identity, the append-only log, self-managed state, and log-driven reconciliation together |
| `state.ts` | This agent's own self-editable configuration: MCP servers to stay connected to or auto-connect to, and FASP peers paired with |
| `fasp.ts` | A client for pairing with a FASP harness (`../fasp_harness/`) as one of its peers, sending it a real signed intent once paired, and holding a persistent channel open for autonomous push delivery -- see "Self-knowledge" and "Autonomous communication" below |
| `webhooks.ts` | Generic incoming/outgoing webhook connectivity, `node:http` + `fetch` only -- available to import, not wired to a command by either bridge today |
| `timestamps.ts` | The one timestamp format used everywhere here |
| `fsjson.ts` | The one atomic-JSON-file read/write every piece of persisted state above goes through |

No `package.json` here on purpose: this directory has zero dependencies
of its own (Node built-ins only). Each bridge's own `package.json` adds
whatever ITS host needs (`@modelcontextprotocol/sdk` for `pi_bridge`,
`@opencode-ai/plugin` for `opencode_bridge`) without this core ever
needing to know that.

## Self-knowledge: what am I connected to, and can I connect myself?

`AgentHarness.state` (`state.ts`) is this agent's own persisted answer
to "what MCP servers do I have" -- every server a host bridge connects
it to is remembered and reconnected automatically next time, and a
human operator can pre-vet further candidates (tagged with what
capability they provide) that this agent may connect to entirely on its
own initiative when it decides it needs one, without ever reaching for
a server nobody vetted. `pi_bridge` uses this directly (it has no
native MCP client of its own); `opencode_bridge` deliberately does not
(OpenCode's own `config.mcp` is that state's one real source of truth
there -- a second, shadow copy of it here would just be something else
to keep in sync).

`AgentHarness.connectFaspPeer()`/`faspPeers()` (`fasp.ts`) is the answer
to "what other physical or AI agents am I connected to": this agent can
pair itself with a FASP harness (`../fasp_harness/`, this repository's
other half) as one of its peers over FASP's real wire protocol, and --
when it holds that harness's admin token, i.e. the same operator runs
both sides -- list every other peer already paired with it, live. This
was verified against a real, running Python `fasp_harness` instance
while writing it (a real `hello` -> `pair/confirm` -> `/peers` round
trip over HTTP, not asserted from the two protocols' schemas alone).

Pairing alone only establishes trust; `AgentHarness.faspPropose()` is
what actually uses it -- a real, signed `intent.propose` envelope sent
to a paired peer for one of the capability prefixes it granted at
pairing time (`observe.`/`coordinate.` by default), with that peer's
real response returned. Verified end to end across two entirely
separate OS processes -- one FASP harness, one bridge_core-based agent
running under a genuinely kernel-enforced memory cgroup limit (not a
simulated one: a deliberately-oversized allocation under the same kind
of limit was confirmed to actually get OOM-killed) -- hello, confirm,
and a `coordinate.chat.v1` intent whose response echoed back exactly
what was sent.

`sendEnvelope()` is the general case `proposeIntent()` is one instance
of: any FASP envelope kind (`reservation.request`, `heartbeat`, ...),
not just `intent.propose`. Every network call in `fasp.ts` (`hello`,
`confirmSelf`, `listPeers`, and both of the above) retries a dropped
connection or a 5xx with exponential backoff + jitter -- a real gap
found by actually injecting packet loss (`tc netem`) between two
containers and comparing: a plain `fetch()` had a measurable failure
rate at 40-60% loss, this bridge's retrying client had none. A 4xx is
never retried -- that's a real rejection, not a transient failure.

## Autonomous communication: no polling, no "did you get my message"

`FaspClient.openChannel()` is what makes two agents genuinely
autonomous with each other instead of one having to keep asking the
other "any news yet": a persistent `/fasp/v1/channel` websocket
connection (Node's own built-in `WebSocket`, no dependency), matching
fasp_harness's own real push-delivery mechanism
(`channels.py`'s `ConnectionRegistry`, `core.py`'s
`_apply_task_outcome`/`_on_adapter_done`) -- a task that outlives its
synchronous wait budget (`max_runtime_s`) has its real result delivered
here the instant it's ready, not on the next poll.

Verified end to end, not asserted from the docstrings: a capability
whose declared `max_runtime_s` (1s) is deliberately shorter than how
long it actually takes (a real 3-second sleep) -- the only way its real
result can reach the caller at all is this push path. Across four
separate runs: an immediate `task.progress` acknowledgement at ~1.0s,
then the real result arriving, unprompted, at ~3.0s -- the client never
polled once in between, it just listened on the channel it opened at
the start.
