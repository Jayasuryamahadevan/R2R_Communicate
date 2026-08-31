# pi_bridge

A bridge between three things this project already has, and one it
doesn't: [pi](https://github.com/earendil-works/pi) (an open-source
terminal coding agent), the
[Agent ID Card](https://github.com/Jayasuryamahadevan/agent-id-card)
identity format, and a generic MCP client.

This is deliberately vendored directly into `R2R_Communicate` rather
than kept as a separate fork of `pi` -- pi is loaded and extended, not
modified; this directory is a pi *extension*, not a patched copy of pi
itself.

## What's here

`extension/` is a single pi extension. The identity layer itself
(`crypto`/`epoch`/`tiers`/`renewal`/`log`/`provenance`/`harness`/
`state`/`fasp`/`webhooks`) is NOT duplicated here -- it lives once,
host-agnostic, in [`../bridge_core/`](../bridge_core/), imported
directly (`../../bridge_core/harness.js`, etc.), and is shared
byte-for-byte with [`opencode_bridge/`](../opencode_bridge/).
(`bridge_core/webhooks.ts` is available there too, but isn't wired to a
command in this bridge -- see "Interoperability" below.) Only what's
actually specific to `pi` lives in this directory:

| File | Purpose |
|---|---|
| `mcp.ts` | A generic MCP client: connect to ANY MCP server (stdio or Streamable HTTP); every tool gained is recorded as `capability_discovered` experience. (`pi` deliberately ships with no built-in MCP support, so this bridge provides one; `opencode_bridge` does not need this file at all, since OpenCode already has a native MCP client.) |
| `index.ts` | The actual pi extension: wires `bridge_core`'s harness + this file's MCP client into pi's `session_start`/`tool_call`/`tool_result` events and eight `/aic-*` commands |

See [`../bridge_core/README.md`](../bridge_core/README.md) for why the
identity layer lives there instead of here.

## Why this belongs next to FASP

`fasp_harness/` (this repository's other half) is a zero-trust
coordination protocol for autonomous systems that already know who they
are -- every FASP peer has an Ed25519 identity, capability-scoped
pairing, and a signed profile from the moment it joins. `pi` is a
general-purpose coding agent with no such concept: nothing about *it*
is signed, versioned, or self-describing across restarts.

`pi_bridge` is what lets a `pi` instance become one of those
FASP-shaped, self-describing participants: on first run in a workspace
it bootstraps a real Agent ID Card (a hash-chained lineage, not a static
credential), keeps it honest over time as its actual toolset changes
(including tools it gains by connecting to an MCP server), and can
speak to the rest of the world -- any MCP server -- while recording
every one of those connections as auditable, tamper-evident history.
It can go one step further than "FASP-shaped": `/aic-fasp-connect`
actually pairs this `pi` instance with a FASP harness as one of its real
peers, so `/aic-fasp-peers` can answer "what other physical or AI agents
am I connected to" for real, not just by analogy.

## Quick start

```bash
cd pi_bridge/extension
npm install
pi --extension index.ts
```

Inside a `pi` session:

```
/aic-status                                                    # show + verify this workspace's card, MCP + FASP self-state
/aic-mcp-connect docs stdio npx -y some-mcp-server              # connect any MCP server; remembered and reconnected on future starts
/aic-mcp-connect remote http https://example.com/mcp
/aic-reconcile                                                  # fold newly discovered capabilities into a fresh epoch
/aic-mcp-disconnect docs                                        # disconnect, and stop reconnecting it automatically
/aic-mcp-allow web web-search,fetch http https://example.com/mcp # pre-approve a server for pi to connect to on its own
/aic-mcp-auto web-search                                        # pi connects itself to a pre-approved candidate providing this
/aic-fasp-connect                                               # pair with a FASP harness (default http://127.0.0.1:8766)
/aic-fasp-peers                                                 # list FASP peers -- other physical/AI agents connected to it
```

`/aic-fasp-connect` self-confirms the pairing (no separate human
approval step) if `AIC_FASP_ADMIN_TOKEN` (that harness's own admin
token) or `AIC_FASP_STATE_DIR` (that harness's state directory, so the
token is read straight from its `admin_token` file) is set in the
environment -- meaningful only when the same operator runs both sides.
Without either, the pairing sits "pending" until that harness's
operator confirms it some other way. Neither is ever accepted as a
plain command argument, since that would put a secret in this session's
own transcript.

## Interoperability

The identity layer's crypto (Ed25519 over a minimal RFC 8785 subset,
using only `node:crypto`) was verified, while building this bridge,
against the Python reference implementation in the linked
`agent-id-card` repository: a bundle produced by this TypeScript code
was confirmed valid by that repository's own `verify_bundle()`. The MCP
client was verified end to end against a real MCP server over stdio.
FASP pairing (`/aic-fasp-connect`/`/aic-fasp-peers`, `bridge_core/fasp.ts`)
was verified against a real, running Python `fasp_harness` instance: a
real `hello` -> `pair/confirm` -> `/peers` round trip over HTTP, with
that harness's own signature verification accepting the card this
TypeScript code signed. None of this is asserted from the spec alone --
it was actually run.

`bridge_core/webhooks.ts` (a generic incoming/outgoing webhook helper,
`node:http` + `fetch` only) was also verified with a real local HTTP
round trip, but isn't wired to a command in this bridge -- it wasn't
earning its keep as part of `pi_bridge`'s default surface, so it's
available to import directly if you want it, not exposed as
`/aic-webhook-*` commands here.

See `agent-id-card`'s `SPEC.md` for the identity format itself,
`HARNESS_BOOTSTRAP.md` for the general bootstrap procedure this
extension implements concretely for `pi`, and `NO_PYTHON.md` for why the
crypto here needed no Python at all.
