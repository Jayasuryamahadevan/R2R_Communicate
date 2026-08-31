# pi_bridge

A bridge between three things this project already has, and one it
doesn't: [pi](https://github.com/earendil-works/pi) (an open-source
terminal coding agent), the
[Agent ID Card](https://github.com/Jayasuryamahadevan/agent-id-card)
identity format, and generic MCP/webhook connectivity.

This is deliberately vendored directly into `R2R_Communicate` rather
than kept as a separate fork of `pi` -- pi is loaded and extended, not
modified; this directory is a pi *extension*, not a patched copy of pi
itself.

## What's here

`extension/` is a single pi extension. The identity layer itself
(`crypto`/`epoch`/`tiers`/`renewal`/`log`/`provenance`/`harness`/
`webhooks`) is NOT duplicated here -- it lives once, host-agnostic, in
[`../bridge_core/`](../bridge_core/), imported directly
(`../../bridge_core/harness.js`, etc.), and is shared byte-for-byte with
[`opencode_bridge/`](../opencode_bridge/). Only what's actually specific
to `pi` lives in this directory:

| File | Purpose |
|---|---|
| `mcp.ts` | A generic MCP client: connect to ANY MCP server (stdio or Streamable HTTP); every tool gained is recorded as `capability_discovered` experience. (`pi` deliberately ships with no built-in MCP support, so this bridge provides one; `opencode_bridge` does not need this file at all, since OpenCode already has a native MCP client.) |
| `index.ts` | The actual pi extension: wires `bridge_core`'s harness + this file's MCP client into pi's `session_start`/`tool_call`/`tool_result` events and nine `/aic-*` commands |

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
speak to the rest of the world -- any MCP server, any webhook -- while
recording every one of those connections as auditable, tamper-evident
history.

## Quick start

```bash
cd pi_bridge/extension
npm install
pi --extension index.ts
```

Inside a `pi` session:

```
/aic-status                                        # show + verify this workspace's card
/aic-mcp-connect docs stdio npx -y some-mcp-server  # connect any MCP server; its tools become pi tools
/aic-mcp-connect remote http https://example.com/mcp
/aic-reconcile                                      # fold newly discovered capabilities into a fresh epoch
/aic-webhook-listen 8787 /hook                      # let an external system trigger this agent
/aic-webhook-notify https://example.com/notify      # get notified of bootstrap/reconcile/tool-failure events
```

## Interoperability

The identity layer's crypto (Ed25519 over a minimal RFC 8785 subset,
using only `node:crypto`) was verified, while building this bridge,
against the Python reference implementation in the linked
`agent-id-card` repository: a bundle produced by this TypeScript code
was confirmed valid by that repository's own `verify_bundle()`. The MCP
client was verified end to end against a real MCP server over stdio;
the webhook receiver/notifier were verified with a real local HTTP
round trip. None of this is asserted from the spec alone -- it was
actually run.

See `agent-id-card`'s `SPEC.md` for the identity format itself,
`HARNESS_BOOTSTRAP.md` for the general bootstrap procedure this
extension implements concretely for `pi`, and `NO_PYTHON.md` for why the
crypto here needed no Python at all.
