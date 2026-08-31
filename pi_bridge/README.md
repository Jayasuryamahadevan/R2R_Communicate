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

`extension/` is a single, self-contained pi extension:

| File | Purpose |
|---|---|
| `crypto.ts` | Ed25519 signing + a minimal RFC 8785 canonicalizer, `node:crypto` only, no external dependency |
| `epoch.ts` | Tier 1 (public) identity content, hash-chained across epochs |
| `tiers.ts` | Tier 2 (detailed) / Tier 3 (sensitive) content, digest-committed by the epoch |
| `renewal.ts` | The liveness heartbeat that replaces a revocation list for the common case |
| `log.ts` | A generic append-only, hash-chained JSON Lines log |
| `provenance.ts` | Honest runtime/environment introspection for Tier 3 |
| `harness.ts` | Ties identity, the action log, and experience-driven reconciliation together |
| `mcp.ts` | A generic MCP client: connect to ANY MCP server (stdio or Streamable HTTP); every tool gained is recorded as `capability_discovered` experience |
| `webhooks.ts` | Generic webhook connectivity in both directions -- an incoming listener and an outgoing notifier, `node:http` + `fetch` only |
| `index.ts` | The actual pi extension: wires all of the above into pi's `session_start`/`tool_call`/`tool_result` events and nine `/aic-*` commands |

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
