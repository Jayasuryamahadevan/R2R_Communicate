# opencode_bridge

A bridge between two things this project already has, and one it
doesn't: [OpenCode](https://github.com/anomalyco/opencode) (an
open-source terminal coding agent), the same
[Agent ID Card](https://github.com/Jayasuryamahadevan/agent-id-card)
identity layer [`pi_bridge/`](../pi_bridge/) already gives `pi` (shared
via [`bridge_core/`](../bridge_core/), not duplicated), and **OpenCode
Zen as the default model provider** -- so a user of this bridge needs no
separate Anthropic/OpenAI API key to get started.

This is vendored directly into `R2R_Communicate` as an OpenCode
*plugin*, not a fork of OpenCode -- OpenCode is loaded and extended
here, never patched.

## What it does

**Primary API key provider.** The plugin's `config` hook sets `model`
and `small_model` to OpenCode Zen (`opencode/claude-opus-5` /
`opencode/claude-haiku-4-5` by default, overridable via
`AIC_OPENCODE_ZEN_MODEL`/`AIC_OPENCODE_ZEN_SMALL_MODEL` env vars) --
**only** if you haven't already set your own. An explicit choice in
your own `opencode.json` is never overridden; this only fills in a
sensible default when nothing else is configured. Authenticate Zen once
with OpenCode's own `/connect` command (see
[opencode.ai/docs/zen](https://opencode.ai/docs/zen)) and every session
in a workspace using this plugin picks it up automatically.

**The same self-describing identity `pi` has.** On load, the plugin is
curious about its surroundings (OS, hardware, accelerator/driver,
whether it's sandboxed) and bootstraps a signed, hash-chained genesis
epoch if this workspace doesn't have one yet -- explicit `"unknown"` for
anything it can't determine, never a guess. Every tool call is appended
to a tamper-evident action log via the `tool.execute.before`/
`tool.execute.after` hooks.

**No duplicated MCP client.** OpenCode already ships a full native MCP
client (`packages/opencode/src/mcp/` upstream) -- this bridge does not
rebuild one. "Connect to any MCP server" is already true for OpenCode
out of the box; nothing extra was needed here.

## Usage

Add to your project's (or global) OpenCode config:

```json
{
  "plugin": ["./opencode_bridge/plugin/index.ts"]
}
```

or, once published, by npm/git reference the same way any OpenCode
plugin is installed. First session in a workspace bootstraps `.aic/`;
inspect it directly, or call `verifyWorkspace(directory)` (exported from
`index.ts`) from a script or CI step without going through OpenCode at
all.

## Interoperability

The identity layer is literally the same files `pi_bridge/` uses
(`bridge_core/`), already cross-verified against the Python
`agent-id-card` reference implementation's `verify_bundle()` -- see
`pi_bridge/README.md` for how that was proven. This bridge's own
`config`-hook logic (default only when unset, real bootstrap producing
a chain that verifies) was run directly against this plugin's exported
functions while building it, not merely assumed to work from the type
signatures.
