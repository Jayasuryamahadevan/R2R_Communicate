# opencode_bridge

A bridge between two things this project already has, and one it
doesn't: [OpenCode](https://github.com/anomalyco/opencode) (an
open-source terminal coding agent), the same
[Agent ID Card](https://github.com/Jayasuryamahadevan/agent-id-card)
identity layer [`pi_bridge/`](../pi_bridge/) already gives `pi` (shared
via [`bridge_core/`](../bridge_core/), not duplicated), and **OpenCode
Zen as the default model provider** -- so a user of this bridge needs no
separate Anthropic/OpenAI API key to get started. Verified for real on
a real device: see "Interoperability" below.

This is vendored directly into `R2R_Communicate` as an OpenCode
*plugin*, not a fork of OpenCode -- OpenCode is loaded and extended
here, never patched.

## What it does

**Primary API key provider.** The plugin's `config` hook sets `model`
and `small_model` to OpenCode Zen (`opencode/big-pickle` /
`opencode/nemotron-3.5-lightning-free` by default -- both genuinely
free, `cost.input`/`cost.output` = 0, confirmed against a real Zen
catalog, not assumed; overridable via
`AIC_OPENCODE_ZEN_MODEL`/`AIC_OPENCODE_ZEN_SMALL_MODEL` env vars) --
**only** if you haven't already set your own. An explicit choice in
your own `opencode.json` is never overridden; this only fills in a
sensible default when nothing else is configured. No `/connect` or
`providers login` step is required for these two models -- confirmed
by running `opencode run` with zero stored credentials
(`~/.local/share/opencode/auth.json` absent) and getting a real
response back. Zen's catalog is OpenCode's own and does rotate, so
re-run `opencode models opencode --refresh` if a later OpenCode version
ever rejects one of these two IDs as unknown.

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
out of the box; nothing extra was needed here. Its self-state for MCP
servers is therefore OpenCode's own `config.mcp`, not a second copy of
it in `bridge_core`.

**Optional FASP pairing.** Set `AIC_FASP_URL` and this plugin pairs
itself, on load, with that [FASP harness](../fasp_harness/) as one of
its peers -- the concrete answer to "what other physical or AI agents
am I connected to" (`verifyWorkspace(directory)`, in `verify.ts`,
reports the result). Off by default: this bridge never reaches out to a
network nobody configured it to. Self-confirms the pairing (no separate
human approval step) if `AIC_FASP_ADMIN_TOKEN` or `AIC_FASP_STATE_DIR`
is also set -- see `pi_bridge/README.md`'s Quick Start for what those
mean; the same rule applies here.

**Only one export from `index.ts`.** `verifyWorkspace` used to live in
`index.ts` too, alongside the plugin's default export. A real running
`opencode` (v1.18.25) turned out to call every function a plugin module
exports, not just the default, as if each one might itself be a plugin
factory -- with `verifyWorkspace` exported there too, OpenCode called it
with the wrong argument and logged a spurious "failed to load plugin"
error (the real plugin still worked despite it). `verifyWorkspace` now
lives in its own file, `verify.ts`, which is never registered as a
plugin entry point.

## Usage

Add to your project's (or global) OpenCode config:

```json
{
  "plugin": ["./opencode_bridge/plugin/index.ts"]
}
```

or, once published, by npm/git reference the same way any OpenCode
plugin is installed. This repository's own root `opencode.json` already
does exactly this, so running `opencode` anywhere in `R2R_Communicate`
uses it by default. First session in a workspace bootstraps `.aic/`;
inspect it directly, or call `verifyWorkspace(directory)` (exported from
`verify.ts`, deliberately not `index.ts` -- see above) from a script or
CI step without going through OpenCode at all.

## Interoperability

The identity layer is literally the same files `pi_bridge/` uses
(`bridge_core/`), already cross-verified against the Python
`agent-id-card` reference implementation's `verify_bundle()` -- see
`pi_bridge/README.md` for how that was proven. This bridge's own
`config`-hook logic was run for real against a real `opencode` binary
(v1.18.25) on a real device, not just its exported functions called
directly: `opencode models` produced a genuine, cryptographically
verified Agent ID Card describing this machine's actual hardware (down
to its real CPU and GPU model), and `opencode run` -- with zero stored
credentials anywhere on the machine -- picked this plugin's default
model with no explicit `--model` flag and got a real completion back
from OpenCode Zen for free. FASP pairing (`bridge_core/fasp.ts`) was
verified the same way as in `pi_bridge/README.md`: a real round trip
against a running
Python `fasp_harness` instance, not merely asserted from the two
protocols' schemas.
