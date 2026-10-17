# OpenCode ↔ FASP MCP ↔ MuJoCo: two-container test

## Result from 2026-10-17

| Check | Observed result |
| --- | --- |
| Two isolated Docker containers and network | **Pass.** OpenCode and robot ran in separate containers, each with its own FASP state volume. They used a user-defined Docker bridge and the internal `robot:8766` address. No host port was published. |
| OpenCode CLI → FASP MCP connection | **Pass.** OpenCode 2.0.1 reported `✓ fasp connected`; its log reported 15 MCP tools. The MCP process uses stdio inside the OpenCode container. |
| MCP call → FASP → MuJoCo → result | **Pass, using a deterministic MCP client inside the OpenCode container.** Three `communicate` calls read the initial pose, navigated, then read the final pose. A fourth call tested rejection. |
| Robot movement | **Pass.** MuJoCo 3.16.0 changed `(x_m, y_m)` from `(0.0, 0.0)` to `(0.2858, 0.0953)` for goal `(0.3, 0.1)`. The robot journal recorded exactly one completed goal. |
| Bounds enforcement | **Pass.** Goal `(2.0, 0.0)` returned `task.fail` / `policy.out_of_bounds`; it produced no second journal entry. |
| OpenCode model-initiated MCP call | **Fail.** OpenCode connected to MCP, but the locally installed `qwen2.5:3b` model produced text describing a call. The OpenCode JSON event stream contained `step_start` and `text`, with **no** `fasp_communicate` `tool_use` event. No navigation was attempted by the OpenCode agent. The model-driven script exits nonzero on this condition. |
| Live laptop telemetry packets | **Pass in a separate two-FASP-container test.** `tests/container_live_stream.sh` sent laptop `/proc` CPU/memory/uptime readings as 5 HTTP and 5 WebSocket reliable packets, plus 2 latest packets. This test does **not** include OpenCode or MuJoCo. |

These results establish the MCP/FASP/robot transport and simulation behavior. They do **not** establish a successful natural-language OpenCode agent controlling the robot, nor a continuous MuJoCo pose stream through OpenCode.

## How the containers communicate

```text
OpenCode CLI process                    MuJoCo robot process
container fasp-oc                       container fasp-robot
  OpenCode 2.0.1                          FASP HTTP server :8766
      │ stdio MCP initialize/tools       │
      ▼                                  │
  python -m fasp_harness mcp             │
      │ FASP signer + durable outbox      │
      └──── HTTP POST signed envelope ──►│ /fasp/v1/envelopes
         Docker bridge, robot:8766       │ verify identity, scope, grant
      ◄──── HTTP receipt.delivered ──────┤ dispatch MuJoCo adapter
           containing task.result        │
           or task.fail                   │
```

OpenCode starts the local FASP MCP server from its [V2 `mcp.servers` configuration](https://dev.opencode.ai/v2/docs/mcp-servers/). This is a child process connected by stdin/stdout, not an MCP HTTP server in the robot container. The MCP server uses the OpenCode container's FASP identity and SQLite state in `/home/fasp/.fasp`. `communicate(peer_id, capability, message, grant_id)` creates an `intent.propose` envelope with an idempotency key, signs it with the local FASP identity, writes it to the durable outbox, then sends it to `http://robot:8766/fasp/v1/envelopes`.

The robot has a different FASP identity and state volume. The script exchanges signed ID cards, confirms the same pairing code on both nodes, and approves only `observe.robot.pose.v1` and `robot.navigate.sim.v1`. It issues a five-minute grant to the OpenCode-side peer for navigation. The robot verifies the sender and grant before dispatching to `robot_adapter.py`. Its local controller accepts only a bounded goal, then advances MuJoCo physics; the remote peer cannot send motor setpoints. The adapter permits goals within ±1 metre and at most 0.5 metre from the current pose.

`receipt.delivered` is the HTTP transport acknowledgement wrapping the application `task.result` or `task.fail`. **The request envelope is signed; the receipt wrapper itself is not a separately signed FASP envelope.** The test checks both receipt and task result and reads the robot journal, so an HTTP 200 alone is insufficient. This demo uses `--insecure-http` only on the isolated Docker bridge; use TLS when deploying across an untrusted network.

OpenCode runs with a local Ollama provider in the same container for the model-driven attempt. The script bind-mounts the installed OpenCode binary, Ollama binary/runtime, and model files read-only; no host credentials are copied into an image. Its provider policy permits only `ollama`. The deterministic `--probe-only` mode needs no Ollama process or model. The optional `opencode_bridge` identity plugin is not used here: OpenCode's **native MCP client** is the connection to FASP.

## Reproduce

From the repository root, with Docker and a Linux OpenCode binary installed:

```bash
OPENCODE_BIN=/absolute/path/to/opencode \
  bash examples/opencode_robot/run_demo.sh --probe-only
```

This builds the three local images and runs the deterministic MCP protocol test. It prints OpenCode's MCP connection status, before/after poses, the out-of-bounds failure, and the robot journal result. Containers, network, and volumes are removed at exit. On failure, the temporary work directory is retained and printed for inspection.

To attempt the model-driven path, install `qwen2.5:3b` in local Ollama and run:

```bash
OPENCODE_BIN=/absolute/path/to/opencode \
  OLLAMA_BIN=/absolute/path/to/ollama \
  OLLAMA_MODELS_DIR=/absolute/path/to/ollama/models \
  bash examples/opencode_robot/run_demo.sh --skip-build
```

The script's `verify_opencode_events.py` requires a completed native `fasp_communicate` tool event and a delivered MuJoCo result for each requested step. On this machine the first step failed that check. It is intentionally a failing integration test until a tool-capable local model actually invokes the tool.

Run the separate laptop live-data packet test with:

```bash
bash tests/container_live_stream.sh fasp-harness:local
```

On 2026-10-17 it reported 10 exact reliable packets retained and replayed, 10 signed WebSocket pushes, two latest packets, seven negative protocol checks (grant, signature, order, checksum, JSON field, duplicate acknowledgement, closed stream), and 2.02/2.8/3.36 ms minimum/average/maximum round-trip time for 10 reliable packets. The observed host CPU counter rose from 4,189,008 to 4,191,117 and uptime from 2631.77 to 2633.1 seconds, so those samples came from changing laptop data.

## Limits of this test

- MuJoCo is headless and simulates a small planar point robot. No physical robot, camera, microphone, or laptop sensor is connected to the OpenCode/MuJoCo pair.
- The robot pose calls are discrete request/response messages. Continuous stream packet behavior was tested separately with laptop `/proc` telemetry, without OpenCode.
- The local `qwen2.5:3b` model did not make a native FASP tool call, even after a dedicated agent prompt and restricted tools. Text that resembles a call is not evidence of a call. Check JSON `tool_use` events and the robot journal before reporting model-driven success.
- An external OpenCode model run was rejected by automatic approval review because the prompt would export internal peer/grant IDs and a robot command. No such run with the robot payload was performed.
