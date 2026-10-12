# Plug-and-play R2R (first usable release)

This is a **thin operator interface** over the existing FASP harness. It does not ship an LLM, automatically run shell commands, or grant network peers general control of the host.

## Install

Requires Python 3.11 or newer.

```bash
git clone https://github.com/Jayasuryamahadevan/R2R_Communicate.git
cd R2R_Communicate
python -m pip install -e ".[mcp]"
r2r --help
```

Use the branch `feat/plug-and-play-r2r` until this change is merged.

## One node per computer

On **Computer A**, choose a hostname/IP and advertise the URL other peers can actually reach:

```bash
r2r init --name laptop --public-url https://laptop.example:8766
r2r serve --name laptop --state-dir .fasp --host 0.0.0.0 --port 8766 \
    --public-url https://laptop.example:8766 --tls-cert cert.pem --tls-key key.pem
```

On **Computer B**:

```bash
r2r init --name worker --public-url https://worker.example:8766
r2r serve --name worker --state-dir .fasp --host 0.0.0.0 --port 8766 \
    --public-url https://worker.example:8766 --tls-cert cert.pem --tls-key key.pem
```

Each computer must have a different state directory **on its own machine**. Keep `.fasp/identity.json` and `.fasp/admin_token` private. The node server must be running to accept network requests.

For an isolated, trusted **development LAN** (never public Internet), you can substitute `http://<LAN-IP>:8766`, run `r2r serve ... --insecure-http`, and use `--insecure-http` for CLI `connect`, `ask`, `status`, and `mcp`. Plain HTTP exposes response contents and can be intercepted; use TLS for real work. A self-signed certificate needs explicit local CA trust configuration; HTTPS validation is not skipped automatically.

## Pair the systems

On Computer A (with Computer B's server already running):

```bash
r2r connect https://worker.example:8766
```

This shows both system IDs and a pairing code. **Compare the code out of band on both machines** before approving. On Computer B, list the pending peer then approve Computer A:

```bash
r2r peers
r2r approve "fasp:system:<COMPUTER-A-ID>" "<PAIR-CODE>"
```

On Computer A, independently approve Computer B:

```bash
r2r approve "fasp:system:<COMPUTER-B-ID>" "<PAIR-CODE>"
r2r peers
```

The two `approve` commands are local operator actions, **not** remote admin commands. Simply discovering a node or receiving an ID card does not make it trusted.

You can narrow permitted capabilities on approval:

```bash
r2r approve "<PEER-ID>" "<PAIR-CODE>" --capability-prefix observe.
```

Both peer records must allow the requested capability for two-way task execution.

## Exchange a task

On Computer A:

```bash
r2r ask worker "Check system status" --capability observe.system.status.v1
```

The command prints an `idempotency_key`, the response, and the task status. If it is still running:

```bash
r2r status worker "<IDEMPOTENCY-KEY>"
```

The built-in adapter only supports the simple observation/chat examples. `coordinate.chat.v1` **echoes** a bounded goal; it does not invoke an AI model.

To delegate coding or sensor analysis, implement a local adapter with `capabilities()` and `handle(intent)` (see `fasp_harness/example_adapter.py`) and start the receiving node with `r2r serve ... --adapter my_module:create_adapter`. That adapter owns the permissions and the actual local execution.

## Connect an MCP-compatible AI app

The optional `mcp` package provides the **official MCP SDK v2** server with stdio transport. It runs locally under the account that owns the `.fasp` state directory.

Install `.[mcp]` as above, then register this executable as a *local* MCP server with your application's MCP configuration:

```json
{
  "mcpServers": {
    "r2r": {
      "command": "r2r",
      "args": ["mcp", "--state-dir", "/ABSOLUTE/PATH/TO/.fasp"]
    }
  }
}
```

The configuration key names vary by MCP host. `mcpServers` is only an illustrative host configuration format; adjust it to your app.

The exposed tools are:

| MCP tool | What it does |
| --- | --- |
| `r2r_list_peers` | List locally known peers and capabilities |
| `r2r_get_capabilities` | Read the signed, stored capability advertisements from a paired peer |
| `r2r_send_task` | Send a bounded goal to a paired, authorized peer |
| `r2r_get_task_status` | Poll a task created by this node |

By default, the MCP gateway allows task submission **only** for exact capability IDs `observe.system.status.v1` and `coordinate.chat.v1`. To expose a further deliberately installed local capability:

```bash
r2r mcp --allow-capability coordinate.plan.v1
```

Configuring an MCP tool does **not** authorize a remote peer: FASP pairing, per-capability authorization, local adapter policy, and grants are checked again by the receiver.

**Security:** The gateway never passes the node admin token, private Ed25519 key, or arbitrary FASP verbs to the MCP host. The receiving device must never execute network-supplied shell commands or motor setpoints. The host still controls what the model may invoke.

## Troubleshooting

```bash
r2r doctor
r2r peers
python -m unittest tests.test_plugplay -v
```

Common issues:

- **Not paired:** run `connect` once, then `approve` on both machines.
- **Peer unavailable:** ensure the receiver's FASP server is running and the signed ID card advertises a reachable address.
- **HTTP rejected:** use HTTPS, or the explicit isolated-LAN development flags.
- **Capability unavailable:** your local adapter does not provide that named capability.
- **Grant required:** reversible operations need explicit authorization from the receiving operator; changing the request's risk field cannot bypass this.
- **Task still running:** use `status` with the original idempotency key.

## Scope and next steps

This first release provides working **pairing + signed task exchange + MCP exposure**, not automatic goal decomposition or autonomous agent collaboration. Production-readiness additionally requires fixes for resource-specific artifact and stream access, longer-running operational tests, third-party interoperability testing, and deployment-specific security review. Connecting a real AI coding agent or robot requires an explicit local adapter and its own safety boundary.
