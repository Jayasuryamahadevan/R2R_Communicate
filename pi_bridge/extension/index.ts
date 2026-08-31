/**
 * pi_bridge: an Agent ID Card + MCP bridge for pi
 * ================================================
 *
 * On first run in a workspace, pi is curious about its surroundings
 * (OS, hardware, accelerator/driver, available tools, its own toolset),
 * and turns what it honestly finds into a signed AIC identity
 * (https://github.com/Jayasuryamahadevan/agent-id-card -- SPEC.md is the
 * normative format; HARNESS_BOOTSTRAP.md is the procedure this
 * extension implements). Every tool call is recorded in an append-only,
 * hash-chained log.
 *
 * On top of that base, this bridge lets pi connect itself to ANY MCP
 * server (stdio or Streamable HTTP) -- its tools are dynamically
 * registered as pi tools, and each one gained is recorded as a
 * `capability_discovered` entry, so connecting to a new MCP server
 * flows straight into the next `/aic-reconcile` instead of silently
 * expanding what this agent can do without its own card ever
 * reflecting that.
 *
 * Two forms of genuine self-management, both backed by
 * `bridge_core/state.ts` so they survive a restart and are visible via
 * `/aic-status`, not just held in memory:
 *  - Every MCP server this bridge connects to is remembered and
 *    reconnected automatically the next time pi starts in this
 *    workspace -- connecting it once is enough.
 *  - A human operator can pre-vet a server as a "candidate" tagged with
 *    what it provides (`/aic-mcp-allow`); pi can then connect to one of
 *    those on its own initiative (`/aic-mcp-auto`) when it decides it
 *    needs a capability none of its current tools provide, without
 *    ever reaching for a server nobody vetted.
 *
 * This bridge can also pair itself with a FASP harness
 * (../../fasp_harness/) as one of its peers -- the concrete answer to
 * "what other physical or AI agents am I connected to": a FASP harness
 * this agent is paired with can list every other peer it already knows
 * about (`/aic-fasp-peers`).
 *
 * No external dependency for the identity layer (`../../bridge_core/`,
 * Node's built-in `node:crypto` only, shared unmodified with
 * opencode_bridge/); the MCP layer depends on the official
 * `@modelcontextprotocol/sdk` (see package.json). Generic webhook
 * connectivity is available at `../../bridge_core/webhooks.ts` if you
 * want it, but isn't wired to a command here -- it wasn't earning its
 * keep as part of this bridge's default surface.
 *
 * State lives in `.aic/` under the project root -- identity.json (the
 * private key, 0600), chain.json, detail.json, sensitive.json,
 * renewal.json, log.jsonl, self_state.json, fasp_identity.json (0600).
 *
 * Commands: /aic-status, /aic-reconcile, /aic-mcp-connect,
 * /aic-mcp-disconnect, /aic-mcp-allow, /aic-mcp-auto, /aic-fasp-connect,
 * /aic-fasp-peers.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { verifyChain } from "../../bridge_core/epoch.js";
import { AgentHarness } from "../../bridge_core/harness.js";
import {
	collectRuntimeProvenance,
	discoverPermissionsAndNetwork,
} from "../../bridge_core/provenance.js";
import type { McpCandidate } from "../../bridge_core/state.js";
import { verifyDetail } from "../../bridge_core/tiers.js";
import {
	McpRegistry,
	type McpServerConfig,
	type McpToolDescriptor,
} from "./mcp.js";

const PURPOSE =
	"Coding agent (pi) assisting a developer in this workspace: reads, edits, and runs commands as directed.";

const DEFAULT_FASP_URL = "http://127.0.0.1:8766";

function stateDirFor(cwd: string): string {
	return join(cwd, ".aic");
}

/** Only ever resolved from the environment, never accepted as a plain
 * command argument -- a chat command's arguments end up in this
 * session's own transcript, which is the wrong place for a secret. */
function resolveFaspAdminToken(): string | undefined {
	if (process.env.AIC_FASP_ADMIN_TOKEN) return process.env.AIC_FASP_ADMIN_TOKEN;
	const stateDir = process.env.AIC_FASP_STATE_DIR;
	if (!stateDir) return undefined;
	try {
		return readFileSync(join(stateDir, "admin_token"), "utf-8").trim();
	} catch {
		return undefined;
	}
}

async function bootstrapIfNeeded(
	harness: AgentHarness,
	pi: ExtensionAPI,
	ctx: ExtensionContext,
): Promise<void> {
	if (harness.isBootstrapped) {
		try {
			harness.verifyOwnChain();
			harness.ensureLive();
		} catch (error) {
			ctx.ui.notify(
				`agent-id-card: existing identity failed to verify (${(error as Error).message}); leaving it untouched for inspection.`,
				"error",
			);
		}
		return;
	}

	const provenance = collectRuntimeProvenance();
	const permissions = discoverPermissionsAndNetwork();
	harness.log.append("environment.discovered", {
		...provenance,
		...permissions,
	});

	const toolNames = pi.getAllTools().map((tool) => tool.name);
	const knownLimitations = [
		"no memory of this workspace beyond entries already written to .aic/",
		"bounded by the active model's context window",
		"can only act through the tools actually registered for this session, plus whatever MCP servers are explicitly connected via /aic-mcp-connect",
	];
	if (permissions.running_as_root === false)
		knownLimitations.push(
			"not running as root: cannot modify files or ports outside the current user's permissions",
		);
	if (
		!provenance.hardware ||
		(provenance.hardware as Record<string, unknown>).accelerator === "cpu-only"
	)
		knownLimitations.push("no local accelerator detected on this host");

	const genesis = harness.bootstrap(
		`pi@${process.env.HOSTNAME ?? "workspace"}`,
		PURPOSE,
		toolNames,
		{
			protocols: ["mcp"],
			knownLimitations,
			sensitive: {
				modelName: "unknown",
				modelVersion: "unknown",
				hardware: provenance.hardware,
				softwareStack: provenance.software_stack,
			},
		},
	);

	ctx.ui.notify(
		[
			"agent-id-card: bootstrapped a new identity for this workspace.",
			`  agent_id: ${genesis.agent_id}`,
			`  capability_categories: ${genesis.capability_categories.join(", ")}`,
			`  known_limitations: ${knownLimitations.length} recorded`,
			"  state saved under .aic/ -- waiting for instructions.",
		].join("\n"),
		"info",
	);
}

function registerMcpTools(
	pi: ExtensionAPI,
	harness: AgentHarness,
	registry: McpRegistry,
	serverName: string,
	tools: McpToolDescriptor[],
): void {
	for (const tool of tools) {
		pi.registerTool({
			name: tool.qualifiedName,
			label: tool.toolName,
			description:
				tool.description ??
				`MCP tool "${tool.toolName}" from server "${serverName}".`,
			// biome-ignore lint/suspicious/noExplicitAny: MCP tool input schemas are arbitrary, server-defined JSON Schema, not known at compile time.
			parameters: tool.inputSchema as any,
			async execute(_toolCallId, params) {
				const connection = registry.getConnection(serverName);
				if (!connection)
					throw new Error(`MCP server "${serverName}" is no longer connected.`);
				const result = await connection.callTool(
					tool.toolName,
					params as Record<string, unknown>,
				);
				if (harness.isBootstrapped)
					harness.log.append("mcp.tool_invoked", {
						server: serverName,
						tool: tool.toolName,
					});
				return {
					content: [{ type: "text", text: JSON.stringify(result) }],
					details: { mcpServer: serverName, mcpTool: tool.toolName },
				};
			},
		});
		if (harness.isBootstrapped)
			harness.log.append("capability_discovered", {
				capability: tool.qualifiedName,
				source: `mcp:${serverName}`,
			});
	}
}

async function connectAndRegister(
	pi: ExtensionAPI,
	harness: AgentHarness,
	registry: McpRegistry,
	config: McpServerConfig,
): Promise<McpToolDescriptor[]> {
	const tools = await registry.connectServer(config);
	registerMcpTools(pi, harness, registry, config.name, tools);
	if (harness.isBootstrapped)
		harness.log.append("mcp.connected", {
			server: config.name,
			transport: config.transport,
			tool_count: tools.length,
		});
	return tools;
}

/** Reconnect every MCP server this agent previously decided to keep
 * connected -- connecting it once (via /aic-mcp-connect) is enough;
 * this is what makes that decision survive a restart instead of
 * silently reverting to "no MCP tools" every time pi starts. Best
 * effort: one server failing to come back up must never block the
 * others, or block the session starting at all. */
async function reconnectSavedMcpServers(
	pi: ExtensionAPI,
	harness: AgentHarness,
	registry: McpRegistry,
	ctx: ExtensionContext,
): Promise<void> {
	if (!harness.isBootstrapped) return;
	for (const server of harness.state.mcpServers) {
		if (registry.getConnection(server.name)) continue;
		try {
			const tools = await connectAndRegister(pi, harness, registry, server);
			ctx.ui.notify(
				`agent-id-card: reconnected remembered MCP server "${server.name}" (${tools.length} tool(s)).`,
				"info",
			);
		} catch (error) {
			ctx.ui.notify(
				`agent-id-card: could not reconnect remembered MCP server "${server.name}": ${(error as Error).message}`,
				"error",
			);
		}
	}
}

function parseMcpServerArgs(
	name: string,
	transport: string,
	rest: string[],
): McpServerConfig | null {
	if (transport !== "stdio" && transport !== "http") return null;
	return transport === "stdio"
		? { name, transport, command: rest[0], args: rest.slice(1) }
		: { name, transport, url: rest[0] };
}

export default function (pi: ExtensionAPI) {
	const harnesses = new Map<string, AgentHarness>();
	const mcpRegistries = new Map<string, McpRegistry>();

	function harnessFor(cwd: string): AgentHarness {
		const stateDir = stateDirFor(cwd);
		let harness = harnesses.get(stateDir);
		if (!harness) {
			harness = new AgentHarness(stateDir, {
				capabilities: () => pi.getAllTools().map((tool) => tool.name),
			});
			harnesses.set(stateDir, harness);
		}
		return harness;
	}

	function mcpRegistryFor(cwd: string): McpRegistry {
		let registry = mcpRegistries.get(cwd);
		if (!registry) {
			registry = new McpRegistry();
			mcpRegistries.set(cwd, registry);
		}
		return registry;
	}

	pi.on("session_start", async (_event, ctx) => {
		const harness = harnessFor(ctx.cwd);
		await bootstrapIfNeeded(harness, pi, ctx);
		await reconnectSavedMcpServers(pi, harness, mcpRegistryFor(ctx.cwd), ctx);
	});

	pi.on("tool_call", async (event, ctx) => {
		const harness = harnessFor(ctx.cwd);
		if (harness.isBootstrapped)
			harness.log.append("tool.invoked", {
				tool: event.toolName,
				tool_call_id: event.toolCallId,
			});
	});

	pi.on("tool_result", async (event, ctx) => {
		const harness = harnessFor(ctx.cwd);
		if (harness.isBootstrapped)
			harness.log.append("tool.completed", {
				tool: event.toolName,
				tool_call_id: event.toolCallId,
				is_error: Boolean(event.isError),
			});
	});

	pi.registerCommand("aic-status", {
		description: "Show this workspace's Agent ID Card and verify its chain.",
		async handler(_args, ctx) {
			const harness = harnessFor(ctx.cwd);
			if (!harness.isBootstrapped) {
				ctx.ui.notify(
					"agent-id-card: no identity yet for this workspace.",
					"info",
				);
				return;
			}
			try {
				harness.verifyOwnChain();
				const detail = harness.detail;
				if (detail) verifyDetail(detail, harness.currentEpoch);
				const epoch = harness.currentEpoch;
				const faspPeers = harness.state.faspPeers;
				const candidates = harness.state.mcpCandidates;
				ctx.ui.notify(
					[
						`agent_id: ${epoch.agent_id}`,
						`epoch: #${epoch.epoch_number} (${epoch.transition})`,
						`purpose: ${epoch.purpose}`,
						`capability_categories: ${epoch.capability_categories.join(", ")}`,
						`declared_capabilities: ${detail?.declared_capabilities.join(", ") ?? "(not disclosed)"}`,
						`known_limitations: ${detail?.known_limitations.join("; ") ?? "(not disclosed)"}`,
						`connected MCP servers: ${mcpRegistryFor(ctx.cwd).listConnectedServers().join(", ") || "(none)"}`,
						`remembered MCP servers (reconnect on start): ${harness.state.mcpServers.map((s) => s.name).join(", ") || "(none)"}`,
						`pre-approved MCP candidates (for /aic-mcp-auto): ${candidates.map((c) => `${c.name}[${c.provides.join("+")}]`).join(", ") || "(none)"}`,
						`FASP peers: ${faspPeers.map((p) => `${p.baseUrl}=${p.state}`).join(", ") || "(none)"}`,
						"chain: verified OK",
					].join("\n"),
					"info",
				);
			} catch (error) {
				ctx.ui.notify(
					`agent-id-card: verification FAILED: ${(error as Error).message}`,
					"error",
				);
			}
		},
	});

	pi.registerCommand("aic-reconcile", {
		description:
			"Reconcile this workspace's Agent ID Card against recorded experience and pi's current toolset.",
		async handler(_args, ctx) {
			const harness = harnessFor(ctx.cwd);
			if (!harness.isBootstrapped) {
				ctx.ui.notify(
					"agent-id-card: no identity yet for this workspace.",
					"info",
				);
				return;
			}
			const report = harness.reconcile(true);
			ctx.ui.notify(
				report.changed
					? `agent-id-card: reconciled -> epoch #${report.newEpochNumber}. capabilities: ${report.capabilitiesAfter.join(", ")}`
					: "agent-id-card: nothing to reconcile; the card already matches recorded experience and pi's current toolset.",
				"info",
			);
		},
	});

	pi.registerCommand("aic-mcp-connect", {
		description:
			"Connect to an MCP server and remember it for future sessions: /aic-mcp-connect <name> stdio <command> [args...]  |  /aic-mcp-connect <name> http <url>",
		async handler(args, ctx) {
			const [name, transport, ...rest] = args
				.trim()
				.split(/\s+/)
				.filter(Boolean);
			const config = name ? parseMcpServerArgs(name, transport, rest) : null;
			if (!config) {
				ctx.ui.notify(
					"usage: /aic-mcp-connect <name> <stdio|http> <command-or-url> [args...]",
					"error",
				);
				return;
			}
			try {
				const harness = harnessFor(ctx.cwd);
				const tools = await connectAndRegister(
					pi,
					harness,
					mcpRegistryFor(ctx.cwd),
					config,
				);
				harness.state.rememberMcpServer(config);
				ctx.ui.notify(
					`agent-id-card: connected to MCP server "${config.name}" (${tools.length} tool(s): ${tools.map((tool) => tool.toolName).join(", ") || "none"}) -- remembered for future sessions.`,
					"info",
				);
			} catch (error) {
				ctx.ui.notify(
					`agent-id-card: MCP connect to "${config.name}" failed: ${(error as Error).message}`,
					"error",
				);
			}
		},
	});

	pi.registerCommand("aic-mcp-disconnect", {
		description:
			"Disconnect a previously connected MCP server, and stop reconnecting it automatically: /aic-mcp-disconnect <name>",
		async handler(args, ctx) {
			const name = args.trim();
			if (!name) {
				ctx.ui.notify("usage: /aic-mcp-disconnect <name>", "error");
				return;
			}
			await mcpRegistryFor(ctx.cwd).disconnectServer(name);
			const harness = harnessFor(ctx.cwd);
			harness.state.forgetMcpServer(name);
			if (harness.isBootstrapped)
				harness.log.append("mcp.disconnected", { server: name });
			ctx.ui.notify(
				`agent-id-card: disconnected MCP server "${name}" and will no longer reconnect it automatically.`,
				"info",
			);
		},
	});

	pi.registerCommand("aic-mcp-allow", {
		description:
			"Pre-approve an MCP server for this agent to connect to on its own initiative (see /aic-mcp-auto): /aic-mcp-allow <name> <provides-csv> <stdio|http> <command-or-url> [args...]",
		async handler(args, ctx) {
			const [name, providesCsv, transport, ...rest] = args
				.trim()
				.split(/\s+/)
				.filter(Boolean);
			const config = name ? parseMcpServerArgs(name, transport, rest) : null;
			if (!config || !providesCsv) {
				ctx.ui.notify(
					"usage: /aic-mcp-allow <name> <provides-csv> <stdio|http> <command-or-url> [args...]",
					"error",
				);
				return;
			}
			const candidate: McpCandidate = {
				...config,
				provides: providesCsv.split(",").filter(Boolean),
			};
			harnessFor(ctx.cwd).state.addMcpCandidate(candidate);
			ctx.ui.notify(
				`agent-id-card: "${name}" pre-approved as an MCP candidate providing: ${candidate.provides.join(", ")}. Use /aic-mcp-auto ${candidate.provides[0] ?? ""} to connect it.`,
				"info",
			);
		},
	});

	pi.registerCommand("aic-mcp-auto", {
		description:
			"Connect, on this agent's own initiative, to a pre-approved MCP candidate providing the given capability: /aic-mcp-auto [capability-hint]",
		async handler(args, ctx) {
			const harness = harnessFor(ctx.cwd);
			const hint = args.trim() || undefined;
			const [candidate] = harness.state.unconnectedCandidates(hint);
			if (!candidate) {
				ctx.ui.notify(
					hint
						? `agent-id-card: no pre-approved, not-yet-connected MCP candidate provides "${hint}". Use /aic-mcp-allow to pre-approve one first.`
						: "agent-id-card: no pre-approved, not-yet-connected MCP candidates. Use /aic-mcp-allow to pre-approve one first.",
					"info",
				);
				return;
			}
			try {
				const tools = await connectAndRegister(
					pi,
					harness,
					mcpRegistryFor(ctx.cwd),
					candidate,
				);
				harness.state.rememberMcpServer(candidate);
				ctx.ui.notify(
					`agent-id-card: connected itself to pre-approved MCP server "${candidate.name}" (providing ${candidate.provides.join(", ")}; ${tools.length} tool(s) gained).`,
					"info",
				);
			} catch (error) {
				ctx.ui.notify(
					`agent-id-card: self-connect to "${candidate.name}" failed: ${(error as Error).message}`,
					"error",
				);
			}
		},
	});

	pi.registerCommand("aic-fasp-connect", {
		description:
			"Pair with a FASP harness as one of its peers (default http://127.0.0.1:8766, or set AIC_FASP_URL): /aic-fasp-connect [baseUrl]",
		async handler(args, ctx) {
			const harness = harnessFor(ctx.cwd);
			const baseUrl =
				args.trim() || process.env.AIC_FASP_URL || DEFAULT_FASP_URL;
			const adminToken = resolveFaspAdminToken();
			const result = await harness.connectFaspPeer(
				baseUrl,
				`pi@${process.env.HOSTNAME ?? "workspace"}`,
				pi.getAllTools().map((tool) => tool.name),
				{ adminToken },
			);
			ctx.ui.notify(
				result.state === "failed"
					? `agent-id-card: FASP pairing with ${baseUrl} failed: ${result.error}`
					: `agent-id-card: FASP pairing with ${baseUrl} -> ${result.state}${result.state === "pending" ? " (waiting for that harness's operator to confirm; set AIC_FASP_ADMIN_TOKEN or AIC_FASP_STATE_DIR to self-confirm when you control both sides)" : ""}.`,
				result.state === "failed" ? "error" : "info",
			);
		},
	});

	pi.registerCommand("aic-fasp-peers", {
		description:
			"List FASP peers (physical or AI agents): live from a harness if AIC_FASP_ADMIN_TOKEN/AIC_FASP_STATE_DIR is set, else this agent's own recollection: /aic-fasp-peers [baseUrl]",
		async handler(args, ctx) {
			const harness = harnessFor(ctx.cwd);
			const baseUrl =
				args.trim() || process.env.AIC_FASP_URL || DEFAULT_FASP_URL;
			const adminToken = resolveFaspAdminToken();
			try {
				const peers = await harness.faspPeers({ baseUrl, adminToken });
				ctx.ui.notify(
					adminToken
						? `FASP peers known to ${baseUrl}:\n${JSON.stringify(peers, null, 2)}`
						: `This agent's own recorded FASP pairings (no admin token available for a live fleet-wide list):\n${JSON.stringify(peers, null, 2)}`,
					"info",
				);
			} catch (error) {
				ctx.ui.notify(
					`agent-id-card: could not list FASP peers: ${(error as Error).message}`,
					"error",
				);
			}
		},
	});
}

// Re-exported for anything that wants to verify this workspace's chain,
// or drive MCP connectivity, programmatically without going through the
// session commands above.
export { verifyChain, AgentHarness, McpRegistry };
