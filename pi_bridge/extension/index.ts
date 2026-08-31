/**
 * pi_bridge: an Agent ID Card + MCP + webhook bridge for pi
 * ==========================================================
 *
 * On first run in a workspace, pi is curious about its surroundings
 * (OS, hardware, accelerator/driver, available tools, its own toolset),
 * and turns what it honestly finds into a signed AIC identity
 * (https://github.com/Jayasuryamahadevan/agent-id-card -- SPEC.md is the
 * normative format; HARNESS_BOOTSTRAP.md is the procedure this
 * extension implements). Every tool call is recorded in an append-only,
 * hash-chained action log.
 *
 * On top of that base, this bridge lets pi connect itself to:
 *   - ANY MCP server (stdio or Streamable HTTP) -- its tools are
 *     dynamically registered as pi tools, and each one gained is
 *     recorded as a `capability_discovered` experience entry, so
 *     connecting to a new MCP server flows straight into the next
 *     `/aic-reconcile` instead of silently expanding what this agent
 *     can do without its own card ever reflecting that.
 *   - ANY webhook, in both directions -- an incoming listener that can
 *     turn an external POST into a message pi actually sees, and an
 *     outgoing notifier that POSTs to configured URLs on bootstrap,
 *     reconciliation, and tool completion.
 *
 * No external dependency for the core identity layer (Node's built-in
 * `node:crypto`/`node:http` only); the MCP layer depends on the
 * official `@modelcontextprotocol/sdk` (see package.json).
 *
 * State lives in `.aic/` under the project root -- identity.json (the
 * private key, 0600), chain.json, detail.json, sensitive.json,
 * renewal.json, action_log.jsonl, experience.jsonl.
 *
 * Commands: /aic-status, /aic-reconcile, /aic-mcp-connect,
 * /aic-mcp-disconnect, /aic-mcp-list, /aic-webhook-listen,
 * /aic-webhook-stop, /aic-webhook-notify, /aic-webhook-targets.
 */

import { join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { verifyChain } from "./epoch.js";
import { AgentHarness } from "./harness.js";
import {
	McpRegistry,
	type McpServerConfig,
	type McpToolDescriptor,
} from "./mcp.js";
import {
	collectRuntimeProvenance,
	discoverPermissionsAndNetwork,
} from "./provenance.js";
import { verifyDetail } from "./tiers.js";
import { WebhookNotifier, WebhookReceiver } from "./webhooks.js";

const PURPOSE =
	"Coding agent (pi) assisting a developer in this workspace: reads, edits, and runs commands as directed.";

function stateDirFor(cwd: string): string {
	return join(cwd, ".aic");
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

	harness.actionLog.append("environment.discovery_started", { cwd: ctx.cwd });
	const provenance = collectRuntimeProvenance();
	const permissions = discoverPermissionsAndNetwork();
	harness.actionLog.append("environment.discovered", {
		...provenance,
		...permissions,
	});

	const toolNames = pi.getAllTools().map((tool) => tool.name);
	const knownLimitations = [
		"no memory of this workspace beyond entries already written to .aic/ (session context is not preserved across process restarts unless pi's own session storage is used)",
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
					harness.actionLog.append("mcp.tool_invoked", {
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
			harness.experience.append("capability_discovered", {
				capability: tool.qualifiedName,
				source: `mcp:${serverName}`,
			});
	}
}

export default function (pi: ExtensionAPI) {
	const harnesses = new Map<string, AgentHarness>();
	const mcpRegistries = new Map<string, McpRegistry>();
	const webhookReceivers = new Map<string, WebhookReceiver>();
	const webhookNotifiers = new Map<string, WebhookNotifier>();

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

	function webhookNotifierFor(cwd: string): WebhookNotifier {
		let notifier = webhookNotifiers.get(cwd);
		if (!notifier) {
			notifier = new WebhookNotifier(
				join(stateDirFor(cwd), "webhook_outbox.jsonl"),
			);
			webhookNotifiers.set(cwd, notifier);
		}
		return notifier;
	}

	pi.on("session_start", async (_event, ctx) => {
		const harness = harnessFor(ctx.cwd);
		await bootstrapIfNeeded(harness, pi, ctx);
		await webhookNotifierFor(ctx.cwd).notify("session_start", {
			agent_id: harness.isBootstrapped ? harness.currentEpoch.agent_id : null,
		});
	});

	pi.on("tool_call", async (event, ctx) => {
		const harness = harnessFor(ctx.cwd);
		if (harness.isBootstrapped) {
			harness.actionLog.append("tool.invoked", {
				tool: event.toolName,
				tool_call_id: event.toolCallId,
			});
		}
	});

	pi.on("tool_result", async (event, ctx) => {
		const harness = harnessFor(ctx.cwd);
		if (harness.isBootstrapped) {
			harness.actionLog.append("tool.completed", {
				tool: event.toolName,
				tool_call_id: event.toolCallId,
				is_error: Boolean(event.isError),
			});
			if (event.isError) {
				await webhookNotifierFor(ctx.cwd).notify("tool_failed", {
					tool: event.toolName,
				});
			}
		}
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
				ctx.ui.notify(
					[
						`agent_id: ${epoch.agent_id}`,
						`epoch: #${epoch.epoch_number} (${epoch.transition})`,
						`purpose: ${epoch.purpose}`,
						`capability_categories: ${epoch.capability_categories.join(", ")}`,
						`declared_capabilities: ${detail?.declared_capabilities.join(", ") ?? "(not disclosed)"}`,
						`known_limitations: ${detail?.known_limitations.join("; ") ?? "(not disclosed)"}`,
						`connected MCP servers: ${mcpRegistryFor(ctx.cwd).listConnectedServers().join(", ") || "(none)"}`,
						`outgoing webhook targets: ${webhookNotifierFor(ctx.cwd).listTargets().join(", ") || "(none)"}`,
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
			await webhookNotifierFor(ctx.cwd).notify(
				"reconciled",
				report as unknown as Record<string, unknown>,
			);
		},
	});

	pi.registerCommand("aic-mcp-connect", {
		description:
			"Connect to an MCP server: /aic-mcp-connect <name> stdio <command> [args...]  |  /aic-mcp-connect <name> http <url>",
		async handler(args, ctx) {
			const [name, transport, ...rest] = args
				.trim()
				.split(/\s+/)
				.filter(Boolean);
			if (!name || (transport !== "stdio" && transport !== "http")) {
				ctx.ui.notify(
					"usage: /aic-mcp-connect <name> <stdio|http> <command-or-url> [args...]",
					"error",
				);
				return;
			}
			const config: McpServerConfig =
				transport === "stdio"
					? { name, transport, command: rest[0], args: rest.slice(1) }
					: { name, transport, url: rest[0] };
			try {
				const registry = mcpRegistryFor(ctx.cwd);
				const tools = await registry.connectServer(config);
				const harness = harnessFor(ctx.cwd);
				registerMcpTools(pi, harness, registry, name, tools);
				if (harness.isBootstrapped)
					harness.actionLog.append("mcp.connected", {
						server: name,
						transport,
						tool_count: tools.length,
					});
				ctx.ui.notify(
					`agent-id-card: connected to MCP server "${name}" (${tools.length} tool(s): ${tools.map((tool) => tool.toolName).join(", ") || "none"}).`,
					"info",
				);
			} catch (error) {
				ctx.ui.notify(
					`agent-id-card: MCP connect to "${name}" failed: ${(error as Error).message}`,
					"error",
				);
			}
		},
	});

	pi.registerCommand("aic-mcp-disconnect", {
		description:
			"Disconnect a previously connected MCP server: /aic-mcp-disconnect <name>",
		async handler(args, ctx) {
			const name = args.trim();
			if (!name) {
				ctx.ui.notify("usage: /aic-mcp-disconnect <name>", "error");
				return;
			}
			await mcpRegistryFor(ctx.cwd).disconnectServer(name);
			const harness = harnessFor(ctx.cwd);
			if (harness.isBootstrapped)
				harness.actionLog.append("mcp.disconnected", { server: name });
			ctx.ui.notify(
				`agent-id-card: disconnected MCP server "${name}".`,
				"info",
			);
		},
	});

	pi.registerCommand("aic-mcp-list", {
		description: "List currently connected MCP servers.",
		handler(_args, ctx) {
			const servers = mcpRegistryFor(ctx.cwd).listConnectedServers();
			ctx.ui.notify(
				servers.length
					? `connected MCP servers: ${servers.join(", ")}`
					: "no MCP servers currently connected.",
				"info",
			);
		},
	});

	pi.registerCommand("aic-webhook-listen", {
		description:
			"Start an incoming webhook listener: /aic-webhook-listen <port> [path]",
		async handler(args, ctx) {
			const [portText, path = "/webhook"] = args
				.trim()
				.split(/\s+/)
				.filter(Boolean);
			const port = Number(portText);
			if (!Number.isInteger(port) || port <= 0) {
				ctx.ui.notify("usage: /aic-webhook-listen <port> [path]", "error");
				return;
			}
			const key = `${ctx.cwd}:${port}`;
			if (webhookReceivers.has(key)) {
				ctx.ui.notify(
					`agent-id-card: already listening on port ${port}.`,
					"info",
				);
				return;
			}
			const harness = harnessFor(ctx.cwd);
			const receiver = new WebhookReceiver(
				path,
				async (payload) => {
					if (harness.isBootstrapped)
						harness.actionLog.append("webhook.event", { path, payload });
					await pi.sendUserMessage(
						`[webhook @ ${path}] ${JSON.stringify(payload)}`,
					);
				},
				join(stateDirFor(ctx.cwd), "webhook_inbox.jsonl"),
			);
			try {
				await receiver.listen(port);
				webhookReceivers.set(key, receiver);
				ctx.ui.notify(
					`agent-id-card: listening for webhooks on http://127.0.0.1:${port}${path}`,
					"info",
				);
			} catch (error) {
				ctx.ui.notify(
					`agent-id-card: failed to start webhook listener: ${(error as Error).message}`,
					"error",
				);
			}
		},
	});

	pi.registerCommand("aic-webhook-stop", {
		description: "Stop an incoming webhook listener: /aic-webhook-stop <port>",
		async handler(args, ctx) {
			const port = args.trim();
			const key = `${ctx.cwd}:${port}`;
			const receiver = webhookReceivers.get(key);
			if (!receiver) {
				ctx.ui.notify(
					`agent-id-card: no webhook listener on port ${port}.`,
					"info",
				);
				return;
			}
			await receiver.close();
			webhookReceivers.delete(key);
			ctx.ui.notify(
				`agent-id-card: stopped webhook listener on port ${port}.`,
				"info",
			);
		},
	});

	pi.registerCommand("aic-webhook-notify", {
		description:
			"Add an outgoing webhook target, notified on bootstrap/reconcile/tool-failure: /aic-webhook-notify <url>",
		handler(args, ctx) {
			const url = args.trim();
			if (!url) {
				ctx.ui.notify("usage: /aic-webhook-notify <url>", "error");
				return;
			}
			webhookNotifierFor(ctx.cwd).addTarget(url);
			ctx.ui.notify(
				`agent-id-card: will notify ${url} of future events.`,
				"info",
			);
		},
	});

	pi.registerCommand("aic-webhook-targets", {
		description: "List outgoing webhook targets.",
		handler(_args, ctx) {
			const targets = webhookNotifierFor(ctx.cwd).listTargets();
			ctx.ui.notify(
				targets.length
					? targets.join(", ")
					: "no outgoing webhook targets configured.",
				"info",
			);
		},
	});
}

// Re-exported for anything that wants to verify this workspace's chain,
// or drive MCP/webhook connectivity, programmatically without going
// through the session commands above.
export {
	verifyChain,
	AgentHarness,
	McpRegistry,
	WebhookReceiver,
	WebhookNotifier,
};
