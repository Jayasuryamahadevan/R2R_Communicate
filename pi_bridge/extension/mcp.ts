/**
 * Generic MCP (Model Context Protocol) client: connect this bridge to
 * ANY MCP server -- stdio (spawns a local process) or Streamable HTTP
 * (a remote endpoint) -- and dynamically surface its tools as pi tools.
 *
 * pi deliberately ships without built-in MCP support (by design, left
 * to extensions); this module is that extension's MCP layer. Every
 * tool gained from a newly connected server is recorded as a
 * `capability_discovered` experience entry (see harness.ts), so
 * connecting to a new MCP server naturally flows into the Agent ID
 * Card's next reconciliation instead of silently expanding what this
 * agent can do without that ever being reflected in its own card.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

export interface McpServerConfig {
	name: string;
	transport: "stdio" | "http";
	/** stdio only: the command to spawn. */
	command?: string;
	args?: string[];
	env?: Record<string, string>;
	/** http only: the Streamable HTTP endpoint URL. */
	url?: string;
	headers?: Record<string, string>;
}

export interface McpToolDescriptor {
	serverName: string;
	/** Namespaced so tools from different servers never collide: `mcp__<server>__<tool>`. */
	qualifiedName: string;
	toolName: string;
	description?: string;
	inputSchema: unknown;
}

function buildTransport(config: McpServerConfig): Transport {
	if (config.transport === "stdio") {
		if (!config.command)
			throw new Error(
				`MCP server "${config.name}": stdio transport requires a command.`,
			);
		return new StdioClientTransport({
			command: config.command,
			args: config.args ?? [],
			env: config.env,
		});
	}
	if (config.transport === "http") {
		if (!config.url)
			throw new Error(
				`MCP server "${config.name}": http transport requires a url.`,
			);
		return new StreamableHTTPClientTransport(
			new URL(config.url),
			config.headers ? { requestInit: { headers: config.headers } } : undefined,
		);
	}
	throw new Error(
		`MCP server "${config.name}": unknown transport "${config.transport}".`,
	);
}

export class McpConnection {
	readonly config: McpServerConfig;
	private readonly client: Client;
	private connected = false;

	constructor(config: McpServerConfig) {
		this.config = config;
		this.client = new Client({
			name: "agent-id-card-bridge",
			version: "1.0.0",
		});
	}

	async connect(): Promise<McpToolDescriptor[]> {
		await this.client.connect(buildTransport(this.config));
		this.connected = true;
		const { tools } = await this.client.listTools();
		return tools.map((tool) => ({
			serverName: this.config.name,
			qualifiedName: `mcp__${this.config.name}__${tool.name}`,
			toolName: tool.name,
			description: tool.description,
			inputSchema: tool.inputSchema,
		}));
	}

	async callTool(
		toolName: string,
		args: Record<string, unknown>,
	): Promise<unknown> {
		if (!this.connected)
			throw new Error(`MCP server "${this.config.name}" is not connected.`);
		return this.client.callTool({ name: toolName, arguments: args });
	}

	async close(): Promise<void> {
		if (this.connected) {
			await this.client.close();
			this.connected = false;
		}
	}
}

/** Tracks every MCP server this bridge instance has connected to, keyed by name. */
export class McpRegistry {
	private readonly connections = new Map<string, McpConnection>();

	async connectServer(config: McpServerConfig): Promise<McpToolDescriptor[]> {
		if (this.connections.has(config.name)) {
			throw new Error(
				`Already connected to an MCP server named "${config.name}"; disconnect it first.`,
			);
		}
		const connection = new McpConnection(config);
		const tools = await connection.connect();
		this.connections.set(config.name, connection);
		return tools;
	}

	async disconnectServer(name: string): Promise<void> {
		const connection = this.connections.get(name);
		if (!connection) return;
		await connection.close();
		this.connections.delete(name);
	}

	getConnection(name: string): McpConnection | undefined {
		return this.connections.get(name);
	}

	listConnectedServers(): string[] {
		return [...this.connections.keys()];
	}

	async closeAll(): Promise<void> {
		await Promise.all(
			[...this.connections.values()].map((connection) => connection.close()),
		);
		this.connections.clear();
	}
}
