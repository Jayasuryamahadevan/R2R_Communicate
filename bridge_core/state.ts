/**
 * SelfState: the one place this agent's own self-managed configuration
 * lives -- which MCP servers it should stay connected to, which ones a
 * human operator has pre-vetted as safe for it to connect to on its own
 * initiative, and which FASP peers (physical or AI agents, see
 * ../fasp_harness/) it has paired with. Plain JSON in the harness's own
 * state directory, so it survives restarts; every change made through
 * `AgentHarness` is also appended to that harness's own log (see
 * harness.ts), so "what did I connect myself to, and when" is itself
 * part of this agent's tamper-evident history, not a config file that
 * could silently drift from what actually happened.
 */

import { readJson, writeJson } from "./fsjson.js";

export interface McpServerRecord {
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

export interface McpCandidate extends McpServerRecord {
	/** Short capability tags a human operator has already vetted this
	 * server for -- e.g. ["web-search", "fetch"]. Lets this agent match
	 * "I need X" against "here is a pre-approved server that provides X"
	 * without ever inventing or reaching for a server nobody vetted. */
	provides: string[];
}

export interface FaspPeerRecord {
	baseUrl: string;
	systemId?: string;
	state: "pending" | "paired" | "failed";
	lastError?: string;
	updatedAt: string;
}

interface SelfStateData {
	mcpServers: Record<string, McpServerRecord>;
	mcpCandidates: Record<string, McpCandidate>;
	faspPeers: Record<string, FaspPeerRecord>;
}

function emptyState(): SelfStateData {
	return { mcpServers: {}, mcpCandidates: {}, faspPeers: {} };
}

export class SelfState {
	private data: SelfStateData;

	constructor(private readonly path: string) {
		this.data = {
			...emptyState(),
			...readJson<Partial<SelfStateData>>(path, {}),
		};
	}

	private save(): void {
		writeJson(this.path, this.data, 0o644);
	}

	/** Servers this agent should reconnect to on its own the next time it
	 * starts up -- populated whenever a host bridge connects one via its
	 * own MCP client and chooses to remember it. */
	get mcpServers(): McpServerRecord[] {
		return Object.values(this.data.mcpServers);
	}

	rememberMcpServer(server: McpServerRecord): void {
		this.data.mcpServers[server.name] = server;
		this.save();
	}

	forgetMcpServer(name: string): void {
		delete this.data.mcpServers[name];
		this.save();
	}

	/** Servers a human operator has pre-vetted, but that aren't
	 * necessarily connected right now -- the bounded menu this agent may
	 * pick from on its own when it decides it needs a capability none of
	 * its current tools provide. */
	get mcpCandidates(): McpCandidate[] {
		return Object.values(this.data.mcpCandidates);
	}

	addMcpCandidate(candidate: McpCandidate): void {
		this.data.mcpCandidates[candidate.name] = candidate;
		this.save();
	}

	removeMcpCandidate(name: string): void {
		delete this.data.mcpCandidates[name];
		this.save();
	}

	/** Pre-vetted candidates not already connected, optionally narrowed
	 * to ones tagged as providing `hint`. */
	unconnectedCandidates(hint?: string): McpCandidate[] {
		return this.mcpCandidates.filter(
			(candidate) =>
				!this.data.mcpServers[candidate.name] &&
				(!hint || candidate.provides.includes(hint)),
		);
	}

	get faspPeers(): FaspPeerRecord[] {
		return Object.values(this.data.faspPeers);
	}

	rememberFaspPeer(record: FaspPeerRecord): void {
		this.data.faspPeers[record.baseUrl] = record;
		this.save();
	}

	forgetFaspPeer(baseUrl: string): void {
		delete this.data.faspPeers[baseUrl];
		this.save();
	}
}
