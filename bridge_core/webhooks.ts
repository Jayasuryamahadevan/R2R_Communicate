/**
 * Generic webhook connectivity, in both directions, using only Node
 * built-ins (`node:http` + the global `fetch`) -- no external
 * dependency, same principle as crypto.ts.
 *
 * Incoming: `WebhookReceiver` starts a tiny local HTTP listener; any
 * external system (a FASP peer, GitHub, Slack, a CI pipeline) that can
 * POST JSON can trigger this agent. Every accepted request is logged
 * before being handed to the caller's own handler -- "each and every
 * movement" (HARNESS_BOOTSTRAP.md ss4) applies to what arrives over the
 * network exactly as much as to tool calls.
 *
 * Outgoing: `WebhookNotifier` posts a JSON payload to zero or more
 * configured URLs whenever told to -- bootstrap completed, a
 * reconciliation changed the card, a tool finished -- so an external
 * system can react without polling.
 */

import {
	createServer,
	type IncomingMessage,
	type Server,
	type ServerResponse,
} from "node:http";
import { AppendOnlyLog } from "./log.js";

const MAX_BODY_BYTES = 1024 * 1024;

export type IncomingWebhookHandler = (
	payload: unknown,
	headers: IncomingMessage["headers"],
) => void | Promise<void>;

export class WebhookReceiver {
	private server: Server | null = null;
	private readonly log: AppendOnlyLog;

	constructor(
		private readonly path: string,
		private readonly onEvent: IncomingWebhookHandler,
		logPath: string,
	) {
		this.log = new AppendOnlyLog(logPath);
	}

	listen(port: number, host = "127.0.0.1"): Promise<void> {
		return new Promise((resolve, reject) => {
			this.server = createServer((request, response) => {
				this.handleRequest(request, response).catch((error: unknown) => {
					this.respond(response, 500, {
						error: "internal_error",
						detail: (error as Error).message,
					});
				});
			});
			this.server.once("error", reject);
			this.server.listen(port, host, () => resolve());
		});
	}

	private async handleRequest(
		request: IncomingMessage,
		response: ServerResponse,
	): Promise<void> {
		if (request.method !== "POST" || (request.url ?? "/") !== this.path) {
			this.respond(response, 404, { error: "not_found" });
			return;
		}
		const chunks: Buffer[] = [];
		let total = 0;
		for await (const chunk of request) {
			total += (chunk as Buffer).length;
			if (total > MAX_BODY_BYTES) {
				this.respond(response, 413, { error: "payload_too_large" });
				request.destroy();
				return;
			}
			chunks.push(chunk as Buffer);
		}
		let payload: unknown;
		try {
			payload = JSON.parse(Buffer.concat(chunks).toString("utf-8") || "{}");
		} catch {
			this.respond(response, 400, { error: "invalid_json" });
			return;
		}
		this.log.append("webhook.received", {
			path: this.path,
			remote: request.socket.remoteAddress,
			contentType: request.headers["content-type"] ?? null,
		});
		await this.onEvent(payload, request.headers);
		this.respond(response, 200, { ok: true });
	}

	private respond(
		response: ServerResponse,
		status: number,
		body: unknown,
	): void {
		const text = JSON.stringify(body);
		response.writeHead(status, {
			"content-type": "application/json",
			"content-length": Buffer.byteLength(text),
		});
		response.end(text);
	}

	close(): Promise<void> {
		return new Promise((resolve) => {
			if (!this.server) {
				resolve();
				return;
			}
			this.server.close(() => resolve());
		});
	}
}

export class WebhookNotifier {
	private readonly targets = new Set<string>();
	private readonly log: AppendOnlyLog;

	constructor(logPath: string) {
		this.log = new AppendOnlyLog(logPath);
	}

	addTarget(url: string): void {
		this.targets.add(url);
	}

	removeTarget(url: string): void {
		this.targets.delete(url);
	}

	listTargets(): string[] {
		return [...this.targets];
	}

	async notify(event: string, payload: Record<string, unknown>): Promise<void> {
		const body = JSON.stringify({
			event,
			payload,
			at: new Date().toISOString(),
		});
		await Promise.all(
			[...this.targets].map(async (url) => {
				try {
					const response = await fetch(url, {
						method: "POST",
						headers: { "content-type": "application/json" },
						body,
					});
					this.log.append("webhook.sent", {
						url,
						event,
						status: response.status,
					});
				} catch (error) {
					this.log.append("webhook.send_failed", {
						url,
						event,
						error: (error as Error).message,
					});
				}
			}),
		);
	}
}
