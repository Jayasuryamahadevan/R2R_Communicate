/**
 * A minimal FASP (../fasp_harness/) peer client: enough for this agent
 * to introduce itself to a FASP harness as a peer (`hello`), get itself
 * confirmed when it holds that harness's admin token (only meaningful
 * when the same operator runs both sides of one machine), and see who
 * else that harness already knows about (`/peers`, admin-only) -- the
 * concrete mechanism behind "what physical or AI agents am I connected
 * to". This does not run FASP's own HTTP server itself -- `endpoints` in
 * the id_card this builds are honestly `null` rather than fabricated --
 * but `openChannel()` gives it a real, persistent, autonomous receive
 * path anyway: a live `/fasp/v1/channel` websocket connection a peer can
 * push results to without this agent ever polling for them.
 *
 * Speaks the real wire protocol (fasp_harness/transport/http_app.py,
 * fasp_harness/core.py) over plain `fetch` and, for the channel, the
 * platform `WebSocket`: RFC 8785 canonicalization + Ed25519, exactly
 * like crypto.ts, but FASP's own record shape -- `fasp:system:<hash>`
 * identities and a `{alg, kid, value}` signature block, not AIC's
 * `aic:agent:<hash>` / `{alg, value}` -- so it gets its own small
 * sign/verify here rather than repurposing crypto.ts's, which is
 * intentionally scoped to AIC's own schemas.
 */

import {
	createHash,
	sign as nodeSign,
	verify as nodeVerify,
	randomBytes,
} from "node:crypto";
import { join } from "node:path";
import {
	type AgentIdentity,
	AICError,
	b64,
	canonicalize,
	generateIdentity,
	identityFromRawPrivateKey,
	privateKeyRawBytes,
	publicKeyFromRaw,
	unb64,
} from "./crypto.js";
import { readJson, writeJson } from "./fsjson.js";
import { stamp } from "./timestamps.js";

const PROTOCOL = "fasp/1.0";
const CARD_VALIDITY_MS = 30 * 24 * 60 * 60 * 1000;
const ENVELOPE_VALIDITY_MS = 5 * 60 * 1000;

interface StoredFaspIdentity {
	system_id: string;
	kid: string;
	public_key: string;
	private_key: string;
}

export interface FaspIdCard {
	fasp: string;
	type: "id_card";
	system_id: string;
	display_name: string;
	public_key: string;
	capabilities: string[];
	endpoints: Record<string, null>;
	issued_at: string;
	expires_at: string;
	signature: { alg: "Ed25519"; kid: string; value: string };
}

export interface FaspHelloResult {
	fasp: string;
	type: "hello.ready";
	/** The remote FASP harness's own system_id -- NOT this agent's. */
	system_id: string;
	id_card: Record<string, unknown>;
	pair_code: string;
	pairing_required: boolean;
}

function faspSystemIdFor(publicKeyB64: string): string {
	return `fasp:system:${b64(createHash("sha256").update(unb64(publicKeyB64)).digest())}`;
}

function faspSign(
	record: Record<string, unknown>,
	identity: AgentIdentity,
	kid: string,
): Record<string, unknown> {
	const { signature: _signature, ...unsigned } = record;
	const value = b64(
		nodeSign(null, canonicalize(unsigned), identity.privateKey),
	);
	return { ...unsigned, signature: { alg: "Ed25519", kid, value } };
}

/** Mirrors fasp_harness/core.py's `FaspHarness.verify_id_card()` exactly
 * -- schema, expiry, signature, and identity-matches-key, in that order.
 * A real, confirmed gap this closes: without this, `hello()` trusted
 * WHATEVER `system_id`/`id_card` a server claimed with zero
 * verification -- proved by standing up a plain HTTP server that
 * returned a completely fabricated identity (an unrelated system_id, an
 * empty/garbage signature) and watching `connectFaspPeer()` accept it
 * and report `state: "paired"`. */
function verifyFaspIdCard(card: Record<string, unknown>): void {
	const required = [
		"fasp",
		"type",
		"system_id",
		"public_key",
		"endpoints",
		"expires_at",
		"signature",
	];
	if (
		!required.every((key) => key in card) ||
		card.fasp !== PROTOCOL ||
		card.type !== "id_card"
	) {
		throw new AICError("schema.invalid", "Invalid FASP ID card.");
	}
	const expiresAt = card.expires_at;
	if (typeof expiresAt !== "string" || Date.parse(expiresAt) <= Date.now()) {
		throw new AICError("auth.card_expired", "ID card has expired.");
	}
	const signature = card.signature as
		| { alg?: string; kid?: string; value?: string }
		| undefined;
	if (
		!signature ||
		signature.alg !== "Ed25519" ||
		typeof signature.value !== "string"
	) {
		throw new AICError(
			"auth.invalid_signature",
			"ID card has no valid signature.",
		);
	}
	const publicKeyB64 = card.public_key;
	if (typeof publicKeyB64 !== "string") {
		throw new AICError("schema.invalid", "ID card is missing public_key.");
	}
	const { signature: _signature, ...unsigned } = card;
	const publicKey = publicKeyFromRaw(unb64(publicKeyB64));
	const ok = nodeVerify(
		null,
		canonicalize(unsigned),
		publicKey,
		unb64(signature.value),
	);
	if (!ok) {
		throw new AICError(
			"auth.invalid_signature",
			"ID card signature does not verify against its own public_key.",
		);
	}
	const expectedSystemId = faspSystemIdFor(publicKeyB64);
	if (card.system_id !== expectedSystemId) {
		throw new AICError(
			"auth.identity_mismatch",
			"ID card's system_id does not match sha256(public_key) -- this card was not honestly derived from its own claimed key.",
		);
	}
}

const MAX_NETWORK_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 200;

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A rejection this agent should never retry blindly: a real answer
 * from a peer that IS reachable (bad auth, bad schema, not authorized)
 * -- retrying changes nothing and just delays surfacing it. Everything
 * else thrown inside `withNetworkRetry` (fetch itself throwing --
 * connection refused/reset/timed out -- or a 5xx from a transiently
 * overloaded peer) is treated as retryable. */
class NonRetryableError extends Error {}

/** A dropped connection (packet loss severe enough to time out or reset
 * the TCP stream, not the odd lost segment TCP already retransmits on
 * its own) surfaces here as `fetch` throwing; a 5xx is a peer that's
 * transiently overloaded. Both get retried with exponential backoff +
 * jitter. This is safe to retry blindly because every caller sends its
 * own idempotency_key (envelopes) or is naturally idempotent
 * (hello/confirm/peers) -- fasp_harness's own `inbox.insert_if_new`
 * (core.py) is the other half of this: a retried request that DID land,
 * whose response just got lost on the way back, replays the original
 * recorded outcome instead of re-running it. */
async function withNetworkRetry<T>(attempt: () => Promise<T>): Promise<T> {
	let lastError: unknown;
	for (let retry = 0; retry <= MAX_NETWORK_RETRIES; retry++) {
		try {
			return await attempt();
		} catch (error) {
			if (error instanceof NonRetryableError) throw error;
			lastError = error;
			if (retry === MAX_NETWORK_RETRIES) break;
			const backoff = RETRY_BASE_DELAY_MS * 2 ** retry;
			const jitter = Math.random() * backoff * 0.5;
			await sleep(backoff + jitter);
		}
	}
	throw lastError;
}

/** Every real FASP response this client expects is a handful of KB (an
 * id_card, a hello result, a peer roster) -- generous enough to cover a
 * large fleet's `/peers` listing, but bounded, because nothing here
 * should ever have to trust a peer's `Content-Length` (a hostile or
 * merely broken peer can lie about it or omit it entirely) to know how
 * much it's about to buffer into memory.
 *
 * A real, confirmed gap this closes: without it, a peer answering 200 OK
 * with an unbounded body made `response.json()`/`response.text()` buffer
 * the entire thing before this client saw a single byte -- proved by a
 * server that kept streaming past the point this process's RSS crossed
 * 3 GiB (a real OOM-kill on any normally-provisioned host), with no
 * timeout or size check anywhere in the unpatched path to stop it. */
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

async function readBoundedText(
	response: Response,
	url: string,
): Promise<string> {
	const body = response.body;
	if (!body) return "";
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > MAX_RESPONSE_BYTES) {
			await reader.cancel().catch(() => {});
			throw new NonRetryableError(
				`Response from ${url} exceeded ${MAX_RESPONSE_BYTES} bytes -- refusing to buffer further. A real FASP response is a few KB; this means either a hostile peer or a serious bug on the other end, not something a retry would fix.`,
			);
		}
		chunks.push(value);
	}
	return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString(
		"utf-8",
	);
}

async function readBoundedJson(
	response: Response,
	url: string,
): Promise<Record<string, unknown>> {
	const text = await readBoundedText(response, url);
	try {
		return JSON.parse(text) as Record<string, unknown>;
	} catch (error) {
		throw new NonRetryableError(
			`Response from ${url} was not valid JSON (${(error as Error).message}).`,
		);
	}
}

async function postJson(
	url: string,
	body: Record<string, unknown>,
	extraHeaders: Record<string, string> = {},
): Promise<Record<string, unknown>> {
	return withNetworkRetry(async () => {
		const response = await fetch(url, {
			method: "POST",
			headers: { "content-type": "application/json", ...extraHeaders },
			body: JSON.stringify(body),
		});
		if (!response.ok) {
			const detail = `POST ${url} failed: HTTP ${response.status} ${await readBoundedText(response, url)}`;
			if (response.status >= 500) throw new Error(detail);
			throw new NonRetryableError(detail);
		}
		return readBoundedJson(response, url);
	});
}

export class FaspClient {
	private readonly identityPath: string;

	constructor(stateDir: string) {
		this.identityPath = join(stateDir, "fasp_identity.json");
	}

	private loadOrCreateIdentity(): {
		identity: AgentIdentity;
		kid: string;
		systemId: string;
	} {
		const stored = readJson<StoredFaspIdentity | null>(this.identityPath, null);
		if (stored) {
			return {
				identity: identityFromRawPrivateKey(unb64(stored.private_key)),
				kid: stored.kid,
				systemId: stored.system_id,
			};
		}
		const identity = generateIdentity();
		const systemId = faspSystemIdFor(identity.publicB64);
		const kid = `ed25519-${identity.publicB64.slice(0, 8)}`;
		writeJson(
			this.identityPath,
			{
				system_id: systemId,
				kid,
				public_key: identity.publicB64,
				private_key: b64(privateKeyRawBytes(identity.privateKey)),
			} satisfies StoredFaspIdentity,
			0o600,
		);
		return { identity, kid, systemId };
	}

	get systemId(): string {
		return this.loadOrCreateIdentity().systemId;
	}

	/** Builds this agent's own signed FASP id_card -- a client-only
	 * participant, so every entry in `endpoints` is honestly `null`
	 * rather than a URL nothing is actually listening on. */
	buildIdCard(displayName: string, capabilities: string[]): FaspIdCard {
		const { identity, kid, systemId } = this.loadOrCreateIdentity();
		const issuedAt = stamp();
		const unsigned = {
			fasp: PROTOCOL,
			type: "id_card" as const,
			system_id: systemId,
			display_name: displayName,
			public_key: identity.publicB64,
			capabilities,
			endpoints: {
				profile: null,
				pair_hello: null,
				envelopes: null,
				receipts: null,
				channel: null,
			},
			issued_at: issuedAt,
			expires_at: stamp(new Date(Date.parse(issuedAt) + CARD_VALIDITY_MS)),
		};
		return faspSign(unsigned, identity, kid) as unknown as FaspIdCard;
	}

	/** `POST /pair/hello`: introduce this agent's id_card to a FASP
	 * harness. Returns that harness's own pair_code for this pairing
	 * attempt (needed for `confirmSelf`) and whether it's already paired
	 * from a prior hello.
	 *
	 * The returned `id_card` is verified the same way fasp_harness's own
	 * `hello()` verifies ours (signature, expiry, system_id-matches-key)
	 * before this method trusts anything in it, and the top-level
	 * `system_id` is cross-checked against that card's own -- without
	 * this, whatever answered at `baseUrl` could claim to be any peer at
	 * all with zero cryptographic backing (confirmed by actually doing
	 * that against the unpatched version of this method). */
	async hello(baseUrl: string, idCard: FaspIdCard): Promise<FaspHelloResult> {
		const body = await postJson(`${baseUrl.replace(/\/$/, "")}/pair/hello`, {
			id_card: idCard,
		});
		const result = body as unknown as FaspHelloResult;
		if (result.type !== "hello.ready" || typeof result.system_id !== "string") {
			throw new AICError(
				"schema.invalid",
				`Malformed hello response from ${baseUrl}.`,
			);
		}
		verifyFaspIdCard(result.id_card);
		if (result.id_card.system_id !== result.system_id) {
			throw new AICError(
				"auth.identity_mismatch",
				`${baseUrl} answered as ${result.system_id} but returned an id_card for a different system_id -- refusing to trust it.`,
			);
		}
		return result;
	}

	/** `POST /pair/confirm`: only succeeds with that FASP harness's own
	 * admin token -- i.e. only when the same operator controls both
	 * sides, or has otherwise granted this agent that token on purpose. */
	async confirmSelf(
		baseUrl: string,
		peerId: string,
		pairCode: string,
		adminToken: string,
	): Promise<void> {
		await postJson(
			`${baseUrl.replace(/\/$/, "")}/pair/confirm`,
			{ peer_id: peerId, pair_code: pairCode },
			{ "X-FASP-Admin-Token": adminToken },
		);
	}

	/** `GET /peers`: every peer (physical or AI agent) that FASP harness
	 * has ever paired with -- admin-only, since it's that harness's full
	 * fleet roster, not just this agent's own pairing. */
	async listPeers(
		baseUrl: string,
		adminToken: string,
	): Promise<Record<string, unknown>> {
		return withNetworkRetry(async () => {
			const response = await fetch(`${baseUrl.replace(/\/$/, "")}/peers`, {
				headers: { "X-FASP-Admin-Token": adminToken },
			});
			if (!response.ok) {
				const detail = `GET /peers at ${baseUrl} failed: HTTP ${response.status}`;
				if (response.status >= 500) throw new Error(detail);
				throw new NonRetryableError(detail);
			}
			return readBoundedJson(response, baseUrl);
		});
	}

	/** Actually use a completed pairing: propose an intent (`kind:
	 * "intent.propose"`) to `toSystemId` at `baseUrl` for one of the
	 * capabilities that peer granted at pairing time (default
	 * `observe.`/`coordinate.` prefixes -- see fasp_harness's `hello()`).
	 * Pairing alone only establishes trust; this is what turns that trust
	 * into a real, signed request-response exchange between two agents.
	 *
	 * `payload` is whatever fields that capability's adapter expects
	 * (`coordinate.chat.v1` wants `{ objective }`; a custom capability can
	 * want anything else entirely) -- this method only owns the envelope
	 * fields every intent needs regardless of capability (idempotency
	 * key, timestamps, signature), never the shape of the capability
	 * itself. */
	async proposeIntent(
		baseUrl: string,
		toSystemId: string,
		capability: string,
		payload: Record<string, unknown>,
	): Promise<Record<string, unknown>> {
		return this.sendEnvelope(baseUrl, "intent.propose", toSystemId, {
			idempotency_key: `idem-${b64(randomBytes(12))}`,
			capability,
			...payload,
		});
	}

	/** Build and sign one FASP envelope of any `kind`
	 * (`intent.propose`/`reservation.request`/`heartbeat`/...) -- the one
	 * piece every transport (an HTTP POST to `/fasp/v1/envelopes`, or a
	 * frame on the persistent `/fasp/v1/channel` websocket) needs
	 * identically. Never sends it anywhere itself. */
	buildEnvelope(
		kind: string,
		toSystemId: string,
		payload: Record<string, unknown>,
	): Record<string, unknown> {
		const { identity, kid, systemId } = this.loadOrCreateIdentity();
		const issuedAt = stamp();
		const envelope = {
			fasp: PROTOCOL,
			kind,
			message_id: `msg-${b64(randomBytes(12))}`,
			from: systemId,
			to: toSystemId,
			issued_at: issuedAt,
			expires_at: stamp(new Date(Date.parse(issuedAt) + ENVELOPE_VALIDITY_MS)),
			nonce: b64(randomBytes(16)),
			payload,
		};
		return faspSign(envelope, identity, kid);
	}

	/** The general case `proposeIntent` is one instance of: build, sign,
	 * and POST any FASP envelope `kind` (`reservation.request`,
	 * `reservation.release`, `heartbeat`, ...), not just `intent.propose`.
	 * `payload` is entirely that kind's own concern, unvalidated here. */
	async sendEnvelope(
		baseUrl: string,
		kind: string,
		toSystemId: string,
		payload: Record<string, unknown>,
	): Promise<Record<string, unknown>> {
		const signed = this.buildEnvelope(kind, toSystemId, payload);
		return postJson(`${baseUrl.replace(/\/$/, "")}/fasp/v1/envelopes`, signed);
	}

	/** Open a persistent connection to a FASP harness's
	 * `/fasp/v1/channel` websocket -- the real answer to "communicate
	 * autonomously, without either side polling": the first envelope
	 * frame sent on it registers this connection for push delivery
	 * (fasp_harness/channels.py's `ConnectionRegistry`), so a task that
	 * outlives its synchronous wait budget (`max_runtime_s`) gets its
	 * real result delivered here the moment it's ready, with nobody
	 * asking "did you get a new message" -- see fasp_harness/core.py's
	 * `_apply_task_outcome`/`_on_adapter_done`.
	 *
	 * `onMessage` fires for every frame this channel receives: the
	 * immediate response to whatever this agent sends over it (a
	 * `task.progress` if a task's synchronous window has already
	 * elapsed), any later `task.push` for that same task, and anything
	 * else pushed to this agent's system_id independently of a request it
	 * made (fasp_harness/core.py also pushes stream messages the same
	 * way). Node's built-in global `WebSocket` -- no dependency, matching
	 * the rest of this file.
	 *
	 * Reconnects on its own, with backoff, if the connection drops after
	 * being established -- a real, confirmed gap this closes: without it,
	 * killing and restarting the harness mid-session (a redeploy, a
	 * network blip, anything short of the caller itself calling
	 * `close()`) left this channel silently, permanently dead. Proved by
	 * doing exactly that against a real running harness: the socket
	 * closed, nothing reconnected, and 20+ seconds of heartbeats sent
	 * afterward -- including well after the harness was healthy and
	 * answering `/health` again -- produced zero further messages. A
	 * demo or a long-running agent that opens a channel once and expects
	 * it to just keep working cannot tolerate that.
	 *
	 * `onStatusChange`, if given, fires `"open"` on every successful
	 * (re)connect and `"reconnecting"` the instant an established
	 * connection drops -- purely informational, since reconnection itself
	 * is automatic; a caller that doesn't care can omit it entirely. */
	async openChannel(
		baseUrl: string,
		onMessage: (message: Record<string, unknown>) => void,
		onStatusChange?: (status: "open" | "reconnecting" | "closed") => void,
	): Promise<FaspChannel> {
		const { systemId } = this.loadOrCreateIdentity();
		const wsUrl = `${baseUrl.replace(/^http/, "ws").replace(/\/$/, "")}/fasp/v1/channel`;
		let socket: WebSocket;
		let closedByCaller = false;
		let reconnectAttempt = 0;
		// Outgoing frames sent while reconnecting are held, not dropped or
		// thrown away silently -- flushed the moment the next connection
		// lands. Bounded because a harness that stays down for a long time
		// must not turn a slow reconnect loop into unbounded memory growth
		// (the same reasoning as `MAX_RESPONSE_BYTES` above, just for the
		// outbound side of this same client).
		const pending: string[] = [];
		const MAX_QUEUED = 50;

		const connectOnce = (): Promise<WebSocket> =>
			new Promise((resolve, reject) => {
				const attempt = new WebSocket(wsUrl);
				attempt.addEventListener("open", () => resolve(attempt), {
					once: true,
				});
				attempt.addEventListener(
					"error",
					() => reject(new Error(`Could not open FASP channel at ${wsUrl}`)),
					{ once: true },
				);
			});

		const scheduleReconnect = (): void => {
			reconnectAttempt += 1;
			const backoff = Math.min(
				RECONNECT_MAX_DELAY_MS,
				RECONNECT_BASE_DELAY_MS * 2 ** (reconnectAttempt - 1),
			);
			const jitter = Math.random() * backoff * 0.5;
			setTimeout(async () => {
				if (closedByCaller) return;
				try {
					socket = await connectOnce();
					reconnectAttempt = 0;
					onStatusChange?.("open");
					attachHandlers();
					// The server registers a new socket for push delivery off
					// the `from` of the FIRST frame it sees on it (see
					// channel_endpoint in http_app.py) -- flushing whatever was
					// actually queued does that; if nothing was queued, an
					// explicit heartbeat still re-registers this connection so
					// the caller doesn't have to know reconnection happened at
					// all to keep receiving pushes.
					if (pending.length > 0) {
						flushPending();
					} else {
						socket.send(
							JSON.stringify(this.buildEnvelope("heartbeat", systemId, {})),
						);
					}
				} catch {
					scheduleReconnect();
				}
			}, backoff + jitter);
		};

		const flushPending = (): void => {
			while (pending.length > 0 && socket.readyState === WebSocket.OPEN) {
				socket.send(pending.shift() as string);
			}
		};

		const attachHandlers = (): void => {
			socket.addEventListener("message", (event) => {
				try {
					onMessage(JSON.parse(event.data as string));
				} catch {
					// A malformed frame is dropped, not fatal to the channel --
					// this is a best-effort optimization layer by design (see
					// channels.py), never the only path to a result.
				}
			});
			socket.addEventListener("close", () => {
				if (closedByCaller) {
					onStatusChange?.("closed");
					return;
				}
				onStatusChange?.("reconnecting");
				scheduleReconnect();
			});
		};

		socket = await connectOnce();
		attachHandlers();

		return {
			send: (envelope) => {
				const line = JSON.stringify(envelope);
				if (socket.readyState === WebSocket.OPEN) {
					socket.send(line);
					return;
				}
				if (pending.length >= MAX_QUEUED) {
					throw new AICError(
						"channel.queue_full",
						`FASP channel to ${baseUrl} has been reconnecting long enough that ${MAX_QUEUED} queued outgoing envelopes is the limit -- this one was dropped rather than buffered forever.`,
					);
				}
				pending.push(line);
			},
			close: () => {
				closedByCaller = true;
				socket.close();
			},
		};
	}
}

/** A short base delay and a low cap on purpose: this is a long-lived
 * background connection a caller opens once and expects to "just keep
 * working" (see `openChannel`'s own doc comment) -- a brief network
 * blip or a harness restart during a live demo has to recover in
 * single-digit seconds, not tens of seconds, for that promise to hold.
 * Still exponential + jittered so a harness that's down for a while
 * doesn't get hammered every 300ms forever. */
const RECONNECT_BASE_DELAY_MS = 300;
const RECONNECT_MAX_DELAY_MS = 5_000;

export interface FaspChannel {
	/** Send an already-built, already-signed envelope (see
	 * `buildEnvelope()`) as a raw frame on this channel. Queued (bounded)
	 * rather than lost if the channel is mid-reconnect when this is
	 * called. */
	send(envelope: Record<string, unknown>): void;
	close(): void;
}
