/**
 * A minimal FASP (../fasp_harness/) peer client: enough for this agent
 * to introduce itself to a FASP harness as a peer (`hello`), get itself
 * confirmed when it holds that harness's admin token (only meaningful
 * when the same operator runs both sides of one machine), and see who
 * else that harness already knows about (`/peers`, admin-only) -- the
 * concrete mechanism behind "what physical or AI agents am I connected
 * to". This is a client only: it does not run FASP's own HTTP server,
 * so it cannot yet receive envelopes pushed back at it -- `endpoints` in
 * the id_card this builds are honestly `null` rather than fabricated.
 *
 * Speaks the real wire protocol (fasp_harness/transport/http_app.py,
 * fasp_harness/core.py) over plain `fetch`: RFC 8785 canonicalization +
 * Ed25519, exactly like crypto.ts, but FASP's own record shape --
 * `fasp:system:<hash>` identities and a `{alg, kid, value}` signature
 * block, not AIC's `aic:agent:<hash>` / `{alg, value}` -- so it gets its
 * own small sign/verify here rather than repurposing crypto.ts's, which
 * is intentionally scoped to AIC's own schemas.
 */

import { createHash, sign as nodeSign, randomBytes } from "node:crypto";
import { join } from "node:path";
import {
	type AgentIdentity,
	b64,
	canonicalize,
	generateIdentity,
	identityFromRawPrivateKey,
	privateKeyRawBytes,
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

async function postJson(
	url: string,
	body: Record<string, unknown>,
	extraHeaders: Record<string, string> = {},
): Promise<Record<string, unknown>> {
	const response = await fetch(url, {
		method: "POST",
		headers: { "content-type": "application/json", ...extraHeaders },
		body: JSON.stringify(body),
	});
	if (!response.ok) {
		throw new Error(
			`POST ${url} failed: HTTP ${response.status} ${await response.text()}`,
		);
	}
	return (await response.json()) as Record<string, unknown>;
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
	 * from a prior hello. */
	async hello(baseUrl: string, idCard: FaspIdCard): Promise<FaspHelloResult> {
		const body = await postJson(`${baseUrl.replace(/\/$/, "")}/pair/hello`, {
			id_card: idCard,
		});
		return body as unknown as FaspHelloResult;
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
		const response = await fetch(`${baseUrl.replace(/\/$/, "")}/peers`, {
			headers: { "X-FASP-Admin-Token": adminToken },
		});
		if (!response.ok) {
			throw new Error(
				`GET /peers at ${baseUrl} failed: HTTP ${response.status}`,
			);
		}
		return (await response.json()) as Record<string, unknown>;
	}

	/** Actually use a completed pairing: propose an intent (`kind:
	 * "intent.propose"`) to `toSystemId` at `baseUrl` for one of the
	 * capabilities that peer granted at pairing time (default
	 * `observe.`/`coordinate.` prefixes -- see fasp_harness's `hello()`).
	 * Pairing alone only establishes trust; this is what turns that trust
	 * into a real, signed request-response exchange between two agents. */
	async proposeIntent(
		baseUrl: string,
		toSystemId: string,
		capability: string,
		objective: string,
	): Promise<Record<string, unknown>> {
		const { identity, kid, systemId } = this.loadOrCreateIdentity();
		const issuedAt = stamp();
		const envelope = {
			fasp: PROTOCOL,
			kind: "intent.propose",
			message_id: `msg-${b64(randomBytes(12))}`,
			from: systemId,
			to: toSystemId,
			issued_at: issuedAt,
			expires_at: stamp(new Date(Date.parse(issuedAt) + ENVELOPE_VALIDITY_MS)),
			nonce: b64(randomBytes(16)),
			payload: {
				idempotency_key: `idem-${b64(randomBytes(12))}`,
				capability,
				objective,
			},
		};
		const signed = faspSign(envelope, identity, kid);
		return postJson(`${baseUrl.replace(/\/$/, "")}/fasp/v1/envelopes`, signed);
	}
}
