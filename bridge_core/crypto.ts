/**
 * Ed25519 signing over a minimal RFC 8785 (JSON Canonicalization Scheme)
 * subset, using only Node's built-in `node:crypto` -- no external
 * dependency. This mirrors https://github.com/Jayasuryamahadevan/agent-id-card's
 * Python reference implementation byte-for-byte; see that repo's SPEC.md
 * (the normative spec) and NO_PYTHON.md (the canonicalization subset this
 * file implements) for the full rationale.
 *
 * The canonicalizer below is intentionally NOT a general RFC 8785
 * implementation -- it covers exactly the shapes AIC's own schemas use
 * (strings, integers, booleans, null, objects, arrays; no floats, no
 * exotic Unicode edge cases) and raises rather than silently producing
 * wrong bytes for anything outside that.
 */

import {
	createHash,
	createPrivateKey,
	createPublicKey,
	generateKeyPairSync,
	type KeyObject,
	sign as nodeSign,
	verify as nodeVerify,
} from "node:crypto";

export const ALG = "Ed25519";

// RFC 8410 fixed DER wrappers for a raw 32-byte Ed25519 key -- verified
// empirically against Node's own generateKeyPairSync('ed25519').export()
// output while writing this module, not merely recalled.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export class AICError extends Error {
	code: string;
	detail: string;
	constructor(code: string, detail: string) {
		super(`${code}: ${detail}`);
		this.code = code;
		this.detail = detail;
	}
}

export function b64(data: Buffer): string {
	return data.toString("base64url");
}

export function unb64(text: string): Buffer {
	return Buffer.from(text, "base64url");
}

export function sha256Hex(data: Buffer): string {
	return createHash("sha256").update(data).digest("hex");
}

export function digest(data: Buffer): string {
	return `sha256:${sha256Hex(data)}`;
}

function canonicalizeValue(value: unknown): string {
	if (value === null || value === undefined) return "null";
	if (typeof value === "boolean") return value ? "true" : "false";
	if (typeof value === "number") {
		if (!Number.isInteger(value)) {
			throw new AICError(
				"canonicalize.unsupported",
				"non-integer numbers are not covered by this minimal canonicalizer -- see NO_PYTHON.md.",
			);
		}
		return String(value);
	}
	if (typeof value === "string") return JSON.stringify(value);
	if (Array.isArray(value))
		return `[${value.map(canonicalizeValue).join(",")}]`;
	if (typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record).sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalizeValue(record[key])}`).join(",")}}`;
	}
	throw new AICError(
		"canonicalize.unsupported",
		`unsupported value type: ${typeof value}`,
	);
}

export function canonicalize(value: unknown): Buffer {
	return Buffer.from(canonicalizeValue(value), "utf-8");
}

export function digestOf(record: Record<string, unknown>): string {
	return digest(canonicalize(record));
}

function unsigned(record: Record<string, unknown>): Record<string, unknown> {
	const { signature: _s, predecessor_signature: _p, ...rest } = record;
	return rest;
}

export function sign(
	record: Record<string, unknown>,
	privateKey: KeyObject,
): Record<string, unknown> {
	const payload = canonicalize(unsigned(record));
	const value = b64(nodeSign(null, payload, privateKey));
	return { ...record, signature: { alg: ALG, value } };
}

export function signPredecessor(
	record: Record<string, unknown>,
	privateKey: KeyObject,
): Record<string, unknown> {
	const payload = canonicalize(unsigned(record));
	const value = b64(nodeSign(null, payload, privateKey));
	return { ...record, predecessor_signature: { alg: ALG, value } };
}

export function verify(
	record: Record<string, unknown>,
	publicKeyB64: string,
	field: "signature" | "predecessor_signature" = "signature",
): void {
	const block = (record as Record<string, unknown>)[field] as
		| { alg?: string; value?: string }
		| undefined;
	if (!block || block.alg !== ALG || typeof block.value !== "string") {
		throw new AICError("signature.missing", `Record has no valid ${field}.`);
	}
	const publicKey = publicKeyFromRaw(unb64(publicKeyB64));
	const payload = canonicalize(unsigned(record));
	const ok = nodeVerify(null, payload, publicKey, unb64(block.value));
	if (!ok)
		throw new AICError(
			"signature.invalid",
			`${field} does not verify against the given public key.`,
		);
}

export function publicKeyFromRaw(raw: Buffer): KeyObject {
	if (raw.length !== 32)
		throw new AICError(
			"crypto.invalid_key",
			`raw Ed25519 public key must be 32 bytes, got ${raw.length}.`,
		);
	return createPublicKey({
		key: Buffer.concat([SPKI_PREFIX, raw]),
		format: "der",
		type: "spki",
	});
}

export function privateKeyFromRaw(raw: Buffer): KeyObject {
	if (raw.length !== 32)
		throw new AICError(
			"crypto.invalid_key",
			`raw Ed25519 private key must be 32 bytes, got ${raw.length}.`,
		);
	return createPrivateKey({
		key: Buffer.concat([PKCS8_PREFIX, raw]),
		format: "der",
		type: "pkcs8",
	});
}

export function rawPublicKeyOf(publicKey: KeyObject): Buffer {
	return publicKey.export({ type: "spki", format: "der" }).subarray(-32);
}

export interface AgentIdentity {
	privateKey: KeyObject;
	publicKey: KeyObject;
	publicB64: string;
	agentId: string;
}

export function agentIdFor(publicKeyB64: string): string {
	return `aic:agent:${b64(createHash("sha256").update(unb64(publicKeyB64)).digest())}`;
}

function identityFromKeyPair(
	privateKey: KeyObject,
	publicKey: KeyObject,
): AgentIdentity {
	const publicB64 = b64(rawPublicKeyOf(publicKey));
	return { privateKey, publicKey, publicB64, agentId: agentIdFor(publicB64) };
}

export function generateIdentity(): AgentIdentity {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return identityFromKeyPair(privateKey, publicKey);
}

export function identityFromRawPrivateKey(raw: Buffer): AgentIdentity {
	const privateKey = privateKeyFromRaw(raw);
	const publicKey = createPublicKey(privateKey);
	return identityFromKeyPair(privateKey, publicKey);
}

export function privateKeyRawBytes(privateKey: KeyObject): Buffer {
	// PKCS8 DER for a raw Ed25519 key is our fixed 16-byte prefix + the 32-byte seed.
	return privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
}
