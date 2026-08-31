/**
 * Renewals: the cheap, frequent heartbeat that separates liveness from
 * identity content -- SPEC.md ss4. Mirrors the Python reference
 * implementation's renewal.py.
 */

import {
	type AgentIdentity,
	AICError,
	digestOf,
	sign,
	verify,
} from "./crypto.js";
import type { Epoch } from "./epoch.js";
import { now, parseStamp, stamp } from "./timestamps.js";

export const DEFAULT_VALIDITY_MS = 24 * 60 * 60 * 1000;
export const MAX_VALIDITY_MS = 7 * 24 * 60 * 60 * 1000;

export interface Renewal extends Record<string, unknown> {
	aic: "1.0";
	type: "renewal";
	agent_id: string;
	epoch_digest: string;
	renewed_at: string;
	valid_until: string;
	signature?: { alg: string; value: string };
}

export function renew(
	epoch: Epoch,
	identity: AgentIdentity,
	validityMs: number = DEFAULT_VALIDITY_MS,
): Renewal {
	if (identity.publicB64 !== epoch.public_key) {
		throw new AICError(
			"renewal.wrong_key",
			"identity does not hold this epoch's key.",
		);
	}
	if (validityMs > MAX_VALIDITY_MS) {
		throw new AICError(
			"renewal.validity_too_long",
			`Renewal validity may not exceed ${MAX_VALIDITY_MS}ms.`,
		);
	}
	const issued = now();
	const renewal: Renewal = {
		aic: "1.0",
		type: "renewal",
		agent_id: epoch.agent_id,
		epoch_digest: digestOf(epoch),
		renewed_at: stamp(issued),
		valid_until: stamp(new Date(issued.getTime() + validityMs)),
	};
	return sign(renewal, identity.privateKey) as Renewal;
}

export function verifyRenewal(
	renewal: Renewal,
	epoch: Epoch,
	at: Date = now(),
): void {
	const required = [
		"aic",
		"type",
		"agent_id",
		"epoch_digest",
		"renewed_at",
		"valid_until",
		"signature",
	];
	if (!required.every((key) => key in renewal) || renewal.type !== "renewal") {
		throw new AICError(
			"renewal.schema_invalid",
			"Renewal is missing required fields.",
		);
	}
	if (
		renewal.agent_id !== epoch.agent_id ||
		renewal.epoch_digest !== digestOf(epoch)
	) {
		throw new AICError(
			"renewal.epoch_mismatch",
			"Renewal does not reference this exact epoch.",
		);
	}
	verify(renewal, epoch.public_key);
	if (parseStamp(renewal.valid_until).getTime() <= at.getTime()) {
		throw new AICError(
			"renewal.expired",
			"Renewal's validity window has passed.",
		);
	}
	if (parseStamp(renewal.renewed_at).getTime() > at.getTime() + 60_000) {
		throw new AICError(
			"renewal.issued_in_future",
			"Renewal is issued too far in the future (clock skew?).",
		);
	}
}
