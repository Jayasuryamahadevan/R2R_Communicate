/**
 * Epochs: Tier 1 (public) identity content, hash-chained across an
 * agent's whole life -- SPEC.md ss3. Mirrors the Python reference
 * implementation's epoch.py.
 */

import {
	type AgentIdentity,
	AICError,
	digestOf,
	sign,
	signPredecessor,
	verify,
} from "./crypto.js";
import {
	deriveCapabilityCategories,
	type Tier2Detail,
	type Tier3Sensitive,
} from "./tiers.js";
import { stamp } from "./timestamps.js";

export const TRANSITIONS = new Set([
	"genesis",
	"capability_update",
	"key_rotation",
]);

export interface Epoch extends Record<string, unknown> {
	aic: "1.0";
	type: "epoch";
	agent_id: string;
	epoch_number: number;
	transition: "genesis" | "capability_update" | "key_rotation";
	prior_epoch_digest: string | null;
	public_key: string;
	display_name: string;
	purpose: string;
	capability_categories: string[];
	detailed_digest: string;
	sensitive_digest: string | null;
	issued_at: string;
	signature?: { alg: string; value: string };
	predecessor_signature?: { alg: string; value: string };
}

export function createGenesisEpoch(
	identity: AgentIdentity,
	displayName: string,
	purpose: string,
	detail: Tier2Detail,
	sensitive?: Tier3Sensitive | null,
): Epoch {
	const epoch: Epoch = {
		aic: "1.0",
		type: "epoch",
		agent_id: identity.agentId,
		epoch_number: 0,
		transition: "genesis",
		prior_epoch_digest: null,
		public_key: identity.publicB64,
		display_name: displayName,
		purpose,
		capability_categories: deriveCapabilityCategories(
			detail.declared_capabilities,
		),
		detailed_digest: digestOf(detail),
		sensitive_digest: sensitive ? digestOf(sensitive) : null,
		issued_at: stamp(),
	};
	return sign(epoch, identity.privateKey) as Epoch;
}

export interface SuccessorOptions {
	newIdentity?: AgentIdentity;
	displayName?: string;
	purpose?: string;
	sensitive?: Tier3Sensitive | null;
}

export function createSuccessorEpoch(
	priorEpoch: Epoch,
	currentIdentity: AgentIdentity,
	transition: "capability_update" | "key_rotation",
	detail: Tier2Detail,
	options: SuccessorOptions = {},
): Epoch {
	if (!TRANSITIONS.has(transition) || transition === "genesis") {
		throw new AICError(
			"epoch.invalid_transition",
			"transition must be capability_update or key_rotation.",
		);
	}
	verify(priorEpoch, priorEpoch.public_key);
	if (currentIdentity.publicB64 !== priorEpoch.public_key) {
		throw new AICError(
			"epoch.wrong_key",
			"currentIdentity does not hold the prior epoch's key.",
		);
	}
	if (transition === "key_rotation" && !options.newIdentity) {
		throw new AICError(
			"epoch.missing_new_identity",
			"key_rotation requires newIdentity.",
		);
	}
	const nextEpochNumber = priorEpoch.epoch_number + 1;
	if (
		detail.epoch_number !== nextEpochNumber ||
		detail.agent_id !== priorEpoch.agent_id
	) {
		throw new AICError(
			"epoch.detail_epoch_mismatch",
			"detail must be built for this exact successor epoch_number/agent_id.",
		);
	}
	if (
		options.sensitive &&
		(options.sensitive.epoch_number !== nextEpochNumber ||
			options.sensitive.agent_id !== priorEpoch.agent_id)
	) {
		throw new AICError(
			"epoch.sensitive_epoch_mismatch",
			"sensitive must be built for this exact successor epoch_number/agent_id.",
		);
	}

	const activeIdentity =
		transition === "key_rotation"
			? (options.newIdentity as AgentIdentity)
			: currentIdentity;
	let epoch: Epoch = {
		aic: "1.0",
		type: "epoch",
		agent_id: priorEpoch.agent_id,
		epoch_number: nextEpochNumber,
		transition,
		prior_epoch_digest: digestOf(priorEpoch),
		public_key: activeIdentity.publicB64,
		display_name: options.displayName ?? priorEpoch.display_name,
		purpose: options.purpose ?? priorEpoch.purpose,
		capability_categories: deriveCapabilityCategories(
			detail.declared_capabilities,
		),
		detailed_digest: digestOf(detail),
		sensitive_digest: options.sensitive ? digestOf(options.sensitive) : null,
		issued_at: stamp(),
	};
	epoch = sign(epoch, activeIdentity.privateKey) as Epoch;
	if (transition === "key_rotation") {
		epoch = signPredecessor(epoch, currentIdentity.privateKey) as Epoch;
	}
	return epoch;
}

export function verifyEpoch(epoch: Epoch, priorEpoch?: Epoch): void {
	const required = [
		"aic",
		"type",
		"agent_id",
		"epoch_number",
		"transition",
		"public_key",
		"issued_at",
		"signature",
		"capability_categories",
		"detailed_digest",
	];
	if (!required.every((key) => key in epoch) || epoch.type !== "epoch") {
		throw new AICError(
			"epoch.schema_invalid",
			"Epoch is missing required fields.",
		);
	}
	if (!TRANSITIONS.has(epoch.transition)) {
		throw new AICError(
			"epoch.schema_invalid",
			`Unknown transition ${epoch.transition}.`,
		);
	}
	verify(epoch, epoch.public_key);
	if (!priorEpoch) {
		if (
			epoch.epoch_number !== 0 ||
			epoch.transition !== "genesis" ||
			epoch.prior_epoch_digest !== null
		) {
			throw new AICError(
				"epoch.not_genesis",
				"First epoch in a chain must be epoch_number 0 with no prior_epoch_digest.",
			);
		}
		return;
	}
	if (epoch.epoch_number !== priorEpoch.epoch_number + 1) {
		throw new AICError(
			"epoch.out_of_order",
			"Epoch numbers must increase by exactly one.",
		);
	}
	if (epoch.agent_id !== priorEpoch.agent_id) {
		throw new AICError(
			"epoch.agent_id_mismatch",
			"Successor epoch must keep the same agent_id.",
		);
	}
	if (epoch.prior_epoch_digest !== digestOf(priorEpoch)) {
		throw new AICError(
			"epoch.chain_broken",
			"prior_epoch_digest does not match the actual prior epoch's digest.",
		);
	}
	if (epoch.transition === "key_rotation") {
		verify(epoch, priorEpoch.public_key, "predecessor_signature");
	} else if (epoch.public_key !== priorEpoch.public_key) {
		throw new AICError(
			"epoch.unauthorized_key_change",
			"Key changed without a key_rotation transition and predecessor_signature.",
		);
	}
}

export function verifyChain(chain: Epoch[]): void {
	if (chain.length === 0)
		throw new AICError("epoch.chain_empty", "epoch_chain is empty.");
	verifyEpoch(chain[0]);
	for (let i = 1; i < chain.length; i++) {
		verifyEpoch(chain[i], chain[i - 1]);
	}
}
