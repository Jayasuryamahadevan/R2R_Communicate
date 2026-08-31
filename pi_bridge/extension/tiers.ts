/**
 * Tiered, privilege-gated disclosure -- SPEC.md ss5. Mirrors the Python
 * reference implementation's tiers.py.
 */

import {
	type AgentIdentity,
	AICError,
	digestOf,
	sign,
	verify,
} from "./crypto.js";
import { stamp } from "./timestamps.js";

export interface Tier2Detail extends Record<string, unknown> {
	aic: "1.0";
	type: "tier2_detail";
	agent_id: string;
	epoch_number: number;
	declared_capabilities: string[];
	operator: Record<string, unknown> | null;
	protocols: string[];
	known_limitations: string[];
	issued_at: string;
	signature?: { alg: string; value: string };
}

export interface Tier3Sensitive extends Record<string, unknown> {
	aic: "1.0";
	type: "tier3_sensitive";
	agent_id: string;
	epoch_number: number;
	model_name: string;
	model_version: string;
	weights_digest: string | null;
	base_model: string | null;
	hardware: Record<string, unknown>;
	software_stack: Record<string, unknown>;
	build_reference: string | null;
	issued_at: string;
	signature?: { alg: string; value: string };
}

export function deriveCapabilityCategories(
	declaredCapabilities: string[],
): string[] {
	const categories = new Set(
		declaredCapabilities
			.filter(Boolean)
			.map((capability) => capability.split(".", 1)[0]),
	);
	return [...categories].sort();
}

export function createDetail(
	agentId: string,
	epochNumber: number,
	identity: AgentIdentity,
	declaredCapabilities: string[],
	options: {
		operator?: Record<string, unknown> | null;
		protocols?: string[];
		knownLimitations?: string[];
	} = {},
): Tier2Detail {
	const detail: Tier2Detail = {
		aic: "1.0",
		type: "tier2_detail",
		agent_id: agentId,
		epoch_number: epochNumber,
		declared_capabilities: [...declaredCapabilities],
		operator: options.operator ?? null,
		protocols: options.protocols ? [...options.protocols] : [],
		known_limitations: options.knownLimitations
			? [...options.knownLimitations]
			: [],
		issued_at: stamp(),
	};
	return sign(detail, identity.privateKey) as Tier2Detail;
}

export function verifyDetail(
	detail: Tier2Detail,
	epoch: Record<string, unknown>,
): void {
	const required = [
		"aic",
		"type",
		"agent_id",
		"epoch_number",
		"declared_capabilities",
		"issued_at",
		"signature",
	];
	if (
		!required.every((key) => key in detail) ||
		detail.type !== "tier2_detail"
	) {
		throw new AICError(
			"tier2.schema_invalid",
			"Tier 2 detail is missing required fields.",
		);
	}
	if (
		detail.agent_id !== epoch.agent_id ||
		detail.epoch_number !== epoch.epoch_number
	) {
		throw new AICError(
			"tier2.epoch_mismatch",
			"Tier 2 detail does not reference this exact epoch.",
		);
	}
	if (epoch.detailed_digest !== digestOf(detail)) {
		throw new AICError(
			"tier2.digest_mismatch",
			"Epoch's detailed_digest does not match this Tier 2 content.",
		);
	}
	verify(detail, epoch.public_key as string);
	const expectedCategories = deriveCapabilityCategories(
		detail.declared_capabilities,
	).join(",");
	const actualCategories = (
		(epoch.capability_categories as string[] | undefined) ?? []
	)
		.slice()
		.sort()
		.join(",");
	if (expectedCategories !== actualCategories) {
		throw new AICError(
			"tier1.categories_dishonest",
			"Epoch's Tier 1 capability_categories do not match the categories implied by Tier 2's actual declared_capabilities.",
		);
	}
}

export function createSensitive(
	agentId: string,
	epochNumber: number,
	identity: AgentIdentity,
	fields: {
		modelName: string;
		modelVersion: string;
		weightsDigest?: string | null;
		baseModel?: string | null;
		hardware?: Record<string, unknown>;
		softwareStack?: Record<string, unknown>;
		buildReference?: string | null;
	},
): Tier3Sensitive {
	const sensitive: Tier3Sensitive = {
		aic: "1.0",
		type: "tier3_sensitive",
		agent_id: agentId,
		epoch_number: epochNumber,
		model_name: fields.modelName,
		model_version: fields.modelVersion,
		weights_digest: fields.weightsDigest ?? null,
		base_model: fields.baseModel ?? null,
		hardware: fields.hardware ?? {},
		software_stack: fields.softwareStack ?? {},
		build_reference: fields.buildReference ?? null,
		issued_at: stamp(),
	};
	return sign(sensitive, identity.privateKey) as Tier3Sensitive;
}

export function verifySensitive(
	sensitive: Tier3Sensitive,
	epoch: Record<string, unknown>,
): void {
	const required = [
		"aic",
		"type",
		"agent_id",
		"epoch_number",
		"model_name",
		"model_version",
		"hardware",
		"software_stack",
		"issued_at",
		"signature",
	];
	if (
		!required.every((key) => key in sensitive) ||
		sensitive.type !== "tier3_sensitive"
	) {
		throw new AICError(
			"tier3.schema_invalid",
			"Tier 3 sensitive content is missing required fields.",
		);
	}
	if (
		sensitive.agent_id !== epoch.agent_id ||
		sensitive.epoch_number !== epoch.epoch_number
	) {
		throw new AICError(
			"tier3.epoch_mismatch",
			"Tier 3 content does not reference this exact epoch.",
		);
	}
	if (epoch.sensitive_digest !== digestOf(sensitive)) {
		throw new AICError(
			"tier3.digest_mismatch",
			"Epoch's sensitive_digest does not match this Tier 3 content.",
		);
	}
	verify(sensitive, epoch.public_key as string);
}
