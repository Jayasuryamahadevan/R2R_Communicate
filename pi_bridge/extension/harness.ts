/**
 * AgentHarness: the operational layer tying identity, the action log,
 * and experience-driven reconciliation together. Mirrors the Python
 * reference implementation's harness.py -- see that repo's README.md
 * for the concept; this is its Node/TypeScript counterpart, built for
 * embedding directly into a pi extension rather than shelling out to
 * Python (see NO_PYTHON.md for why that matters).
 */

import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
	type AgentIdentity,
	AICError,
	b64,
	generateIdentity,
	identityFromRawPrivateKey,
	privateKeyRawBytes,
	sign,
	unb64,
} from "./crypto.js";
import {
	createGenesisEpoch,
	createSuccessorEpoch,
	type Epoch,
	verifyChain,
} from "./epoch.js";
import { AppendOnlyLog } from "./log.js";
import {
	DEFAULT_VALIDITY_MS,
	type Renewal,
	renew,
	verifyRenewal,
} from "./renewal.js";
import {
	createDetail,
	createSensitive,
	type Tier2Detail,
	type Tier3Sensitive,
} from "./tiers.js";
import { now } from "./timestamps.js";

interface StoredIdentity {
	agent_id: string;
	public_key: string;
	private_key: string;
}

function readJson<T>(path: string, fallback: T): T {
	if (!existsSync(path)) return fallback;
	return JSON.parse(readFileSync(path, "utf-8")) as T;
}

function writeJson(path: string, value: unknown, mode: number): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const tmp = `${path}.tmp`;
	writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, "utf-8");
	chmodSync(tmp, mode);
	writeFileSync(path, readFileSync(tmp));
	chmodSync(path, mode);
}

export interface AgentAdapter {
	capabilities(): string[];
}

export class AgentHarness {
	readonly stateDir: string;
	readonly adapter: AgentAdapter | undefined;
	readonly actionLog: AppendOnlyLog;
	readonly experience: AppendOnlyLog;

	private readonly identityPath: string;
	private readonly chainPath: string;
	private readonly detailPath: string;
	private readonly sensitivePath: string;
	private readonly renewalPath: string;

	constructor(stateDir: string, adapter?: AgentAdapter) {
		this.stateDir = stateDir;
		this.adapter = adapter;
		this.identityPath = join(stateDir, "identity.json");
		this.chainPath = join(stateDir, "chain.json");
		this.detailPath = join(stateDir, "detail.json");
		this.sensitivePath = join(stateDir, "sensitive.json");
		this.renewalPath = join(stateDir, "renewal.json");
		this.actionLog = new AppendOnlyLog(join(stateDir, "action_log.jsonl"));
		this.experience = new AppendOnlyLog(join(stateDir, "experience.jsonl"));
	}

	get isBootstrapped(): boolean {
		return existsSync(this.identityPath);
	}

	get identity(): AgentIdentity {
		const stored = readJson<StoredIdentity | null>(this.identityPath, null);
		if (!stored)
			throw new AICError(
				"harness.not_bootstrapped",
				"No identity found; call bootstrap() first.",
			);
		return identityFromRawPrivateKey(unb64(stored.private_key));
	}

	private saveIdentity(identity: AgentIdentity): void {
		const record: StoredIdentity = {
			agent_id: identity.agentId,
			public_key: identity.publicB64,
			private_key: b64(privateKeyRawBytes(identity.privateKey)),
		};
		writeJson(this.identityPath, record, 0o600);
	}

	get chain(): Epoch[] {
		return readJson<Epoch[]>(this.chainPath, []);
	}

	private saveChain(chain: Epoch[]): void {
		writeJson(this.chainPath, chain, 0o644);
	}

	get currentEpoch(): Epoch {
		const chain = this.chain;
		if (chain.length === 0)
			throw new AICError(
				"harness.not_bootstrapped",
				"No epoch chain found; call bootstrap() first.",
			);
		return chain[chain.length - 1];
	}

	get detail(): Tier2Detail | null {
		return readJson<Tier2Detail | null>(this.detailPath, null);
	}

	private saveDetail(detail: Tier2Detail): void {
		writeJson(this.detailPath, detail, 0o644);
	}

	get sensitive(): Tier3Sensitive | null {
		return readJson<Tier3Sensitive | null>(this.sensitivePath, null);
	}

	private saveSensitive(sensitive: Tier3Sensitive): void {
		writeJson(this.sensitivePath, sensitive, 0o644);
	}

	get renewal(): Renewal | null {
		return readJson<Renewal | null>(this.renewalPath, null);
	}

	private saveRenewal(renewal: Renewal): void {
		writeJson(this.renewalPath, renewal, 0o644);
	}

	bootstrap(
		displayName: string,
		purpose: string,
		declaredCapabilities: string[],
		options: {
			operator?: Record<string, unknown> | null;
			protocols?: string[];
			knownLimitations?: string[];
			sensitive?: {
				modelName: string;
				modelVersion: string;
				hardware?: Record<string, unknown>;
				softwareStack?: Record<string, unknown>;
			};
		} = {},
	): Epoch {
		if (this.isBootstrapped) {
			throw new AICError(
				"harness.already_bootstrapped",
				"This state directory already has an identity.",
			);
		}
		this.actionLog.append("bootstrap.started", { display_name: displayName });

		const identity = generateIdentity();
		const detail = createDetail(
			identity.agentId,
			0,
			identity,
			declaredCapabilities,
			{
				operator: options.operator,
				protocols: options.protocols,
				knownLimitations: options.knownLimitations,
			},
		);
		const sensitive = options.sensitive
			? createSensitive(identity.agentId, 0, identity, {
					modelName: options.sensitive.modelName,
					modelVersion: options.sensitive.modelVersion,
					hardware: options.sensitive.hardware,
					softwareStack: options.sensitive.softwareStack,
				})
			: undefined;
		const genesis = createGenesisEpoch(
			identity,
			displayName,
			purpose,
			detail,
			sensitive,
		);

		this.saveIdentity(identity);
		this.saveChain([genesis]);
		this.saveDetail(detail);
		if (sensitive) this.saveSensitive(sensitive);
		this.saveRenewal(renew(genesis, identity));

		this.actionLog.append("bootstrap.completed", {
			agent_id: identity.agentId,
		});
		return genesis;
	}

	ensureLive(validityMs: number = DEFAULT_VALIDITY_MS): Renewal {
		const epoch = this.currentEpoch;
		const existing = this.renewal;
		if (existing) {
			try {
				verifyRenewal(existing, epoch, now());
				return existing;
			} catch {
				// fall through to renew
			}
		}
		return this.renewCurrent(validityMs);
	}

	renewCurrent(validityMs: number = DEFAULT_VALIDITY_MS): Renewal {
		const renewal = renew(this.currentEpoch, this.identity, validityMs);
		this.saveRenewal(renewal);
		this.actionLog.append("identity.renewed", {
			valid_until: renewal.valid_until,
		});
		return renewal;
	}

	updateCapabilities(
		declaredCapabilities: string[],
		knownLimitations: string[],
	): Epoch {
		const identity = this.identity;
		const priorEpoch = this.currentEpoch;
		const priorDetail = this.detail as Tier2Detail;
		const priorSensitive = this.sensitive;
		const nextNumber = priorEpoch.epoch_number + 1;

		const detail = createDetail(
			priorEpoch.agent_id,
			nextNumber,
			identity,
			declaredCapabilities,
			{
				operator: priorDetail.operator,
				protocols: priorDetail.protocols,
				knownLimitations,
			},
		);
		const sensitive = priorSensitive
			? (resignForNextEpoch(
					priorSensitive,
					nextNumber,
					identity,
				) as Tier3Sensitive)
			: undefined;
		const epoch = createSuccessorEpoch(
			priorEpoch,
			identity,
			"capability_update",
			detail,
			{ sensitive },
		);
		this.commitNewEpoch(epoch, detail, sensitive, identity);
		return epoch;
	}

	rotateKey(): Epoch {
		const oldIdentity = this.identity;
		const newIdentity = generateIdentity();
		const priorEpoch = this.currentEpoch;
		const priorDetail = this.detail as Tier2Detail;
		const priorSensitive = this.sensitive;
		const nextNumber = priorEpoch.epoch_number + 1;

		const detail = resignForNextEpoch(
			priorDetail,
			nextNumber,
			newIdentity,
		) as Tier2Detail;
		const sensitive = priorSensitive
			? (resignForNextEpoch(
					priorSensitive,
					nextNumber,
					newIdentity,
				) as Tier3Sensitive)
			: undefined;
		const epoch = createSuccessorEpoch(
			priorEpoch,
			oldIdentity,
			"key_rotation",
			detail,
			{ sensitive, newIdentity },
		);

		this.saveIdentity(newIdentity);
		this.commitNewEpoch(epoch, detail, sensitive, newIdentity);
		this.actionLog.append("identity.key_rotated", {
			epoch_number: epoch.epoch_number,
		});
		return epoch;
	}

	private commitNewEpoch(
		epoch: Epoch,
		detail: Tier2Detail,
		sensitive: Tier3Sensitive | undefined,
		activeIdentity: AgentIdentity,
	): void {
		this.saveChain([...this.chain, epoch]);
		this.saveDetail(detail);
		if (sensitive) this.saveSensitive(sensitive);
		this.saveRenewal(renew(epoch, activeIdentity));
	}

	/** Diff accumulated experience (capability_discovered/lost,
	 * limitation_discovered/resolved) and, if an adapter is attached, its
	 * live capabilities(), against the current Tier 2 content. Only
	 * mints a capability_update epoch if `applyChanges` is true AND
	 * something actually changed. */
	reconcile(applyChanges: boolean): {
		changed: boolean;
		capabilitiesBefore: string[];
		capabilitiesAfter: string[];
		limitationsBefore: string[];
		limitationsAfter: string[];
		newEpochNumber?: number;
	} {
		const detail = this.detail;
		if (!detail)
			throw new AICError(
				"harness.not_bootstrapped",
				"No Tier 2 detail found; call bootstrap() first.",
			);
		const capabilitiesBefore = detail.declared_capabilities;
		const limitationsBefore = detail.known_limitations ?? [];

		if (this.adapter) {
			const live = new Set(this.adapter.capabilities());
			for (const capability of [...live]
				.filter((c) => !capabilitiesBefore.includes(c))
				.sort()) {
				this.experience.append("capability_discovered", {
					capability,
					source: "adapter",
				});
			}
			for (const capability of capabilitiesBefore
				.filter((c) => !live.has(c))
				.sort()) {
				this.experience.append("capability_lost", {
					capability,
					source: "adapter",
				});
			}
		}

		const capabilitiesAfter = replaySet(
			this.experience.entries(),
			"capability_discovered",
			"capability_lost",
			"capability",
			capabilitiesBefore,
		);
		const limitationsAfter = replaySet(
			this.experience.entries(),
			"limitation_discovered",
			"limitation_resolved",
			"limitation",
			limitationsBefore,
		);
		const changed =
			!sameSortedArrays(capabilitiesBefore, capabilitiesAfter) ||
			!sameSortedArrays(limitationsBefore, limitationsAfter);

		if (changed && applyChanges) {
			const epoch = this.updateCapabilities(
				capabilitiesAfter,
				limitationsAfter,
			);
			this.actionLog.append("identity.reconciled", {
				epoch_number: epoch.epoch_number,
				capabilities: capabilitiesAfter,
				limitations: limitationsAfter,
			});
			return {
				changed,
				capabilitiesBefore,
				capabilitiesAfter,
				limitationsBefore,
				limitationsAfter,
				newEpochNumber: epoch.epoch_number,
			};
		}
		return {
			changed,
			capabilitiesBefore,
			capabilitiesAfter,
			limitationsBefore,
			limitationsAfter,
		};
	}

	buildBundle(
		options: {
			discloseTier2?: boolean;
			discloseTier3?: boolean;
			attestations?: Record<string, unknown>[];
			delegateCard?: Record<string, unknown> | null;
		} = {},
	): Record<string, unknown> {
		const disclosedTiers = [1];
		const detail = options.discloseTier2 !== false ? this.detail : null;
		const sensitive = options.discloseTier3 ? this.sensitive : null;
		if (detail) disclosedTiers.push(2);
		if (sensitive) disclosedTiers.push(3);
		return {
			aic: "1.0",
			type: "bundle",
			disclosed_tiers: disclosedTiers,
			epoch_chain: this.chain,
			detail,
			sensitive,
			renewal: this.renewal,
			attestations: options.attestations ?? [],
			delegate: options.delegateCard ?? null,
		};
	}

	verifyOwnChain(): void {
		verifyChain(this.chain);
	}
}

function resignForNextEpoch(
	content: Record<string, unknown>,
	epochNumber: number,
	identity: AgentIdentity,
): Record<string, unknown> {
	const { epoch_number: _e, signature: _s, ...rest } = content;
	return sign({ ...rest, epoch_number: epochNumber }, identity.privateKey);
}

function replaySet(
	entries: { kind: string; detail: Record<string, unknown> }[],
	addKind: string,
	removeKind: string,
	field: string,
	baseline: string[],
): string[] {
	const set = new Set(baseline);
	for (const entry of entries) {
		const value = entry.detail[field];
		if (typeof value !== "string" || !value) continue;
		if (entry.kind === addKind) set.add(value);
		else if (entry.kind === removeKind) set.delete(value);
	}
	return [...set].sort();
}

function sameSortedArrays(a: string[], b: string[]): boolean {
	const sortedA = [...a].sort();
	const sortedB = [...b].sort();
	return (
		sortedA.length === sortedB.length &&
		sortedA.every((value, index) => value === sortedB[index])
	);
}
