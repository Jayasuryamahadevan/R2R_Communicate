/**
 * AgentHarness: the operational layer tying identity, the append-only
 * log, and log-driven reconciliation together. Mirrors the Python
 * reference implementation's harness.py -- see that repo's README.md
 * for the concept; this is its Node/TypeScript counterpart, built to be
 * embedded directly into a host agent's own extension/plugin mechanism
 * rather than shelling out to Python (see NO_PYTHON.md for why that
 * matters). Lives once here in bridge_core/ and is imported unmodified
 * by both pi_bridge/ and opencode_bridge/ -- see bridge_core/README.md
 * for why. Deliberately has no dependency on either host -- only on the
 * sibling files in this same directory.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
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
import { FaspClient } from "./fasp.js";
import { readJson, writeJson } from "./fsjson.js";
import { AppendOnlyLog } from "./log.js";
import {
	DEFAULT_VALIDITY_MS,
	type Renewal,
	renew,
	verifyRenewal,
} from "./renewal.js";
import { type FaspPeerRecord, SelfState } from "./state.js";
import {
	createDetail,
	createSensitive,
	type Tier2Detail,
	type Tier3Sensitive,
} from "./tiers.js";
import { now, stamp } from "./timestamps.js";

interface StoredIdentity {
	agent_id: string;
	public_key: string;
	private_key: string;
}

export interface AgentAdapter {
	capabilities(): string[];
}

export class AgentHarness {
	readonly stateDir: string;
	readonly adapter: AgentAdapter | undefined;
	/** One append-only, hash-chained log for everything this agent does
	 * or learns -- tool calls, bootstrap/renewal/reconciliation events,
	 * and capability_discovered/capability_lost/limitation_discovered/
	 * limitation_resolved entries, distinguished by `kind`. Filtering by
	 * kind (see `reconcile()` below) is enough to tell "what did I do"
	 * from "what did I learn" without needing two separate files for it. */
	readonly log: AppendOnlyLog;
	/** This agent's own self-managed configuration -- which MCP servers
	 * it should stay connected to or may connect to on its own
	 * initiative, and which FASP peers it has paired with. See
	 * state.ts. */
	readonly state: SelfState;

	private readonly identityPath: string;
	private readonly chainPath: string;
	private readonly detailPath: string;
	private readonly sensitivePath: string;
	private readonly renewalPath: string;
	private readonly fasp: FaspClient;

	constructor(stateDir: string, adapter?: AgentAdapter) {
		this.stateDir = stateDir;
		this.adapter = adapter;
		this.identityPath = join(stateDir, "identity.json");
		this.chainPath = join(stateDir, "chain.json");
		this.detailPath = join(stateDir, "detail.json");
		this.sensitivePath = join(stateDir, "sensitive.json");
		this.renewalPath = join(stateDir, "renewal.json");
		this.log = new AppendOnlyLog(join(stateDir, "log.jsonl"));
		this.state = new SelfState(join(stateDir, "self_state.json"));
		this.fasp = new FaspClient(stateDir);
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
		this.log.append("bootstrap.started", { display_name: displayName });

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

		this.log.append("bootstrap.completed", {
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
		this.log.append("identity.renewed", {
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
		this.log.append("identity.key_rotated", {
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
				this.log.append("capability_discovered", {
					capability,
					source: "adapter",
				});
			}
			for (const capability of capabilitiesBefore
				.filter((c) => !live.has(c))
				.sort()) {
				this.log.append("capability_lost", {
					capability,
					source: "adapter",
				});
			}
		}

		const capabilitiesAfter = replaySet(
			this.log.entries(),
			"capability_discovered",
			"capability_lost",
			"capability",
			capabilitiesBefore,
		);
		const limitationsAfter = replaySet(
			this.log.entries(),
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
			this.log.append("identity.reconciled", {
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

	/** Assembles the one JSON object actually shown to a verifier. Only
	 * covers what this harness can itself produce (the chain, Tier 2/3,
	 * a renewal) -- attestations and delegate cards are real parts of
	 * the AIC format, but this Node/TypeScript harness has no way to
	 * create either yet, so a bundle that claimed to carry them would
	 * always be empty. Add those fields back here if/when this harness
	 * grows a real way to produce them; the Python reference
	 * implementation already can, if you need that today. */
	buildBundle(
		options: { discloseTier2?: boolean; discloseTier3?: boolean } = {},
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
			attestations: [],
			delegate: null,
		};
	}

	verifyOwnChain(): void {
		verifyChain(this.chain);
	}

	/** Pair with a FASP harness (../fasp_harness/) as one of its peers --
	 * the concrete mechanism behind "what physical or AI agents am I
	 * connected to": a FASP harness this agent is paired with can list
	 * every other peer it already knows about (see faspPeers() below).
	 * If `adminToken` is given (that harness's own admin token -- only
	 * meaningful when the same operator runs both sides, or has handed
	 * this agent that token on purpose), this also confirms the pairing
	 * itself with no separate human approval step; without one, the
	 * pairing sits "pending" until that harness's operator confirms it
	 * some other way. Never throws: a failed attempt is recorded (state
	 * "failed", with the error) rather than raised, since this is
	 * expected to be called speculatively/autonomously. */
	async connectFaspPeer(
		baseUrl: string,
		displayName: string,
		capabilities: string[],
		options: { adminToken?: string } = {},
	): Promise<{
		systemId: string;
		state: "pending" | "paired" | "failed";
		error?: string;
	}> {
		const idCard = this.fasp.buildIdCard(displayName, capabilities);
		try {
			const hello = await this.fasp.hello(baseUrl, idCard);
			let state: "pending" | "paired" = "pending";
			if (options.adminToken) {
				await this.fasp.confirmSelf(
					baseUrl,
					idCard.system_id,
					hello.pair_code,
					options.adminToken,
				);
				state = "paired";
			}
			this.state.rememberFaspPeer({
				baseUrl,
				systemId: hello.system_id,
				state,
				updatedAt: stamp(now()),
			});
			this.log.append("fasp.peer_connected", {
				base_url: baseUrl,
				remote_system_id: hello.system_id,
				state,
			});
			return { systemId: hello.system_id, state };
		} catch (error) {
			const message = (error as Error).message;
			this.state.rememberFaspPeer({
				baseUrl,
				state: "failed",
				lastError: message,
				updatedAt: stamp(now()),
			});
			this.log.append("fasp.peer_connect_failed", {
				base_url: baseUrl,
				error: message,
			});
			return { systemId: "", state: "failed", error: message };
		}
	}

	/** If `adminToken` is given, fetch the live peer list from that FASP
	 * harness at `baseUrl` -- every physical or AI agent it has ever
	 * paired with, not just this one. Otherwise falls back to this
	 * agent's own recollection of what it has tried to pair with, which
	 * needs no admin rights on anything but is necessarily incomplete. */
	async faspPeers(
		options: { baseUrl?: string; adminToken?: string } = {},
	): Promise<Record<string, unknown> | FaspPeerRecord[]> {
		if (options.baseUrl && options.adminToken)
			return this.fasp.listPeers(options.baseUrl, options.adminToken);
		return this.state.faspPeers;
	}

	/** Actually use a completed FASP pairing: propose an intent to
	 * `toSystemId` at `baseUrl` for one of the capabilities it granted at
	 * pairing time. `connectFaspPeer` only establishes that two agents
	 * trust each other; this is the real, signed request-response
	 * exchange that trust was for. Logged either way, success or not. */
	async faspPropose(
		baseUrl: string,
		toSystemId: string,
		capability: string,
		objective: string,
	): Promise<Record<string, unknown>> {
		try {
			const response = await this.fasp.proposeIntent(
				baseUrl,
				toSystemId,
				capability,
				objective,
			);
			this.log.append("fasp.intent_proposed", {
				base_url: baseUrl,
				to: toSystemId,
				capability,
			});
			return response;
		} catch (error) {
			this.log.append("fasp.intent_propose_failed", {
				base_url: baseUrl,
				to: toSystemId,
				capability,
				error: (error as Error).message,
			});
			throw error;
		}
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
