/**
 * opencode_bridge: an Agent ID Card identity + primary-provider plugin
 * for OpenCode (https://github.com/anomalyco/opencode)
 * ======================================================================
 *
 * Two things, kept deliberately separate:
 *
 * 1. Primary API key provider: the `config` hook defaults `model` and
 *    `small_model` to OpenCode Zen (`opencode/...`) -- OpenCode's own
 *    hosted model gateway -- ONLY if the user has not already set one
 *    themselves. This is the whole "make Zen the primary provider" ask:
 *    a user of this bridge needs no separate Anthropic/OpenAI API key
 *    at all, but an explicit choice they already made is never
 *    overridden.
 *
 * 2. The same Agent ID Card identity layer `pi_bridge/` gives `pi` --
 *    imported directly from `../../bridge_core/` (harness/epoch/tiers/
 *    renewal/log/provenance/crypto/webhooks), the ONE shared,
 *    host-agnostic implementation both bridges use, rather than two
 *    copies that could quietly drift apart. On load, this plugin is
 *    curious about its surroundings and bootstraps a signed genesis
 *    epoch if this workspace doesn't have one yet; every tool call is
 *    appended to a tamper-evident action log via the `tool.execute.
 *    before`/`tool.execute.after` hooks.
 *
 * Deliberately NOT built here: an MCP client (OpenCode already ships a
 * full native one -- packages/opencode/src/mcp/ -- duplicating it would
 * be the over-engineering this bridge was explicitly asked to avoid).
 * `bridge_core/webhooks.ts` is available (pure Node, no host coupling)
 * but not wired to a command surface here, since OpenCode's command
 * model differs from pi's -- import `WebhookReceiver`/`WebhookNotifier`
 * directly if you want it from your own OpenCode config or plugin.
 */

import { join } from "node:path";
import type { Config, Plugin, PluginInput } from "@opencode-ai/plugin";
import { AgentHarness } from "../../bridge_core/harness.js";
import {
	collectRuntimeProvenance,
	discoverPermissionsAndNetwork,
} from "../../bridge_core/provenance.js";
import { verifyDetail } from "../../bridge_core/tiers.js";

const PURPOSE =
	"OpenCode coding agent assisting a developer in this workspace: reads, edits, and runs commands as directed.";

/** OpenCode Zen model IDs -- see opencode.ai/docs/zen. Override by
 * setting AIC_OPENCODE_ZEN_MODEL / AIC_OPENCODE_ZEN_SMALL_MODEL, or by
 * simply setting your own "model"/"small_model" in opencode.json --
 * either takes precedence over this default. */
const DEFAULT_ZEN_MODEL =
	process.env.AIC_OPENCODE_ZEN_MODEL ?? "opencode/claude-opus-5";
const DEFAULT_ZEN_SMALL_MODEL =
	process.env.AIC_OPENCODE_ZEN_SMALL_MODEL ?? "opencode/claude-haiku-4-5";

function stateDirFor(directory: string): string {
	return join(directory, ".aic");
}

async function bootstrapIfNeeded(harness: AgentHarness): Promise<void> {
	if (harness.isBootstrapped) {
		try {
			harness.verifyOwnChain();
			harness.ensureLive();
		} catch {
			// Leave an existing-but-broken identity untouched for a human to inspect; never silently repair or discard it.
		}
		return;
	}

	harness.actionLog.append("environment.discovery_started", {});
	const provenance = collectRuntimeProvenance();
	const permissions = discoverPermissionsAndNetwork();
	harness.actionLog.append("environment.discovered", {
		...provenance,
		...permissions,
	});

	const knownLimitations = [
		"no memory of this workspace beyond entries already written to .aic/",
		"bounded by the active model's context window",
		"can only act through the tools OpenCode itself has registered for this session, plus whatever MCP servers OpenCode's own native MCP client is configured to reach",
	];
	if (permissions.running_as_root === false)
		knownLimitations.push(
			"not running as root: cannot modify files or ports outside the current user's permissions",
		);
	if (
		!provenance.hardware ||
		(provenance.hardware as Record<string, unknown>).accelerator === "cpu-only"
	)
		knownLimitations.push("no local accelerator detected on this host");

	harness.bootstrap(
		`opencode@${process.env.HOSTNAME ?? "workspace"}`,
		PURPOSE,
		["chat", "tool.execute"],
		{
			protocols: ["mcp"],
			knownLimitations,
			sensitive: {
				modelName: "unknown",
				modelVersion: "unknown",
				hardware: provenance.hardware,
				softwareStack: provenance.software_stack,
			},
		},
	);
}

function applyPrimaryProviderDefaults(config: Config): void {
	const withModel = config as Config & { model?: string; small_model?: string };
	if (!withModel.model) withModel.model = DEFAULT_ZEN_MODEL;
	if (!withModel.small_model) withModel.small_model = DEFAULT_ZEN_SMALL_MODEL;
}

export const AgentIdCardPlugin: Plugin = async (input: PluginInput) => {
	const harness = new AgentHarness(stateDirFor(input.directory));
	await bootstrapIfNeeded(harness);

	return {
		async config(config) {
			applyPrimaryProviderDefaults(config);
		},

		async "tool.execute.before"(hookInput) {
			if (harness.isBootstrapped) {
				harness.actionLog.append("tool.invoked", {
					tool: hookInput.tool,
					session_id: hookInput.sessionID,
					call_id: hookInput.callID,
				});
			}
		},

		async "tool.execute.after"(hookInput) {
			if (harness.isBootstrapped) {
				harness.actionLog.append("tool.completed", {
					tool: hookInput.tool,
					session_id: hookInput.sessionID,
					call_id: hookInput.callID,
				});
			}
		},
	};
};

/** Verify this workspace's card without going through OpenCode at all
 * -- e.g. from a shell script or CI step. */
export function verifyWorkspace(directory: string): {
	ok: boolean;
	agentId?: string;
	error?: string;
} {
	const harness = new AgentHarness(stateDirFor(directory));
	if (!harness.isBootstrapped) return { ok: false, error: "not bootstrapped" };
	try {
		harness.verifyOwnChain();
		const detail = harness.detail;
		if (detail) verifyDetail(detail, harness.currentEpoch);
		return { ok: true, agentId: harness.currentEpoch.agent_id };
	} catch (error) {
		return { ok: false, error: (error as Error).message };
	}
}

export { AgentHarness };
export default AgentIdCardPlugin;
