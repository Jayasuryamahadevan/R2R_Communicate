/**
 * opencode_bridge: an Agent ID Card identity + primary-provider plugin
 * for OpenCode (https://github.com/anomalyco/opencode)
 * ======================================================================
 *
 * Three things, kept deliberately separate:
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
 * 3. Optional FASP pairing (../../fasp_harness/): if AIC_FASP_URL is set,
 *    this plugin pairs itself with that FASP harness as one of its
 *    peers on load -- the concrete mechanism behind "what other
 *    physical or AI agents am I connected to" (see `faspPeers` on
 *    `AgentHarness`, and `verifyWorkspace` in ./verify.ts). Off by
 *    default: this never reaches out to a network nobody asked it to.
 *
 * Deliberately NOT built here: an MCP client (OpenCode already ships a
 * full native one -- packages/opencode/src/mcp/ -- duplicating it would
 * be the over-engineering this bridge was explicitly asked to avoid).
 * OpenCode's own `config.mcp` is this workspace's real, live MCP
 * self-state; bridge_core's MCP self-state (state.ts) is deliberately
 * left unused here rather than kept as a second, shadow copy of it.
 * `bridge_core/webhooks.ts` is available (pure Node, no host coupling)
 * but not wired to a command surface here, since OpenCode's command
 * model differs from pi's -- import `WebhookReceiver`/`WebhookNotifier`
 * directly if you want it from your own OpenCode config or plugin.
 *
 * This file exports ONLY its default plugin function, on purpose: a
 * real running `opencode` (v1.18.25) calls every function a plugin
 * module exports, not just the default, as if each one might itself be
 * a plugin factory. `verifyWorkspace` used to be a second named export
 * here and OpenCode called it too, with the wrong argument, logging a
 * spurious "failed to load plugin" error (harmlessly, since the real
 * plugin still worked) -- it now lives in ./verify.ts instead, which is
 * never registered as a plugin entry point.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Config, Plugin, PluginInput } from "@opencode-ai/plugin";
import { AgentHarness } from "../../bridge_core/harness.js";
import {
	collectRuntimeProvenance,
	discoverPermissionsAndNetwork,
} from "../../bridge_core/provenance.js";

const PURPOSE =
	"OpenCode coding agent assisting a developer in this workspace: reads, edits, and runs commands as directed.";

/** OpenCode Zen model IDs -- see opencode.ai/docs/zen. These two were
 * confirmed to actually exist by running `opencode models opencode`
 * against a real Zen catalog (both free: cost.input/output = 0, no
 * OpenCode account required) rather than assumed -- Zen's catalog is
 * OpenCode's own and rotates over time, so re-run that command if a
 * later OpenCode version rejects either as unknown. Override by setting
 * AIC_OPENCODE_ZEN_MODEL / AIC_OPENCODE_ZEN_SMALL_MODEL, or by simply
 * setting your own "model"/"small_model" in opencode.json -- either
 * takes precedence over this default. */
const DEFAULT_ZEN_MODEL =
	process.env.AIC_OPENCODE_ZEN_MODEL ?? "opencode/big-pickle";
const DEFAULT_ZEN_SMALL_MODEL =
	process.env.AIC_OPENCODE_ZEN_SMALL_MODEL ??
	"opencode/nemotron-3.5-lightning-free";

function stateDirFor(directory: string): string {
	return join(directory, ".aic");
}

/** Only ever resolved from the environment, never accepted as a config
 * value that might end up written back to disk or logged. */
function resolveFaspAdminToken(): string | undefined {
	if (process.env.AIC_FASP_ADMIN_TOKEN) return process.env.AIC_FASP_ADMIN_TOKEN;
	const stateDir = process.env.AIC_FASP_STATE_DIR;
	if (!stateDir) return undefined;
	try {
		return readFileSync(join(stateDir, "admin_token"), "utf-8").trim();
	} catch {
		return undefined;
	}
}

/** Pair with a FASP harness (../../fasp_harness/) as one of its peers,
 * but only if the operator opted in by setting AIC_FASP_URL -- this
 * bridge must never reach out to a network nobody configured it to.
 * Best effort: a failed attempt is recorded on the card's own log, not
 * thrown, since this must never block OpenCode from starting. */
async function connectFaspIfConfigured(harness: AgentHarness): Promise<void> {
	const baseUrl = process.env.AIC_FASP_URL;
	if (!baseUrl) return;
	await harness.connectFaspPeer(
		baseUrl,
		`opencode@${process.env.HOSTNAME ?? "workspace"}`,
		["chat", "tool.execute"],
		{ adminToken: resolveFaspAdminToken() },
	);
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

	const provenance = collectRuntimeProvenance();
	const permissions = discoverPermissionsAndNetwork();
	harness.log.append("environment.discovered", {
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

const agentIdCardPlugin: Plugin = async (input: PluginInput) => {
	const harness = new AgentHarness(stateDirFor(input.directory));
	await bootstrapIfNeeded(harness);
	await connectFaspIfConfigured(harness);

	return {
		async config(config) {
			applyPrimaryProviderDefaults(config);
		},

		async "tool.execute.before"(hookInput) {
			if (harness.isBootstrapped) {
				harness.log.append("tool.invoked", {
					tool: hookInput.tool,
					session_id: hookInput.sessionID,
					call_id: hookInput.callID,
				});
			}
		},

		async "tool.execute.after"(hookInput) {
			if (harness.isBootstrapped) {
				harness.log.append("tool.completed", {
					tool: hookInput.tool,
					session_id: hookInput.sessionID,
					call_id: hookInput.callID,
				});
			}
		},
	};
};

export default agentIdCardPlugin;
