/**
 * verifyWorkspace(directory): check this workspace's Agent ID Card
 * without going through OpenCode at all -- e.g. from a shell script or
 * CI step.
 *
 * Deliberately its own file, NOT exported from index.ts. Confirmed
 * against a real running `opencode` (v1.18.25): its plugin loader calls
 * every function a plugin module exports, not just the default, as if
 * each one might itself be a `Plugin` factory. With `verifyWorkspace`
 * exported from index.ts too, OpenCode called it with the whole
 * `PluginInput` object in place of the `directory: string` it expects,
 * which crashed inside `path.join` and got logged as "failed to load
 * plugin" -- even though the real plugin (the default export) still
 * loaded and worked correctly right alongside it. A file registered as
 * an OpenCode plugin entry point should export nothing but its one
 * default plugin function; anything else meant for scripts or CI lives
 * here instead.
 */

import { join } from "node:path";
import { AgentHarness } from "../../bridge_core/harness.js";
import type { FaspPeerRecord } from "../../bridge_core/state.js";
import { verifyDetail } from "../../bridge_core/tiers.js";

export function verifyWorkspace(directory: string): {
	ok: boolean;
	agentId?: string;
	error?: string;
	faspPeers?: FaspPeerRecord[];
} {
	const harness = new AgentHarness(join(directory, ".aic"));
	if (!harness.isBootstrapped) return { ok: false, error: "not bootstrapped" };
	try {
		harness.verifyOwnChain();
		const detail = harness.detail;
		if (detail) verifyDetail(detail, harness.currentEpoch);
		return {
			ok: true,
			agentId: harness.currentEpoch.agent_id,
			faspPeers: harness.state.faspPeers,
		};
	} catch (error) {
		return { ok: false, error: (error as Error).message };
	}
}
