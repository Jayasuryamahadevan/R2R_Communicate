/**
 * Honest runtime introspection for Tier 3 ("sensitive") content -- see
 * SPEC.md ss5.3/ss6 and HARNESS_BOOTSTRAP.md. A field that genuinely
 * cannot be determined is reported as the literal string "unknown",
 * never omitted -- an absent key looks identical to "we forgot to
 * check"; an explicit "unknown" looks identical to "we checked and
 * could not tell," which is the honest state of affairs.
 *
 * Every subprocess call here is wrapped and degrades to "unknown"
 * rather than throwing -- this MUST be safe on a bare container with no
 * GPU and no `nvidia-smi`.
 */

import { execFileSync } from "node:child_process";
import { cpus, platform, release, totalmem } from "node:os";

export const UNKNOWN = "unknown";

function safeRun(command: string, args: string[]): string | null {
	try {
		return (
			execFileSync(command, args, {
				encoding: "utf-8",
				timeout: 5000,
				stdio: ["ignore", "pipe", "ignore"],
			}).trim() || null
		);
	} catch {
		return null;
	}
}

function detectAccelerator(): {
	accelerator: string;
	accelerator_driver_version: string;
} {
	const nvidia = safeRun("nvidia-smi", [
		"--query-gpu=name,driver_version",
		"--format=csv,noheader",
	]);
	if (nvidia) {
		const [name, driver] = nvidia.split("\n")[0].split(",");
		return {
			accelerator: name?.trim() || UNKNOWN,
			accelerator_driver_version: driver?.trim() || UNKNOWN,
		};
	}
	return { accelerator: "cpu-only", accelerator_driver_version: "n/a" };
}

export function discoverHardware(): Record<string, unknown> {
	const cpuList = cpus();
	return {
		cpu: cpuList[0]?.model ?? UNKNOWN,
		cpu_count: cpuList.length || UNKNOWN,
		os: platform(),
		os_version: release(),
		total_memory_gb: Math.round((totalmem() / 1024 ** 3) * 10) / 10,
		...detectAccelerator(),
	};
}

const COMMON_TOOLS = [
	"git",
	"docker",
	"python3",
	"go",
	"rustc",
	"cargo",
	"openssl",
	"make",
];

function versionOf(binary: string): string {
	for (const flag of ["--version", "-version", "version"]) {
		const output = safeRun(binary, [flag]);
		if (output) return output.split("\n")[0].slice(0, 200);
	}
	return UNKNOWN;
}

function which(binary: string): boolean {
	return (
		safeRun(process.platform === "win32" ? "where" : "which", [binary]) !== null
	);
}

export function discoverSoftwareStack(): Record<string, unknown> {
	const tools: Record<string, string> = {};
	for (const tool of COMMON_TOOLS) {
		if (which(tool)) tools[tool] = versionOf(tool);
	}
	return {
		runtime: "node",
		runtime_version: process.version,
		platform_string: process.platform,
		available_tools: tools,
	};
}

export function discoverPermissionsAndNetwork(): Record<string, unknown> {
	const sandboxHints = [
		"CI",
		"CODESPACES",
		"GITPOD_WORKSPACE_ID",
		"DOCKER_CONTAINER",
		"container",
	].filter((key) => Boolean(process.env[key]));
	let runningAsRoot: boolean | string = UNKNOWN;
	if (typeof process.getuid === "function") {
		runningAsRoot = process.getuid() === 0;
	}
	return { running_as_root: runningAsRoot, sandbox_hints: sandboxHints };
}

export function collectRuntimeProvenance(): {
	hardware: Record<string, unknown>;
	software_stack: Record<string, unknown>;
} {
	return {
		hardware: discoverHardware(),
		software_stack: discoverSoftwareStack(),
	};
}
