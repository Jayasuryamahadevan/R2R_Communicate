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

/** Checked in order, each degrading silently to the next: NVIDIA (any
 * platform with the proprietary driver), AMD/ROCm (Linux), then Apple's
 * own GPU on Apple Silicon Macs -- covers the accelerators actually
 * common on the devices this harness runs on (a dev workstation, a Mac,
 * a Linux server) without pretending to enumerate every possible one
 * (an edge TPU, an FPGA, ...). None of these three commands existing is
 * not an error -- it just means "cpu-only", reported as honestly as
 * finding one. */
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

	const rocm = safeRun("rocm-smi", ["--showproductname"]);
	// Wording varies by rocm-smi version ("Card series:" vs "Card Series:",
	// with or without a leading "GPU[0] :") -- match the field name
	// itself rather than anchoring to one exact layout.
	const rocmName = rocm?.match(/card\s*series\s*:\s*(.+)/i)?.[1]?.trim();
	if (rocmName) {
		return { accelerator: rocmName, accelerator_driver_version: UNKNOWN };
	}

	if (process.platform === "darwin") {
		const displays = safeRun("system_profiler", ["SPDisplaysDataType"]);
		const chipset = displays?.match(/Chipset Model:\s*(.+)/)?.[1]?.trim();
		if (chipset) {
			// Apple doesn't expose a separate GPU driver version to query --
			// it's bundled with the OS build, already captured in os_version.
			return { accelerator: chipset, accelerator_driver_version: "n/a" };
		}
	}

	return { accelerator: "cpu-only", accelerator_driver_version: "n/a" };
}

export function discoverHardware(): Record<string, unknown> {
	const cpuList = cpus();
	return {
		cpu: cpuList[0]?.model ?? UNKNOWN,
		cpu_count: cpuList.length || UNKNOWN,
		// arm64, x64, ... -- process.arch, not os.arch(): they agree except
		// under Rosetta/32-on-64 emulation, where process.arch is the one
		// that reflects what this actual Node process is running as.
		cpu_architecture: process.arch,
		os: platform(),
		os_version: release(),
		// An integer count of MB, not a rounded GB float: this data flows
		// into signed Tier 3 content, and the canonicalizer this bridge
		// uses (crypto.ts) deliberately only covers integers -- see
		// NO_PYTHON.md. Still precise to within a fraction of a percent.
		total_memory_mb: Math.round(totalmem() / 1024 ** 2),
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
