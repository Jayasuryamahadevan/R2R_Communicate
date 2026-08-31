/**
 * Tiny atomic JSON file read/write. Every piece of state this core
 * persists (identity, chain, self-state, FASP pairings) goes through
 * this one pair of functions -- so a fix to the write path (or the
 * file-mode discipline around it) never needs making twice.
 */

import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { AICError } from "./crypto.js";

export function readJson<T>(path: string, fallback: T): T {
	if (!existsSync(path)) return fallback;
	const raw = readFileSync(path, "utf-8");
	try {
		return JSON.parse(raw) as T;
	} catch (error) {
		// A crash or disk issue mid-write is the realistic cause, not a
		// bug in this code -- confirmed by actually truncating a real
		// chain.json and watching a raw, unhandled SyntaxError propagate
		// with no indication of which file or what to do about it. Never
		// silently repair or discard a corrupted identity/chain file (same
		// rule harness.ts already applies to a broken-but-present
		// identity) -- surface it clearly instead.
		throw new AICError(
			"state.corrupted",
			`${path} exists but is not valid JSON (${(error as Error).message}). This file will not be silently repaired or discarded -- if it holds identity or chain state, treat this workspace's identity as broken until it's restored from backup or a new identity is bootstrapped in a fresh state directory.`,
		);
	}
}

export function writeJson(path: string, value: unknown, mode: number): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const tmp = `${path}.tmp`;
	writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, "utf-8");
	chmodSync(tmp, mode);
	writeFileSync(path, readFileSync(tmp));
	chmodSync(path, mode);
}
