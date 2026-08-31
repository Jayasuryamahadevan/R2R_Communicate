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

export function readJson<T>(path: string, fallback: T): T {
	if (!existsSync(path)) return fallback;
	return JSON.parse(readFileSync(path, "utf-8")) as T;
}

export function writeJson(path: string, value: unknown, mode: number): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const tmp = `${path}.tmp`;
	writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, "utf-8");
	chmodSync(tmp, mode);
	writeFileSync(path, readFileSync(tmp));
	chmodSync(path, mode);
}
