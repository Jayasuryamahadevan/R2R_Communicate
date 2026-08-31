/**
 * A generic append-only, hash-chained JSON Lines log -- used for both
 * the action log ("what did this agent do") and the experience store
 * ("what did this agent learn"). Mirrors the Python reference
 * implementation's log.py exactly (same field names, same chaining
 * rule), so a log written by this extension and one written by the
 * Python `aic` CLI are structurally identical and cross-verifiable.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { AICError, digestOf } from "./crypto.js";
import { stamp } from "./timestamps.js";

export interface LogEntry extends Record<string, unknown> {
	seq: number;
	at: string;
	kind: string;
	detail: Record<string, unknown>;
	prev_digest: string | null;
	digest: string;
}

export class AppendOnlyLog {
	private readonly path: string;
	private lastDigest: string | null = null;
	private nextSeq = 0;

	constructor(path: string) {
		this.path = path;
		if (existsSync(path)) {
			for (const entry of this.entries()) {
				this.lastDigest = entry.digest;
				this.nextSeq = entry.seq + 1;
			}
		}
	}

	append(kind: string, detail: Record<string, unknown>): LogEntry {
		const entry: Omit<LogEntry, "digest"> = {
			seq: this.nextSeq,
			at: stamp(),
			kind,
			detail,
			prev_digest: this.lastDigest,
		};
		const withDigest: LogEntry = { ...entry, digest: digestOf(entry) };
		mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
		appendFileSync(this.path, `${JSON.stringify(withDigest)}\n`, "utf-8");
		this.lastDigest = withDigest.digest;
		this.nextSeq += 1;
		return withDigest;
	}

	entries(kind?: string): LogEntry[] {
		if (!existsSync(this.path)) return [];
		const lines = readFileSync(this.path, "utf-8")
			.split("\n")
			.filter((line) => line.trim().length > 0);
		const rows = lines.map((line) => JSON.parse(line) as LogEntry);
		return kind ? rows.filter((row) => row.kind === kind) : rows;
	}

	get lastDigestValue(): string | null {
		return this.lastDigest;
	}

	verify(): void {
		let expectedSeq = 0;
		let expectedPrev: string | null = null;
		for (const entry of this.entries()) {
			if (entry.seq !== expectedSeq) {
				throw new AICError(
					"log.sequence_broken",
					`Expected seq ${expectedSeq}, found ${entry.seq}.`,
				);
			}
			if (entry.prev_digest !== expectedPrev) {
				throw new AICError(
					"log.chain_broken",
					`Entry seq ${entry.seq} does not chain from the previous entry.`,
				);
			}
			const { digest: recordedDigest, ...withoutDigest } = entry;
			const recomputed = digestOf(withoutDigest);
			if (recomputed !== recordedDigest) {
				throw new AICError(
					"log.tampered",
					`Entry seq ${entry.seq} was altered after being written.`,
				);
			}
			expectedSeq += 1;
			expectedPrev = recordedDigest;
		}
	}
}
