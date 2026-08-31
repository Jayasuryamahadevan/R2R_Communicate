/**
 * A generic append-only, hash-chained JSON Lines log -- used for both
 * the action log ("what did this agent do") and the experience store
 * ("what did this agent learn"). Mirrors the Python reference
 * implementation's log.py exactly (same field names, same chaining
 * rule), so a log written by this extension and one written by the
 * Python `aic` CLI are structurally identical and cross-verifiable.
 *
 * Safe across two separate PROCESSES appending to the same file (e.g.
 * the same workspace opened in two terminals) -- confirmed NOT true
 * before the lock/revalidation below existed: two real Node processes,
 * synchronized to start appending at the same instant, reliably
 * produced a broken chain (both believed they held seq 0). A single
 * process's own calls were never at risk -- `append()` has no `await`
 * in it, so two calls from the same process can't interleave -- this is
 * specifically the cross-process case.
 */

import {
	appendFileSync,
	closeSync,
	existsSync,
	mkdirSync,
	openSync,
	readFileSync,
	statSync,
	unlinkSync,
} from "node:fs";
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

const LOCK_STALE_MS = 10_000;
const LOCK_RETRY_DELAY_MS = 15;
const LOCK_MAX_WAIT_MS = 3_000;

/** A synchronous sleep, using Atomics.wait on a throwaway buffer nobody
 * else touches -- this class is deliberately synchronous throughout
 * (every caller across bridge_core/pi_bridge/opencode_bridge calls
 * `append()` without `await`), so a real `setTimeout`-based async sleep
 * would mean making `append()` async and rippling that through every
 * call site for a lock that's normally held for microseconds. */
function sleepSync(ms: number): void {
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function withFileLock<T>(path: string, fn: () => T): T {
	const lockPath = `${path}.lock`;
	const deadline = Date.now() + LOCK_MAX_WAIT_MS;
	for (;;) {
		try {
			closeSync(openSync(lockPath, "wx"));
			break;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			try {
				if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
					unlinkSync(lockPath); // abandoned by a crashed process -- safe to reclaim
					continue;
				}
			} catch {
				continue; // the lock vanished between our check and stat -- just retry
			}
			if (Date.now() > deadline) {
				throw new AICError(
					"log.lock_timeout",
					`Could not acquire the write lock on ${path} within ${LOCK_MAX_WAIT_MS}ms -- another process may be stuck holding it (a stale lock older than ${LOCK_STALE_MS}ms is reclaimed automatically; delete ${lockPath} by hand only if you're certain nothing legitimate still holds it).`,
				);
			}
			sleepSync(LOCK_RETRY_DELAY_MS);
		}
	}
	try {
		return fn();
	} finally {
		try {
			unlinkSync(lockPath);
		} catch {
			// already gone -- fine, nothing to clean up
		}
	}
}

export class AppendOnlyLog {
	private readonly path: string;
	private lastDigest: string | null = null;
	private nextSeq = 0;
	/** The file's own size the last time this instance's in-memory state
	 * was known-correct -- if the file is still that size, nothing else
	 * has appended to it since, and the cheap in-memory state can be
	 * trusted without re-scanning. If it's grown, some OTHER process
	 * wrote in the meantime and this instance must catch up first. This
	 * is what keeps the common case (one process, one log) O(1) per
	 * append while still being correct under real cross-process
	 * contention, which only costs an O(entries) rescan when it actually
	 * happens. */
	private knownSize = 0;

	constructor(path: string) {
		this.path = path;
		this.refreshFromDisk();
	}

	private refreshFromDisk(): void {
		if (!existsSync(this.path)) {
			this.lastDigest = null;
			this.nextSeq = 0;
			this.knownSize = 0;
			return;
		}
		for (const entry of this.entries()) {
			this.lastDigest = entry.digest;
			this.nextSeq = entry.seq + 1;
		}
		this.knownSize = statSync(this.path).size;
	}

	append(kind: string, detail: Record<string, unknown>): LogEntry {
		mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
		return withFileLock(this.path, () => {
			const currentSize = existsSync(this.path) ? statSync(this.path).size : 0;
			if (currentSize !== this.knownSize) this.refreshFromDisk();

			const entry: Omit<LogEntry, "digest"> = {
				seq: this.nextSeq,
				at: stamp(),
				kind,
				detail,
				prev_digest: this.lastDigest,
			};
			const withDigest: LogEntry = { ...entry, digest: digestOf(entry) };
			const line = `${JSON.stringify(withDigest)}\n`;
			appendFileSync(this.path, line, "utf-8");
			this.lastDigest = withDigest.digest;
			this.nextSeq += 1;
			this.knownSize = currentSize + Buffer.byteLength(line, "utf-8");
			return withDigest;
		});
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
