/** UTC, millisecond precision, `Z`-suffixed ISO 8601 -- see SPEC.md ss2.3. */

export function now(): Date {
	return new Date();
}

export function stamp(moment: Date = now()): string {
	// Date#toISOString() already yields exactly 3 fractional-second digits
	// and a trailing "Z" -- precisely SPEC.md ss2.3's format, no adjustment needed.
	return moment.toISOString();
}

export function parseStamp(value: string): Date {
	return new Date(value);
}
