/**
 * Zero-dependency deterministic PRNG & property-testing harness for Tengu.
 * Control seed via TENGU_TEST_SEED and iteration count via TENGU_PROP_RUNS.
 */

export class SeededRng {
	private state: number;

	constructor(seed: number) {
		this.state = seed >>> 0;
	}

	/** Mulberry32 deterministic float in [0, 1). */
	next(): number {
		this.state = (this.state + 0x6d2b79f5) >>> 0;
		let t = this.state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	}

	int(min: number, max: number): number {
		return min + Math.floor(this.next() * (max - min + 1));
	}

	bool(prob = 0.5): boolean {
		return this.next() < prob;
	}

	pick<T>(items: readonly T[]): T {
		return items[this.int(0, items.length - 1)]!;
	}

	shuffle<T>(items: readonly T[]): T[] {
		const out = [...items];
		for (let i = out.length - 1; i > 0; i--) {
			const j = this.int(0, i);
			[out[i], out[j]] = [out[j]!, out[i]!];
		}
		return out;
	}

	asciiString(minLen = 0, maxLen = 24, alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_."): string {
		const len = this.int(minLen, maxLen);
		let out = "";
		for (let i = 0; i < len; i++) {
			out += alphabet[this.int(0, alphabet.length - 1)];
		}
		return out;
	}

	hostileString(minLen = 0, maxLen = 40): string {
		const pool = [
			"a", "Z", "0", " ", "\t", "\n", "\r", "<", ">", "&", "\"", "'", "/", "\\",
			"(", ")", "[", "]", "{", "}", ";", "|", "$", "`", "!", "=", "~", "*", "?",
			"日", "本", "語", "中", "🔥", "🧪", "é", "ñ", "\x1b[31m", "\x1b[0m",
		];
		const len = this.int(minLen, maxLen);
		let out = "";
		for (let i = 0; i < len; i++) out += this.pick(pool);
		return out;
	}

	ipv4(): string {
		return `${this.int(0, 255)}.${this.int(0, 255)}.${this.int(0, 255)}.${this.int(0, 255)}`;
	}

	domain(): string {
		const labels = this.int(2, 4);
		const parts: string[] = [];
		for (let i = 0; i < labels - 1; i++) {
			parts.push(this.asciiString(1, 8, "abcdefghijklmnopqrstuvwxyz0123456789"));
		}
		parts.push(this.pick(["com", "net", "org", "io", "test", "local"]));
		return parts.join(".");
	}

	bytes(minLen = 0, maxLen = 512): Buffer {
		const len = this.int(minLen, maxLen);
		const buf = Buffer.alloc(len);
		for (let i = 0; i < len; i++) buf[i] = this.int(0, 255);
		return buf;
	}

	arrayOf<T>(minLen: number, maxLen: number, gen: (rng: SeededRng) => T): T[] {
		const len = this.int(minLen, maxLen);
		const out: T[] = [];
		for (let i = 0; i < len; i++) out.push(gen(this));
		return out;
	}
}

export function getDefaultSeed(): number {
	const raw = process.env.TENGU_TEST_SEED;
	if (raw && /^\d+$/.test(raw)) return Number(raw) >>> 0;
	return 0x54454e47; // "TENG" — deterministic by default, override via TENGU_TEST_SEED
}

export function getDefaultPropRuns(fallback = 200): number {
	const raw = process.env.TENGU_PROP_RUNS;
	if (raw && /^\d+$/.test(raw)) return Math.max(1, Number(raw));
	return fallback;
}

export function assertProperty<T>(
	name: string,
	generate: (rng: SeededRng, iteration: number) => T,
	check: (sample: T, iteration: number) => void,
	options: { runs?: number; seed?: number } = {},
): void {
	const seed = options.seed ?? getDefaultSeed();
	const runs = options.runs ?? getDefaultPropRuns();
	const rng = new SeededRng(seed);

	for (let i = 0; i < runs; i++) {
		const sample = generate(rng, i);
		try {
			check(sample, i);
		} catch (err) {
			const detail = err instanceof Error ? err.message : String(err);
			let serialized = "";
			try {
				serialized = JSON.stringify(sample, (_k, v) => (Buffer.isBuffer(v) ? `<Buffer len=${v.length}>` : v));
			} catch {
				serialized = String(sample);
			}
			if (serialized.length > 500) serialized = serialized.slice(0, 500) + "...";
			throw new Error(
				`Property "${name}" failed at iteration ${i}/${runs} (TENGU_TEST_SEED=${seed}): ${detail}\nCounterexample: ${serialized}`,
			);
		}
	}
}
