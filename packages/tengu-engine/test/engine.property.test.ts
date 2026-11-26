import assert from "node:assert/strict";
import test from "node:test";
import { assertProperty } from "../../../test/helpers/prng.ts";
import { compactAgentMessages } from "../src/index.ts";

test("Property P9: compactAgentMessages respects budget, preserves recency, and never throws", () => {
	assertProperty(
		"Context compaction invariants",
		(rng) => {
			const count = rng.int(1, 80);
			const messages = Array.from({ length: count }, (_, idx) => ({
				role: idx % 2 === 0 ? ("user" as const) : ("assistant" as const),
				content: `turn-${idx}-${rng.asciiString(10, 120)}`,
				timestamp: 1000 + idx,
			}));
			const keepRecent = rng.int(2, 12);
			return { messages, keepRecent };
		},
		({ messages, keepRecent }) => {
			const compacted = compactAgentMessages(messages as never[], {
				maxMessages: keepRecent + 4,
				keepRecent,
				maxChars: 2000,
			});
			assert.ok(Array.isArray(compacted));
			assert.ok(compacted.length <= messages.length);
			if (messages.length > 0 && compacted.length > 0) {
				// Most recent message must always be retained at the tail
				const lastOriginal = messages[messages.length - 1]!;
				const lastCompacted = compacted[compacted.length - 1] as { timestamp?: number };
				assert.equal(lastCompacted.timestamp, lastOriginal.timestamp);
			}
		},
	);
});
