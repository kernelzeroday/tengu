import type { AgentMessage } from "@earendil-works/pi-agent-core";

export interface CompactionOptions {
	/** Keep the last N messages verbatim without compacting tool outputs (default 8). */
	keepRecent?: number;
	/** Compact older toolResult text blocks exceeding this length (default 1200 chars). */
	maxOldToolOutputChars?: number;
	/** Hard message cap; drops oldest middle turns while keeping the first user message (default 48). */
	maxMessages?: number;
}

/**
 * Compacts long Worker / Chat transcripts before sending to the LLM (ARTEX compaction parity).
 * Wired directly into Pi Agent's `transformContext` hook.
 */
export function compactAgentMessages(
	messages: AgentMessage[],
	options: CompactionOptions = {},
): AgentMessage[] {
	const keepRecent = options.keepRecent ?? 8;
	const maxOldChars = options.maxOldToolOutputChars ?? 1200;
	const maxMessages = options.maxMessages ?? 48;

	if (messages.length <= keepRecent) return messages;

	let working = messages;
	if (working.length > maxMessages) {
		const head = working.slice(0, 2);
		const tail = working.slice(-(maxMessages - 2));
		working = [...head, ...tail];
	}

	const cutoff = Math.max(0, working.length - keepRecent);
	return working.map((msg, idx) => {
		if (idx >= cutoff) return msg;
		if (msg.role === "toolResult" && "content" in msg && Array.isArray(msg.content)) {
			let changed = false;
			const newContent = msg.content.map((c) => {
				if (c.type === "text" && c.text.length > maxOldChars) {
					changed = true;
					return {
						...c,
						text: `${c.text.slice(0, Math.floor(maxOldChars * 0.6))}\n\n[...compacted ${c.text.length - maxOldChars} chars of earlier tool output...]`,
					};
				}
				return c;
			});
			return changed ? ({ ...msg, content: newContent } as AgentMessage) : msg;
		}
		return msg;
	});
}
