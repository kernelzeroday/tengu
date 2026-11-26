import { wrapTextWithAnsi } from "@earendil-works/pi-tui";
import { renderMarkdown, theme } from "./tui-theme.ts";

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

export type ChatPhase = "idle" | "prefill" | "thinking" | "tool" | "streaming";

export interface InlineToolEvent {
	name: string;
	argsPreview: string;
	status: "running" | "done" | "error";
	startedAt: number;
	durationMs: number | null;
}

/**
 * Sparkle-grade live chat turn state: animated prefill spinner, live thinking block,
 * inline tool call pills, and token-by-token streaming Markdown with tok/s telemetry.
 */
export class ChatStreamState {
	public phase: ChatPhase = "idle";
	public modelId = "";
	public startedAt = 0;
	public firstTokenAt = 0;
	public thinkingStartedAt = 0;
	public thinkingEndedAt = 0;
	public thinkingText = "";
	public thinkingTokens = 0;
	public responseText = "";
	public responseTokens = 0;
	public tools: InlineToolEvent[] = [];
	public spinnerTick = 0;
	public showFullThinking = false;
	public aborted = false;

	start(modelId: string): void {
		this.phase = "prefill";
		this.modelId = modelId;
		this.startedAt = Date.now();
		this.firstTokenAt = 0;
		this.thinkingStartedAt = 0;
		this.thinkingEndedAt = 0;
		this.thinkingText = "";
		this.thinkingTokens = 0;
		this.responseText = "";
		this.responseTokens = 0;
		this.tools = [];
		this.spinnerTick = 0;
		this.aborted = false;
	}

	tick(): void {
		this.spinnerTick = (this.spinnerTick + 1) % SPINNER_FRAMES.length;
	}

	onThinkingDelta(delta: string): void {
		const now = Date.now();
		if (!this.firstTokenAt) this.firstTokenAt = now;
		if (!this.thinkingStartedAt) this.thinkingStartedAt = now;
		this.phase = "thinking";
		this.thinkingText += delta;
		this.thinkingTokens += Math.max(1, Math.ceil(delta.length / 4));
	}

	onTextDelta(delta: string): void {
		const now = Date.now();
		if (!this.firstTokenAt) this.firstTokenAt = now;
		if (this.thinkingStartedAt && !this.thinkingEndedAt) this.thinkingEndedAt = now;
		this.phase = "streaming";
		this.responseText += delta;
		this.responseTokens += Math.max(1, Math.ceil(delta.length / 4));
	}

	onToolStart(name: string, args: unknown): void {
		const now = Date.now();
		if (this.thinkingStartedAt && !this.thinkingEndedAt) this.thinkingEndedAt = now;
		this.phase = "tool";
		const preview = typeof args === "string" ? args : JSON.stringify(args ?? {});
		this.tools.push({
			name,
			argsPreview: preview.length > 60 ? `${preview.slice(0, 57)}…` : preview,
			status: "running",
			startedAt: now,
			durationMs: null,
		});
	}

	onToolEnd(name: string, isError: boolean): void {
		const now = Date.now();
		const target = [...this.tools].reverse().find((t) => t.name === name && t.status === "running");
		if (target) {
			target.status = isError ? "error" : "done";
			target.durationMs = now - target.startedAt;
		}
		this.phase = "prefill";
	}

	private elapsedSec(from = this.startedAt): string {
		if (!from) return "0.0s";
		return `${((Date.now() - from) / 1000).toFixed(1)}s`;
	}

	private tokensPerSec(): number {
		const total = this.thinkingTokens + this.responseTokens;
		if (total === 0 || !this.firstTokenAt) return 0;
		const sec = Math.max(0.2, (Date.now() - this.firstTokenAt) / 1000);
		return Math.round((total / sec) * 10) / 10;
	}

	/**
	 * Renders the live in-progress turn (spinner, prefill/thinking/tool/streaming Markdown + cursor).
	 */
	renderLive(width: number): string[] {
		if (this.phase === "idle") return [];
		const w = Math.max(24, width);
		const spin = SPINNER_FRAMES[this.spinnerTick]!;
		const lines: string[] = [];
		const tps = this.tokensPerSec();
		const totalTok = this.thinkingTokens + this.responseTokens;

		// 1. Animated status header
		if (this.phase === "prefill") {
			lines.push(
				`${theme.amberBold(spin)} ${theme.bold("Prefilling prompt…")} ${theme.muted(`${this.elapsedSec()} · ${this.modelId} · Esc to abort`)}`,
			);
		} else if (this.phase === "thinking") {
			lines.push(
				`${theme.violet(spin)} ${theme.bold("Thinking…")} ${theme.muted(`${this.elapsedSec(this.thinkingStartedAt)} · ${this.thinkingTokens} tok · ${tps} tok/s · Esc to abort`)}`,
			);
		} else if (this.phase === "tool") {
			lines.push(
				`${theme.cyanBold(spin)} ${theme.bold("Running tool…")} ${theme.muted(`${this.elapsedSec()} · Esc to abort`)}`,
			);
		} else if (this.phase === "streaming") {
			lines.push(
				`${theme.emerald(spin)} ${theme.violet("◆ tengu")} ${theme.muted(`${this.elapsedSec()} · ${totalTok} tok · ${tps} tok/s · Esc to abort`)}`,
			);
		}

		// 2. Thinking block (live excerpt while thinking, or collapsed summary once done)
		if (this.thinkingText.length > 0) {
			if (this.phase === "thinking" || this.showFullThinking) {
				const wrappedThink = wrapTextWithAnsi(this.thinkingText.trim(), Math.max(16, w - 4));
				const slice = this.showFullThinking ? wrappedThink : wrappedThink.slice(-6);
				for (const l of slice) {
					lines.push(`${theme.violet("│")} ${theme.italic(theme.muted(l))}`);
				}
			} else {
				const thinkSec = this.thinkingStartedAt
					? (((this.thinkingEndedAt || Date.now()) - this.thinkingStartedAt) / 1000).toFixed(1)
					: "0.0";
				lines.push(theme.subtle(`  💭 Thought for ${thinkSec}s (${this.thinkingTokens} tok) — /think to toggle`));
			}
		}

		// 3. Inline tool call pills
		for (const t of this.tools) {
			if (t.status === "running") {
				lines.push(`  ${theme.cyanBold(spin)} ${theme.cyan(`⚙ ${t.name}`)} ${theme.subtle(t.argsPreview)} ${theme.muted(`(${this.elapsedSec(t.startedAt)})`)}`);
			} else if (t.status === "done") {
				lines.push(`  ${theme.emerald("✓")} ${theme.cyan(`⚙ ${t.name}`)} ${theme.subtle(`${t.durationMs ?? 0}ms`)}`);
			} else {
				lines.push(`  ${theme.crimson("✗")} ${theme.crimson(`⚙ ${t.name}`)} ${theme.subtle(`error · ${t.durationMs ?? 0}ms`)}`);
			}
		}

		// 4. Live streaming Markdown with block cursor
		if (this.responseText.length > 0) {
			const rendered = renderMarkdown(`${this.responseText}▍`, w);
			lines.push(...rendered);
		}

		return lines;
	}

	/**
	 * Produces the final committed transcript lines once the turn completes or is aborted.
	 */
	finalize(width: number): string[] {
		const w = Math.max(24, width);
		const lines: string[] = [];
		const totalTok = this.thinkingTokens + this.responseTokens;
		const tps = this.tokensPerSec();
		const dur = this.elapsedSec();

		lines.push(
			`${theme.violet("◆ tengu")} ${theme.subtle(`· ${this.modelId} · ${dur}${totalTok > 0 ? ` · ${totalTok} tok · ${tps} tok/s` : ""}${this.aborted ? " · ABORTED" : ""}`)}`,
		);

		if (this.thinkingText.length > 0) {
			const thinkSec = this.thinkingStartedAt
				? (((this.thinkingEndedAt || Date.now()) - this.thinkingStartedAt) / 1000).toFixed(1)
				: "0.0";
			lines.push(theme.subtle(`  💭 Thought for ${thinkSec}s (${this.thinkingTokens} tok)`));
			if (this.showFullThinking) {
				for (const l of wrapTextWithAnsi(this.thinkingText.trim(), Math.max(16, w - 4))) {
					lines.push(`${theme.violet("│")} ${theme.italic(theme.muted(l))}`);
				}
			}
		}

		for (const t of this.tools) {
			const icon = t.status === "error" ? theme.crimson("✗") : theme.emerald("✓");
			lines.push(`  ${icon} ${theme.cyan(`⚙ ${t.name}`)} ${theme.subtle(`${t.durationMs ?? 0}ms`)}`);
		}

		if (this.responseText.trim().length > 0) {
			lines.push(...renderMarkdown(this.responseText, w));
		} else if (this.aborted) {
			lines.push(theme.amber("  ⏹ Generation aborted."));
		}

		lines.push("");
		this.phase = "idle";
		return lines;
	}
}
