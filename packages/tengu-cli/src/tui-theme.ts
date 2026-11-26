import { Markdown, type MarkdownTheme, truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";
import type { Severity } from "@tengu/store";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const ITALIC = "\x1b[3m";
const UNDERLINE = "\x1b[4m";
const STRIKE = "\x1b[9m";

const fg = (r: number, g: number, b: number) => `\x1b[38;2;${r};${g};${b}m`;
const bg = (r: number, g: number, b: number) => `\x1b[48;2;${r};${g};${b}m`;

export const theme = {
	reset: RESET,
	bold: (s: string) => `${BOLD}${s}${RESET}`,
	dim: (s: string) => `${DIM}${s}${RESET}`,
	italic: (s: string) => `${ITALIC}${s}${RESET}`,
	underline: (s: string) => `${UNDERLINE}${s}${RESET}`,
	strike: (s: string) => `${STRIKE}${s}${RESET}`,
	crimson: (s: string) => `${fg(239, 68, 68)}${s}${RESET}`,
	crimsonBold: (s: string) => `${BOLD}${fg(248, 113, 113)}${s}${RESET}`,
	brandBadge: (s: string) => `${BOLD}${bg(185, 28, 28)}${fg(255, 255, 255)}${s}${RESET}`,
	amber: (s: string) => `${fg(245, 158, 11)}${s}${RESET}`,
	amberBold: (s: string) => `${BOLD}${fg(251, 191, 36)}${s}${RESET}`,
	emerald: (s: string) => `${fg(52, 211, 153)}${s}${RESET}`,
	cyan: (s: string) => `${fg(56, 189, 248)}${s}${RESET}`,
	cyanBold: (s: string) => `${BOLD}${fg(125, 211, 252)}${s}${RESET}`,
	violet: (s: string) => `${fg(167, 139, 250)}${s}${RESET}`,
	muted: (s: string) => `${fg(148, 163, 184)}${s}${RESET}`,
	subtle: (s: string) => `${fg(100, 116, 139)}${s}${RESET}`,
	border: (s: string) => `${fg(63, 76, 94)}${s}${RESET}`,
	borderActive: (s: string) => `${fg(239, 68, 68)}${s}${RESET}`,
	scrollThumb: (s: string) => `${fg(248, 113, 113)}${s}${RESET}`,
	scrollTrack: (s: string) => `${fg(51, 65, 85)}${s}${RESET}`,
	headerBg: (s: string) => `${bg(15, 23, 42)}${fg(241, 245, 249)}${s}${RESET}`,
	tabActive: (s: string) => `${BOLD}${bg(220, 38, 38)}${fg(255, 255, 255)}${s}${RESET}`,
	tabInactive: (s: string) => `${bg(30, 41, 59)}${fg(148, 163, 184)}${s}${RESET}`,
	rowSelected: (s: string) => `${BOLD}${bg(38, 49, 66)}${fg(248, 250, 252)}${s}${RESET}`,
	accentBar: () => `${fg(248, 113, 113)}▌${RESET}`,
	footerBg: (s: string) => `${bg(15, 23, 42)}${fg(148, 163, 184)}${s}${RESET}`,
	keyHint: (s: string) => `${BOLD}${fg(251, 191, 36)}${s}${RESET}`,
	codeBg: (s: string) => `${bg(30, 41, 59)}${fg(125, 211, 252)}${s}${RESET}`,
};

export const tenguMarkdownTheme: MarkdownTheme = {
	heading: (t) => theme.amberBold(t),
	link: (t) => theme.cyan(t),
	linkUrl: (t) => theme.subtle(t),
	code: (t) => theme.codeBg(` ${t} `),
	codeBlock: (t) => `${fg(203, 213, 225)}${t}${RESET}`,
	codeBlockBorder: (t) => theme.subtle(t),
	quote: (t) => theme.italic(theme.muted(t)),
	quoteBorder: (t) => theme.violet(t),
	hr: (t) => theme.subtle(t),
	listBullet: (t) => theme.crimsonBold(t),
	bold: (t) => theme.bold(t),
	italic: (t) => theme.italic(t),
	strikethrough: (t) => theme.strike(t),
	underline: (t) => theme.underline(t),
	codeBlockIndent: "  ",
};

/**
 * Renders Markdown text into ANSI-styled terminal lines wrapped to `width`.
 */
export function renderMarkdown(markdownText: string, width: number): string[] {
	const safeW = Math.max(16, width);
	const md = new Markdown(markdownText, 0, 0, tenguMarkdownTheme);
	return [...md.render(safeW)];
}

export function severityBadge(sev: Severity): string {
	switch (sev) {
		case "critical":
			return `${BOLD}${bg(153, 27, 27)}${fg(255, 255, 255)} CRIT ${RESET}`;
		case "high":
			return `${BOLD}${bg(194, 65, 12)}${fg(255, 255, 255)} HIGH ${RESET}`;
		case "medium":
			return `${BOLD}${bg(161, 98, 7)}${fg(255, 255, 255)} MED  ${RESET}`;
		case "low":
			return `${BOLD}${bg(29, 78, 216)}${fg(255, 255, 255)} LOW  ${RESET}`;
		default:
			return `${bg(51, 65, 85)}${fg(226, 232, 240)} INFO ${RESET}`;
	}
}

export function padRight(str: string, width: number): string {
	const clipped = truncateToWidth(str, width, "…");
	const vis = visibleWidth(clipped);
	return vis < width ? clipped + " ".repeat(width - vis) : clipped;
}

export function selectedRow(text: string, innerWidth: number): string {
	return `${theme.accentBar()}${theme.rowSelected(padRight(` ${text}`, Math.max(1, innerWidth - 1)))}`;
}

export function progressBar(current: number, total: number, barWidth = 20): string {
	const ratio = total > 0 ? Math.max(0, Math.min(1, current / total)) : 0;
	const filled = Math.round(ratio * barWidth);
	const empty = Math.max(0, barWidth - filled);
	const pct = Math.round(ratio * 100);
	return `${theme.emerald("█".repeat(filled))}${theme.subtle("░".repeat(empty))} ${theme.bold(`${pct}%`)} ${theme.muted(`(${current}/${total})`)}`;
}

/**
 * Renders a rounded-corner Unicode panel of exact dimensions (width x height),
 * with an optional integrated scrollbar thumb (`┃`) on the right border when content overflows.
 */
export function renderPanel(options: {
	title: string;
	subtitle?: string;
	lines: string[];
	width: number;
	height: number;
	active?: boolean;
	scroll?: { offset: number; total: number; visibleRows?: number };
}): string[] {
	const w = Math.max(8, options.width);
	const h = Math.max(3, options.height);
	const innerW = w - 2;
	const innerH = h - 2;
	const borderFn = options.active ? theme.borderActive : theme.border;

	const titlePart = options.active ? theme.crimsonBold(` ${options.title} `) : theme.cyanBold(` ${options.title} `);
	const subPart = options.subtitle ? theme.muted(` ${options.subtitle} `) : "";
	const topContent = `${titlePart}${subPart}`;
	const topVis = visibleWidth(topContent);
	const rem = Math.max(0, innerW - 1 - topVis);
	const top = `${borderFn("╭─")}${truncateToWidth(topContent, Math.max(0, innerW - 1), "…")}${borderFn(`${"─".repeat(rem)}╮`)}`;

	const scrollRows = options.scroll?.visibleRows ?? innerH;
	const hasScrollbar = Boolean(options.scroll && options.scroll.total > scrollRows);
	let thumbStart = 0;
	let thumbEnd = 0;
	if (hasScrollbar && options.scroll) {
		const { offset, total } = options.scroll;
		const thumbSize = Math.max(1, Math.round((scrollRows / total) * scrollRows));
		const maxOffset = Math.max(1, total - scrollRows);
		thumbStart = Math.round((Math.min(offset, maxOffset) / maxOffset) * (scrollRows - thumbSize));
		thumbEnd = thumbStart + thumbSize;
	}

	const out: string[] = [top];
	for (let i = 0; i < innerH; i++) {
		const raw = options.lines[i] ?? "";
		const padded = padRight(` ${raw}`, innerW);
		const rightEdge = hasScrollbar && i < scrollRows
			? i >= thumbStart && i < thumbEnd
				? theme.scrollThumb("┃")
				: theme.scrollTrack("│")
			: borderFn("│");
		out.push(`${borderFn("│")}${padded}${rightEdge}`);
	}
	out.push(borderFn(`╰${"─".repeat(innerW)}╯`));
	return out;
}

/**
 * Side-by-side horizontal join of two equal-height panels with a 1-char gap.
 */
export function hJoin(left: string[], right: string[], leftW: number, rightW: number): string[] {
	const h = Math.max(left.length, right.length);
	const out: string[] = [];
	for (let i = 0; i < h; i++) {
		const l = padRight(left[i] ?? "", leftW);
		const r = padRight(right[i] ?? "", rightW);
		out.push(`${l} ${r}`);
	}
	return out;
}
