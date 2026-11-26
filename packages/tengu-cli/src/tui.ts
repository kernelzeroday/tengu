import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Agent, type AgentMessage } from "@earendil-works/pi-agent-core";
import {
	type Component,
	Input,
	isKeyRelease,
	Key,
	matchesKey,
	type OverlayHandle,
	ProcessTerminal,
	TuiAltScreen, type Terminal,
	type TuiMouseEvent,
	type TuiMouseEventResult,
	visibleWidth,
	wrapTextWithAnsi,
} from "@earendil-works/pi-tui";
import {
	buildMainAgentPrompt,
	type LiveTaskStatusSnapshot,
	loadSkills,
	type TenguEngineEvent,
	type TenguOrchestrator,
	type TenguSkill,
} from "@tengu/engine";
import { InterceptEngine } from "@tengu/intercept";
import { EvidenceStore, maskTrafficRecord, ReportGenerator, type ReportFormat } from "@tengu/ops";
import type { ApprovalRequest, Severity, TenguStore } from "@tengu/store";
import { ChatStreamState } from "./chat-stream.ts";
import {
	getBackgroundTaskStatus,
	signalBackgroundPauseToggle,
	startBackgroundTask,
	stopBackgroundTask,
} from "./daemon.ts";
import type { PiModelConfig, ResolvedPiEndpoint } from "./pi-config.ts";
import { type LoadedSession, TenguSessionManager } from "./sessions.ts";
import {
	hJoin,
	padRight,
	progressBar,
	renderMarkdown,
	renderPanel,
	selectedRow,
	severityBadge,
	theme,
} from "./tui-theme.ts";

export interface TenguTuiOptions {
	store: TenguStore;
	intercept: InterceptEngine;
	piConfig?: PiModelConfig;
	orchestrator?: TenguOrchestrator;
	tenguHome?: string;
	dbPath?: string;
	initialTaskId?: number;
	resumeSessionId?: string | true;
	terminal?: Terminal;
	onRegisterAskHandler?: (fn: (req: ApprovalRequest) => Promise<{ approved: boolean; decidedBy: string; reason?: string }>) => void;
}

export type SidebarMode = "live" | "graph" | "findings";

const SIDEBAR_MODES: Array<{ id: SidebarMode; label: string }> = [
	{ id: "live", label: "Live" },
	{ id: "graph", label: "Graph" },
	{ id: "findings", label: "Findings" },
];

const REPORT_FORMATS: ReportFormat[] = ["markdown", "json", "sarif", "html", "docx"];

const SLASH_COMMANDS = [
	"/help",
	"/new",
	"/sessions",
	"/model",
	"/bg",
	"/pause",
	"/resume",
	"/stop",
	"/report",
	"/rules",
	"/skills",
	"/tasks",
	"/evidence",
	"/traffic",
	"/approvals",
	"/usage",
	"/think",
	"/sidebar",
	"/clear",
	"/quit",
];

function setInputTextAtEnd(input: Input, text: string): void {
	input.setValue("");
	if (text.length > 0) input.handleInput(text);
}

export function sliceWindow<T>(items: T[], selectedIndex: number, visibleRows: number): {
	start: number;
	end: number;
	slice: T[];
} {
	const cap = Math.max(1, visibleRows);
	if (items.length <= cap) return { start: 0, end: items.length, slice: items };
	const clamped = Math.max(0, Math.min(selectedIndex, items.length - 1));
	let start = Math.max(0, clamped - Math.floor(cap / 2));
	if (start + cap > items.length) start = Math.max(0, items.length - cap);
	return { start, end: Math.min(items.length, start + cap), slice: items.slice(start, start + cap) };
}

function wrapLines(lines: string[], width: number): string[] {
	const w = Math.max(16, width);
	const out: string[] = [];
	for (const line of lines) {
		if (!line) out.push("");
		else out.push(...wrapTextWithAnsi(line, w));
	}
	return out;
}

/**
 * Scrollable modal overlay (Report Preview, Finding Inspector, Help, Skills).
 */
export class ScrollableModal implements Component {
	readonly capturesViewportInput = true;
	public title: string;
	public scrollOffset = 0;
	private rawLines: string[];
	private markdownText: string | null;
	private footerHint: string;
	private lastMaxScroll = 0;
	private pageSize = 1;
	private readonly getRows: () => number;

	constructor(
		title: string,
		lines: string[],
		footerHint = "↑↓ / PgUp / PgDn / Wheel: Scroll   Home/End: Top/Bottom   Esc/q: Close",
		markdownText: string | null = null,
		getRows: () => number = () => 24,
	) {
		this.title = title;
		this.rawLines = lines;
		this.markdownText = markdownText;
		this.footerHint = footerHint;
		this.getRows = getRows;
	}

	setContent(title: string, lines: string[], resetScroll = true, markdownText: string | null = null): void {
		this.title = title;
		this.rawLines = lines;
		this.markdownText = markdownText;
		if (resetScroll) this.scrollOffset = 0;
	}

	scroll(delta: number): void {
		this.scrollOffset = Math.max(0, Math.min(this.lastMaxScroll, this.scrollOffset + delta));
	}

	scrollPage(direction: -1 | 1): void {
		this.scroll(direction * this.pageSize);
	}

	scrollToTop(): void {
		this.scrollOffset = 0;
	}

	scrollToBottom(): void {
		this.scrollOffset = this.lastMaxScroll;
	}

	handleMouse(event: TuiMouseEvent): TuiMouseEventResult | undefined {
		if (event.type === "wheel" && event.wheelDelta) {
			this.scroll(event.wheelDelta);
			return { handled: true };
		}
		return undefined;
	}

	invalidate(): void {}

	render(width: number, maxHeight = this.getRows()): string[] {
		const w = Math.min(width, 90);
		if (w < 8 || maxHeight < 3) return [];
		const innerW = w - 4;
		const wrapped = this.markdownText !== null ? renderMarkdown(this.markdownText, innerW) : wrapLines(this.rawLines, innerW);
		const showFooter = maxHeight >= 5;
		const bodyH = Math.min(maxHeight - (showFooter ? 4 : 2), 22);
		this.pageSize = bodyH;
		this.lastMaxScroll = Math.max(0, wrapped.length - bodyH);
		const offset = Math.min(this.scrollOffset, this.lastMaxScroll);
		this.scrollOffset = offset;

		const visible = wrapped.slice(offset, offset + bodyH);
		const rangeSub =
			wrapped.length > bodyH
				? `Lines ${offset + 1}-${Math.min(wrapped.length, offset + bodyH)} of ${wrapped.length}`
				: `${wrapped.length} lines`;

		const lines = showFooter ? [...visible, "", theme.muted(this.footerHint)] : visible;
		return renderPanel({
			title: this.title,
			subtitle: rangeSub,
			lines,
			width: w,
			height: lines.length + 2,
			active: true,
			scroll: { offset, total: wrapped.length, visibleRows: bodyH },
		});
	}
}

export interface PickerItem {
	id: string;
	label: string;
	detail?: string;
}

/**
 * Interactive selectable modal picker (Session Switcher, Model Switcher, Intercept Rules).
 */
export class PickerModal implements Component {
	readonly capturesViewportInput = true;
	public readonly title: string;
	public items: PickerItem[];
	public selectedIndex = 0;
	public readonly footerHint: string;
	public onSelect?: (item: PickerItem) => void;

	constructor(title: string, items: PickerItem[], footerHint = "↑↓ / Wheel: Select   Enter: Choose   Esc: Close") {
		this.title = title;
		this.items = items;
		this.footerHint = footerHint;
	}

	move(delta: number): void {
		if (this.items.length === 0) return;
		this.selectedIndex = (this.selectedIndex + delta + this.items.length) % this.items.length;
	}

	selectedItem(): PickerItem | null {
		return this.items[this.selectedIndex] ?? null;
	}

	handleMouse(event: TuiMouseEvent): TuiMouseEventResult | undefined {
		if (event.type === "wheel" && event.wheelDelta) {
			this.move(event.wheelDelta > 0 ? 1 : -1);
			return { handled: true };
		}
		return undefined;
	}

	invalidate(): void {}

	render(width: number): string[] {
		const w = Math.min(Math.max(52, width), 84);
		const innerW = w - 4;
		const visibleRows = Math.min(14, Math.max(4, this.items.length));
		const win = sliceWindow(this.items, this.selectedIndex, visibleRows);

		const lines: string[] = [];
		if (this.items.length === 0) {
			lines.push(theme.muted("(no items)"));
		} else {
			for (let i = 0; i < win.slice.length; i++) {
				const absIdx = win.start + i;
				const item = win.slice[i]!;
				const text = item.detail ? `${item.label}  ${theme.subtle(item.detail)}` : item.label;
				lines.push(absIdx === this.selectedIndex ? selectedRow(text, innerW) : `  ${text}`);
			}
		}
		lines.push("", theme.muted(this.footerHint));

		return renderPanel({
			title: this.title,
			subtitle: `${this.items.length} items`,
			lines,
			width: w,
			height: lines.length + 2,
			active: true,
			scroll: { offset: win.start, total: this.items.length },
		});
	}
}

/**
 * Modern Chat-First, Session-Backed Tengu Cockpit.
 * Chat is the primary interface; a toggleable Mission Sidebar shows live workers/tokens,
 * Dual Graph, and Findings; Sessions, Models, Reports, and Intercept rules open as clean overlays.
 */
export class TenguCockpitApp implements Component {
	readonly capturesViewportInput = true;
	private readonly store: TenguStore;
	private readonly intercept: InterceptEngine;
	private readonly reports: ReportGenerator;
	private readonly skills: TenguSkill[];
	private readonly piConfig?: PiModelConfig;
	private readonly orchestrator?: TenguOrchestrator;
	private readonly tenguHome: string;
	private readonly dbPath: string;
	public dispose?: () => void;
	public readonly sessions: TenguSessionManager;
	private readonly getRows: () => number;

	private lastWidth = 100;
	private headerHitAreas: { start: number; end: number; target: "sessions" | "models" | "sidebar" }[] = [];
	private lastHeight = 32;

	public currentSession: LoadedSession;
	public activeTaskId: number | null;
	public activeEndpoint: ResolvedPiEndpoint | null;

	public sidebarOpen = true;
	public sidebarMode: SidebarMode = "live";
	public sidebarScroll = 0;

	public chatLines: string[] = [];
	public chatHistory: string[] = [];
	public queuedMessages: string[] = [];
	private readonly sessionDrafts = new Map<string, string>();
	private readonly sessionQueues = new Map<string, string[]>();
	public multilinePrefix = "";
	private historyCursor = -1;
	private exitArm: { key: "c" | "d"; at: number } | null = null;
	private tabCompleteState: { prefix: string; matches: string[]; idx: number } | null = null;
	public chatScrollOffset = 0;
	public chatBusy = false;
	public readonly chatStream = new ChatStreamState();
	private chatAnimTimer: NodeJS.Timeout | null = null;
	private chatAgent: Agent | null = null;

	public readonly promptInput = new Input({
		prompt: "",
		placeholder: "Ask Tengu to configure scope, tune workers, run a pentest, or type /help…",
		placeholderStyle: (t) => theme.subtle(t),
	});
	public statusMessage = "Ready — type a message or /help · Ctrl+S Sessions · Ctrl+M Model · Ctrl+R Report";

	public onOpenOverlay?: (kind: "sessions" | "models" | "report" | "rules" | "help" | "skills" | "detail", detail?: { title: string; markdown: string }) => void;
	public onQuit?: () => void;
	public onRenderNeeded?: () => void;

	constructor(options: TenguTuiOptions & { getRows?: () => number }) {
		this.store = options.store;
		this.intercept = options.intercept;
		this.intercept.seedBuiltinRules();
		this.reports = new ReportGenerator(this.store);
		this.skills = loadSkills();
		this.piConfig = options.piConfig;
		this.activeEndpoint = options.piConfig?.active ?? null;
		this.orchestrator = options.orchestrator;
		this.tenguHome = options.tenguHome ?? join(homedir(), ".tengu");
		this.dbPath = options.dbPath ?? join(this.tenguHome, "tengu.db");
		this.sessions = new TenguSessionManager(this.tenguHome);
		this.loadPromptHistory();
		this.getRows = options.getRows ?? (() => process.stdout.rows || 32);
		this.activeTaskId = options.initialTaskId ?? this.store.listTasks()[0]?.id ?? null;

		// Load requested session, resume latest, or create a new persistent JSONL session
		let loaded: LoadedSession | null = null;
		if (typeof options.resumeSessionId === "string") {
			loaded = this.sessions.loadSession(options.resumeSessionId);
		} else if (options.resumeSessionId === true) {
			loaded = this.sessions.getLatestSession();
		}
		if (!loaded) {
			const activeTask = this.activeTaskId != null ? this.store.getTask(this.activeTaskId) : null;
			loaded = this.sessions.createSession({
				title: activeTask ? activeTask.name : "New Engagement",
				taskId: this.activeTaskId,
				model: this.activeEndpoint ? `${this.activeEndpoint.provider}/${this.activeEndpoint.model.id}` : "",
			});
		}
		this.currentSession = loaded;
		const taskId = loaded.header.taskId;
		this.activeTaskId = taskId != null && this.store.getTask(taskId) ? taskId : null;
		this.hydrateTranscriptFromSession(loaded);

		(this.promptInput as unknown as { capturesViewportInput: boolean }).capturesViewportInput = true;
		this.promptInput.onSubmit = (val: string) => {
			const full = this.multilinePrefix ? `${this.multilinePrefix}\n${val}` : val;
			this.multilinePrefix = "";
			this.promptInput.setValue("");
			this.historyCursor = -1;
			void this.submitPrompt(full);
			this.onRenderNeeded?.();
		};
		this.promptInput.onEscape = () => {
			this.handleEscapeKey();
		};
	}

	invalidate(): void {}


	private loadPromptHistory(): void {
		const histPath = join(this.tenguHome, "history.json");
		if (!existsSync(histPath)) return;
		try {
			const parsed = JSON.parse(readFileSync(histPath, "utf8")) as unknown;
			if (Array.isArray(parsed)) {
				this.chatHistory = parsed.filter((x): x is string => typeof x === "string").slice(-200);
			}
		} catch {
			// ignore corrupt history
		}
	}

	private savePromptHistory(): void {
		try {
			mkdirSync(this.tenguHome, { recursive: true });
			writeFileSync(join(this.tenguHome, "history.json"), JSON.stringify(this.chatHistory.slice(-200), null, 2), "utf8");
		} catch {
			// best-effort
		}
	}

	private handleExitChord(key: "c" | "d"): void {
		// Ctrl+C while streaming aborts generation first
		if (key === "c" && this.chatBusy && this.chatAgent) {
			this.exitArm = null;
			this.chatStream.aborted = true;
			this.chatAgent.abort();
			this.setStatus("Aborted generation");
			return;
		}
		// Ctrl+C with text in prompt clears the prompt first
		if (key === "c" && this.promptInput.getValue().length > 0) {
			this.exitArm = null;
			this.promptInput.setValue("");
			this.setStatus("Cleared input");
			return;
		}
		// Ctrl+D only arms exit when prompt is empty
		if (key === "d" && this.promptInput.getValue().length > 0) {
			return;
		}
		const now = Date.now();
		if (this.exitArm && this.exitArm.key === key && now - this.exitArm.at <= 2000) {
			this.exitArm = null;
			this.onQuit?.();
			return;
		}
		this.exitArm = { key, at: now };
		this.setStatus(`Press Ctrl+${key.toUpperCase()} again to exit`);
	}

	private handleEscapeKey(): boolean {
		this.exitArm = null;
		if (this.chatBusy && this.chatAgent) {
			this.chatStream.aborted = true;
			this.chatAgent.abort();
			this.setStatus("Aborted generation");
			return true;
		}
		if (this.queuedMessages.length > 0) {
			this.queuedMessages = [];
			this.setStatus("Cleared queued messages");
			return true;
		}
		if (this.promptInput.getValue().length > 0) {
			this.promptInput.setValue("");
			this.setStatus("Cleared input");
			return true;
		}
		return false;
	}

	private handleTabCompletion(): boolean {
		const val = this.promptInput.getValue();
		if (!val.startsWith("/")) return false;
		if (this.tabCompleteState && this.tabCompleteState.matches[this.tabCompleteState.idx] === val) {
			this.tabCompleteState.idx = (this.tabCompleteState.idx + 1) % this.tabCompleteState.matches.length;
			setInputTextAtEnd(this.promptInput, this.tabCompleteState.matches[this.tabCompleteState.idx]!);
			this.onRenderNeeded?.();
			return true;
		}
		const matches = SLASH_COMMANDS.filter((c) => c.startsWith(val.toLowerCase()));
		if (matches.length === 0) return false;
		this.tabCompleteState = { prefix: val, matches, idx: 0 };
		setInputTextAtEnd(this.promptInput, matches[0]!);
		this.setStatus(matches.length > 1 ? `Matches: ${matches.join(" ")}` : `Completed ${matches[0]}`);
		return true;
	}


	private hydrateTranscriptFromSession(session: LoadedSession): void {
		this.chatLines = [];
		this.chatScrollOffset = 0;
		if (session.messages.length === 0) {
			const task = this.activeTaskId != null ? this.store.getTask(this.activeTaskId) : null;
			this.chatLines.push(
				`${theme.brandBadge(" TENGU ")} ${theme.bold("Autonomous Pentest Cockpit")} ${theme.muted(`· session ${session.header.id.slice(-8)}`)}`,
				theme.muted(
					task
						? `Linked to Task #${task.id} (${task.name}). Talk naturally to configure scope, workers, intercept rules, or launch an engagement.`
						: "Describe your authorized target, scope, and testing parameters—or type /help.",
				),
				"",
			);
			return;
		}
		const renderW = Math.max(44, Math.floor(this.lastWidth * 0.64));
		for (const entry of session.messages) {
			const text = entry.message.content.map((c) => c.text).join("\n");
			if (entry.message.role === "user") {
				this.chatLines.push(`${theme.amberBold("› you")} ${text}`, "");
			} else if (entry.message.role === "assistant") {
				const meta = [
					entry.message.model,
					entry.message.durationSec,
					entry.message.tokens ? `${entry.message.tokens} tok` : "",
				]
					.filter(Boolean)
					.join(" · ");
				this.chatLines.push(`${theme.violet("◆ tengu")}${meta ? ` ${theme.subtle(`· ${meta}`)}` : ""}`);
				if (entry.message.tools?.length) {
					for (const t of entry.message.tools) {
						const ic = t.status === "error" ? theme.crimson("✗") : theme.emerald("✓");
						this.chatLines.push(`  ${ic} ${theme.cyan(`⚙ ${t.name}`)} ${theme.subtle(`${t.durationMs ?? 0}ms`)}`);
					}
				}
				this.chatLines.push(...renderMarkdown(text, renderW), "");
			} else {
				this.chatLines.push(theme.muted(text));
			}
		}
	}

	private saveCurrentSessionInputState(): void {
		const id = this.currentSession.header.id;
		const draft = this.multilinePrefix ? `${this.multilinePrefix}\n${this.promptInput.getValue()}` : this.promptInput.getValue();
		this.sessionDrafts.set(id, draft);
		this.sessionQueues.set(id, [...this.queuedMessages]);
	}

	private restoreSessionInputState(sessionId: string): void {
		const draft = this.sessionDrafts.get(sessionId) ?? "";
		const lines = draft.split("\n");
		this.multilinePrefix = lines.length > 1 ? lines.slice(0, -1).join("\n") : "";
		setInputTextAtEnd(this.promptInput, lines[lines.length - 1] ?? "");
		this.queuedMessages = [...(this.sessionQueues.get(sessionId) ?? [])];
	}

	public switchToSession(sessionId: string): void {
		const loaded = this.sessions.loadSession(sessionId);
		if (!loaded) return;
		this.saveCurrentSessionInputState();
		this.currentSession = loaded;
		this.chatAgent = null;
		// Opening an unlinked session clears the prior task
		this.activeTaskId = loaded.header.taskId != null && this.store.getTask(loaded.header.taskId) ? loaded.header.taskId : null;
		this.restoreSessionInputState(loaded.header.id);
		this.hydrateTranscriptFromSession(loaded);
		this.setStatus(`Resumed session: ${loaded.header.title} (${loaded.messages.length} msgs)`);
	}

	public startNewSession(title?: string, linkTask = false): void {
		this.saveCurrentSessionInputState();
		const linkedTaskId = linkTask ? this.activeTaskId : null;
		const task = linkedTaskId != null ? this.store.getTask(linkedTaskId) : null;
		const fresh = this.sessions.createSession({
			title: title || task?.name || "New Engagement",
			taskId: linkedTaskId,
			model: this.activeEndpoint ? `${this.activeEndpoint.provider}/${this.activeEndpoint.model.id}` : "",
		});
		this.currentSession = fresh;
		this.activeTaskId = linkedTaskId;
		this.chatAgent = null;
		this.restoreSessionInputState(fresh.header.id);
		this.hydrateTranscriptFromSession(fresh);
		this.setStatus(`Started new session (${fresh.header.id.slice(-8)})`);
	}

	public switchModel(endpoint: ResolvedPiEndpoint): void {
		if (this.chatBusy) {
			this.setStatus("Wait for the current response or press Esc to abort.");
			return;
		}
		this.activeEndpoint = endpoint;
		this.chatAgent = null;
		this.sessions.updateHeader(this.currentSession.header.id, {
			model: `${endpoint.provider}/${endpoint.model.id}`,
		});
		this.setStatus(`Switched model to ${endpoint.provider}/${endpoint.model.id}`);
	}

	public pushChatLine(line: string): void {
		for (const part of line.split("\n")) this.chatLines.push(part);
		if (this.chatLines.length > 800) this.chatLines.splice(0, this.chatLines.length - 800);
		this.chatScrollOffset = 0;
		this.onRenderNeeded?.();
	}

	public pushEvent(ev: TenguEngineEvent): void {
		const tag =
			ev.type === "error" || ev.type === "intercept_blocked"
				? theme.crimson(`[${ev.type}]`)
				: ev.type === "finding_reported" || ev.type === "task_completed"
					? theme.emerald(`[${ev.type}]`)
					: ev.type === "task_paused"
						? theme.amber(`[${ev.type}]`)
						: theme.cyan(`[${ev.type}]`);
		this.pushChatLine(`${tag} ${ev.message}`);
	}

	public setStatus(msg: string): void {
		this.statusMessage = msg;
		this.onRenderNeeded?.();
	}

	public getEffectiveLiveStatus(taskId: number): { snapshot: LiveTaskStatusSnapshot | null; isBackground: boolean } {
		const local = this.orchestrator?.getLiveStatus(taskId) ?? null;
		if (local) return { snapshot: local, isBackground: false };
		const bg = getBackgroundTaskStatus(this.tenguHome, taskId);
		if (bg.alive && bg.snapshot) return { snapshot: bg.snapshot, isBackground: true };
		return { snapshot: bg.snapshot, isBackground: false };
	}

	public triggerBackgroundRun(taskId = this.activeTaskId, maxRounds?: number): { pid: number; statusFile: string } | null {
		if (taskId == null) {
			this.setStatus("No active task yet — tell Tengu what target to test first.");
			return null;
		}
		const res = startBackgroundTask({
			tenguHome: this.tenguHome,
			dbPath: this.dbPath,
			taskId,
			maxRounds,
			provider: this.activeEndpoint?.provider,
			model: this.activeEndpoint?.model.id,
		});
		this.pushChatLine(
			theme.emerald(`▶ Started detached background daemon for Task #${taskId} (PID ${res.pid}) — survives TUI close.`),
		);
		this.setStatus(`Background daemon running (PID ${res.pid})`);
		return res;
	}

	public togglePauseResume(taskId = this.activeTaskId): boolean {
		if (taskId == null) return false;
		if (this.orchestrator?.isPaused(taskId)) {
			this.orchestrator.resumeTask(taskId);
			this.setStatus(`Resumed Task #${taskId}`);
			return true;
		}
		if (this.orchestrator?.isRunning(taskId)) {
			this.orchestrator.pauseTask(taskId);
			this.setStatus(`Paused Task #${taskId}`);
			return true;
		}
		if (signalBackgroundPauseToggle(this.tenguHome, taskId)) {
			this.setStatus(`Signaled pause/resume to background daemon for Task #${taskId}`);
			return true;
		}
		this.setStatus(`Task #${taskId} is not currently running`);
		return false;
	}

	public stopActiveRun(taskId = this.activeTaskId): boolean {
		if (taskId == null) return false;
		if (this.orchestrator?.stopTask(taskId)) {
			this.setStatus(`Stopped Task #${taskId}`);
			return true;
		}
		if (stopBackgroundTask(this.tenguHome, taskId)) {
			this.setStatus(`Stopped background daemon for Task #${taskId}`);
			return true;
		}
		this.setStatus(`Task #${taskId} is not running`);
		return false;
	}

	// ── Mouse & Keyboard Input ─────────────────────────────────────────────

	handleMouse(event: TuiMouseEvent): TuiMouseEventResult | undefined {
		const mainW = this.sidebarOpen ? Math.floor((this.lastWidth - 1) * 0.67) : this.lastWidth;

		if (event.type === "wheel" && event.wheelDelta) {
			const step = event.wheelDelta > 0 ? Math.max(1, Math.min(3, event.wheelDelta)) : Math.min(-1, Math.max(-3, event.wheelDelta));
			if (this.sidebarOpen && event.x >= mainW + 1) {
				this.sidebarScroll = Math.max(0, this.sidebarScroll + step);
				this.onRenderNeeded?.();
				return { handled: true };
			}
			this.chatScrollOffset = Math.max(0, this.chatScrollOffset - step);
			this.onRenderNeeded?.();
			return { handled: true };
		}

		if (event.type === "press" && event.button === "left") {
			if (event.y === 0) {
				const hit = this.headerHitAreas.find(({ start, end }) => event.x >= start && event.x < end);
				if (hit) {
					if (hit.target === "sidebar") {
						this.sidebarOpen = !this.sidebarOpen;
						this.onRenderNeeded?.();
					} else {
						this.onOpenOverlay?.(hit.target);
					}
					return { handled: true };
				}
			}
			// Row 1 inside sidebar: clickable Live | Graph | Findings pills
			if (this.sidebarOpen && event.y === 1 && event.x >= mainW + 1) {
				let cx = mainW + 2;
				for (const m of SIDEBAR_MODES) {
					const pw = visibleWidth(` ${m.label} `);
					if (event.x >= cx && event.x < cx + pw) {
						this.sidebarMode = m.id;
						this.sidebarScroll = 0;
						this.onRenderNeeded?.();
						return { handled: true };
					}
					cx += pw + 1;
				}
			}
		}
		return undefined;
	}

	handleGlobalKey(data: string): boolean {
		if (isKeyRelease(data)) return false;

		// Established double-press Ctrl+C / Ctrl+D exit pattern (sparkle / sd-tui)
		if (matchesKey(data, Key.ctrl("c"))) {
			this.handleExitChord("c");
			return true;
		}
		if (matchesKey(data, Key.ctrl("d"))) {
			this.handleExitChord("d");
			return true;
		}
		// Any other key clears armed exit state
		this.exitArm = null;

		if (matchesKey(data, Key.ctrl("t"))) {
			this.chatStream.showFullThinking = !this.chatStream.showFullThinking;
			this.setStatus(`Thinking display: ${this.chatStream.showFullThinking ? "expanded" : "collapsed"}`);
			return true;
		}
		if (matchesKey(data, Key.shift("enter")) || matchesKey(data, Key.ctrl("j"))) {
			const cur = this.promptInput.getValue();
			this.multilinePrefix = this.multilinePrefix ? `${this.multilinePrefix}\n${cur}` : cur;
			this.promptInput.setValue("");
			this.setStatus(`Multiline draft (${this.multilinePrefix.split("\n").length + 1} lines) — Enter to send`);
			return true;
		}
		if (matchesKey(data, Key.ctrl("u"))) {
			this.multilinePrefix = "";
			this.promptInput.setValue("");
			this.setStatus("Cleared input");
			return true;
		}
		if (matchesKey(data, Key.ctrl("s"))) {
			this.onOpenOverlay?.("sessions");
			return true;
		}
		if (data !== "\r" && data !== "\n" && matchesKey(data, Key.ctrl("m"))) {
			this.onOpenOverlay?.("models");
			return true;
		}
		if (matchesKey(data, Key.ctrl("r"))) {
			if (this.activeTaskId == null) this.setStatus("No active task to report on yet.");
			else this.onOpenOverlay?.("report");
			return true;
		}
		if (matchesKey(data, Key.ctrl("b"))) {
			this.sidebarOpen = !this.sidebarOpen;
			this.onRenderNeeded?.();
			return true;
		}
		if (matchesKey(data, Key.ctrl("p"))) {
			this.togglePauseResume();
			return true;
		}
		if (matchesKey(data, Key.ctrl("g"))) {
			this.onOpenOverlay?.("rules");
			return true;
		}
		if (matchesKey(data, Key.ctrl("k"))) {
			this.onOpenOverlay?.("help");
			return true;
		}
		if (matchesKey(data, Key.tab)) {
			if (this.handleTabCompletion()) return true;
			if (this.sidebarOpen) {
				const idx = SIDEBAR_MODES.findIndex((m) => m.id === this.sidebarMode);
				this.sidebarMode = SIDEBAR_MODES[(idx + 1) % SIDEBAR_MODES.length]!.id;
				this.sidebarScroll = 0;
				this.onRenderNeeded?.();
			}
			return true;
		}
		this.tabCompleteState = null;

		if (matchesKey(data, Key.escape)) {
			return this.handleEscapeKey();
		}
		if (matchesKey(data, Key.shift("up"))) {
			this.chatScrollOffset += 2;
			this.onRenderNeeded?.();
			return true;
		}
		if (matchesKey(data, Key.shift("down"))) {
			this.chatScrollOffset = Math.max(0, this.chatScrollOffset - 2);
			this.onRenderNeeded?.();
			return true;
		}
		if (matchesKey(data, Key.pageUp)) {
			this.chatScrollOffset += 8;
			this.onRenderNeeded?.();
			return true;
		}
		if (matchesKey(data, Key.pageDown)) {
			this.chatScrollOffset = Math.max(0, this.chatScrollOffset - 8);
			this.onRenderNeeded?.();
			return true;
		}
		if (matchesKey(data, Key.up)) {
			// Sparkle pattern: Up on empty input pops last queued message back for editing
			if (this.promptInput.getValue() === "" && this.queuedMessages.length > 0) {
				const popped = this.queuedMessages.pop()!;
				setInputTextAtEnd(this.promptInput, popped);
				this.setStatus("Recalled queued message into input");
				return true;
			}
			if (this.chatHistory.length > 0) {
				this.historyCursor =
					this.historyCursor < 0 ? this.chatHistory.length - 1 : Math.max(0, this.historyCursor - 1);
				setInputTextAtEnd(this.promptInput, this.chatHistory[this.historyCursor]!);
				this.onRenderNeeded?.();
			}
			return true;
		}
		if (matchesKey(data, Key.down)) {
			if (this.historyCursor >= 0) {
				this.historyCursor++;
				if (this.historyCursor >= this.chatHistory.length) {
					this.historyCursor = -1;
					this.promptInput.setValue("");
				} else {
					setInputTextAtEnd(this.promptInput, this.chatHistory[this.historyCursor]!);
				}
				this.onRenderNeeded?.();
			}
			return true;
		}
		return false;
	}

	// ── Chat & Slash Command Execution ─────────────────────────────────────

	async submitPrompt(raw: string): Promise<void> {
		const line = raw.trim();
		if (!line) return;
		if (this.chatHistory[this.chatHistory.length - 1] !== line) {
			this.chatHistory.push(line);
			if (this.chatHistory.length > 200) this.chatHistory.shift();
			this.savePromptHistory();
		}

		if (line.startsWith("/")) {
			await this.handleSlashCommand(line);
			return;
		}

		// Sparkle pattern: queue message if a reply is currently streaming
		if (this.chatBusy) {
			this.queuedMessages.push(line);
			this.setStatus(`Queued (${this.queuedMessages.length}): press Up on empty prompt to edit`);
			return;
		}

		// Persist user turn to JSONL session
		this.sessions.appendMessage(this.currentSession.header.id, {
			role: "user",
			content: [{ type: "text", text: line }],
		});
		if (this.currentSession.messages.length === 0) {
			const autoTitle = line.slice(0, 48);
			this.currentSession.header.title = autoTitle;
			this.sessions.updateHeader(this.currentSession.header.id, { title: autoTitle });
		}
		this.currentSession.messages.push({
			type: "message",
			id: "local",
			parentId: null,
			timestamp: new Date().toISOString(),
			message: { role: "user", content: [{ type: "text", text: line }] },
		});

		this.pushChatLine(`${theme.amberBold("› you")} ${line}\n`);
		await this.runStreamingChat(line);
	}

	private async handleSlashCommand(line: string): Promise<void> {
		const [cmd, ...rest] = line.split(/\s+/);
		switch (cmd) {
			case "/help":
				this.onOpenOverlay?.("help");
				return;
			case "/new":
				this.startNewSession(rest.join(" ") || undefined);
				return;
			case "/sessions":
				this.onOpenOverlay?.("sessions");
				return;
			case "/model":
				this.onOpenOverlay?.("models");
				return;
			case "/rules":
			case "/intercept":
				this.onOpenOverlay?.("rules");
				return;
			case "/skills":
				this.onOpenOverlay?.("skills");
				return;
			case "/tasks": {
				const tasks = this.store.listTasks();
				const companies = this.store.listCompanies();
				const md = [
					"## Tasks & Company Scope",
					...tasks.map((t) => {
						const tScope = this.store.listTaskScope(t.id);
						const cScope = t.companyId ? this.store.listCompanyScope(t.companyId) : [];
						const scopeLines = [
							...tScope.map((r) => `  - [${r.exclude ? "EXCLUDED" : "INCLUDED"}] ${r.kind}: \`${r.pattern}\``),
							...cScope.map((r) => `  - [INHERITED ${r.exclude ? "EXCLUDED" : "INCLUDED"}] ${r.kind}: \`${r.pattern}\``),
						];
						return [`### #${t.id} ${t.name} (\`${t.status}\`)`, `Workers: ${t.maxWorkers} · Turns: ${t.maxTurns}`, ...(scopeLines.length ? scopeLines : ["  - _No scope rules_"])].join("\n");
					}),
					"",
					`**Companies:** ${companies.length ? companies.map((c) => c.name).join(", ") : "None"}`,
				].join("\n\n");
				this.onOpenOverlay?.("detail", { title: "Tasks & Scope", markdown: md });
				return;
			}
			case "/evidence": {
				if (this.activeTaskId == null) { this.pushChatLine(theme.amber("No active task.")); return; }
				const evStore = new EvidenceStore(this.store, join(this.tenguHome, "workspace", "evidence"));
				const arts = this.store.listArtifacts(this.activeTaskId);
				const md = arts.length === 0
					? "_No evidence artifacts for this task._"
					: arts.map((a) => {
						const insp = evStore.inspectArtifact(a.id, 400);
						return `### #${a.id} ${a.name} [\`${insp.status.toUpperCase()}\`]
- **SHA-256:** \`${a.sha256.slice(0, 16)}...\` · **Size:** ${a.sizeBytes}B · ${insp.reason}
${insp.redactedPreview ? `\`\`\`\n${insp.redactedPreview}\n\`\`\`` : ""}`;
					}).join("\n\n");
				this.onOpenOverlay?.("detail", { title: `Evidence — Task #${this.activeTaskId}`, markdown: md });
				return;
			}
			case "/traffic": {
				if (this.activeTaskId == null) { this.pushChatLine(theme.amber("No active task.")); return; }
				const recs = this.store.listTrafficRecords({ taskId: this.activeTaskId, limit: 30 }).map(maskTrafficRecord);
				const md = recs.length === 0
					? "_No recorded HTTP traffic for this task._"
					: recs.map((r) => `- **#${r.id}** \`${r.method} ${r.statusCode}\` ${r.url} (${r.durationMs}ms)`).join("\n");
				this.onOpenOverlay?.("detail", { title: `Recorded Traffic (Redacted) — Task #${this.activeTaskId}`, markdown: md });
				return;
			}
			case "/approvals": {
				const reqs = this.store.listApprovalRequests({ taskId: this.activeTaskId ?? undefined });
				const md = reqs.length === 0
					? "_No persisted approval decisions yet._"
					: reqs.map((a) => `- **#${a.id}** [\`${a.status.toUpperCase()}\`] \`${a.toolName}\` (rule: ${a.ruleName}, by: ${a.decidedBy || "pending"}) — ${a.reason}`).join("\n");
				this.onOpenOverlay?.("detail", { title: "Approval & Intercept Decision History", markdown: md });
				return;
			}
			case "/usage": {
				if (this.activeTaskId == null) { this.pushChatLine(theme.amber("No active task.")); return; }
				const bd = this.store.getTaskUsageBreakdown(this.activeTaskId);
				const live = this.getEffectiveLiveStatus(this.activeTaskId);
				const md = [
					`## Usage & Cost — Task #${this.activeTaskId}`,
					`- **Recorded Total:** ${bd.totalTokens.toLocaleString()} tokens (in: ${bd.totalInputTokens.toLocaleString()}, out: ${bd.totalOutputTokens.toLocaleString()})`,
					`- **Recorded Cost:** ${bd.knownCostUsd != null ? `${bd.knownCostUsd.toFixed(4)}` : "unknown (cost metadata not reported)"}`,
					live.snapshot ? `- **Live Stream Estimate:** ${live.snapshot.totalTokensGenerated.toLocaleString()} tok (${live.snapshot.tokensPerSec} tok/s, status: ${live.snapshot.status})` : "- **Live Stream Estimate:** idle",
					"",
					"### By Model",
					...(bd.byModel.length ? bd.byModel.map((m) => `- \`${m.provider}/${m.model}\`: ${m.totalTokens.toLocaleString()} tok · cost: ${m.costUsd != null ? `${m.costUsd.toFixed(4)}` : "unknown"}`) : ["_No recorded usage yet._"]),
				].join("\n");
				this.onOpenOverlay?.("detail", { title: `Usage & Cost — Task #${this.activeTaskId}`, markdown: md });
				return;
			}
			case "/report":
				if (this.activeTaskId == null) this.pushChatLine(theme.amber("No active task yet."));
				else this.onOpenOverlay?.("report");
				return;
			case "/think":
				this.chatStream.showFullThinking = !this.chatStream.showFullThinking;
				this.pushChatLine(theme.violet(`Expanded thinking display: ${this.chatStream.showFullThinking ? "ON" : "OFF"}`));
				return;
			case "/sidebar":
				this.sidebarOpen = !this.sidebarOpen;
				this.onRenderNeeded?.();
				return;
			case "/bg":
				this.triggerBackgroundRun();
				return;
			case "/pause":
			case "/resume":
				this.togglePauseResume();
				return;
			case "/stop":
				this.stopActiveRun();
				return;
			case "/clear":
				this.chatLines = [];
				this.chatScrollOffset = 0;
				this.onRenderNeeded?.();
				return;
			case "/quit":
			case "/exit":
				this.onQuit?.();
				return;
			default:
				this.pushChatLine(theme.muted(`Unknown command "${cmd}". Type /help or just talk to Tengu directly.`));
		}
	}


	private buildRestoredAgentMessages(excludeLastUserText?: string): AgentMessage[] {
		const msgs = [...this.currentSession.messages];
		if (excludeLastUserText && msgs.length > 0) {
			const last = msgs[msgs.length - 1]!;
			if (last.message.role === "user" && last.message.content.map((c) => c.text).join("\n") === excludeLastUserText) {
				msgs.pop();
			}
		}
		const out: AgentMessage[] = [];
		for (const entry of msgs) {
			const text = entry.message.content.map((c) => c.text).join("\n");
			const ts = Date.parse(entry.timestamp) || Date.now();
			if (entry.message.role === "user") {
				out.push({ role: "user", content: [{ type: "text", text }], timestamp: ts });
			} else if (entry.message.role === "assistant") {
				out.push({
					role: "assistant",
					content: [{ type: "text", text }],
					api: this.activeEndpoint?.model.api ?? "openai-completions",
					provider: this.activeEndpoint?.provider ?? "unknown",
					model: entry.message.model || this.activeEndpoint?.model.id || "unknown",
					usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: entry.message.tokens ?? 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
					stopReason: "stop",
					timestamp: ts,
				});
			}
		}
		return out;
	}

	private async runStreamingChat(prompt: string): Promise<void> {
		if (!this.activeEndpoint || !this.piConfig) {
			this.pushChatLine(theme.amber("No Pi model configured. Check ~/.pi/agent/settings.json."));
			return;
		}
		if (this.chatBusy) {
			this.pushChatLine(theme.amber("Already responding — press Esc to abort."));
			return;
		}

		// Ensure there is an active task so all 50+ tools & conversational config work immediately
		if (this.activeTaskId == null) {
			const autoTask = this.store.createTask({ name: prompt.slice(0, 48) || "Engagement" });
			this.activeTaskId = autoTask.id;
			this.sessions.updateHeader(this.currentSession.header.id, { taskId: autoTask.id });
		}

		const owningSessionId = this.currentSession.header.id;
		this.chatBusy = true;
		const { model, apiKey } = this.activeEndpoint;
		this.chatStream.start(model.id);
		this.chatScrollOffset = 0;
		this.setStatus(`Prefilling (${model.id})… Esc to abort`);

		this.chatAnimTimer = setInterval(() => {
			this.chatStream.tick();
			this.onRenderNeeded?.();
		}, 100);

		let unsub: (() => void) | null = null;
		try {
			if (!this.chatAgent) {
				const task = this.store.getTask(this.activeTaskId);
				const tools = this.orchestrator
					? this.orchestrator
							.createToolSet(this.activeTaskId, null, "mainagent", {
								onTaskChanged: (newTaskId) => {
									this.activeTaskId = newTaskId;
									this.sessions.updateHeader(this.currentSession.header.id, { taskId: newTaskId });
									this.onRenderNeeded?.();
								},
								onStartEngagement: async (tid, opts) => {
									if (opts.background !== false) {
										return this.triggerBackgroundRun(tid, opts.maxRounds);
									}
									void this.orchestrator?.runTask(tid, { maxRounds: opts.maxRounds });
									return { started: true, mode: "foreground" };
								},
								onPauseEngagement: (tid) => this.togglePauseResume(tid),
								onStopEngagement: (tid) => this.stopActiveRun(tid),
							})
							.allTools()
					: [];

				this.chatAgent = new Agent({
					streamFn: this.piConfig.streamFn,
					getApiKey: apiKey ? () => apiKey : undefined,
					initialState: {
						systemPrompt: buildMainAgentPrompt(task),
						model,
						tools,
						messages: this.buildRestoredAgentMessages(prompt),
					},
					beforeToolCall: async (ctx) => {
						if (this.activeTaskId == null) return undefined;
						const decision = await this.intercept.evaluate({
							taskId: this.activeTaskId,
							toolName: ctx.toolCall.name,
							toolArgs: ctx.args,
						});
						if (!decision.allowed) {
							this.pushChatLine(theme.crimson(`[intercept] Blocked ${ctx.toolCall.name}: ${decision.reason}`));
							return { block: true, reason: decision.reason };
						}
						return undefined;
					},
				});
			}

			unsub = this.chatAgent.subscribe((ev) => {
				if (ev.type === "message_update") {
					const ae = ev.assistantMessageEvent;
					if (ae.type === "thinking_delta") {
						this.chatStream.onThinkingDelta(ae.delta);
						this.onRenderNeeded?.();
					} else if (ae.type === "text_delta") {
						this.chatStream.onTextDelta(ae.delta);
						this.onRenderNeeded?.();
					}
				} else if (ev.type === "tool_execution_start") {
					this.chatStream.onToolStart(ev.toolName, ev.args);
					this.onRenderNeeded?.();
				} else if (ev.type === "tool_execution_end") {
					this.chatStream.onToolEnd(ev.toolName, ev.isError);
					this.onRenderNeeded?.();
				}
			});

			await this.chatAgent.prompt(prompt);

			if (!this.chatStream.responseText) {
				const last = [...this.chatAgent.state.messages].reverse().find((m) => m.role === "assistant");
				const fallbackText =
					last && "content" in last && Array.isArray(last.content)
						? last.content
								.filter((c): c is { type: "text"; text: string } => c.type === "text")
								.map((c) => c.text)
								.join("\n")
						: "";
				if (fallbackText) this.chatStream.responseText = fallbackText;
				else if (last && "errorMessage" in last && last.errorMessage) {
					this.pushChatLine(theme.crimson(`Model error: ${last.errorMessage}`));
				}
			}

			// Persist assistant turn to JSONL session
			const totalTok = this.chatStream.thinkingTokens + this.chatStream.responseTokens;
			const savedText = this.chatStream.responseText;
			if (savedText || this.chatStream.tools.length > 0) {
				this.sessions.appendMessage(owningSessionId, {
					role: "assistant",
					content: [{ type: "text", text: savedText }],
					thinking: this.chatStream.thinkingText || undefined,
					tools: this.chatStream.tools.map((t) => ({ name: t.name, status: t.status, durationMs: t.durationMs })),
					model: model.id,
					tokens: totalTok,
				});
			}

			const mainW = this.sidebarOpen ? Math.floor((this.lastWidth - 1) * 0.67) : this.lastWidth;
			const committed = this.chatStream.finalize(Math.max(36, mainW - 4));
			if (this.currentSession.header.id === owningSessionId) {
				this.pushChatLine(committed.join("\n"));
			}
			this.setStatus(`Ready (${model.id})`);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			const mainW = this.sidebarOpen ? Math.floor((this.lastWidth - 1) * 0.67) : this.lastWidth;
			const committed = this.chatStream.finalize(Math.max(36, mainW - 4));
			if (committed.length > 0) this.pushChatLine(committed.join("\n"));
			if (!this.chatStream.aborted) {
				this.pushChatLine(theme.crimson(`Chat error: ${msg}`));
				this.setStatus(`Error: ${msg}`);
			}
		} finally {
			unsub?.();
			if (this.chatAnimTimer) {
				clearInterval(this.chatAnimTimer);
				this.chatAnimTimer = null;
			}
			this.chatBusy = false;
			this.onRenderNeeded?.();
			if (!this.chatStream.aborted && this.queuedMessages.length > 0) {
				const next = this.queuedMessages.shift()!;
				void this.submitPrompt(next);
			}
		}
	}

	// ── Rendering ──────────────────────────────────────────────────────────

	render(width: number): string[] {
		const w = Math.max(20, width);
		const totalRows = Math.max(6, this.getRows());
		this.lastWidth = w;
		this.lastHeight = totalRows;
		const bodyH = Math.max(3, totalRows - 3);

		const header = this.renderHeader(w);
		const body = this.sidebarOpen ? this.renderSplitCockpit(w, bodyH) : this.renderChatColumn(w, bodyH);
		const status = padRight(` ${theme.subtle("●")} ${theme.muted(this.statusMessage)}`, w);
		const footer = theme.footerBg(
			padRight(
				` ${theme.keyHint("Enter")} Send  ${theme.keyHint("Esc")} Abort  ${theme.keyHint("Ctrl+S")} Sessions  ${theme.keyHint("Ctrl+M")} Model  ${theme.keyHint("Ctrl+R")} Report  ${theme.keyHint("Ctrl+B")} Sidebar  ${theme.keyHint("Ctrl+P")} Pause  ${theme.keyHint("Ctrl+C")} Quit`,
				w,
			),
		);

		const clampedBody = body.slice(0, bodyH);
		while (clampedBody.length < bodyH) clampedBody.push(" ".repeat(w));
		return [header, ...clampedBody, status, footer];
	}

	private renderHeader(width: number): string {
		const task = this.activeTaskId != null ? this.store.getTask(this.activeTaskId) : null;
		let runBadge = "";
		if (task) {
			const { snapshot, isBackground } = this.getEffectiveLiveStatus(task.id);
			if (snapshot && (snapshot.status === "running" || snapshot.status === "paused")) {
				const bg = isBackground ? ` BG:${snapshot.pid}` : "";
				runBadge =
					snapshot.status === "paused"
						? ` ${theme.amberBold(`⏸ PAUSED${bg}`)}`
						: ` ${theme.emerald(`▶ R${snapshot.round}/${snapshot.maxRounds} ${snapshot.tokensPerSec}t/s${bg}`)}`;
			}
		}

		const sessLabel = `${this.currentSession.header.title.slice(0, 26)}${task ? ` (#${task.id})` : ""}`;
		const session = `${theme.bold(sessLabel)} ${theme.subtle("▾")}`;
		const brand = `${theme.brandBadge(" TENGU ")}  `;
		const left = `${brand}${session}${runBadge}`;
		const modelName = this.activeEndpoint ? `${theme.violet(this.activeEndpoint.model.id)} ${theme.subtle("▾")}` : theme.amber("no model");
		const sideBtn = this.sidebarOpen ? theme.cyan("[Sidebar ▾]") : theme.muted("[Sidebar ▸]");
		const right = `${modelName}   ${sideBtn} `;

		const gap = Math.max(1, width - visibleWidth(left) - visibleWidth(right));
		const modelStart = visibleWidth(left) + gap;
		const sideStart = modelStart + visibleWidth(modelName) + 3;
		this.headerHitAreas = [
			{ start: visibleWidth(brand), end: Math.min(width, visibleWidth(brand + session)), target: "sessions" },
			{ start: modelStart, end: Math.min(width, modelStart + visibleWidth(modelName)), target: "models" },
			{ start: sideStart, end: Math.min(width, sideStart + visibleWidth(sideBtn)), target: "sidebar" },
		];
		return theme.headerBg(padRight(`${left}${" ".repeat(gap)}${right}`, width));
	}

	private renderSplitCockpit(width: number, height: number): string[] {
		const leftW = Math.floor((width - 1) * 0.67);
		const rightW = width - 1 - leftW;
		const chatCol = this.renderChatColumn(leftW, height);
		const sideCol = this.renderSidebar(rightW, height);
		return hJoin(chatCol, sideCol, leftW, rightW);
	}

	private renderChatColumn(width: number, height: number): string[] {
		const logH = Math.max(6, height - 3);
		const innerW = Math.max(20, width - 4);
		const wrapped = wrapLines(this.chatLines, innerW);
		if (this.chatStream.phase !== "idle") {
			wrapped.push(...this.chatStream.renderLive(innerW));
		}

		const cap = Math.max(1, logH - 2);
		const maxScroll = Math.max(0, wrapped.length - cap);
		const clamped = Math.min(this.chatScrollOffset, maxScroll);
		this.chatScrollOffset = clamped;
		const endIdx = wrapped.length - clamped;
		const startIdx = Math.max(0, endIdx - cap);

		const sub = clamped > 0 ? `↑${clamped} lines` : this.chatBusy ? "streaming…" : `session ${this.currentSession.header.id.slice(-8)}`;
		const logPanel = renderPanel({
			title: "Chat",
			subtitle: sub,
			lines: wrapped.slice(startIdx, endIdx),
			width,
			height: logH,
			active: false,
			scroll: { offset: startIdx, total: wrapped.length },
		});

		const inputLine = this.promptInput.render(Math.max(12, width - 4))[0] ?? "";
		const inputPanel = renderPanel({
			title: this.queuedMessages.length > 0 ? `Prompt · ${this.queuedMessages.length} queued (↑ to edit)` : this.chatBusy ? "Prompt · Generating (Enter queues · Esc aborts)" : "Prompt",
			lines: [inputLine],
			width,
			height: 3,
			active: true,
		});
		return [...logPanel, ...inputPanel];
	}

	private renderSidebar(width: number, height: number): string[] {
		const pillLine = SIDEBAR_MODES.map((m) =>
			m.id === this.sidebarMode ? theme.tabActive(` ${m.label} `) : theme.tabInactive(` ${m.label} `),
		).join(" ");

		const panelH = Math.max(6, height - 1);
		const innerW = Math.max(16, width - 4);
		const innerH = Math.max(1, panelH - 2);
		const task = this.activeTaskId != null ? this.store.getTask(this.activeTaskId) : null;

		let contentLines: string[] = [];
		let title = "Mission";

		if (this.sidebarMode === "live") {
			title = "Live Mission";
			const live = task ? this.getEffectiveLiveStatus(task.id) : { snapshot: null, isBackground: false };
			const cov = task ? this.store.getAssetCoverage(task.id) : { total: 0, tested: 0, untested: 0, byKind: {} };
			const findings = this.store.listFindings(task?.id);
			const pending = this.store.listApprovalRequests({ status: "pending" }).length;
			const scopeCount = task ? this.store.listTaskScope(task.id).length : 0;

			if (live.snapshot && (live.snapshot.status === "running" || live.snapshot.status === "paused")) {
				const s = live.snapshot;
				contentLines.push(
					`${s.status === "paused" ? theme.amberBold("⏸ PAUSED") : theme.emerald("▶ ACTIVE")} ${theme.bold(`R${s.round}/${s.maxRounds}`)} · ${theme.cyan(`${s.tokensPerSec} t/s`)}`,
					theme.muted(`${s.totalTokensGenerated} tok · ${live.isBackground ? `BG PID ${s.pid}` : `PID ${s.pid}`}`),
					"",
					theme.bold(`Active Agents (${s.agents.length}):`),
				);
				for (const ag of s.agents) {
					const st = ag.phase === "tool" ? theme.amber(`⚙ ${ag.currentTool}`) : theme.cyan(ag.phase);
					contentLines.push(`  • ${theme.bold(ag.role)} [${st}] ${ag.tokensGenerated}t`);
				}
				contentLines.push("");
			} else {
				contentLines.push(theme.muted("Idle — ask Tengu to start an engagement or type /bg."), "");
			}

			const sevCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
			for (const f of findings) sevCounts[f.severity]++;
			contentLines.push(
				theme.bold("Coverage:"),
				`  ${progressBar(cov.tested, cov.total, Math.max(8, Math.min(14, innerW - 14)))}`,
				`${theme.bold("Scope:")} ${scopeCount} rules · ${theme.bold("Approvals:")} ${pending} pending`,
				"",
				theme.bold(`Findings (${findings.length}):`),
				`  ${severityBadge("critical")} ${sevCounts.critical}  ${severityBadge("high")} ${sevCounts.high}`,
				`  ${severityBadge("medium")} ${sevCounts.medium}  ${severityBadge("low")} ${sevCounts.low}  ${severityBadge("info")} ${sevCounts.info}`,
			);
		} else if (this.sidebarMode === "graph") {
			title = "Dual Graph";
			if (!task) {
				contentLines.push(theme.muted("No active task yet."));
			} else {
				const assets = this.store.listAssets({ taskId: task.id });
				const ov = this.store.getGraphOverview(task.id);
				contentLines.push(theme.bold(`Assets (${assets.length}):`));
				for (const a of assets) {
					contentLines.push(`  ${a.tested ? theme.emerald("●") : theme.amber("○")} ${theme.violet(`[${a.kind}]`)} ${a.value}`);
				}
				contentLines.push("", theme.bold(`Intents (${ov.intents.length}):`));
				for (const i of ov.intents) {
					contentLines.push(`  ${theme.cyan(`#${i.id}`)} ${theme.amber(`[${i.state}]`)} ${i.summary}`);
				}
				contentLines.push("", theme.bold(`Facts (${ov.recentFacts.length}):`));
				for (const f of ov.recentFacts) {
					contentLines.push(`  ${theme.emerald(`#${f.id}`)} ${f.summary}`);
				}
			}
		} else {
			title = "Findings";
			const findings = this.store.listFindings(task?.id);
			if (findings.length === 0) {
				contentLines.push(theme.muted("No vulnerabilities reported yet."));
			} else {
				for (const f of findings) {
					contentLines.push(`${severityBadge(f.severity)} ${theme.bold(`#${f.id} ${f.title}`)}`);
					contentLines.push(`  ${theme.muted(f.summary)}`);
					contentLines.push("");
				}
			}
		}

		const wrapped = wrapLines(contentLines, innerW);
		const maxScroll = Math.max(0, wrapped.length - innerH);
		this.sidebarScroll = Math.min(this.sidebarScroll, maxScroll);
		const panel = renderPanel({
			title,
			subtitle: "Tab to switch",
			lines: wrapped.slice(this.sidebarScroll, this.sidebarScroll + innerH),
			width,
			height: panelH,
			active: false,
			scroll: { offset: this.sidebarScroll, total: wrapped.length },
		});
		return [padRight(` ${pillLine}`, width), ...panel];
	}
}

// Keep backward-compatible alias for existing imports
export { TenguCockpitApp as TenguFullscreenApp };

/**
 * Launches Tengu's modern chat-first, session-backed fullscreen Pi TUI.
 */
export function startTenguTui(options: TenguTuiOptions): TenguCockpitApp {
	const terminal = options.terminal ?? new ProcessTerminal();
	const tui = new TuiAltScreen(terminal);

	const app = new TenguCockpitApp({
		...options,
		getRows: () => terminal.rows || 32,
	});

	let activeOverlay: OverlayHandle | null = null;
	let activeScrollModal: ScrollableModal | null = null;
	let activePickerModal: PickerModal | null = null;
	let reportModalState: { taskId: number; formatIdx: number; content: string } | null = null;
	let pendingApprovalResolve: ((res: { approved: boolean; decidedBy: string; reason?: string }) => void) | null = null;

	const closeOverlay = () => {
		if (activeOverlay) {
			activeOverlay.hide();
			activeOverlay = null;
		}
		activeScrollModal = null;
		activePickerModal = null;
		reportModalState = null;
		if (pendingApprovalResolve) {
			const r = pendingApprovalResolve;
			pendingApprovalResolve = null;
			r({ approved: false, decidedBy: "tui_operator", reason: "Dismissed by operator" });
		}
		tui.setFocus(app.promptInput);
		tui.requestRender();
	};

	options.onRegisterAskHandler?.((req) => {
		return new Promise((resolve) => {
			const md = [
				`## Approval Required: \`${req.toolName}\``,
				`**Rule:** ${req.ruleName} · **Task:** #${req.taskId}`,
				"",
				req.reason || "Operator confirmation required before executing this action.",
				"",
				"### Tool Arguments",
				"```json",
				req.toolInput.slice(0, 1200),
				"```",
			].join("\n");
			openScrollableModal(
				`⚠ Intercept Approval #${req.id}`,
				[],
				"[Y / Enter] Allow    [N / Esc] Deny    ↑↓: Scroll",
				md,
			);
			// Set resolver AFTER openScrollableModal (which calls closeOverlay) so it is NOT dismissed on open!
			pendingApprovalResolve = resolve;
		});
	});

	const openScrollableModal = (title: string, lines: string[], footerHint?: string, markdownText: string | null = null) => {
		closeOverlay();
		const modal = new ScrollableModal(title, lines, footerHint, markdownText, () => terminal.rows);
		activeScrollModal = modal;
		activeOverlay = tui.showOverlay(modal, {
			anchor: "center",
			width: Math.min(90, Math.max(54, (terminal.columns || 100) - 8)),
		});
		tui.setFocus(modal);
		tui.requestRender();
	};

	const openPickerModal = (title: string, items: PickerItem[], onSelect: (item: PickerItem) => void, footerHint?: string) => {
		closeOverlay();
		const modal = new PickerModal(title, items, footerHint);
		modal.onSelect = (item) => {
			closeOverlay();
			onSelect(item);
			tui.requestRender();
		};
		activePickerModal = modal;
		activeOverlay = tui.showOverlay(modal, { anchor: "center", width: Math.min(82, Math.max(54, (terminal.columns || 100) - 10)) });
		tui.setFocus(modal);
		tui.requestRender();
	};

	const showReport = (taskId: number, formatIdx: number) => {
		const format = REPORT_FORMATS[formatIdx]!;
		try {
			const content = new ReportGenerator(options.store).generate(taskId, format);
			const title = `Report Preview — Task #${taskId} [${format.toUpperCase()}]`;
			// Evidence can contain terminal control bytes. Keep them out of the preview.
			const preview = content.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, (char) =>
				char === "\r" ? "" : `\\x${char.charCodeAt(0).toString(16).padStart(2, "0")}`,
			);
			const lines = format === "markdown" ? [] : preview.split("\n");
			const markdown = format === "markdown" ? preview : null;
			if (reportModalState && activeScrollModal) {
				activeScrollModal.setContent(title, lines, true, markdown);
			} else {
				openScrollableModal(title, lines, "↑↓ / PgUp / PgDn / Wheel: Scroll   f: Format   w: Save   Esc/q: Close", markdown);
			}
			reportModalState = { taskId, formatIdx, content };
			tui.requestRender();
		} catch (err) {
			closeOverlay();
			app.setStatus(`Could not generate report: ${err instanceof Error ? err.message : String(err)}`);
		}
	};

	app.onOpenOverlay = (kind, detail) => {
		if (kind === "sessions") {
			const list = app.sessions.listSessions();
			const items: PickerItem[] = [
				{ id: "__new__", label: "＋ New Session", detail: "Start a fresh persistent JSONL session" },
				...list.map((s) => ({
					id: s.id,
					label: `${s.id === app.currentSession.header.id ? "★ " : ""}${s.title}`,
					detail: `${s.messageCount} msgs · ${s.model || "default"} · ${s.updatedAt.slice(0, 16).replace("T", " ")}`,
				})),
			];
			openPickerModal("Sessions (~/.tengu/sessions)", items, (item) => {
				if (item.id === "__new__") app.startNewSession();
				else app.switchToSession(item.id);
			});
		} else if (kind === "models") {
			const avail = options.piConfig?.available ?? [];
			const items: PickerItem[] = avail.map((ep) => ({
				id: `${ep.provider}/${ep.model.id}`,
				label: `${ep.model.id === app.activeEndpoint?.model.id && ep.provider === app.activeEndpoint?.provider ? "★ " : ""}${ep.model.name}`,
				detail: `${ep.provider} · ${Math.round(ep.model.contextWindow / 1000)}k ctx`,
			}));
			openPickerModal("Pi Models (~/.pi/agent/models.json)", items, (item) => {
				const found = avail.find((ep) => `${ep.provider}/${ep.model.id}` === item.id);
				if (found) app.switchModel(found);
			});
		} else if (kind === "rules") {
			const rules = options.store.listInterceptRules();
			const items: PickerItem[] = rules.map((r) => ({
				id: r.name,
				label: `${r.enabled ? "●" : "○"} [${r.ruleClass.toUpperCase()}] ${r.name}`,
				detail: `P${r.priority} · ${r.action}`,
			}));
			openPickerModal("3-Layer Intercept Rules (Enter to toggle)", items, (item) => {
				const rule = rules.find((r) => r.name === item.id);
				if (rule) {
					options.store.upsertInterceptRule({ ...rule, enabled: !rule.enabled });
					app.setStatus(`Rule ${rule.name} ${!rule.enabled ? "ENABLED" : "DISABLED"}`);
				}
			});
		} else if (kind === "report" && app.activeTaskId != null) {
			showReport(app.activeTaskId, 0);
		} else if (kind === "skills") {
			const md = loadSkills()
				.map((s) => `### ${s.name} (\`${s.id}\`)\n${s.summary}\n\n> ${s.guidance}`)
				.join("\n\n");
			openScrollableModal("23 Built-in Pentest Skills", [], undefined, md);
		} else if (kind === "detail" && detail) {
			openScrollableModal(detail.title, [], undefined, detail.markdown);
		} else if (kind === "help") {
			const md = [
				"## Tengu — Chat-First Autonomous Pentest Cockpit",
				"",
				"Just **talk naturally** to configure scope, workers, constraints, intercept rules, or launch background pentests.",
				"",
				"### Keyboard Shortcuts",
				"- `Enter` — Send message or slash command",
				"- `Esc` — Abort streaming response / close overlay",
				"- `↑ / ↓` — Prompt history",
				"- `PgUp / PgDn` or **Trackpad Wheel** — Scroll chat or right sidebar",
				"- `Tab` — Cycle Mission Sidebar (`Live` · `Graph` · `Findings`)",
				"- `Ctrl+B` — Toggle Mission Sidebar",
				"- `Ctrl+S` — Session Switcher (persistent JSONL sessions)",
				"- `Ctrl+M` — Pi Model Switcher",
				"- `Ctrl+R` — Rendered Markdown Report Preview (`f` format, `w` save)",
				"- `Ctrl+G` — 3-Layer Intercept Rules",
				"- `Ctrl+P` — Pause / Resume active engagement",
				"- `Ctrl+C` — Quit (background daemons keep running)",
				"",
				"### Slash Commands",
				"`/new` · `/sessions` · `/model` · `/bg` · `/pause` · `/stop` · `/report` · `/rules` · `/skills` · `/think` · `/clear` · `/quit`",
			].join("\n");
			openScrollableModal("Help & Shortcuts", [], undefined, md);
		}
	};

	const refreshTimer = setInterval(() => {
		if (app.activeTaskId != null) {
			const { snapshot } = app.getEffectiveLiveStatus(app.activeTaskId);
			if (snapshot && (snapshot.status === "running" || snapshot.status === "paused")) {
				tui.requestRender();
			}
		}
	}, 600);
	refreshTimer.unref?.();

	app.onQuit = () => {
		clearInterval(refreshTimer);
		if (app.activeTaskId != null && options.orchestrator?.isRunning(app.activeTaskId)) {
			options.orchestrator.stopTask(app.activeTaskId);
		}
		tui.stop();
		options.store.close();
		process.exit(0);
	};

	app.dispose = () => {
		clearInterval(refreshTimer);
		tui.stop();
	};

	app.onRenderNeeded = () => {
		tui.requestRender();
	};

	tui.addInputListener((data) => {
		if (activeOverlay) {
			if (isKeyRelease(data)) return undefined;
			if (matchesKey(data, Key.escape) || (activeScrollModal && (data === "q" || data === "Q"))) {
				closeOverlay();
				return { consume: true };
			}
			if (activePickerModal) {
				if (matchesKey(data, Key.down)) {
					activePickerModal.move(1);
					tui.requestRender();
					return { consume: true };
				}
				if (matchesKey(data, Key.up)) {
					activePickerModal.move(-1);
					tui.requestRender();
					return { consume: true };
				}
				if (matchesKey(data, Key.enter)) {
					const sel = activePickerModal.selectedItem();
					if (sel) activePickerModal.onSelect?.(sel);
					return { consume: true };
				}
				return { consume: true };
			}
			if (activeScrollModal) {
				if (pendingApprovalResolve) {
					if (data === "y" || data === "Y" || matchesKey(data, Key.enter)) {
						const r = pendingApprovalResolve;
						pendingApprovalResolve = null;
						closeOverlay();
						r({ approved: true, decidedBy: "tui_operator", reason: "Approved in TUI" });
						return { consume: true };
					}
					if (data === "n" || data === "N") {
						const r = pendingApprovalResolve;
						pendingApprovalResolve = null;
						closeOverlay();
						r({ approved: false, decidedBy: "tui_operator", reason: "Denied in TUI" });
						return { consume: true };
					}
				}
				if (matchesKey(data, Key.down)) {
					activeScrollModal.scroll(1);
					tui.requestRender();
					return { consume: true };
				}
				if (matchesKey(data, Key.up)) {
					activeScrollModal.scroll(-1);
					tui.requestRender();
					return { consume: true };
				}
				if (matchesKey(data, Key.pageUp)) {
					activeScrollModal.scrollPage(-1);
					tui.requestRender();
					return { consume: true };
				}
				if (matchesKey(data, Key.pageDown)) {
					activeScrollModal.scrollPage(1);
					tui.requestRender();
					return { consume: true };
				}
				if (matchesKey(data, Key.home)) {
					activeScrollModal.scrollToTop();
					tui.requestRender();
					return { consume: true };
				}
				if (matchesKey(data, Key.end)) {
					activeScrollModal.scrollToBottom();
					tui.requestRender();
					return { consume: true };
				}
				if (reportModalState && (data === "f" || data === "F")) {
					showReport(reportModalState.taskId, (reportModalState.formatIdx + 1) % REPORT_FORMATS.length);
					return { consume: true };
				}
				if (reportModalState && (data === "w" || data === "W")) {
					const fmt = REPORT_FORMATS[reportModalState.formatIdx]!;
					const ext = fmt === "markdown" ? "md" : fmt;
					const outDir = join(options.tenguHome ?? join(homedir(), ".tengu"), "reports");
					const outPath = join(outDir, `task-${reportModalState.taskId}.${ext}`);
					try {
						mkdirSync(outDir, { recursive: true, mode: 0o700 });
						writeFileSync(outPath, reportModalState.content, { encoding: "utf8", mode: 0o600 });
						app.setStatus(`Saved ${fmt} report to ${outPath}`);
					} catch (err) {
						app.setStatus(`Could not save report: ${err instanceof Error ? err.message : String(err)}`);
					}
					closeOverlay();
					return { consume: true };
				}
				return { consume: true };
			}
			return undefined;
		}
		if (app.handleGlobalKey(data)) {
			return { consume: true };
		}
		return undefined;
	});

	tui.setLayoutRoot(app);
	tui.setFocus(app.promptInput);
	tui.start();
	return app;
}
