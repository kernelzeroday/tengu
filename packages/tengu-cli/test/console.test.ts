import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createAssistantMessageEventStream, type AssistantMessage } from "@earendil-works/pi-ai";
import { TuiAltScreen, visibleWidth, type Terminal } from "@earendil-works/pi-tui";
import { writeLiveStatusSnapshot } from "@tengu/engine";
import { InterceptEngine } from "@tengu/intercept";
import { SqliteTenguStore } from "@tengu/store";
import {
	ChatStreamState,
	getStatusFilePath,
	PickerModal,
	renderMarkdown,
	ScrollableModal,
	TenguCockpitApp,
	TenguSessionManager,
	type PiModelConfig,
} from "../src/index.ts";

function makeMockPiConfig(replyText: string): PiModelConfig {
	const model = {
		id: "inkling-2-mini",
		name: "Inkling 2 Mini",
		api: "openai-completions" as const,
		provider: "kelsey-ai-llama.cpp",
		baseUrl: "http://127.0.0.1:8080/v1",
		reasoning: false,
		input: ["text" as const],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 262144,
		maxTokens: 8192,
	};
	return {
		agentDir: "/tmp/mock-pi",
		defaultProvider: model.provider,
		defaultModelId: model.id,
		active: { provider: model.provider, model, apiKey: "test-key", isDefault: true },
		available: [{ provider: model.provider, model, apiKey: "test-key", isDefault: true }],
		streamFn: () => {
			const stream = createAssistantMessageEventStream();
			const msg: AssistantMessage = {
				role: "assistant",
				content: [{ type: "text", text: replyText }],
				api: model.api,
				provider: model.provider,
				model: model.id,
				usage: { input: 10, output: 10, cacheRead: 0, cacheWrite: 0, totalTokens: 20, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
				stopReason: "stop",
				timestamp: Date.now(),
			};
			queueMicrotask(() => {
				stream.push({ type: "start", partial: msg });
				stream.push({ type: "done", reason: "stop", message: msg });
			});
			return stream;
		},
	};
}

test("Persistent JSONL sessions save, list, and resume full chat transcripts", async () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-sess-"));
	const store = new SqliteTenguStore(":memory:");
	try {
		const piConfig = makeMockPiConfig("Configured localhost scope and max 2 workers.");
		const app = new TenguCockpitApp({
			store,
			intercept: new InterceptEngine({ store }),
			piConfig,
			tenguHome: dir,
			getRows: () => 28,
		});

		await app.submitPrompt("configure localhost with 2 workers");
		const sessId = app.currentSession.header.id;

		// Verify saved on disk in ~/.tengu/sessions/*.jsonl
		const mgr = new TenguSessionManager(dir);
		const list = mgr.listSessions();
		assert.equal(list.length, 1);
		assert.equal(list[0]!.id, sessId);
		assert.equal(list[0]!.messageCount, 2);

		// Resume in a fresh cockpit instance and verify transcript restored
		const resumed = new TenguCockpitApp({
			store,
			intercept: new InterceptEngine({ store }),
			piConfig,
			tenguHome: dir,
			resumeSessionId: true,
			getRows: () => 28,
		});
		assert.equal(resumed.currentSession.header.id, sessId);
		const transcript = resumed.chatLines.join("\n");
		assert.ok(transcript.includes("configure localhost with 2 workers"));
		assert.ok(transcript.includes("Configured localhost scope and max 2 workers."));
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("Sparkle-grade ChatStreamState animates prefill -> thinking -> tool -> live streaming Markdown -> finalize", () => {
	const cs = new ChatStreamState();
	cs.start("inkling-2-mini");
	assert.ok(cs.renderLive(70).join("\n").includes("Prefilling prompt…"));
	cs.tick();
	assert.ok(cs.renderLive(70).join("\n").includes("⠙"));

	cs.onThinkingDelta("Checking port 8080 headers...");
	assert.ok(cs.renderLive(70).join("\n").includes("Thinking…"));

	cs.onToolStart("configure_task", { max_workers: 2 });
	assert.ok(cs.renderLive(70).join("\n").includes("⚙ configure_task"));
	cs.onToolEnd("configure_task", false);

	cs.onTextDelta("## Ready\n\nUpdated **max_workers** to `2`.");
	const live = cs.renderLive(70).join("\n");
	assert.ok(live.includes("▍"));
	assert.ok(live.includes("Thought for"));

	const committed = cs.finalize(70).join("\n");
	assert.equal(cs.phase, "idle");
	assert.ok(committed.includes("◆ tengu"));
	assert.ok(!committed.includes("▍"));
});

test("Real Markdown rendering, ScrollableModal scrollbar, and PickerModal selection", () => {
	const md = "# Pentest Report\n\n- **Severity**: `HIGH`\n\n```bash\ncurl http://127.0.0.1:8080/health\n```\n";
	const lines = renderMarkdown(md, 60);
	assert.ok(!lines.join("\n").includes("# Pentest Report"));
	assert.ok(lines.join("\n").includes("\x1b["));

	const longMd = Array.from({ length: 25 }, (_, i) => `### Finding ${i + 1}\n\nDetails for **issue ${i + 1}**.`).join("\n\n");
	const modal = new ScrollableModal("Report", [], undefined, longMd);
	const rendered = modal.render(76, 22);
	assert.ok(rendered.some((l) => l.includes("┃")));
	for (const l of rendered) assert.ok(visibleWidth(l) <= 76);

	const picker = new PickerModal("Sessions", [
		{ id: "a", label: "Session A" },
		{ id: "b", label: "Session B" },
	]);
	picker.move(1);
	assert.equal(picker.selectedItem()?.id, "b");
});

test("End-to-end TuiAltScreen routes prompt typing, Tab sidebar switch, SGR wheel scroll, and live telemetry", async () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-e2e-"));
	const store = new SqliteTenguStore(":memory:");
	let onInputCb: ((data: string) => void) | null = null;
	const mockTerminal: Terminal = {
		columns: 120,
		rows: 30,
		kittyProtocolActive: true,
		start(onInput) {
			onInputCb = onInput;
		},
		stop() {},
		async drainInput() {},
		write() {},
		moveBy() {},
		hideCursor() {},
		showCursor() {},
		clearLine() {},
		clearFromCursor() {},
		clearScreen() {},
		setTitle() {},
	};

	try {
		const task = store.createTask({ name: "E2E Live Test" });
		writeLiveStatusSnapshot(getStatusFilePath(dir, task.id), {
			taskId: task.id,
			pid: process.pid,
			status: "running",
			model: "kelsey-ai-llama.cpp/inkling-2-mini",
			round: 2,
			maxRounds: 12,
			totalTokensGenerated: 1200,
			tokensPerSec: 42.5,
			startedAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			agents: [
				{
					role: "worker-10",
					intentId: 10,
					phase: "streaming",
					currentTool: "",
					toolStartedAt: null,
					tokensGenerated: 300,
					tokensPerSec: 38.0,
					lastSnippet: "Probing /health",
					updatedAt: new Date().toISOString(),
				},
			],
		});

		const tui = new TuiAltScreen(mockTerminal);
		const app = new TenguCockpitApp({
			store,
			intercept: new InterceptEngine({ store }),
			tenguHome: dir,
			initialTaskId: task.id,
			getRows: () => 30,
		});
		app.onRenderNeeded = () => tui.requestRender();
		tui.addInputListener((data) => (app.handleGlobalKey(data) ? { consume: true } : undefined));
		tui.setLayoutRoot(app);
		tui.setFocus(app.promptInput);
		tui.start();

		await new Promise((r) => setTimeout(r, 35));

		// Live telemetry renders in header & sidebar
		const frame = app.render(120).join("\n");
		assert.ok(frame.includes("42.5t/s"));
		assert.ok(frame.includes("worker-10"));

		// Typing goes straight into promptInput (no vi mode, focused by default!)
		onInputCb!("h");
		onInputCb!("i");
		assert.equal(app.promptInput.getValue(), "hi");

		// Tab cycles Mission Sidebar: live -> graph -> findings
		onInputCb!("\t");
		assert.equal(app.sidebarMode, "graph");
		onInputCb!("\t");
		assert.equal(app.sidebarMode, "findings");

		// Trackpad wheel over sidebar (x=100, y=10) scrolls sidebar
		onInputCb!("\x1b[<65;100;10M");
		assert.ok(app.sidebarScroll >= 0);

		// Ctrl+B collapses sidebar
		onInputCb!("\x02");
		assert.equal(app.sidebarOpen, false);

		tui.stop();
		await new Promise((r) => setTimeout(r, 25));
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("Established TUI patterns: Ctrl+C/Ctrl+D double-press exit, Tab /command completion, Ctrl+T thinking, Shift+Up/Down scroll, message queue", () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-pat-"));
	const store = new SqliteTenguStore(":memory:");
	try {
		let quitCount = 0;
		const app = new TenguCockpitApp({
			store,
			intercept: new InterceptEngine({ store }),
			tenguHome: dir,
			getRows: () => 28,
		});
		app.onQuit = () => quitCount++;

		// 1. Ctrl+C with non-empty input clears input and does NOT quit
		app.promptInput.handleInput("hello");
		app.handleGlobalKey("\x03");
		assert.equal(app.promptInput.getValue(), "");
		assert.equal(quitCount, 0);

		// 2. Ctrl+C twice on empty input quits on the second press
		app.handleGlobalKey("\x03");
		assert.equal(quitCount, 0);
		assert.ok(app.statusMessage.includes("Ctrl+C again"));
		app.handleGlobalKey("\x03");
		assert.equal(quitCount, 1);

		// 3. Ctrl+D twice on empty input quits on the second press
		app.handleGlobalKey("\x04");
		assert.equal(quitCount, 1);
		assert.ok(app.statusMessage.includes("Ctrl+D again"));
		app.handleGlobalKey("\x04");
		assert.equal(quitCount, 2);

		// 4. Tab completes /command and cycles matches
		app.promptInput.handleInput("/re");
		app.handleGlobalKey("\t");
		assert.equal(app.promptInput.getValue(), "/resume");
		app.handleGlobalKey("\t");
		assert.equal(app.promptInput.getValue(), "/report");

		// 5. Ctrl+U clears input
		app.handleGlobalKey("\x15");
		assert.equal(app.promptInput.getValue(), "");

		// 6. Ctrl+T toggles thinking display
		assert.equal(app.chatStream.showFullThinking, false);
		app.handleGlobalKey("\x14");
		assert.equal(app.chatStream.showFullThinking, true);

		// 7. Shift+Up / Shift+Down scrolls conversation
		app.handleGlobalKey("\x1b[1;2A");
		assert.equal(app.chatScrollOffset, 2);
		app.handleGlobalKey("\x1b[1;2B");
		assert.equal(app.chatScrollOffset, 0);

		// 8. Message queuing while busy + Up recalls queued message into empty prompt
		app.chatBusy = true;
		void app.submitPrompt("follow-up question");
		assert.equal(app.queuedMessages.length, 1);
		app.handleGlobalKey("\x1b[A");
		assert.equal(app.queuedMessages.length, 0);
		assert.equal(app.promptInput.getValue(), "follow-up question");
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

import { createPiLlmJudge } from "../src/index.ts";

test("createPiLlmJudge evaluates safety rules via Pi model and parses JSON verdict", async () => {
	const piConfig = makeMockPiConfig(JSON.stringify({ allow: false, reason: "Targets production table" }));
	const judge = createPiLlmJudge(piConfig);
	const verdict = await judge({
		rule: {
			id: 1,
			name: "judge_sql_destructive_statement",
			scope: "global",
			taskId: null,
			assetPattern: "",
			target: "tool_input",
			matchType: "regex",
			pattern: "DROP TABLE",
			action: "judge",
			ruleClass: "judge",
			rationale: "Destructive SQL",
			message: "",
			priority: 80,
			enabled: true,
			seedBatch: "v2",
			timeoutEnabled: true,
			timeoutSeconds: 10,
			timeoutAction: "deny",
			createdAt: "",
			updatedAt: "",
		},
		toolName: "bash",
		serializedArgs: '{"command":"psql -c \'DROP TABLE users;\'"}',
		staticSignals: [],
		signal: new AbortController().signal,
	});
	assert.equal(verdict.allow, false);
	assert.equal(verdict.reason, "Targets production table");
});

test("Session resume restores conversation history to Agent, clears task on unlinked session, keeps per-session drafts, and supports multiline composer", async () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-res-"));
	const store = new SqliteTenguStore(":memory:");
	try {
		const seenMessageCounts: number[] = [];
		const model = {
			id: "inkling-2-mini",
			name: "Inkling 2 Mini",
			api: "openai-completions" as const,
			provider: "kelsey-ai-llama.cpp",
			baseUrl: "http://127.0.0.1:8080/v1",
			reasoning: false,
			input: ["text" as const],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 262144,
			maxTokens: 8192,
		};
		const piConfig: PiModelConfig = {
			agentDir: "/tmp/mock-pi",
			defaultProvider: model.provider,
			defaultModelId: model.id,
			active: { provider: model.provider, model, apiKey: "k", isDefault: true },
			available: [{ provider: model.provider, model, apiKey: "k", isDefault: true }],
			streamFn: (_m, ctx) => {
				seenMessageCounts.push(ctx.messages.length);
				const stream = createAssistantMessageEventStream();
				const msg: AssistantMessage = {
					role: "assistant",
					content: [{ type: "text", text: `Seen ${ctx.messages.length} messages` }],
					api: model.api,
					provider: model.provider,
					model: model.id,
					usage: { input: 10, output: 5, cacheRead: 0, cacheWrite: 0, totalTokens: 15, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
					stopReason: "stop",
					timestamp: Date.now(),
				};
				queueMicrotask(() => {
					stream.push({ type: "start", partial: msg });
					stream.push({ type: "done", reason: "stop", message: msg });
				});
				return stream;
			},
		};

		const task = store.createTask({ name: "Linked Task" });
		const app1 = new TenguCockpitApp({
			store,
			intercept: new InterceptEngine({ store }),
			piConfig,
			tenguHome: dir,
			initialTaskId: task.id,
			getRows: () => 28,
		});
		await app1.submitPrompt("remember the secret word falcon");
		const sess1Id = app1.currentSession.header.id;

		// Multiline composer (Ctrl+J) + per-session draft isolation
		app1.promptInput.handleInput("line one");
		app1.handleGlobalKey("\n"); // Ctrl+J
		app1.promptInput.handleInput("line two");
		assert.equal(app1.multilinePrefix, "line one");

		// Start unlinked new session -> clears prior task AND saves sess1 draft
		app1.startNewSession("Unlinked Chat", false);
		assert.equal(app1.activeTaskId, null, "Unlinked session must clear prior activeTaskId");
		assert.equal(app1.promptInput.getValue(), "");

		// Switch back to sess1 -> restores multiline draft AND linked task
		app1.switchToSession(sess1Id);
		assert.equal(app1.activeTaskId, task.id);
		assert.equal(app1.multilinePrefix, "line one");
		assert.equal(app1.promptInput.getValue(), "line two");

		// Resume in a fresh cockpit instance and send follow-up -> model sees restored history!
		const app2 = new TenguCockpitApp({
			store,
			intercept: new InterceptEngine({ store }),
			piConfig,
			tenguHome: dir,
			resumeSessionId: sess1Id,
			getRows: () => 28,
		});
		await app2.submitPrompt("what was the secret word?");
		// First call had 1 user msg (+system); resumed call must include prior user + assistant + new user (>= 3 non-system msgs)
		assert.ok(seenMessageCounts[1]! >= 3, `Expected restored history in resumed Agent, saw ${seenMessageCounts[1]} messages`);

		// Usage breakdown distinguishes unknown cost explicitly
		store.recordLlmUsage({
			taskId: task.id,
			intentId: null,
			role: "worker",
			provider: "kelsey-ai-llama.cpp",
			model: "inkling-2-mini",
			inputTokens: 120,
			outputTokens: 80,
			cacheReadTokens: 0,
			costUsd: 0,
		});
		const bd = store.getTaskUsageBreakdown(task.id);
		assert.equal(bd.totalTokens, 200);
		assert.equal(bd.knownCostUsd, null, "Zero/local cost should be reported as unknown (null)");
		assert.equal(bd.byModel[0]!.model, "inkling-2-mini");
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("Narrow terminal resize (60x18, 80x22, 140x40) stays within exact viewport bounds across modes and modals", () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-resize-"));
	const store = new SqliteTenguStore(":memory:");
	try {
		const task = store.createTask({ name: "Resize QA" });
		const app = new TenguCockpitApp({
			store,
			intercept: new InterceptEngine({ store }),
			tenguHome: dir,
			initialTaskId: task.id,
			getRows: () => 18,
		});

		for (const [cols, rows] of [
			[60, 18],
			[80, 22],
			[140, 40],
		] as const) {
			const sizedApp = new TenguCockpitApp({
				store,
				intercept: new InterceptEngine({ store }),
				tenguHome: dir,
				initialTaskId: task.id,
				getRows: () => rows,
			});
			for (const open of [true, false]) {
				sizedApp.sidebarOpen = open;
				const lines = sizedApp.render(cols);
				assert.equal(lines.length, rows, `Expected ${rows} rows at ${cols}x${rows}`);
				for (const line of lines) {
					assert.ok(visibleWidth(line) <= cols, `Overflow at ${cols}x${rows}: ${visibleWidth(line)}`);
				}
			}
			const modal = new ScrollableModal("Narrow Modal", ["Long line ".repeat(20)]);
			for (const l of modal.render(Math.min(cols - 4, 80), rows - 4)) {
				assert.ok(visibleWidth(l) <= Math.max(50, cols), `Modal overflow at ${cols}x${rows}`);
			}
		}
		assert.ok(app.render(60).length === 18);
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});
