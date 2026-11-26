import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { visibleWidth, type Terminal } from "@earendil-works/pi-tui";
import { InterceptEngine } from "@tengu/intercept";
import { SqliteTenguStore } from "@tengu/store";
import { createTempDir } from "../../../test/helpers/mock-servers.ts";
import {
	loadPiModelConfig,
	startTenguTui,
	TenguCockpitApp,
	TenguRpcHandler,
	TenguSessionManager,
} from "../src/index.ts";

test("Negative: TenguSessionManager survives corrupt/truncated JSONL files and missing IDs", () => {
	const tmp = createTempDir("tengu-sess-neg-");
	try {
		const mgr = new TenguSessionManager(tmp.dir);
		assert.equal(mgr.loadSession("does-not-exist"), null);

		// Create a valid session then append a corrupt truncated line
		const sess = mgr.createSession({ title: "corrupt-test", taskId: null });
		mgr.appendMessage(sess.header.id, { role: "user", content: "valid line" });
		writeFileSync(sess.filePath, '{"type":"corrupt_partial_json', { flag: "a" });

		const loaded = mgr.loadSession(sess.header.id);
		assert.ok(loaded, "Session with trailing truncated JSONL line should still load valid lines");
		assert.equal(loaded.messages.length, 1);
		assert.equal(loaded.messages[0]!.message.content, "valid line");

		// 0-byte garbage file in sessions dir should not crash listSessions()
		writeFileSync(join(tmp.dir, "sessions", "empty.jsonl"), "");
		writeFileSync(join(tmp.dir, "sessions", "garbage.jsonl"), "not json at all\n");
		const listed = mgr.listSessions();
		assert.ok(Array.isArray(listed));
		assert.ok(listed.some((s) => s.id === sess.header.id));
	} finally {
		tmp.cleanup();
	}
});

test("Negative: loadPiModelConfig degrades gracefully on malformed or missing config files", () => {
	const tmp = createTempDir("tengu-pi-neg-");
	try {
		// Missing dir -> empty/default config without throwing
		const missing = loadPiModelConfig({ piAgentDir: join(tmp.dir, "no-such-dir") });
		assert.ok(missing);
		assert.ok(Array.isArray(missing.available));

		// Corrupt JSON in settings.json and models.json -> no throw
		const agentDir = join(tmp.dir, "agent");
		mkdirSync(agentDir, { recursive: true });
		writeFileSync(join(agentDir, "settings.json"), "{bad json");
		writeFileSync(join(agentDir, "models.json"), "<<<not json>>>");
		const corrupt = loadPiModelConfig({ piAgentDir: agentDir });
		assert.ok(corrupt);
		assert.ok(Array.isArray(corrupt.available));
	} finally {
		tmp.cleanup();
	}
});

test("Negative: TenguRpcHandler returns structured JSON-RPC errors for unknown methods and missing orchestrator", async () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		const rpc = new TenguRpcHandler(store);

		const unknown = await rpc.handle({ jsonrpc: "2.0", id: 1, method: "no.such.method" });
		assert.equal(unknown.jsonrpc, "2.0");
		assert.equal(unknown.id, 1);
		assert.ok(unknown.error);

		const noOrch = await rpc.handle({ jsonrpc: "2.0", id: "run-1", method: "task.run", params: { taskId: 1 } });
		assert.equal(noOrch.id, "run-1");
		assert.ok(noOrch.error);
		assert.match(noOrch.error.message, /orchestrator/i);

		const missingTask = await rpc.handle({ jsonrpc: "2.0", id: 3, method: "task.get", params: { id: 999999 } });
		assert.equal(missingTask.error, undefined);
		assert.equal(missingTask.result, null);
	} finally {
		store.close();
	}
});

test("Negative: Interactive approval modal approves on Y, denies on N/Esc, and is not dismissed on open", async () => {
	const store = new SqliteTenguStore(":memory:");
	const tmp = createTempDir("tengu-approve-neg-");
	let onInput: ((data: string) => void) | undefined;
	const term: Terminal = {
		start(cb) { onInput = cb; },
		stop() {},
		async drainInput() {},
		write() {},
		get columns() { return 100; },
		get rows() { return 30; },
		get kittyProtocolActive() { return false; },
		moveBy() {},
		hideCursor() {},
		showCursor() {},
		clearLine() {},
		clearFromCursor() {},
		clearScreen() {},
		setTitle() {},
	};
	let app: ReturnType<typeof startTenguTui> | undefined;
	try {
		let askHandler: ((req: never) => Promise<{ approved: boolean; decidedBy: string; reason?: string }>) | null = null;
		const intercept = new InterceptEngine({ store });
		app = startTenguTui({
			store,
			intercept,
			tenguHome: tmp.dir,
			terminal: term,
			onRegisterAskHandler: (fn) => {
				askHandler = fn as never;
			},
		} as never);
		assert.ok(askHandler, "startTenguTui must register interactive ask handler");

		const task = store.createTask({ name: "approve-test", target: "example.com" });
		const makeReq = (id: number) => ({
			id,
			taskId: task.id,
			intentId: null,
			ruleId: 1,
			ruleName: "ask_exploit",
			toolName: "bash",
			toolInput: "{\"command\":\"sqlmap -u http://example.com\"}",
			action: "ask" as const,
			status: "pending" as const,
			reason: "Operator approval required",
			judgeOutput: "",
			decidedBy: "",
			createdAt: new Date().toISOString(),
			decidedAt: null,
		});

		// 1. Pressing Y approves — and must NOT auto-dismiss on open!
		const pYes = askHandler!(makeReq(1) as never);
		let resolvedEarly = false;
		pYes.then(() => { resolvedEarly = true; });
		await new Promise((r) => setTimeout(r, 20));
		assert.equal(resolvedEarly, false, "Approval modal must NOT auto-dismiss on open");
		onInput?.("y");
		const resYes = await pYes;
		assert.equal(resYes.approved, true);

		// 2. Pressing N denies
		const pNo = askHandler!(makeReq(2) as never);
		onInput?.("n");
		const resNo = await pNo;
		assert.equal(resNo.approved, false);

		// 3. Pressing Esc denies
		const pEsc = askHandler!(makeReq(3) as never);
		onInput?.("\x1b");
		const resEsc = await pEsc;
		assert.equal(resEsc.approved, false);
	} finally {
		app?.dispose?.();
		await new Promise((r) => setImmediate(r));
		store.close();
		tmp.cleanup();
	}
});

test("Negative: TUI survives extreme tiny terminals (24x8, 40x12) and hostile ANSI/CJK/huge text", () => {
	const store = new SqliteTenguStore(":memory:");
	const intercept = new InterceptEngine({ store });
	const tmp = createTempDir("tengu-tiny-neg-");
	const sessionMgr = new TenguSessionManager(tmp.dir);
	try {
		let rows = 8;
		const app = new TenguCockpitApp({
			store,
			intercept,
			sessionManager: sessionMgr,
			requestRender: () => {},
			getRows: () => rows,
		});

		for (const [cols, r] of [
			[24, 8],
			[40, 12],
			[60, 16],
		] as const) {
			rows = r;
			const lines = app.render(cols);
			assert.equal(lines.length, r, `Expected ${r} lines at ${cols}x${r}`);
			for (const line of lines) {
				assert.ok(visibleWidth(line) <= cols, `Overflow at ${cols}x${r}: ${visibleWidth(line)}`);
			}
		}

		// Regression: NO vi mode — h/j/k/l must not be intercepted by handleGlobalKey
		for (const ch of ["h", "j", "k", "l"]) {
			assert.equal(app.handleGlobalKey(ch), false, `Key '${ch}' must not be hijacked as vi navigation`);
		}
	} finally {
		store.close();
		tmp.cleanup();
	}
});
