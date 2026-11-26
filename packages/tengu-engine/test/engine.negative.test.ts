import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { InterceptEngine } from "@tengu/intercept";
import { EvidenceStore } from "@tengu/ops";
import { SqliteTenguStore } from "@tengu/store";
import { createTempDir } from "../../../test/helpers/mock-servers.ts";
import {
	BUILTIN_TENGU_SKILLS,
	detectRefusal,
	findSkill,
	isProcessAlive,
	LlmPool,
	loadMcpServerConfigs,
	readLiveStatusSnapshot,
	TenguToolSet,
	writeLiveStatusSnapshot,
} from "../src/index.ts";

const mockModel = (id: string) =>
	({
		id,
		name: id,
		api: "openai-completions",
		provider: "mock",
		baseUrl: "http://127.0.0.1:9999/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 32000,
		maxTokens: 4096,
	}) as never;

test("Negative: LlmPool handles failover, refusal detection, and empty/all-unhealthy pools", () => {
	assert.equal(detectRefusal("I cannot assist with unauthorized hacking."), true);
	assert.equal(detectRefusal("This is against my ethical guidelines."), true);
	assert.equal(detectRefusal("Found open port 8080 serving HTTP/1.1"), false);
	assert.equal(detectRefusal(""), false);

	const pool = new LlmPool([
		{ id: "ep1", model: mockModel("m1") },
		{ id: "ep2", model: mockModel("m2") },
	]);
	const first = pool.select();
	assert.ok(first);
	pool.markFailure(first.id, "503 overloaded");
	const next = pool.select();
	assert.ok(next);
	assert.notEqual(next.id, first.id, "Pool should fail over to healthy secondary endpoint");

	// Fail second endpoint too -> select returns null or falls back cleanly without throwing
	pool.markFailure(next.id, "503 overloaded");
	const bothDown = pool.select();
	assert.ok(bothDown === null || typeof bothDown.id === "string");

	// Empty pool throws or returns null cleanly
	const emptyPool = new LlmPool([]);
	assert.equal(emptyPool.select(), null);
});

test("Negative: loadMcpServerConfigs handles missing, malformed, and disabled MCP configs", () => {
	const tmp = createTempDir("tengu-mcp-neg-");
	try {
		// Missing file -> empty array
		assert.deepEqual(loadMcpServerConfigs(tmp.dir), []);

		// Malformed JSON -> empty array (never throws)
		writeFileSync(join(tmp.dir, "mcp.json"), "{broken json!!!");
		assert.deepEqual(loadMcpServerConfigs(tmp.dir), []);

		// Disabled server filtered out, enabled server preserved
		writeFileSync(
			join(tmp.dir, "mcp.json"),
			JSON.stringify({
				servers: {
					disabledSrv: { command: "npx", args: ["foo"], enabled: false },
					activeHttp: { url: "http://127.0.0.1:4321/mcp", enabled: true },
				},
			}),
		);
		const configs = loadMcpServerConfigs(tmp.dir);
		assert.equal(configs.length, 1);
		assert.equal(configs[0]!.name, "activeHttp");
		assert.equal(configs[0]!.transport, "http");
	} finally {
		tmp.cleanup();
	}
});

test("Negative: live-status snapshot handles missing/corrupt files and invalid PIDs cleanly", () => {
	const tmp = createTempDir("tengu-live-neg-");
	try {
		const p = join(tmp.dir, "run-1.status.json");
		assert.equal(readLiveStatusSnapshot(p), null);
		writeFileSync(p, "{not-valid-json");
		assert.equal(readLiveStatusSnapshot(p), null);

		writeLiveStatusSnapshot(p, {
			taskId: 1,
			pid: process.pid,
			status: "running",
			model: "mock",
			round: 1,
			maxRounds: 5,
			totalTokensGenerated: 10,
			tokensPerSec: 5,
			startedAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			agents: [],
		});
		const snap = readLiveStatusSnapshot(p);
		assert.ok(snap);
		assert.equal(snap.taskId, 1);

		assert.equal(isProcessAlive(process.pid), true);
		assert.equal(isProcessAlive(0), false);
		assert.equal(isProcessAlive(-42), false);
		assert.equal(isProcessAlive(999_999_999), false);
	} finally {
		tmp.cleanup();
	}
});

test("Negative: skills registry has unique IDs and returns null for unknown skills", () => {
	assert.ok(BUILTIN_TENGU_SKILLS.length >= 20);
	const ids = new Set(BUILTIN_TENGU_SKILLS.map((s) => s.id));
	assert.equal(ids.size, BUILTIN_TENGU_SKILLS.length, "All built-in skill IDs must be unique");
	assert.equal(findSkill("nonexistent-skill-xyz-999"), null);
});

test("Negative: TenguToolSet registers unique tool names and blocks hard_deny bash calls", async () => {
	const store = new SqliteTenguStore(":memory:");
	const tmp = createTempDir("tengu-tools-neg-");
	try {
		const task = store.createTask({ name: "tool-neg", target: "example.com" });
		const intercept = new InterceptEngine({ store });
		intercept.seedBuiltinRules();
		const evidence = new EvidenceStore(store, join(tmp.dir, "ev"));
		const toolset = new TenguToolSet({
			store,
			intercept,
			evidence,
			taskId: task.id,
			workDir: tmp.dir,
		});
		const tools = toolset.allTools();
		assert.ok(tools.length >= 50, `Expected >=50 tools, got ${tools.length}`);
		const names = new Set(tools.map((t) => t.name));
		assert.equal(names.size, tools.length, "All registered tool names must be unique");

		const bashTool = tools.find((t) => t.name === "bash");
		assert.ok(bashTool);
		const res = await bashTool.execute("call-1", { command: "rm -rf /" }, undefined, undefined);
		const text = res.content.map((c) => ("text" in c ? c.text : "")).join("\n");
		assert.match(text, /blocked|denied|intercept/i);
	} finally {
		store.close();
		tmp.cleanup();
	}
});
