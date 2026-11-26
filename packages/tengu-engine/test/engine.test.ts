import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EvidenceStore, JobManager, ListenerManager, ScriptWorkspace, VulnIntelService } from "@tengu/ops";
import { SqliteTenguStore } from "@tengu/store";
import { BUILTIN_TENGU_SKILLS, detectRefusal, TenguToolSet } from "../src/index.ts";

test("TenguToolSet registers all 50+ ARTEX tools and executes end-to-end", async () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-eng-"));
	const store = new SqliteTenguStore(":memory:");
	const jobs = new JobManager();
	const listeners = new ListenerManager();
	try {
		const task = store.createTask({ name: "Engine Tool Test" });
		const toolSet = new TenguToolSet({
			store,
			evidence: new EvidenceStore(store, join(dir, "evidence")),
			listeners,
			jobs,
			scripts: new ScriptWorkspace(join(dir, "scripts")),
			vulnIntel: new VulnIntelService(store),
			taskId: task.id,
			runDir: dir,
		});

		const all = toolSet.allTools();
		assert.ok(all.length >= 50, `Expected >= 50 tools, got ${all.length}`);

		const byName = new Map(all.map((t) => [t.name, t]));
		for (const expected of [
			"graph_overview",
			"add_intent",
			"record_fact",
			"report_finding",
			"insert_assets",
			"save_evidence",
			"evidence_check",
			"http_request",
			"session_login",
			"auth_request",
			"diff_responses",
			"api_contract",
			"http_probe",
			"js_audit",
			"listener_start",
			"search_vulns",
			"scan_with_nuclei",
			"bash",
		]) {
			assert.ok(byName.has(expected), `Missing tool: ${expected}`);
		}

		// Execute tool workflow
		const ins = await byName.get("insert_assets")!.execute("c1", {
			assets: [{ kind: "endpoint", value: "https://app.test/api/orders" }],
		});
		assert.equal(ins.isError, undefined);

		const intentRes = await byName.get("add_intent")!.execute("c2", { summary: "Test IDOR on /api/orders" });
		assert.equal(intentRes.isError, undefined);

		const findingRes = await byName.get("report_finding")!.execute("c3", {
			title: "Order IDOR",
			vuln_class: "idor",
			severity: "high",
			summary: "Accessed another user's order",
			evidence: "GET /api/orders/2 -> 200 OK",
		});
		assert.equal(findingRes.isError, undefined);

		const scriptSave = await byName.get("save_script")!.execute("c4", {
			name: "hello.py",
			content: "print('tengu-ok')\n",
		});
		assert.equal(scriptSave.isError, undefined);

		const scriptRun = await byName.get("run_script")!.execute("c5", { name: "hello.py", interpreter: "python3" });
		assert.ok(scriptRun.content[0].type === "text" && scriptRun.content[0].text.includes("tengu-ok"));

		// Skills & refusal detection
		assert.equal(BUILTIN_TENGU_SKILLS.length, 23);
		assert.equal(detectRefusal("I cannot assist with unauthorized hacking."), true);
		assert.equal(detectRefusal("Verified HTTP 200 response on authorized target."), false);
	} finally {
		jobs.stopAll();
		await listeners.stopAll();
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

import { existsSync, readFileSync } from "node:fs";
import { createAssistantMessageEventStream, type AssistantMessage } from "@earendil-works/pi-ai";
import { InterceptEngine } from "@tengu/intercept";
import { LlmPool, TenguOrchestrator } from "../src/index.ts";

test("TenguOrchestrator supports pause/resume/stop, writes tengu.log, and records llm_usage", async () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-orch-"));
	const store = new SqliteTenguStore(":memory:");
	try {
		const task = store.createTask({ name: "Pause Resume Test", maxTurns: 3 });
		const model = {
			id: "mock-model",
			name: "Mock Model",
			api: "openai-completions" as const,
			provider: "mock",
			baseUrl: "http://127.0.0.1:1",
			reasoning: false,
			input: ["text" as const],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 32000,
			maxTokens: 4096,
		};
		const pool = new LlmPool([{ id: "mock/1", model, apiKey: "k" }], store);
		let calls = 0;
		const logFile = join(dir, "tengu.log");
		const orch = new TenguOrchestrator({
			store,
			intercept: new InterceptEngine({ store }),
			pool,
			workspaceDir: join(dir, "workspace"),
			logFilePath: logFile,
			streamFn: () => {
				calls++;
				const stream = createAssistantMessageEventStream();
				const msg: AssistantMessage = {
					role: "assistant",
					content: [{ type: "text", text: `Round ${calls} ok` }],
					api: model.api,
					provider: model.provider,
					model: model.id,
					usage: { input: 100, output: 50, cacheRead: 0, cacheWrite: 0, totalTokens: 150, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0.001 } },
					stopReason: "stop",
					timestamp: Date.now(),
				};
				setTimeout(() => {
					stream.push({ type: "start", partial: msg });
					stream.push({ type: "done", reason: "stop", message: msg });
				}, 20);
				return stream;
			},
		});

		const runPromise = orch.runTask(task.id, { maxRounds: 2 });
		// Pause immediately after start
		assert.equal(orch.pauseTask(task.id), true);
		assert.equal(orch.isPaused(task.id), true);
		assert.equal(store.getTask(task.id)?.status, "paused");

		// Resume and let it finish
		assert.equal(orch.resumeTask(task.id), true);
		assert.equal(orch.isPaused(task.id), false);
		const finished = await runPromise;
		assert.equal(finished.status, "completed");

		// Verify token usage recorded & log file written
		const totals = store.getTaskTokenTotals(task.id);
		assert.ok(totals.totalTokens >= 150, `Expected >= 150 tokens, got ${totals.totalTokens}`);
		assert.equal(existsSync(logFile), true);
		const logText = readFileSync(logFile, "utf8");
		assert.ok(logText.includes("[task_paused]"));
		assert.ok(logText.includes("[task_resumed]"));
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

import { discoverHostTools, formatHostToolsForPrompt } from "@tengu/ops";
import { compactAgentMessages, findSkill, renderSkillPlaybook } from "../src/index.ts";

test("Hosttools discovery, load_skill playbooks, and context compaction work cleanly", () => {
	const tools = discoverHostTools();
	assert.ok(tools.length > 0, "Should discover host tools like node/python3/curl on PATH");
	const summary = formatHostToolsForPrompt(tools);
	assert.ok(summary.includes("Available host security binaries:"));

	const skill = findSkill("api-security-testing");
	assert.ok(skill !== null);
	const playbook = renderSkillPlaybook(skill!);
	assert.ok(playbook.includes("API Security Testing"));
	assert.ok(playbook.includes("Verification & Evidence Standards"));

	const hugeText = "X".repeat(5000);
	const msgs = Array.from({ length: 12 }, (_, i) => ({
		role: "toolResult" as const,
		toolCallId: `c${i}`,
		toolName: "bash",
		content: [{ type: "text" as const, text: hugeText }],
		isError: false,
		timestamp: Date.now(),
	}));
	const compacted = compactAgentMessages(msgs, { keepRecent: 4, maxOldToolOutputChars: 500 });
	assert.equal(compacted.length, 12);
	const firstText = (compacted[0] as { content: Array<{ text: string }> }).content[0]!.text;
	const lastText = (compacted[11] as { content: Array<{ text: string }> }).content[0]!.text;
	assert.ok(firstText.includes("compacted"), "Older verbose tool output should be compacted");
	assert.equal(lastText.length, 5000, "Recent tool output should remain verbatim");
});
