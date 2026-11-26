import assert from "node:assert/strict";
import test from "node:test";
import { SqliteTenguStore } from "@tengu/store";
import { InterceptEngine } from "../src/index.ts";

test("InterceptEngine three-layer rules, scope guard, and static analyzer", async () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		const task = store.createTask({ name: "Safety Test" });
		store.addTaskScope({ taskId: task.id, pattern: "target.local", kind: "domain", exclude: false, note: "" });

		let judgeCalled = false;
		let askCalled = false;

		const engine = new InterceptEngine({
			store,
			judge: async () => {
				judgeCalled = true;
				return { allow: false, reason: "Destructive SQL denied by judge" };
			},
			ask: async () => {
				askCalled = true;
				return { approved: true, decidedBy: "operator", reason: "Approved local OOB listener" };
			},
		});
		const seeded = engine.seedBuiltinRules();
		assert.ok(seeded.length >= 8);

		// 1. Out-of-scope blocked
		const oos = await engine.evaluate({
			taskId: task.id,
			toolName: "http_request",
			toolArgs: { url: "https://evil.example.com" },
			targetUrlOrHost: "https://evil.example.com",
		});
		assert.equal(oos.allowed, false);
		assert.equal(oos.ruleName, "scope_guard");

		// 2. Hard deny (no LLM judge needed)
		const hard = await engine.evaluate({
			taskId: task.id,
			toolName: "bash",
			toolArgs: { command: "rm -rf /" },
		});
		assert.equal(hard.allowed, false);
		assert.equal(hard.ruleName, "hard_deny_root_destruction");
		assert.equal(judgeCalled, false);

		// 3. Judge layer
		const judged = await engine.evaluate({
			taskId: task.id,
			toolName: "bash",
			toolArgs: { command: "psql -c 'DROP TABLE users;'" },
		});
		assert.equal(judged.allowed, false);
		assert.equal(judgeCalled, true);

		// 4. Ask layer
		const asked = await engine.evaluate({
			taskId: task.id,
			toolName: "listener_start",
			toolArgs: { protocol: "http", port: 0 },
		});
		assert.equal(asked.allowed, true);
		assert.equal(askCalled, true);

		// 5. Static analyzer catches obfuscated base64 pipe to shell
		const obf = await engine.evaluate({
			taskId: task.id,
			toolName: "bash",
			toolArgs: { command: "echo cm0gLXJmIC8= | base64 -d | sh" },
		});
		assert.equal(obf.allowed, false);
		assert.ok(obf.staticSignals.some((s) => s.code === "base64_shell_exec"));
	} finally {
		store.close();
	}
});
