import assert from "node:assert/strict";
import test from "node:test";
import { SqliteTenguStore } from "@tengu/store";
import { assertProperty } from "../../../test/helpers/prng.ts";
import { InterceptEngine } from "../src/index.ts";

test("Property P12: InterceptEngine is deterministic and hard_deny beats judge/ask regardless of rule order", async () => {
	const results: Array<Promise<void>> = [];
	assertProperty(
		"InterceptEngine rule-order invariance",
		(rng) => {
			const token = `TOK_${rng.asciiString(4, 10, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")}`;
			const rules = rng.shuffle([
				{
					name: "r_ask",
					ruleClass: "ask" as const,
					action: "ask" as const,
					priority: rng.int(1, 200),
				},
				{
					name: "r_judge",
					ruleClass: "judge" as const,
					action: "judge" as const,
					priority: rng.int(1, 200),
				},
				{
					name: "r_hard",
					ruleClass: "hard_deny" as const,
					action: "deny" as const,
					priority: rng.int(1, 200),
				},
			]);
			return { token, rules };
		},
		({ token, rules }) => {
			results.push(
				(async () => {
					const store = new SqliteTenguStore(":memory:");
					try {
						const task = store.createTask({ name: "prop", target: "example.com" });
						for (const r of rules) {
							store.upsertInterceptRule({
								name: r.name,
								scope: "global",
								taskId: null,
								assetPattern: "",
								target: "tool_input",
								matchType: "string",
								pattern: token,
								action: r.action,
								ruleClass: r.ruleClass,
								rationale: "prop",
								message: "blocked",
								priority: r.priority,
								enabled: true,
								seedBatch: "prop",
								timeoutEnabled: false,
								timeoutSeconds: 5,
								timeoutAction: "deny",
							});
						}
						const engine = new InterceptEngine({
							store,
							judge: async () => ({ allow: true, reason: "ok" }),
							ask: async () => ({ approved: true, decidedBy: "user" }),
						});
						const d1 = await engine.evaluate({ taskId: task.id, toolName: "bash", toolArgs: { command: token } });
						const d2 = await engine.evaluate({ taskId: task.id, toolName: "bash", toolArgs: { command: token } });
						assert.equal(d1.allowed, false, "hard_deny must always win over permissive judge/ask");
						assert.equal(d1.action, "deny");
						assert.equal(d1.allowed, d2.allowed);
						assert.equal(d1.action, d2.action);
					} finally {
						store.close();
					}
				})(),
			);
		},
		{ runs: 60 },
	);
	await Promise.all(results);
});
