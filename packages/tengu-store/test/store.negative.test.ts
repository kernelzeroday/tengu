import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";
import { createTempDir } from "../../../test/helpers/mock-servers.ts";
import { checkTargetScope, matchCidr, parseAssetDsl, SqliteTenguStore } from "../src/index.ts";

test("Negative: missing IDs return null/empty cleanly without throwing", () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		assert.equal(store.getTask(999999), null);
		assert.equal(store.getTask(-1), null);
		assert.deepEqual(store.listAssets({ taskId: 999999 }), []);
		assert.deepEqual(store.listFindings(999999), []);
		assert.deepEqual(store.listTaskScope(999999), []);
		assert.deepEqual(store.listWorkerTraces({ taskId: 999999 }), []);
		assert.equal(store.getArtifact(999999), null);
		assert.equal(store.getFinding(999999), null);
		assert.equal(store.getAsset(999999), null);
	} finally {
		store.close();
	}
});

test("Negative: matchCidr and checkTargetScope reject malformed IPs, out-of-range masks, and invalid regexes", () => {
	assert.equal(matchCidr("999.0.0.1", "10.0.0.0/8"), false);
	assert.equal(matchCidr("10.0.0.1", "10.0.0.0/33"), false);
	assert.equal(matchCidr("10.0.0.1", "10.0.0.0/-1"), false);
	assert.equal(matchCidr("not-an-ip", "10.0.0.0/24"), false);
	assert.equal(matchCidr("10.0.0.1", "10.0.0.0/abc"), false);

	const res = checkTargetScope("https://example.com", [
		{ pattern: "[invalid(regex", kind: "regex", exclude: false },
	]);
	assert.equal(res.inScope, false);
});

test("Negative: parseAssetDsl handles empty, whitespace, unbalanced quotes, and garbage without throwing", () => {
	assert.deepEqual(parseAssetDsl(""), []);
	assert.deepEqual(parseAssetDsl("   \t\n  "), []);
	assert.ok(Array.isArray(parseAssetDsl('kind:"unclosed quote AND === != ~~~')));
	assert.ok(Array.isArray(parseAssetDsl("AND AND AND")));
});

test("Negative: getTaskUsageBreakdown reports null cost when local model has zero recorded cost", () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		const task = store.createTask({ name: "cost-null", target: "example.com" });
		store.recordLlmUsage({
			taskId: task.id,
			intentId: null,
			role: "main",
			provider: "local-llama",
			model: "inkling-2-mini",
			inputTokens: 1000,
			outputTokens: 250,
			cacheReadTokens: 0,
			costUsd: 0,
		});
		const breakdown = store.getTaskUsageBreakdown(task.id);
		assert.equal(breakdown.totalInputTokens, 1000);
		assert.equal(breakdown.totalOutputTokens, 250);
		assert.equal(breakdown.knownCostUsd, null);
	} finally {
		store.close();
	}
});

test("Negative: concurrent WAL reader and writer connections do not hit SQLITE_BUSY", () => {
	const tmp = createTempDir("tengu-wal-");
	const dbPath = join(tmp.dir, "concurrent.db");
	const writer = new SqliteTenguStore(dbPath);
	const reader = new SqliteTenguStore(dbPath);
	try {
		const task = writer.createTask({ name: "wal-test", target: "example.com" });
		const intent = writer.addExplorationNode({
			taskId: task.id,
			kind: "intent",
			title: "Recon",
			summary: "Concurrent test",
		});
		for (let i = 0; i < 40; i++) {
			writer.addWorkerTrace({
				taskId: task.id,
				intentId: intent.id,
				workerId: "w1",
				turn: i,
				role: "tool",
				toolName: "http_request",
				toolArgs: "{}",
				toolOutput: "ok",
				content: `payload-${i}`,
				isError: false,
				durationMs: 5,
			});
			const traces = reader.listWorkerTraces({ taskId: task.id, limit: 100 });
			assert.ok(traces.length >= i + 1);
		}
	} finally {
		reader.close();
		writer.close();
		tmp.cleanup();
	}
});

test("Negative: oversized fields and SQL-injection payloads round-trip safely in SQLite", () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		const task = store.createTask({ name: "big-fields", target: "example.com" });
		const bigBody = "A".repeat(250_000) + "日本語🔥'\"--; DROP TABLE tasks; --";
		const finding = store.addFinding({
			taskId: task.id,
			nodeId: null,
			intentId: null,
			fingerprint: "fp-sqli-neg",
			title: "SQLi'; DROP TABLE findings; --",
			vulnClass: "sqli",
			severity: "high",
			status: "open",
			cwe: "CWE-89",
			cvss: 8.6,
			summary: bigBody,
			description: bigBody,
			evidence: "raw evidence",
			evidenceIds: [],
			assetIds: [],
			reproduction: "curl 'http://example.com/?q=1%27'",
			remediation: "Use parameterized queries",
		});
		const loaded = store.listFindings(task.id);
		assert.equal(loaded.length, 1);
		assert.equal(loaded[0]!.id, finding.id);
		assert.equal(loaded[0]!.summary.length, bigBody.length);
		assert.equal(store.listTasks().length, 1);
	} finally {
		store.close();
	}
});
