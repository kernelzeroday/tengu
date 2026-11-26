import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { SqliteTenguStore } from "@tengu/store";
import { createTempDir, startMockHttpServer } from "../../../test/helpers/mock-servers.ts";
import {
	EvidenceStore,
	executeHttpRequest,
	exportTaskArchive,
	JobManager,
	ListenerManager,
	NotificationDispatcher,
	ReportGenerator,
	restoreTaskArchive,
	ScopeSentrySyncClient,
	ScriptWorkspace,
	validateTaskArchive,
} from "../src/index.ts";

test("Negative: validateTaskArchive rejects malformed JSON and tampered artifact hash, and restore is atomic", () => {
	const r1 = validateTaskArchive("{not valid json");
	assert.equal(r1.valid, false);
	assert.ok(r1.errors.length > 0);

	const store = new SqliteTenguStore(":memory:");
	const tmp = createTempDir("tengu-arch-neg-");
	try {
		const evidence = new EvidenceStore(store, join(tmp.dir, "evidence"));
		const task = store.createTask({ name: "tamper-test", target: "example.com" });
		evidence.saveText({
			taskId: task.id,
			kind: "http_response",
			name: "resp.txt",
			content: "original-evidence-bytes",
		});
		const archive = exportTaskArchive(store, task.id);
		assert.equal(validateTaskArchive(archive).valid, true);

		const tampered = structuredClone(archive);
		tampered.artifacts[0]!.base64 = Buffer.from("tampered-bytes").toString("base64");
		const vTampered = validateTaskArchive(tampered);
		assert.equal(vTampered.valid, false);
		assert.ok(vTampered.errors.some((e) => /hash|sha256|mismatch/i.test(e)));

		const destStore = new SqliteTenguStore(":memory:");
		try {
			assert.throws(() => restoreTaskArchive(destStore, join(tmp.dir, "dest-ev"), tampered));
			assert.equal(destStore.listTasks().length, 0, "Failed restore must not leave orphaned task rows");
		} finally {
			destStore.close();
		}
	} finally {
		store.close();
		tmp.cleanup();
	}
});

test("Negative: EvidenceStore exportArtifact fails cleanly on corrupted or missing artifact", () => {
	const store = new SqliteTenguStore(":memory:");
	const tmp = createTempDir("tengu-ev-neg-");
	try {
		const evidence = new EvidenceStore(store, join(tmp.dir, "evidence"));
		const task = store.createTask({ name: "ev-neg", target: "example.com" });
		const art = evidence.saveText({
			taskId: task.id,
			kind: "log",
			name: "trace.log",
			content: "trusted-data",
		});

		writeFileSync(art.path, "corrupted-data");
		const inspected = evidence.inspectArtifact(art.id);
		assert.equal(inspected.status, "corrupt");
		assert.throws(() => evidence.exportArtifact(art.id, join(tmp.dir, "out.log")));
		assert.throws(() => evidence.exportArtifact(999999, join(tmp.dir, "out2.log")));
	} finally {
		store.close();
		tmp.cleanup();
	}
});

test("Negative: executeHttpRequest handles HTTP 500 and connection refused cleanly", async () => {
	const store = new SqliteTenguStore(":memory:");
	const srv = await startMockHttpServer((_req, res) => {
		res.writeHead(500, { "content-type": "text/plain" });
		res.end("internal server error");
	});
	try {
		const task = store.createTask({ name: "http-neg", target: "127.0.0.1" });
		const res500 = await executeHttpRequest({
			store,
			taskId: task.id,
			method: "GET",
			url: `${srv.url}/boom`,
		});
		assert.equal(res500.status, 500);
		assert.match(res500.body, /internal server error/);

		await assert.rejects(() =>
			executeHttpRequest({
				store,
				taskId: task.id,
				method: "GET",
				url: "http://127.0.0.1:1/unreachable",
				timeoutMs: 1000,
			}),
		);
	} finally {
		await srv.close();
		store.close();
	}
});

test("Negative: NotificationDispatcher reports structured failure on HTTP 500 and unreachable endpoint", async () => {
	const store = new SqliteTenguStore(":memory:");
	const srv = await startMockHttpServer((_req, res) => {
		res.writeHead(500, { "content-type": "application/json" });
		res.end(JSON.stringify({ error: "webhook down" }));
	});
	try {
		const notifier = new NotificationDispatcher(store);
		store.upsertNotificationChannel({
			name: "broken-webhook",
			kind: "webhook",
			enabled: true,
			config: { url: `${srv.url}/hook` },
			events: ["finding_created"],
			minSeverity: "low",
		});
		store.upsertNotificationChannel({
			name: "dead-webhook",
			kind: "webhook",
			enabled: true,
			config: { url: "http://127.0.0.1:1/hook" },
			events: ["finding_created"],
			minSeverity: "low",
		});
		const results = await notifier.dispatch({
			type: "finding_created",
			severity: "high",
			title: "XSS",
			body: "Reflected XSS",
		});
		assert.equal(results.length, 2);
		assert.ok(results.every((r) => r.ok === false));
	} finally {
		await srv.close();
		store.close();
	}
});

test("Negative: ListenerManager rejects duplicate port bind and handles idempotent stopAll", async () => {
	const listeners = new ListenerManager();
	try {
		const l1 = await listeners.start({ protocol: "http", host: "127.0.0.1", port: 0 });
		await assert.rejects(() => listeners.start({ protocol: "http", host: "127.0.0.1", port: l1.port }));
		await listeners.stopAll();
		await listeners.stopAll();
	} finally {
		await listeners.stopAll();
	}
});

test("Negative: JobManager captures non-zero exit codes and ScriptWorkspace neutralizes path traversal", async () => {
	const tmp = createTempDir("tengu-job-neg-");
	const jobs = new JobManager();
	const scripts = new ScriptWorkspace(tmp.dir);
	try {
		const job = jobs.start("node -e 'process.exit(42)'", tmp.dir);
		for (let i = 0; i < 40; i++) {
			const list = jobs.status(job.id);
			if (list[0] && list[0].status !== "running") break;
			await new Promise((r) => setTimeout(r, 25));
		}
		const done = jobs.status(job.id)[0];
		assert.ok(done);
		assert.equal(done.exitCode, 42);

		const savedPath = scripts.saveScript("../../outside-escape.sh", "echo safe");
		assert.ok(savedPath.startsWith(tmp.dir), `Script escaped workspace: ${savedPath}`);
	} finally {
		jobs.stopAll();
		tmp.cleanup();
	}
});

test("Negative: ReportGenerator rejects missing task ID and escapes HTML in findings", () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		const gen = new ReportGenerator(store);
		assert.throws(() => gen.generate(999999, "markdown"));

		const task = store.createTask({ name: "xss-report", target: "example.com" });
		store.addFinding({
			taskId: task.id,
			nodeId: null,
			intentId: null,
			fingerprint: "fp-xss-html",
			title: "<script>alert(1)</script>",
			vulnClass: "xss",
			severity: "high",
			status: "open",
			cwe: "CWE-79",
			cvss: 7.5,
			summary: "Payload <img src=x onerror=alert(2)> & friends",
			description: "Payload <img src=x onerror=alert(2)> & friends",
			evidence: "",
			evidenceIds: [],
			assetIds: [],
			reproduction: "",
			remediation: "",
		});
		const html = gen.generate(task.id, "html");
		assert.ok(!html.includes("<script>alert(1)</script>"), "HTML report must escape raw <script> tags");
		assert.ok(html.includes("&lt;script&gt;"));
	} finally {
		store.close();
	}
});

test("Negative: ScopeSentrySyncClient reports HTTP 401 errors cleanly", async () => {
	const store = new SqliteTenguStore(":memory:");
	const srv = await startMockHttpServer((_req, res) => {
		res.writeHead(401, { "content-type": "application/json" });
		res.end(JSON.stringify({ message: "unauthorized" }));
	});
	try {
		const task = store.createTask({ name: "ss-neg", target: "example.com" });
		const client = new ScopeSentrySyncClient(store, { baseUrl: srv.url, apiKey: "bad-key" });
		await assert.rejects(() => client.syncProjectAssets({ taskId: task.id, projectId: "proj-1" }));
	} finally {
		await srv.close();
		store.close();
	}
});
