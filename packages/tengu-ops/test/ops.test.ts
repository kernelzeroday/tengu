import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { SqliteTenguStore } from "@tengu/store";
import {
	auditJavaScriptSource,
	diffHttpResponses,
	EvidenceStore,
	ListenerManager,
	maskSecrets,
	parseApiContract,
	ReportGenerator,
} from "../src/index.ts";

test("EvidenceStore, ListenerManager, HTTP diff, JS audit, API contract, and ReportGenerator", async () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-ops-"));
	const store = new SqliteTenguStore(":memory:");
	const listeners = new ListenerManager();
	try {
		const task = store.createTask({ name: "Ops Verification" });

		// EvidenceStore integrity + tamper detection
		const ev = new EvidenceStore(store, join(dir, "evidence"));
		const art = ev.saveText({ taskId: task.id, name: "poc.txt", content: "HTTP/1.1 200 OK\nflag{ok}" });
		assert.equal(ev.verifyArtifact(art.id).ok, true);
		writeFileSync(art.path, "tampered");
		assert.equal(ev.verifyArtifact(art.id).ok, false);

		// ListenerManager real local HTTP callback
		const info = await listeners.start({ id: "oob-1", protocol: "http", host: "127.0.0.1", port: 0 });
		const cbRes = await fetch(`http://127.0.0.1:${info.port}/ssrf-proof?id=42`);
		assert.equal(cbRes.status, 200);
		const sess = listeners.listSessions("oob-1");
		assert.equal(sess.events.length, 1);
		assert.equal(sess.events[0].path, "/ssrf-proof?id=42");

		// Diff responses
		const diff = diffHttpResponses(
			{ status: 200, body: JSON.stringify({ role: "admin", secret: "xyz" }) },
			{ status: 403, body: JSON.stringify({ error: "forbidden" }) },
		);
		assert.equal(diff.statusChanged, true);
		assert.deepEqual(diff.jsonKeyDiffs?.onlyInA, ["role", "secret"]);

		// JS audit & API contract
		const js = auditJavaScriptSource('const api = "/api/v1/secret"; const key = "AKIA1234567890ABCDEF"; el.innerHTML = x;');
		assert.ok(js.endpoints.includes("/api/v1/secret"));
		assert.ok(js.secrets.some((s) => s.kind === "aws_access_key"));
		assert.ok(js.sinks.some((s) => s.sink === "innerHTML"));

		const contract = parseApiContract(
			JSON.stringify({ openapi: "3.0.0", info: { title: "Demo", version: "1.0" }, paths: { "/users": { get: { summary: "List" } } } }),
		);
		assert.equal(contract.endpoints.length, 1);

		// Report generation + secret sanitization
		store.addFinding({
			taskId: task.id,
			nodeId: null,
			intentId: null,
			title: "Broken Object Level Authorization",
			vulnClass: "idor",
			severity: "high",
			status: "verified",
			summary: "Any user can read admin profile",
			description: "Missing ownership check",
			reproduction: "Authorization: Bearer supersecrettoken12345",
			remediation: "Enforce RBAC",
			evidence: "token=sk-1234567890abcdef",
			evidenceIds: [art.id],
			assetIds: [],
			cvss: 8.1,
			cwe: "CWE-639",
			fingerprint: "fp-1",
		});

		const reports = new ReportGenerator(store);
		const md = reports.generate(task.id, "markdown", true);
		assert.ok(md.includes("Broken Object Level Authorization"));
		assert.ok(!md.includes("sk-1234567890abcdef"));
		assert.ok(md.includes("***REDACTED***"));

		const sarif = JSON.parse(reports.generate(task.id, "sarif", true)) as { version: string; runs: Array<{ results: unknown[] }> };
		assert.equal(sarif.version, "2.1.0");
		assert.equal(sarif.runs[0].results.length, 1);

		assert.equal(maskSecrets("Authorization: Bearer abc123").includes("abc123"), false);
	} finally {
		await listeners.stopAll();
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});

import {
	exportTaskArchive,
	maskTrafficRecord,
	NotificationDispatcher,
	restoreTaskArchive,
	validateTaskArchive,
} from "../src/index.ts";

test("DOCX reports, single-finding export, portable archive atomic restore, evidence inspect, traffic mask, and notify preview", () => {
	const dir1 = mkdtempSync(join(tmpdir(), "tengu-arch-src-"));
	const dir2 = mkdtempSync(join(tmpdir(), "tengu-arch-dst-"));
	const store1 = new SqliteTenguStore(":memory:");
	const store2 = new SqliteTenguStore(":memory:");
	try {
		const task = store1.createTask({ name: "Archive & Report QA" });
		store1.addTaskScope({ taskId: task.id, pattern: "demo.local", kind: "domain", exclude: false, note: "" });
		const [asset] = store1.upsertAssets([{ taskId: task.id, kind: "endpoint", value: "http://demo.local/api" }]);

		const ev1 = new EvidenceStore(store1, join(dir1, "evidence"));
		const art = ev1.saveText({ taskId: task.id, name: "proof.http", content: "Authorization: Bearer secret123456\nHTTP/1.1 200 OK" });

		// Evidence inspect: readable + redacted preview, then export single artifact
		const insp = ev1.inspectArtifact(art.id);
		assert.equal(insp.status, "readable");
		assert.ok(!insp.redactedPreview.includes("secret123456"));
		assert.ok(insp.redactedPreview.includes("***REDACTED***"));
		const exportedArtPath = join(dir1, "exported-proof.http");
		ev1.exportArtifact(art.id, exportedArtPath);

		// Finding + retest
		const finding = store1.addFinding({
			taskId: task.id,
			nodeId: null,
			intentId: null,
			title: "Auth Bypass",
			vulnClass: "authz",
			severity: "high",
			status: "verified",
			summary: "Bypass via header",
			description: "",
			reproduction: "Authorization: Bearer supersecret999",
			remediation: "Enforce auth middleware",
			evidence: "token=sk-1234567890abcdef",
			evidenceIds: [art.id],
			assetIds: [asset!.id],
			cvss: 8.2,
			cwe: "CWE-287",
			fingerprint: "fp-arch-1",
		});
		store1.addFindingRetest({ findingId: finding.id, taskId: task.id, status: "still_vulnerable", notes: "Reproduced cleanly", evidence: "" });

		// Single-finding export & DOCX valid ZIP header
		const gen = new ReportGenerator(store1);
		const fMd = gen.generateFinding(finding.id, "markdown", true);
		assert.ok(fMd.includes("Verification History"));
		assert.ok(fMd.includes("still_vulnerable"));
		assert.ok(!fMd.includes("sk-1234567890abcdef"));

		const docxBuf = gen.generateDocx(task.id, true);
		assert.equal(docxBuf[0], 0x50); // 'P'
		assert.equal(docxBuf[1], 0x4b); // 'K'
		assert.ok(docxBuf.toString("latin1").includes("word/document.xml"));
		assert.ok(!docxBuf.toString("utf8").includes("sk-1234567890abcdef"));

		const fDocxBuf = gen.generateFindingDocx(finding.id, true);
		assert.equal(fDocxBuf[0], 0x50);
		assert.equal(fDocxBuf[1], 0x4b);

		// Traffic masking
		const tr = store1.addTrafficRecord({
			taskId: task.id,
			intentId: null,
			findingId: finding.id,
			method: "GET",
			url: "http://demo.local/api",
			host: "demo.local",
			statusCode: 200,
			requestHeaders: { Authorization: "Bearer mytoken", Cookie: "sid=abc", Accept: "application/json" },
			requestBody: "",
			responseHeaders: { "Set-Cookie": "sid=xyz" },
			responseBody: "ok",
			durationMs: 12,
		});
		const masked = maskTrafficRecord(tr);
		assert.equal(masked.requestHeaders.Authorization, "***REDACTED***");
		assert.equal(masked.requestHeaders.Cookie, "***REDACTED***");
		assert.equal(masked.responseHeaders["Set-Cookie"], "***REDACTED***");
		assert.equal(masked.requestHeaders.Accept, "application/json");

		// Notification redacted payload preview
		const disp = new NotificationDispatcher(store1);
		const prev = disp.previewPayload({
			type: "finding_created",
			severity: "high",
			title: "Leak sk-1234567890abcdef",
			body: "Authorization: Bearer mytoken",
		});
		assert.ok(!prev.title.includes("sk-1234567890abcdef"));
		assert.ok(!prev.body.includes("mytoken"));

		// Portable Task Archive: export -> validate -> restore into separate store2
		const archive = exportTaskArchive(store1, task.id);
		const valid = validateTaskArchive(archive);
		assert.equal(valid.valid, true);
		assert.equal(valid.summary?.artifacts, 1);

		const restored = restoreTaskArchive(store2, join(dir2, "evidence"), archive);
		assert.equal(restored.restoredAssets, 1);
		assert.equal(restored.restoredFindings, 1);
		assert.equal(restored.restoredArtifacts, 1);
		assert.equal(store2.listTasks().length, 1);

		// Tampered archive MUST fail validation and leave store2 untouched!
		const tampered = JSON.parse(JSON.stringify(archive));
		tampered.artifacts[0].base64 = Buffer.from("corrupted").toString("base64");
		assert.equal(validateTaskArchive(tampered).valid, false);
		assert.throws(() => restoreTaskArchive(store2, join(dir2, "evidence"), tampered), /SHA-256 mismatch/);
		assert.equal(store2.listTasks().length, 1, "Failed import must leave existing records intact");
	} finally {
		store1.close();
		store2.close();
		rmSync(dir1, { recursive: true, force: true });
		rmSync(dir2, { recursive: true, force: true });
	}
});

import { createServer } from "node:http";
import { unlinkSync } from "node:fs";

test("EvidenceStore distinguishes readable/corrupt/missing and NotificationDispatcher reports real HTTP 200 vs 500 failures", async () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-ev-nt-"));
	const store = new SqliteTenguStore(":memory:");
	const server = createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (c: Buffer) => chunks.push(c));
		req.on("end", () => {
			if (req.url === "/ok" || req.url === "/email") {
				res.writeHead(200, { "content-type": "application/json" });
				res.end('{"ok":true}');
			} else {
				res.writeHead(500, { "content-type": "text/plain" });
				res.end("upstream error");
			}
		});
	});
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
	const port = (server.address() as { port: number }).port;

	try {
		const task = store.createTask({ name: "Evidence & Notify QA" });
		const ev = new EvidenceStore(store, join(dir, "evidence"));

		// 1. readable -> corrupt -> missing
		const art = ev.saveText({ taskId: task.id, name: "check.txt", content: "clean evidence" });
		assert.equal(ev.inspectArtifact(art.id).status, "readable");

		writeFileSync(art.path, "tampered bytes!");
		assert.equal(ev.inspectArtifact(art.id).status, "corrupt");
		assert.throws(() => ev.exportArtifact(art.id, join(dir, "out.txt")), /Cannot export/);

		unlinkSync(art.path);
		assert.equal(ev.inspectArtifact(art.id).status, "missing");

		// 2. NotificationDispatcher real mock HTTP 200, 500 failure, email relay, and severity filtering
		store.upsertNotificationChannel({
			name: "wh-ok",
			kind: "webhook",
			enabled: true,
			config: { url: `http://127.0.0.1:${port}/ok` },
			events: ["finding_created"],
			minSeverity: "medium",
		});
		store.upsertNotificationChannel({
			name: "wh-fail",
			kind: "webhook",
			enabled: true,
			config: { url: `http://127.0.0.1:${port}/fail` },
			events: ["finding_created"],
			minSeverity: "medium",
		});
		store.upsertNotificationChannel({
			name: "email-ok",
			kind: "email",
			enabled: true,
			config: { relayUrl: `http://127.0.0.1:${port}/email`, to: "sec@example.test" },
			events: ["finding_created"],
			minSeverity: "high",
		});

		const disp = new NotificationDispatcher(store);
		const results = await disp.dispatch({
			type: "finding_created",
			severity: "high",
			title: "High Finding",
			body: "Confirmed issue",
			taskId: task.id,
		});
		assert.equal(results.length, 3);
		assert.equal(results.find((r) => r.channel === "wh-ok")?.ok, true);
		assert.equal(results.find((r) => r.channel === "wh-fail")?.ok, false);
		assert.ok(results.find((r) => r.channel === "wh-fail")?.error?.includes("500"));
		assert.equal(results.find((r) => r.channel === "email-ok")?.ok, true);

		// Low severity should be filtered out by all channels
		const filtered = await disp.dispatch({
			type: "finding_created",
			severity: "low",
			title: "Low Note",
			body: "Info",
			taskId: task.id,
		});
		assert.equal(filtered.length, 0);
	} finally {
		await new Promise<void>((r) => server.close(() => r()));
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});
