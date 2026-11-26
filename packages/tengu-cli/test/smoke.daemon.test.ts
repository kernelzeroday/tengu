import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";
import { isProcessAlive, writeLiveStatusSnapshot } from "@tengu/engine";
import { SqliteTenguStore } from "@tengu/store";
import { createTempDir, startMockOpenAiServer } from "../../../test/helpers/mock-servers.ts";
import {
	getBackgroundTaskStatus,
	getStatusFilePath,
	signalBackgroundPauseToggle,
	startBackgroundTask,
	stopBackgroundTask,
} from "../src/index.ts";

const CLI_BIN = resolve(import.meta.dirname, "../dist/cli.js");

test("Smoke: detached background daemon lifecycle (start -> status -> SIGUSR1 -> SIGTERM -> stale PID cleanup)", async () => {
	const tmp = createTempDir("tengu-smoke-daemon-");
	const tenguHome = join(tmp.dir, ".tengu");
	const piAgentDir = join(tmp.dir, ".pi", "agent");
	mkdirSync(tenguHome, { recursive: true });
	mkdirSync(piAgentDir, { recursive: true });

	const mockLlm = await startMockOpenAiServer({ delayMs: 400, replyText: "Daemon step complete." });
	try {
		// Configure isolated Pi model pointing to local mock OpenAI server
		writeFileSync(
			join(piAgentDir, "settings.json"),
			JSON.stringify({ defaultProvider: "mock-local", defaultModel: "mock-mini" }),
		);
		writeFileSync(
			join(piAgentDir, "models.json"),
			JSON.stringify({
				providers: {
					"mock-local": {
						baseUrl: `${mockLlm.url}/v1`,
						api: "openai-completions",
						apiKey: "test-key",
						models: [{ id: "mock-mini", name: "Mock Mini" }],
					},
				},
			}),
		);

		const dbPath = join(tenguHome, "tengu.db");
		const store = new SqliteTenguStore(dbPath);
		const task = store.createTask({ name: "Daemon Smoke", target: "127.0.0.1" });
		store.close();

		const prevHome = process.env.HOME;
		process.env.HOME = tmp.dir;
		let spawnedPid = 0;
		try {
			const launched = startBackgroundTask({
				cliEntryPath: CLI_BIN,
				tenguHome,
				dbPath,
				taskId: task.id,
				maxRounds: 3,
			});
			spawnedPid = launched.pid;
			assert.ok(spawnedPid > 0, "Expected valid background daemon PID");

			// Wait briefly for status snapshot to be written
			await new Promise((r) => setTimeout(r, 350));
			const status = getBackgroundTaskStatus(tenguHome, task.id);
			assert.ok(status.snapshot, "Expected live status snapshot file");
			assert.equal(status.snapshot.taskId, task.id);

			// Send SIGUSR1 pause toggle and then SIGTERM stop
			signalBackgroundPauseToggle(tenguHome, task.id);
			await new Promise((r) => setTimeout(r, 150));
			stopBackgroundTask(tenguHome, task.id);

			// Wait for process exit
			for (let i = 0; i < 30; i++) {
				if (!isProcessAlive(spawnedPid)) break;
				await new Promise((r) => setTimeout(r, 100));
			}
			assert.equal(isProcessAlive(spawnedPid), false, "Daemon should exit cleanly after SIGTERM");

			// Stale PID detection: write snapshot with dead PID and verify running === false
			writeLiveStatusSnapshot(getStatusFilePath(tenguHome, 999), {
				taskId: 999,
				pid: 999_999_999,
				status: "running",
				model: "mock-mini",
				round: 1,
				maxRounds: 3,
				totalTokensGenerated: 0,
				tokensPerSec: 0,
				startedAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
				agents: [],
			});
			const stale = getBackgroundTaskStatus(tenguHome, 999);
			assert.equal(stale.alive, false, "Stale dead PID must not be reported as running");
		} finally {
			if (spawnedPid > 0 && isProcessAlive(spawnedPid)) {
				try {
					process.kill(spawnedPid, "SIGKILL");
				} catch {
					// ignore
				}
			}
			process.env.HOME = prevHome;
		}
	} finally {
		await mockLlm.close();
		tmp.cleanup();
	}
});
