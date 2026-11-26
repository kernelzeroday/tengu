import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";
import { createTempDir, startMockOpenAiServer } from "../../../test/helpers/mock-servers.ts";

const CLI_BIN = resolve(import.meta.dirname, "../dist/cli.js");

test("Smoke: tengu -p headless mode streams live telemetry, exports MD/JSON/SARIF/HTML/DOCX reports, and exits 0", async () => {
	const tmp = createTempDir("tengu-smoke-headless-");
	const tenguHome = join(tmp.dir, ".tengu");
	const piAgentDir = join(tmp.dir, ".pi", "agent");
	const outDir = join(tmp.dir, "out");
	mkdirSync(tenguHome, { recursive: true });
	mkdirSync(piAgentDir, { recursive: true });

	const mockLlm = await startMockOpenAiServer({
		delayMs: 30,
		replyText: "Recon complete. No critical issues observed on mock target.",
	});
	try {
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

		const child = spawn(
			process.execPath,
			[
				CLI_BIN,
				"-p",
				"Assess 127.0.0.1 for exposed services",
				"--target",
				"127.0.0.1",
				"--scope",
				"127.0.0.1",
				"--rounds",
				"1",
				"--max-workers",
				"1",
				"--out",
				outDir,
				"--json",
			],
			{
				env: { ...process.env, HOME: tmp.dir, TENGU_HOME: tenguHome },
				stdio: ["ignore", "pipe", "pipe"],
			},
		);

		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (d: Buffer) => {
			stdout += d.toString("utf8");
		});
		child.stderr.on("data", (d: Buffer) => {
			stderr += d.toString("utf8");
		});

		const exitCode = await new Promise<number | null>((resolveExit, reject) => {
			const timer = setTimeout(() => {
				child.kill("SIGKILL");
				reject(new Error(`tengu -p timed out.\nSTDERR:\n${stderr}`));
			}, 20_000);
			child.once("exit", (code) => {
				clearTimeout(timer);
				resolveExit(code);
			});
		});

		assert.equal(exitCode, 0, `Expected exit 0 from tengu -p, got ${exitCode}.\nSTDERR:\n${stderr}`);
		const summary = JSON.parse(stdout) as {
			taskId: number;
			name: string;
			status: string;
			model: string;
			usage: { totalTokens: number };
			assets: unknown[];
		};
		assert.equal(summary.taskId, 1);
		assert.equal(summary.model, "mock-local/mock-mini");
		assert.ok(summary.assets.length >= 1, "Expected initial target asset seeded");
		assert.ok(mockLlm.requestCount() >= 1, "Expected live LLM requests to mock OpenAI server");

		// Verify all 6 exported artifacts exist and are non-empty
		for (const file of ["report.md", "report.json", "report.sarif", "report.html", "report.docx", "summary.json"]) {
			const fp = join(outDir, file);
			assert.ok(existsSync(fp), `Missing exported artifact ${file}`);
			assert.ok(readFileSync(fp).length > 0, `Empty exported artifact ${file}`);
		}
		assert.equal(JSON.parse(readFileSync(join(outDir, "report.sarif"), "utf8")).version, "2.1.0");
	} finally {
		await mockLlm.close();
		tmp.cleanup();
	}
});
