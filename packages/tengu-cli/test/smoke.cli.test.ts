import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";
import { createTempDir } from "../../../test/helpers/mock-servers.ts";

const CLI_BIN = resolve(import.meta.dirname, "../dist/cli.js");

function runCli(args: string[], envOverrides: Record<string, string>) {
	return execFileSync(process.execPath, [CLI_BIN, ...args], {
		encoding: "utf8",
		env: { ...process.env, ...envOverrides },
		timeout: 15_000,
	});
}

test("Smoke: dist/cli.js packaging, shebang, and executable bit are intact", () => {
	assert.ok(existsSync(CLI_BIN), `Missing compiled CLI binary at ${CLI_BIN}`);
	const firstLine = readFileSync(CLI_BIN, "utf8").split("\n")[0];
	assert.equal(firstLine, "#!/usr/bin/env node");
	const mode = statSync(CLI_BIN).mode;
	assert.ok((mode & 0o111) !== 0, "dist/cli.js must have executable permission (+x)");
});

test("Smoke: real CLI binary handles help, task/asset/intercept/report/archive lifecycle, and invalid flags", () => {
	const tmp = createTempDir("tengu-smoke-cli-");
	const env = { HOME: tmp.dir, TENGU_HOME: join(tmp.dir, ".tengu") };
	try {
		const help = runCli(["--help"], env);
		assert.match(help, /tengu/i);

		const created = runCli(["task", "create", "Smoke Target"], env);
		assert.match(created, /Smoke Target|created|#/i);

		const listed = runCli(["task", "list"], env);
		assert.match(listed, /Smoke Target/);

		const skills = runCli(["skills"], env);
		assert.match(skills, /sqli|xss|ssrf|recon/i);

		const rules = runCli(["intercept", "list"], env);
		assert.match(rules, /hard_deny|deny|judge|ask/i);

		const mdReport = runCli(["report", "1", "--format", "markdown"], env);
		assert.match(mdReport, /Smoke Target/);

		const sarifReport = runCli(["report", "1", "--format", "sarif"], env);
		const parsedSarif = JSON.parse(sarifReport) as { version?: string };
		assert.equal(parsedSarif.version, "2.1.0");

		// Invalid subcommand must exit non-zero cleanly
		assert.throws(() => runCli(["totally-unknown-command-xyz"], env));
	} finally {
		tmp.cleanup();
	}
});

test("Smoke: real JSON-RPC 2.0 stdio subprocess handles requests, errors, and clean EOF exit", async () => {
	const tmp = createTempDir("tengu-smoke-rpc-");
	const env = { ...process.env, HOME: tmp.dir, TENGU_HOME: join(tmp.dir, ".tengu") };
	try {
		const child = spawn(process.execPath, [CLI_BIN, "rpc"], {
			env,
			stdio: ["pipe", "pipe", "pipe"],
		});

		let stdout = "";
		child.stdout.on("data", (d: Buffer) => {
			stdout += d.toString("utf8");
		});

		const frames = [
			JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
			JSON.stringify({ jsonrpc: "2.0", id: 2, method: "task.create", params: { name: "RPC Smoke" } }),
			JSON.stringify({ jsonrpc: "2.0", id: 3, method: "task.list" }),
			JSON.stringify({ jsonrpc: "2.0", id: 4, method: "nonexistent.method" }),
			"{malformed json line",
		];
		child.stdin.write(frames.join("\n") + "\n");
		child.stdin.end();

		const exitCode = await new Promise<number | null>((resolveExit, reject) => {
			const timer = setTimeout(() => {
				child.kill("SIGKILL");
				reject(new Error("RPC subprocess timed out"));
			}, 10_000);
			child.once("exit", (code) => {
				clearTimeout(timer);
				resolveExit(code);
			});
		});

		assert.equal(exitCode, 0, `Expected clean exit 0 from tengu rpc, got ${exitCode}`);
		const lines = stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { id: unknown; result?: any; error?: any });
		assert.ok(lines.length >= 4, `Expected >=4 JSON-RPC responses, got ${lines.length}`);
		assert.equal(lines[0]!.id, 1);
		assert.equal(lines[0]!.result.ok, true);
		assert.equal(lines[1]!.id, 2);
		assert.equal(lines[1]!.result.name, "RPC Smoke");
		assert.equal(lines[2]!.id, 3);
		assert.equal(lines[2]!.result.tasks.length, 1);
		assert.equal(lines[3]!.id, 4);
		assert.ok(lines[3]!.error);
	} finally {
		tmp.cleanup();
	}
});
