import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import test from "node:test";
import { createTempDir } from "../../../test/helpers/mock-servers.ts";

const CLI_BIN = resolve(import.meta.dirname, "../dist/cli.js");
const PTY_DRIVER = resolve(import.meta.dirname, "../../../test/helpers/pty-driver.py");

test("Smoke: real PTY TUI renders alt-screen, handles /help, Esc, Tab, Kitty Shift+Enter, SGR mouse, SIGWINCH, and Ctrl+C x2 exit", () => {
	const tmp = createTempDir("tengu-smoke-pty-");
	try {
		const spec = {
			argv: [process.execPath, CLI_BIN],
			env: {
				HOME: tmp.dir,
				TENGU_HOME: join(tmp.dir, ".tengu"),
				TERM: "xterm-256color",
			},
			cols: 120,
			rows: 35,
			timeout: 15,
			steps: [
				{ op: "wait_for", text: "TENGU", timeout: 6 },
				{ op: "send", data: "/help\r", afterMs: 200 },
				{ op: "send", data: "\x1b", afterMs: 150 },
				{ op: "send", data: "\t", afterMs: 150 },
				// Kitty CSI-u Shift+Enter + text into multiline composer
				{ op: "send", data: "hi\x1b[13;2uworld", afterMs: 150 },
				// SGR mouse wheel up
				{ op: "send", data: "\x1b[<64;20;10M", afterMs: 150 },
				// Real SIGWINCH resizes
				{ op: "resize", cols: 70, rows: 20, afterMs: 150 },
				{ op: "resize", cols: 140, rows: 40, afterMs: 150 },
				// Ctrl+C clears composer -> Ctrl+C arms exit -> Ctrl+C exits cleanly
				{ op: "send", data: "\x03", afterMs: 120 },
				{ op: "send", data: "\x03", afterMs: 120 },
				{ op: "send", data: "\x03", afterMs: 250 },
			],
		};

		const raw = execFileSync("python3", [PTY_DRIVER], {
			input: JSON.stringify(spec),
			encoding: "utf8",
			timeout: 20_000,
		});
		const result = JSON.parse(raw) as {
			exitCode: number | null;
			output: string;
			timedOut: boolean;
			stepErrors: string[];
		};

		assert.deepEqual(result.stepErrors, [], `PTY step errors: ${result.stepErrors.join("; ")}`);
		assert.equal(result.timedOut, false, "Real PTY TUI should exit cleanly after Ctrl+C double-press");
		assert.equal(result.exitCode, 0, `Expected exit code 0, got ${result.exitCode}`);
		assert.ok(result.output.includes("\x1b[?1049h"), "Expected alt-screen entry sequence");
		assert.ok(result.output.includes("\x1b[?1049l"), "Expected alt-screen restore sequence on exit");
		assert.ok(result.output.includes("TENGU"), "Expected TENGU cockpit header in PTY output");
	} finally {
		tmp.cleanup();
	}
});
