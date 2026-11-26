#!/usr/bin/env node
/**
 * Fully automated live E2E pentest harness for Tengu.
 *
 * 1. Spins up an isolated local training target (OWASP Juice Shop) via Vagrant (libvirt) or Podman.
 * 2. Runs `tengu -p` against the live target using the real configured Pi LLM (`~/.pi/agent/`).
 * 3. Streams live agent/tool/token/finding telemetry and tengu.log.
 * 4. Exports all reports (MD/JSON/SARIF/HTML/DOCX) + writes a structured capability & issue audit.
 * 5. ALWAYS spins down and cleans up the target VM/container on exit or signal.
 *
 * Usage:
 *   node e2e/lab/run-live-e2e.ts [--mode vagrant|podman] [--rounds 3] [--max-workers 2] [--out /tmp/tengu-e2e-out]
 */
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "../..");
const LAB_DIR = resolve(import.meta.dirname);
const CLI_BIN = join(ROOT, "packages/tengu-cli/dist/cli.js");

function parseArgs(argv: string[]) {
	const opts: Record<string, string> = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!;
		if (a.startsWith("--")) {
			const k = a.slice(2);
			const next = argv[i + 1];
			if (next && !next.startsWith("--")) {
				opts[k] = next;
				i++;
			} else {
				opts[k] = "true";
			}
		}
	}
	return {
		mode: (opts.mode === "podman" ? "podman" : "vagrant") as "vagrant" | "podman",
		rounds: Number(opts.rounds ?? "3"),
		maxWorkers: Number(opts["max-workers"] ?? "2"),
		maxTurns: Number(opts["max-turns"] ?? "12"),
		outDir: opts.out ? resolve(opts.out) : join(tmpdir(), `tengu-live-e2e-${Date.now()}`),
		provider: opts.provider,
		model: opts.model,
	};
}

function vagrantEnv() {
	// Ensure system Ruby (/usr/bin) precedes Linuxbrew Ruby so Fedora's vagrant-libvirt gems load cleanly.
	return { ...process.env, PATH: `/usr/bin:/bin:${process.env.PATH ?? ""}` };
}

async function waitForHttp(url: string, timeoutMs = 120_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
			if (res.ok) return;
		} catch {
			// retry
		}
		await new Promise((r) => setTimeout(r, 1500));
	}
	throw new Error(`Target did not become ready at ${url} within ${timeoutMs / 1000}s`);
}

async function spinUp(mode: "vagrant" | "podman"): Promise<{ targetHost: string; targetUrl: string; teardown: () => void }> {
	if (mode === "vagrant") {
		console.error("[e2e] Spinning up Vagrant (libvirt) lab VM...");
		execFileSync("/usr/bin/vagrant", ["up", "--provider=libvirt"], {
			cwd: LAB_DIR,
			env: vagrantEnv(),
			stdio: "inherit",
		});
		const rawIp = execFileSync("/usr/bin/vagrant", ["ssh", "-c", "hostname -I | awk '{print $1}'"], {
			cwd: LAB_DIR,
			env: vagrantEnv(),
			encoding: "utf8",
		}).trim();
		const targetHost = rawIp.split(/\s+/)[0]!;
		if (!targetHost) throw new Error("Failed to determine Vagrant VM IP");
		const targetUrl = `http://${targetHost}:3000`;
		await waitForHttp(`${targetUrl}/rest/admin/application-version`, 120_000);
		return {
			targetHost,
			targetUrl,
			teardown: () => {
				console.error("[e2e] Destroying Vagrant lab VM...");
				try {
					execFileSync("/usr/bin/vagrant", ["destroy", "-f"], {
						cwd: LAB_DIR,
						env: vagrantEnv(),
						stdio: "inherit",
					});
				} catch (err) {
					console.error("[e2e] Vagrant destroy error:", err);
				}
			},
		};
	}

	const containerName = `tengu-e2e-lab-${process.pid}`;
	const port = 33000 + (process.pid % 2000);
	console.error(`[e2e] Starting isolated Podman lab container (${containerName}) on 127.0.0.1:${port}...`);
	execFileSync(
		"podman",
		["run", "-d", "--rm", "--name", containerName, "-p", `127.0.0.1:${port}:3000`, "docker.io/bkimminich/juice-shop:latest"],
		{ stdio: "inherit" },
	);
	const targetUrl = `http://127.0.0.1:${port}`;
	try {
		await waitForHttp(`${targetUrl}/rest/admin/application-version`, 90_000);
	} catch (err) {
		try {
			execFileSync("podman", ["rm", "-f", containerName], { stdio: "ignore" });
		} catch {
			// ignore
		}
		throw err;
	}
	return {
		targetHost: "127.0.0.1",
		targetUrl,
		teardown: () => {
			console.error(`[e2e] Stopping & removing Podman lab container (${containerName})...`);
			try {
				execFileSync("podman", ["rm", "-f", containerName], { stdio: "inherit" });
			} catch (err) {
				console.error("[e2e] Podman rm error:", err);
			}
		},
	};
}

function buildCapabilityAudit(summary: any, targetUrl: string, mode: string, stderrLog: string): string {
	const findings = Array.isArray(summary.findings) ? summary.findings : [];
	const approvals = Array.isArray(summary.approvals) ? summary.approvals : [];
	const denied = approvals.filter((a: any) => a.status === "denied");
	const bySev: Record<string, number> = {};
	for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;

	const lines = [
		`# Tengu Live E2E Capability Audit`,
		``,
		`- **Target:** ${targetUrl} (mode: \`${mode}\`)`,
		`- **Model:** ${summary.model ?? "unknown"}`,
		`- **Task Status:** ${summary.status}`,
		`- **Duration:** ${(summary.durationMs / 1000).toFixed(1)}s`,
		`- **Tokens:** ${summary.usage?.totalTokens ?? 0} total (${summary.usage?.totalInputTokens ?? 0} in / ${summary.usage?.totalOutputTokens ?? 0} out)`,
		`- **Assets Discovered:** ${summary.assets?.length ?? 0} (tested: ${summary.assetCoverage?.tested ?? 0}/${summary.assetCoverage?.total ?? 0})`,
		`- **Worker Traces:** ${summary.traceCount ?? 0} (tool errors: ${summary.toolErrors ?? 0})`,
		`- **Intercept Events:** ${approvals.length} total (${denied.length} denied)`,
		`- **Findings Recorded:** ${findings.length} (${Object.entries(bySev).map(([k, v]) => `${k}: ${v}`).join(", ") || "none"})`,
		``,
		`## Recorded Findings`,
		...(findings.length > 0
			? findings.map((f: any) => `- **[${String(f.severity).toUpperCase()}]** ${f.title} (${f.vulnClass || "n/a"}, status: ${f.status})`)
			: [`- _(No findings recorded during this run)_`]),
		``,
		`## Intercept / Safety Blocks`,
		...(denied.length > 0
			? denied.map((d: any) => `- \`${d.toolName}\` blocked by \`${d.ruleName}\`: ${d.reason}`)
			: [`- _(No intercept blocks triggered)_`]),
		``,
		`## Observed Diagnostics & Potential Issues`,
		...(summary.toolErrors > 0 ? [`- **Tool Errors:** ${summary.toolErrors} worker tool calls returned errors — inspect \`tengu.log\` and traces.`] : [`- Zero worker tool errors observed.`]),
		...(findings.length === 0 ? [`- **Low Finding Yield:** 0 findings recorded — check whether rounds/turns were too low or whether the model failed to call \`report_finding\`.`] : []),
		...((summary.assets?.length ?? 0) <= 1 ? [`- **Shallow Recon:** Only ${summary.assets?.length ?? 0} asset(s) recorded — check whether recon tools discovered and inserted child endpoints.`] : []),
		``,
		`## Live Telemetry Tail`,
		"```text",
		stderrLog.trim().split("\n").slice(-35).join("\n"),
		"```",
	];
	return lines.join("\n") + "\n";
}

async function main() {
	const cfg = parseArgs(process.argv.slice(2));
	mkdirSync(cfg.outDir, { recursive: true });
	const isolatedTenguHome = mkdtempSync(join(tmpdir(), "tengu-e2e-home-"));
	let teardownFn: (() => void) | null = null;
	let cleanedUp = false;

	const cleanup = () => {
		if (cleanedUp) return;
		cleanedUp = true;
		if (teardownFn) teardownFn();
		try {
			// Copy tengu.log into outDir before removing temp home
			const logSrc = join(isolatedTenguHome, "tengu.log");
			if (existsSync(logSrc)) {
				writeFileSync(join(cfg.outDir, "tengu.log"), readFileSync(logSrc));
			}
			rmSync(isolatedTenguHome, { recursive: true, force: true });
		} catch {
			// best effort
		}
	};

	process.on("SIGINT", () => {
		cleanup();
		process.exit(130);
	});
	process.on("SIGTERM", () => {
		cleanup();
		process.exit(143);
	});

	try {
		const lab = await spinUp(cfg.mode);
		teardownFn = lab.teardown;
		console.error(`[e2e] Target live at ${lab.targetUrl}`);

		const prompt = [
			`Perform an authorized autonomous web & API security assessment against ${lab.targetUrl} (strictly scoped to ${lab.targetHost}).`,
			`Discover endpoints, APIs, client-side JS routes, authentication mechanisms, and common web vulnerabilities (SQLi, XSS, IDOR, auth bypass, info disclosure, misconfiguration).`,
			`Insert discovered endpoints into the Asset Graph, verify findings with concrete HTTP evidence, and record each verified vulnerability with report_finding.`,
		].join(" ");

		const args = [
			CLI_BIN,
			"-p",
			prompt,
			"--name",
			`Live E2E (${cfg.mode})`,
			"--target",
			lab.targetUrl,
			"--scope",
			`${lab.targetUrl},${lab.targetHost}`,
			"--rounds",
			String(cfg.rounds),
			"--max-workers",
			String(cfg.maxWorkers),
			"--max-turns",
			String(cfg.maxTurns),
			"--out",
			cfg.outDir,
			"--json",
			"--auto-approve",
		];
		if (cfg.provider) args.push("--provider", cfg.provider);
		if (cfg.model) args.push("--model", cfg.model);

		console.error(`[e2e] Launching tengu -p (rounds=${cfg.rounds}, maxWorkers=${cfg.maxWorkers}, out=${cfg.outDir})...`);
		const child = spawn(process.execPath, args, {
			env: {
				...process.env,
				// Keep real HOME so ~/.pi/agent/models.json (kelsey-ai.local) is used,
				// while isolating Tengu's DB/logs/runs in TENGU_HOME!
				HOME: homedir(),
				TENGU_HOME: isolatedTenguHome,
			},
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (d: Buffer) => {
			stdout += d.toString("utf8");
		});
		child.stderr.on("data", (d: Buffer) => {
			const chunk = d.toString("utf8");
			stderr += chunk;
			process.stderr.write(chunk);
		});

		const exitCode = await new Promise<number | null>((resolveExit) => {
			child.once("exit", (code) => resolveExit(code));
		});

		if (exitCode !== 0) {
			throw new Error(`tengu -p exited with code ${exitCode}`);
		}

		const summary = JSON.parse(stdout);
		const auditMd = buildCapabilityAudit(summary, lab.targetUrl, cfg.mode, stderr);
		writeFileSync(join(cfg.outDir, "capability-audit.md"), auditMd, "utf8");
		console.log("\n" + auditMd);
		console.log(`[e2e] Artifacts saved to: ${cfg.outDir}`);
	} finally {
		cleanup();
	}
}

main().catch((err) => {
	console.error("[e2e] FATAL:", err instanceof Error ? err.message : String(err));
	process.exit(1);
});
