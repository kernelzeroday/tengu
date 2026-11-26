#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { LlmPool, loadSkills, readLiveStatusSnapshot, TenguOrchestrator } from "@tengu/engine";
import { InterceptEngine } from "@tengu/intercept";
import { exportTaskArchive, ReportGenerator, restoreTaskArchive, ScopeSentrySyncClient, validateTaskArchive, VulnIntelService, type ReportFormat } from "@tengu/ops";
import { SqliteTenguStore, type ApprovalRequest, type AssetKind } from "@tengu/store";
import {
	getBackgroundTaskStatus,
	signalBackgroundPauseToggle,
	startBackgroundTask,
	stopBackgroundTask,
} from "./daemon.ts";
import { createPiLlmJudge, loadPiModelConfig } from "./pi-config.ts";
import { TenguSessionManager } from "./sessions.ts";
import { startJsonRpcServer } from "./rpc.ts";
import { startTenguTui } from "./tui.ts";

function parseFlags(args: string[]): { positional: string[]; flags: Record<string, string | boolean> } {
	const positional: string[] = [];
	const flags: Record<string, string | boolean> = {};
	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		if (a.startsWith("--")) {
			const key = a.slice(2);
			const next = args[i + 1];
			if (next && !next.startsWith("-")) {
				flags[key] = next;
				i++;
			} else {
				flags[key] = true;
			}
		} else if (a === "-p" || a === "-h") {
			const key = a.slice(1);
			const next = args[i + 1];
			if (key === "p" && next && !next.startsWith("-")) {
				flags[key] = next;
				i++;
			} else {
				flags[key] = true;
			}
		} else {
			positional.push(a);
		}
	}
	return { positional, flags };
}

function printHelp(): void {
	console.log(`Tengu — AI Autonomous Penetration Testing Platform (Pi Core)

Usage:
  tengu [tui] [--resume [id]] [--db path] [--task id] [--provider p] [--model m]
  tengu -p "<prompt>" [--target host] [--scope s1,s2] [--rounds N] [--max-workers N] [--out dir] [--bg] [--json] [--auto-approve]
  tengu sessions                                  List saved persistent JSONL sessions
  tengu model                                     Show active Pi model & configured providers
  tengu rpc [--db path]                           Start headless JSON-RPC 2.0 server on stdio
  tengu task create <name> [--desc text]          Create a new pentest task
  tengu task list                                 List all tasks
  tengu task overview <taskId>                    Print dual-graph overview JSON
  tengu task start <taskId> [--rounds N]          Start detached background daemon (survives TUI close)
  tengu task status <taskId>                      Show live worker/token status of a running task
  tengu task pause <taskId>                       Pause or resume a running background task
  tengu task stop <taskId>                        Stop a running background task
  tengu task run <taskId> [--rounds N]            Run autonomous Planner/Worker engagement in foreground
  tengu scope add <taskId> <pattern> [--kind domain|cidr|ip|url|regex] [--exclude]
  tengu assets add <taskId> <kind> <value>        Insert an asset into the Asset Graph
  tengu assets list [--task id] [--query dsl]     List assets (supports Asset DSL)
  tengu assets coverage <taskId>                  Show asset test coverage summary
  tengu findings list [--task id]                 List recorded findings
  tengu intercept rules                           List three-layer intercept rules
  tengu intercept approvals [--task id]           List intercept approval audit log
  tengu report <taskId> [--format markdown|json|sarif|html|docx] [--out file]
  tengu report finding <findingId> [--format markdown|json|sarif|html|docx] [--out file]
  tengu archive export <taskId> [--out file] | validate <file> | restore <file>
  tengu usage <taskId>                            Show recorded token & cost breakdown by model
  tengu sync scopesentry --url <url> --key <key> --project <id> [--task id]
  tengu logs [--lines N]                          Tail ~/.tengu/tengu.log
  tengu skills list                               List all 23 built-in security skills
  tengu vuln search <query> | sync-kev            Search local vuln intel or sync CISA KEV
`);
}

async function main(): Promise<void> {
	const { positional, flags } = parseFlags(process.argv.slice(2));
	if (flags.help || flags.h || positional[0] === "help") {
		printHelp();
		return;
	}

	const tenguHome = process.env.TENGU_HOME || join(homedir(), ".tengu");
	const dbPath = typeof flags.db === "string" ? flags.db : process.env.TENGU_DB || join(tenguHome, "tengu.db");
	const store = new SqliteTenguStore(dbPath);
	const piConfig = loadPiModelConfig({
		overrideProvider: typeof flags.provider === "string" ? flags.provider : undefined,
		overrideModel: typeof flags.model === "string" ? flags.model : undefined,
	});

	let askHandler: ((req: ApprovalRequest) => Promise<{ approved: boolean; decidedBy: string; reason?: string }>) | null = null;
	const intercept = new InterceptEngine({
		store,
		judge: piConfig.active ? createPiLlmJudge(piConfig) : undefined,
		ask: async (req) => {
			if (askHandler) return await askHandler(req);
			if (flags["auto-approve"]) return { approved: true, decidedBy: "headless_auto_approve", reason: "Explicit --auto-approve flag" };
			return { approved: false, decidedBy: "non_interactive", reason: "No interactive operator attached" };
		},
	});
	intercept.seedBuiltinRules();

	const pool = new LlmPool(
		piConfig.active
			? [{ id: `${piConfig.active.provider}/${piConfig.active.model.id}`, model: piConfig.active.model, apiKey: piConfig.active.apiKey }]
			: [],
		store,
	);

	let tuiApp: ReturnType<typeof startTenguTui> | null = null;
	const orchestrator = new TenguOrchestrator({
		store,
		intercept,
		pool,
		streamFn: piConfig.streamFn,
		workspaceDir: join(tenguHome, "workspace"),
		logFilePath: join(tenguHome, "tengu.log"),
		onEvent: (ev) => {
			if (tuiApp) tuiApp.pushEvent(ev);
			if ((positional[0] === "task" && positional[1] === "run") || flags.p || flags.print) {
				console.error(`[${ev.timestamp}] [${ev.type}] ${ev.message}`);
			}
		},
	});

	const [cmd, sub, ...rest] = positional;

	const printPrompt = typeof flags.p === "string" ? flags.p : typeof flags.print === "string" ? flags.print : null;
	if (printPrompt) {
		try {
			const targetRaw = typeof flags.target === "string" ? flags.target.trim() : "";
			const scopeRaw = typeof flags.scope === "string" ? flags.scope : targetRaw;
			const taskName = typeof flags.name === "string" ? flags.name : (targetRaw ? `Headless Pentest (${targetRaw})` : printPrompt.slice(0, 60));
			const maxWorkers = typeof flags["max-workers"] === "string" ? Number(flags["max-workers"]) : 3;
			const maxRounds = typeof flags.rounds === "string" ? Number(flags.rounds) : 5;
			const task = store.createTask({ name: taskName, description: printPrompt, maxWorkers });

			// Seed strict scope rules from --scope / --target
			for (const item of scopeRaw.split(",").map((x) => x.trim()).filter(Boolean)) {
				const kind = /^https?:\/\//i.test(item)
					? "url"
					: /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(item)
						? "cidr"
						: /^\d+\.\d+\.\d+\.\d+$/.test(item)
							? "ip"
							: "domain";
				store.addTaskScope({ taskId: task.id, pattern: item, kind, exclude: false, note: "headless -p scope" });
			}
			if (targetRaw) {
				const assetKind: AssetKind = /^https?:\/\//i.test(targetRaw) ? "site" : /^\d+\.\d+\.\d+\.\d+$/.test(targetRaw) ? "ip" : "domain";
				store.upsertAssets([{ taskId: task.id, kind: assetKind, value: targetRaw, label: targetRaw, source: "headless_cli" }]);
			}
			store.addExplorationNode({
				taskId: task.id,
				kind: "goal",
				state: "pending",
				summary: printPrompt,
			});

			if (flags.bg) {
				const started = startBackgroundTask({
					tenguHome,
					dbPath,
					taskId: task.id,
					maxRounds,
					provider: typeof flags.provider === "string" ? flags.provider : undefined,
					model: typeof flags.model === "string" ? flags.model : undefined,
				});
				console.log(JSON.stringify({ mode: "background", taskId: task.id, dbPath, logFile: join(tenguHome, "tengu.log"), ...started }, null, 2));
				return;
			}

			const statusFile = join(tenguHome, "runs", `run-${task.id}.status.json`);
			const startedAt = Date.now();
			const stopHandler = () => {
				console.error(`[tengu -p] Signal received, stopping task #${task.id}...`);
				orchestrator.stopTask(task.id);
			};
			process.on("SIGINT", stopHandler);
			process.on("SIGTERM", stopHandler);

			const pollTimer = setInterval(() => {
				const snap = orchestrator.getLiveStatus(task.id) ?? readLiveStatusSnapshot(statusFile);
				const ov = store.getGraphOverview(task.id);
				const cov = store.getAssetCoverage(task.id);
				const usage = store.getTaskUsageBreakdown(task.id);
				const elapsedSec = Math.round((Date.now() - startedAt) / 1000);
				const activeAgents = snap?.agents.map((a) => `${a.role}:${a.phase}${a.currentTool ? `(${a.currentTool})` : ""}`).join(",") || "idle";
				console.error(
					`[telemetry ${elapsedSec}s] round=${snap?.round ?? 0}/${maxRounds} status=${snap?.status ?? "init"} agents=[${activeAgents}] tokens=${usage.totalTokens} liveTok=${snap?.totalTokensGenerated ?? 0} (${snap?.tokensPerSec ?? 0}t/s) assets=${cov.total} findings=${ov.findings.length}`,
				);
			}, 2500);
			pollTimer.unref?.();

			try {
				await orchestrator.runTask(task.id, { maxRounds });
			} finally {
				clearInterval(pollTimer);
				process.off("SIGINT", stopHandler);
				process.off("SIGTERM", stopHandler);
			}

			const durationMs = Date.now() - startedAt;
			const overview = store.getGraphOverview(task.id);
			const usage = store.getTaskUsageBreakdown(task.id);
			const approvals = store.listApprovalRequests({ taskId: task.id });
			const traces = store.listWorkerTraces({ taskId: task.id, limit: 500 });
			const reports = new ReportGenerator(store);
			const markdown = reports.generate(task.id, "markdown");

			const summary = {
				taskId: task.id,
				name: task.name,
				status: store.getTask(task.id)?.status ?? "unknown",
				durationMs,
				model: piConfig.active ? `${piConfig.active.provider}/${piConfig.active.model.id}` : null,
				usage,
				assets: store.listAssets({ taskId: task.id }),
				assetCoverage: store.getAssetCoverage(task.id),
				findings: overview.findings,
				approvals,
				traceCount: traces.length,
				toolErrors: traces.filter((t) => t.isError).length,
			};

			if (typeof flags.out === "string") {
				mkdirSync(flags.out, { recursive: true });
				writeFileSync(join(flags.out, "report.md"), markdown, "utf8");
				writeFileSync(join(flags.out, "report.json"), reports.generate(task.id, "json"), "utf8");
				writeFileSync(join(flags.out, "report.sarif"), reports.generate(task.id, "sarif"), "utf8");
				writeFileSync(join(flags.out, "report.html"), reports.generate(task.id, "html"), "utf8");
				writeFileSync(join(flags.out, "report.docx"), reports.generateDocx(task.id));
				writeFileSync(join(flags.out, "summary.json"), JSON.stringify(summary, null, 2), "utf8");
			}

			if (flags.json) {
				console.log(JSON.stringify(summary, null, 2));
			} else {
				console.log(markdown);
			}
		} finally {
			store.close();
		}
		return;
	}

	if (!cmd || cmd === "tui") {
		tuiApp = startTenguTui({
			onRegisterAskHandler: (fn) => {
				askHandler = fn;
			},
			store,
			intercept,
			piConfig,
			orchestrator,
			tenguHome,
			dbPath,
			initialTaskId: typeof flags.task === "string" ? Number(flags.task) : undefined,
			resumeSessionId: typeof flags.resume === "string" ? flags.resume : flags.resume === true ? true : undefined,
		});
		return;
	}

	if (cmd === "rpc") {
		startJsonRpcServer(store, orchestrator);
		return;
	}

	try {
		switch (cmd) {
			case "model": {
				console.log(
					JSON.stringify(
						{
							piAgentDir: piConfig.agentDir,
							active: piConfig.active
								? {
										provider: piConfig.active.provider,
										id: piConfig.active.model.id,
										name: piConfig.active.model.name,
										api: piConfig.active.model.api,
										baseUrl: piConfig.active.model.baseUrl,
										contextWindow: piConfig.active.model.contextWindow,
										hasApiKey: Boolean(piConfig.active.apiKey),
									}
								: null,
							available: piConfig.available.map((e) => ({
								provider: e.provider,
								id: e.model.id,
								name: e.model.name,
								isDefault: e.isDefault,
							})),
						},
						null,
						2,
					),
				);
				break;
			}
			case "task": {
				if (sub === "create") {
					const name = rest.join(" ") || "Pentest Task";
					const t = store.createTask({
						name,
						description: typeof flags.desc === "string" ? flags.desc : "",
					});
					console.log(JSON.stringify(t, null, 2));
				} else if (sub === "list") {
					console.log(JSON.stringify(store.listTasks(), null, 2));
				} else if (sub === "overview") {
					console.log(JSON.stringify(store.getGraphOverview(Number(rest[0])), null, 2));
				} else if (sub === "start") {
					const taskId = Number(rest[0]);
					const maxRounds = typeof flags.rounds === "string" ? Number(flags.rounds) : undefined;
					const started = startBackgroundTask({
						tenguHome,
						dbPath,
						taskId,
						maxRounds,
						provider: typeof flags.provider === "string" ? flags.provider : undefined,
						model: typeof flags.model === "string" ? flags.model : undefined,
					});
					console.log(JSON.stringify({ started: true, taskId, ...started }, null, 2));
				} else if (sub === "status") {
					const taskId = Number(rest[0]);
					const bg = getBackgroundTaskStatus(tenguHome, taskId);
					console.log(JSON.stringify({ task: store.getTask(taskId), daemon: bg }, null, 2));
				} else if (sub === "pause") {
					const taskId = Number(rest[0]);
					console.log(JSON.stringify({ taskId, signaled: signalBackgroundPauseToggle(tenguHome, taskId) }));
				} else if (sub === "stop") {
					const taskId = Number(rest[0]);
					console.log(JSON.stringify({ taskId, stopped: stopBackgroundTask(tenguHome, taskId) }));
				} else if (sub === "run") {
					const taskId = Number(rest[0]);
					const maxRounds = typeof flags.rounds === "string" ? Number(flags.rounds) : undefined;
					process.on("SIGUSR1", () => {
						if (orchestrator.isPaused(taskId)) orchestrator.resumeTask(taskId);
						else orchestrator.pauseTask(taskId);
					});
					const handleStop = () => {
						orchestrator.stopTask(taskId);
					};
					process.on("SIGTERM", handleStop);
					process.on("SIGINT", handleStop);
					const result = await orchestrator.runTask(taskId, { maxRounds });
					console.log(JSON.stringify(result, null, 2));
				} else {
					printHelp();
				}
				break;
			}
			case "scope": {
				if (sub === "add") {
					const rule = store.addTaskScope({
						taskId: Number(rest[0]),
						pattern: String(rest[1] ?? ""),
						kind: (typeof flags.kind === "string" ? flags.kind : "domain") as "domain" | "cidr" | "ip" | "url" | "regex",
						exclude: Boolean(flags.exclude),
						note: typeof flags.note === "string" ? flags.note : "",
					});
					console.log(JSON.stringify(rule, null, 2));
				} else {
					console.log(JSON.stringify(store.listTaskScope(Number(rest[0])), null, 2));
				}
				break;
			}
			case "assets": {
				if (sub === "add") {
					const inserted = store.upsertAssets([
						{
							taskId: Number(rest[0]),
							kind: String(rest[1]) as AssetKind,
							value: String(rest[2]),
							source: "cli",
						},
					]);
					console.log(JSON.stringify(inserted, null, 2));
				} else if (sub === "coverage") {
					console.log(JSON.stringify(store.getAssetCoverage(Number(rest[0])), null, 2));
				} else {
					const assets = store.listAssets({
						taskId: typeof flags.task === "string" ? Number(flags.task) : undefined,
						query: typeof flags.query === "string" ? flags.query : undefined,
					});
					console.log(JSON.stringify(assets, null, 2));
				}
				break;
			}
			case "findings": {
				const taskId = typeof flags.task === "string" ? Number(flags.task) : undefined;
				console.log(JSON.stringify(store.listFindings(taskId), null, 2));
				break;
			}
			case "intercept": {
				if (sub === "approvals") {
					const taskId = typeof flags.task === "string" ? Number(flags.task) : undefined;
					console.log(JSON.stringify(store.listApprovalRequests({ taskId }), null, 2));
				} else {
					console.log(JSON.stringify(store.listInterceptRules(), null, 2));
				}
				break;
			}
			case "report": {
				const gen = new ReportGenerator(store);
				const fmt = (typeof flags.format === "string" ? flags.format : "markdown") as ReportFormat;
				if (sub === "finding") {
					const findingId = Number(rest[0]);
					if (fmt === "docx") {
						const buf = gen.generateFindingDocx(findingId, true);
						const out = typeof flags.out === "string" ? flags.out : `finding-${findingId}.docx`;
						writeFileSync(out, buf);
						console.log(`Wrote DOCX finding report (${buf.byteLength} bytes) to ${out}`);
					} else {
						const content = gen.generateFinding(findingId, fmt, true);
						if (typeof flags.out === "string") {
							writeFileSync(flags.out, content, "utf8");
							console.log(`Wrote ${fmt} finding report to ${flags.out}`);
						} else console.log(content);
					}
				} else {
					const taskId = Number(sub);
					if (fmt === "docx") {
						const buf = gen.generateDocx(taskId, true);
						const out = typeof flags.out === "string" ? flags.out : `task-${taskId}.docx`;
						writeFileSync(out, buf);
						console.log(`Wrote DOCX report (${buf.byteLength} bytes) to ${out}`);
					} else {
						const content = gen.generate(taskId, fmt, true);
						if (typeof flags.out === "string") {
							writeFileSync(flags.out, content, "utf8");
							console.log(`Wrote ${fmt} report to ${flags.out}`);
						} else console.log(content);
					}
				}
				break;
			}
			case "archive": {
				if (sub === "export") {
					const bundle = exportTaskArchive(store, Number(rest[0]));
					const json = JSON.stringify(bundle, null, 2);
					if (typeof flags.out === "string") {
						writeFileSync(flags.out, json, "utf8");
						console.log(`Exported archive to ${flags.out}`);
					} else console.log(json);
				} else if (sub === "validate") {
					const raw = readFileSync(String(rest[0]), "utf8");
					console.log(JSON.stringify(validateTaskArchive(raw), null, 2));
				} else if (sub === "restore") {
					const raw = readFileSync(String(rest[0]), "utf8");
					const res = restoreTaskArchive(store, join(tenguHome, "workspace", "evidence"), raw);
					console.log(JSON.stringify(res, null, 2));
				} else printHelp();
				break;
			}
			case "usage": {
				console.log(JSON.stringify(store.getTaskUsageBreakdown(Number(sub)), null, 2));
				break;
			}
			case "sync": {
				if (sub === "scopesentry") {
					const client = new ScopeSentrySyncClient(store, {
						baseUrl: String(flags.url ?? ""),
						apiKey: String(flags.key ?? ""),
					});
					const res = await client.syncProjectAssets({
						projectId: String(flags.project ?? ""),
						taskId: typeof flags.task === "string" ? Number(flags.task) : null,
					});
					console.log(JSON.stringify(res, null, 2));
				} else {
					printHelp();
				}
				break;
			}
			case "logs": {
				const logPath = join(tenguHome, "tengu.log");
				if (!existsSync(logPath)) {
					console.log(`No log file yet at ${logPath}`);
				} else {
					const n = typeof flags.lines === "string" ? Number(flags.lines) : 60;
					const lines = readFileSync(logPath, "utf8").trim().split("\n");
					console.log(lines.slice(-n).join("\n"));
				}
				break;
			}
			case "sessions": {
				console.log(JSON.stringify(new TenguSessionManager(tenguHome).listSessions(), null, 2));
				break;
			}
			case "skills": {
				console.log(JSON.stringify(loadSkills(), null, 2));
				break;
			}
			case "vuln": {
				const svc = new VulnIntelService(store);
				if (sub === "sync-kev") {
					const count = await svc.syncCisaKev();
					console.log(JSON.stringify({ source: "kev", synced: count }));
				} else if (sub === "sync-nvd") {
					const count = await svc.syncNvdRecent(rest.join(" "));
					console.log(JSON.stringify({ source: "nvd", synced: count }));
				} else if (sub === "sync-ghsa") {
					const count = await svc.syncGhsaAdvisories();
					console.log(JSON.stringify({ source: "ghsa", synced: count }));
				} else {
					console.log(JSON.stringify(svc.search(rest.join(" ")), null, 2));
				}
				break;
			}
			default:
				console.error(`Unknown command: ${cmd}`);
				printHelp();
				process.exitCode = 1;
		}
	} finally {
		store.close();
	}
}

main().catch((err) => {
	console.error(err instanceof Error ? err.message : String(err));
	process.exit(1);
});
