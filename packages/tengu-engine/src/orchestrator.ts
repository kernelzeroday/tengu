import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { Agent, type AgentTool, type BeforeToolCallContext, type StreamFn } from "@earendil-works/pi-agent-core";
import type { Api, Model } from "@earendil-works/pi-ai";
import type { InterceptEngine } from "@tengu/intercept";
import {
	EvidenceStore,
	JobManager,
	ListenerManager,
	maskSecrets,
	NotificationDispatcher,
	ScriptWorkspace,
	VulnIntelService,
} from "@tengu/ops";
import type { FindingRetest, SideQuestion, Task, TenguStore } from "@tengu/store";
import { compactAgentMessages } from "./compaction.ts";
import { detectRefusal, LlmPool } from "./llm-pool.ts";
import { type LiveAgentStatus, type LiveTaskStatusSnapshot, writeLiveStatusSnapshot } from "./live-status.ts";
import { buildPlannerPrompt, buildRetesterPrompt, buildWorkerPrompt } from "./prompts.ts";
import { type TenguToolContext, TenguToolSet } from "./tools.ts";

export interface TenguEngineEvent {
	type:
		| "task_started"
		| "task_paused"
		| "task_resumed"
		| "task_stopped"
		| "planner_round"
		| "worker_started"
		| "worker_finished"
		| "tool_call"
		| "intercept_blocked"
		| "finding_reported"
		| "task_completed"
		| "error";
	taskId: number;
	intentId?: number;
	message: string;
	data?: unknown;
	timestamp: string;
}

export interface TenguOrchestratorOptions {
	store: TenguStore;
	intercept: InterceptEngine;
	pool: LlmPool;
	streamFn: StreamFn;
	workspaceDir: string;
	logFilePath?: string;
	onEvent?: (event: TenguEngineEvent) => void;
}

interface TaskRunControl {
	paused: boolean;
	stopped: boolean;
	resumeResolvers: Array<() => void>;
	activePlanner: Agent | null;
	round: number;
	maxRounds: number;
	model: string;
	startedAt: string;
	startedMs: number;
	totalTokensGenerated: number;
	agents: Map<string, LiveAgentStatus>;
}

function extractTargetFromArgs(args: unknown): string | undefined {
	if (!args || typeof args !== "object") return undefined;
	const rec = args as Record<string, unknown>;
	for (const k of ["url", "login_url", "target"]) {
		if (typeof rec[k] === "string" && rec[k]) return rec[k] as string;
	}
	if (Array.isArray(rec.urls) && typeof rec.urls[0] === "string") {
		return rec.urls[0];
	}
	return undefined;
}

export class TenguOrchestrator {
	private readonly store: TenguStore;
	private readonly intercept: InterceptEngine;
	private readonly pool: LlmPool;
	private readonly streamFn: StreamFn;
	private readonly workspaceDir: string;
	public readonly logFilePath: string;
	private readonly onEvent?: (event: TenguEngineEvent) => void;

	public readonly evidence: EvidenceStore;
	public readonly listeners: ListenerManager;
	public readonly jobs: JobManager;
	public readonly vulnIntel: VulnIntelService;
	public readonly notifier: NotificationDispatcher;

	private readonly activeWorkers = new Map<number, Agent>();
	private readonly taskControls = new Map<number, TaskRunControl>();

	public getStatusFilePath(taskId: number): string {
		return join(dirname(this.workspaceDir), `run-${taskId}.status.json`);
	}

	public getLiveStatus(taskId: number): LiveTaskStatusSnapshot | null {
		const ctrl = this.taskControls.get(taskId);
		if (!ctrl) return null;
		const elapsedSec = Math.max(0.5, (Date.now() - ctrl.startedMs) / 1000);
		return {
			taskId,
			pid: process.pid,
			status: ctrl.stopped ? "stopped" : ctrl.paused ? "paused" : "running",
			model: ctrl.model,
			round: ctrl.round,
			maxRounds: ctrl.maxRounds,
			totalTokensGenerated: ctrl.totalTokensGenerated,
			tokensPerSec: Math.round((ctrl.totalTokensGenerated / elapsedSec) * 10) / 10,
			startedAt: ctrl.startedAt,
			updatedAt: new Date().toISOString(),
			agents: [...ctrl.agents.values()],
		};
	}

	private flushLiveStatus(taskId: number, finalStatus?: LiveTaskStatusSnapshot["status"]): void {
		const snap = this.getLiveStatus(taskId);
		if (!snap) return;
		if (finalStatus) snap.status = finalStatus;
		writeLiveStatusSnapshot(this.getStatusFilePath(taskId), snap);
	}

	constructor(options: TenguOrchestratorOptions) {
		this.store = options.store;
		this.intercept = options.intercept;
		this.pool = options.pool;
		this.streamFn = options.streamFn;
		this.workspaceDir = options.workspaceDir;
		this.logFilePath = options.logFilePath ?? join(dirname(this.workspaceDir), "tengu.log");
		this.onEvent = options.onEvent;

		this.evidence = new EvidenceStore(this.store, join(this.workspaceDir, "evidence"));
		this.listeners = new ListenerManager();
		this.jobs = new JobManager();
		this.vulnIntel = new VulnIntelService(this.store);
		this.notifier = new NotificationDispatcher(this.store);
	}

	private appendLogFile(line: string): void {
		try {
			mkdirSync(dirname(this.logFilePath), { recursive: true });
			appendFileSync(this.logFilePath, `${line}\n`, "utf8");
		} catch {
			// Best-effort file logging
		}
	}

	private emit(
		type: TenguEngineEvent["type"],
		taskId: number,
		message: string,
		extra?: { intentId?: number; data?: unknown },
	): void {
		const timestamp = new Date().toISOString();
		const intentTag = extra?.intentId != null ? ` intent=#${extra.intentId}` : "";
		this.appendLogFile(`${timestamp} [task=#${taskId}${intentTag}] [${type}] ${maskSecrets(message)}`);
		this.onEvent?.({
			type,
			taskId,
			intentId: extra?.intentId,
			message,
			data: extra?.data,
			timestamp,
		});
	}

	// ── Pause / Resume / Stop Controls ────────────────────────────────────

	isRunning(taskId: number): boolean {
		const ctrl = this.taskControls.get(taskId);
		return Boolean(ctrl && !ctrl.stopped);
	}

	isPaused(taskId: number): boolean {
		return Boolean(this.taskControls.get(taskId)?.paused);
	}

	pauseTask(taskId: number): boolean {
		const ctrl = this.taskControls.get(taskId);
		if (!ctrl || ctrl.stopped || ctrl.paused) return false;
		ctrl.paused = true;
		this.store.updateTaskStatus(taskId, "paused");
		this.flushLiveStatus(taskId, "paused");
		this.emit("task_paused", taskId, `Task #${taskId} paused (waiting between tool calls / rounds)`);
		return true;
	}

	resumeTask(taskId: number): boolean {
		const ctrl = this.taskControls.get(taskId);
		if (!ctrl || ctrl.stopped || !ctrl.paused) return false;
		ctrl.paused = false;
		this.store.updateTaskStatus(taskId, "running");
		const waiters = ctrl.resumeResolvers.splice(0, ctrl.resumeResolvers.length);
		for (const resolve of waiters) resolve();
		this.flushLiveStatus(taskId, "running");
		this.emit("task_resumed", taskId, `Task #${taskId} resumed`);
		return true;
	}

	stopTask(taskId: number): boolean {
		const ctrl = this.taskControls.get(taskId);
		if (!ctrl || ctrl.stopped) return false;
		ctrl.stopped = true;
		ctrl.paused = false;
		const waiters = ctrl.resumeResolvers.splice(0, ctrl.resumeResolvers.length);
		for (const resolve of waiters) resolve();
		ctrl.activePlanner?.abort();
		for (const [intentId, worker] of this.activeWorkers.entries()) {
			const node = this.store.getExplorationNode(intentId);
			if (node && node.taskId === taskId) {
				worker.abort();
				this.store.updateExplorationNode(intentId, { state: "stopped", blockedReason: "task stopped by operator" });
			}
		}
		this.store.updateTaskStatus(taskId, "stopped");
		this.flushLiveStatus(taskId, "stopped");
		this.emit("task_stopped", taskId, `Task #${taskId} stopped by operator`);
		return true;
	}

	private async waitIfPaused(taskId: number): Promise<boolean> {
		const ctrl = this.taskControls.get(taskId);
		if (!ctrl) return true;
		if (ctrl.stopped) return false;
		if (!ctrl.paused) return true;
		await new Promise<void>((resolve) => {
			ctrl.resumeResolvers.push(resolve);
		});
		return !ctrl.stopped;
	}

	private recordAgentUsage(taskId: number, intentId: number | null, role: string, model: Model<Api>, agent: Agent): void {
		let inputTokens = 0;
		let outputTokens = 0;
		let cacheReadTokens = 0;
		let costUsd = 0;
		for (const msg of agent.state.messages) {
			if (msg.role === "assistant" && "usage" in msg && msg.usage) {
				inputTokens += msg.usage.input ?? 0;
				outputTokens += msg.usage.output ?? 0;
				cacheReadTokens += msg.usage.cacheRead ?? 0;
				costUsd += msg.usage.cost?.total ?? 0;
			}
		}
		if (inputTokens > 0 || outputTokens > 0) {
			this.pool.recordUsage({
				taskId,
				intentId,
				role,
				model,
				inputTokens,
				outputTokens,
				cacheReadTokens,
				costUsd,
			});
		}
	}

	private createGuardedAgent(input: {
		taskId: number;
		intentId?: number | null;
		role: string;
		systemPrompt: string;
		tools: AgentTool<any>[];
		model: Model<Api>;
		apiKey?: string;
	}): Agent {
		let turn = 0;
		const agent = new Agent({
			streamFn: this.streamFn,
			transformContext: async (msgs) => compactAgentMessages(msgs),
			getApiKey: input.apiKey ? () => input.apiKey : undefined,
			toolExecution: "parallel",
			initialState: {
				systemPrompt: input.systemPrompt,
				model: input.model,
				tools: input.tools,
			},
			beforeToolCall: async (ctx: BeforeToolCallContext) => {
				const shouldContinue = await this.waitIfPaused(input.taskId);
				if (!shouldContinue) {
					return { block: true, reason: "Task stopped by operator", terminate: true };
				}
				const decision = await this.intercept.evaluate({
					taskId: input.taskId,
					intentId: input.intentId ?? null,
					toolName: ctx.toolCall.name,
					toolArgs: ctx.args,
					targetUrlOrHost: extractTargetFromArgs(ctx.args),
				});
				if (!decision.allowed) {
					this.emit("intercept_blocked", input.taskId, `Blocked ${ctx.toolCall.name}: ${decision.reason}`, {
						intentId: input.intentId ?? undefined,
						data: decision,
					});
					return { block: true, reason: decision.reason };
				}
				return undefined;
			},
			afterToolCall: async (ctx) => {
				turn++;
				const outText = ctx.result.content
					.map((c) => (c.type === "text" ? c.text : "[image]"))
					.join("\n")
					.slice(0, 16_000);
				this.emit(
					"tool_call",
					input.taskId,
					`${input.role} → ${ctx.toolCall.name}${ctx.isError ? " [ERR]" : ""}`,
					{ intentId: input.intentId ?? undefined },
				);
				if (input.intentId != null) {
					this.store.addWorkerTrace({
						taskId: input.taskId,
						intentId: input.intentId,
						workerId: input.role,
						turn,
						toolName: ctx.toolCall.name,
						toolArgs: maskSecrets(JSON.stringify(ctx.args ?? {})).slice(0, 4096),
						toolOutput: maskSecrets(outText),
						isError: ctx.isError,
						durationMs: 0,
					});
				}
				return undefined;
			},
		});
		const ctrl = this.taskControls.get(input.taskId);
		if (ctrl) {
			const agentStartedMs = Date.now();
			const status: LiveAgentStatus = {
				role: input.role,
				intentId: input.intentId ?? null,
				phase: "thinking",
				currentTool: "",
				toolStartedAt: null,
				tokensGenerated: 0,
				tokensPerSec: 0,
				lastSnippet: "",
				updatedAt: new Date().toISOString(),
			};
			ctrl.agents.set(input.role, status);
			let lastFlush = 0;
			agent.subscribe((ev) => {
				if (ev.type === "message_update") {
					const ae = ev.assistantMessageEvent;
					if (ae.type === "text_delta" || ae.type === "thinking_delta") {
						const estTok = Math.max(1, Math.ceil(ae.delta.length / 4));
						status.phase = ae.type === "thinking_delta" ? "thinking" : "streaming";
						status.tokensGenerated += estTok;
						ctrl.totalTokensGenerated += estTok;
						const elapsed = Math.max(0.25, (Date.now() - agentStartedMs) / 1000);
						status.tokensPerSec = Math.round((status.tokensGenerated / elapsed) * 10) / 10;
						if (ae.type === "text_delta") {
							status.lastSnippet = (status.lastSnippet + ae.delta).replace(/\s+/g, " ").slice(-80);
						}
						status.updatedAt = new Date().toISOString();
					}
				} else if (ev.type === "tool_execution_start") {
					status.phase = "tool";
					status.currentTool = ev.toolName;
					status.toolStartedAt = Date.now();
					status.updatedAt = new Date().toISOString();
				} else if (ev.type === "tool_execution_end") {
					status.phase = "thinking";
					status.currentTool = "";
					status.toolStartedAt = null;
					status.updatedAt = new Date().toISOString();
				} else if (ev.type === "agent_end") {
					ctrl.agents.delete(input.role);
				}
				const now = Date.now();
				if (now - lastFlush >= 350 || ev.type === "tool_execution_start" || ev.type === "agent_end") {
					lastFlush = now;
					this.flushLiveStatus(input.taskId);
				}
			});
			this.flushLiveStatus(input.taskId);
		}
		return agent;
	}

	createToolSet(
		taskId: number,
		intentId?: number | null,
		workerId?: string,
		extraCallbacks?: Partial<Pick<TenguToolContext, "onStartEngagement" | "onPauseEngagement" | "onResumeEngagement" | "onStopEngagement" | "onTaskChanged">>,
	): TenguToolSet {
		const runDir = join(this.workspaceDir, `task-${taskId}`);
		mkdirSync(runDir, { recursive: true });
		const scripts = new ScriptWorkspace(join(runDir, "scripts"));
		return new TenguToolSet({
			store: this.store,
			evidence: this.evidence,
			listeners: this.listeners,
			jobs: this.jobs,
			scripts,
			vulnIntel: this.vulnIntel,
			taskId,
			intentId,
			workerId,
			runDir,
			onKillWork: (id) => this.killWork(id),
			onSteerWork: (id, msg) => this.steerWork(id, msg),
			...extraCallbacks,
		});
	}

	killWork(intentId: number): boolean {
		const worker = this.activeWorkers.get(intentId);
		if (!worker) return false;
		worker.abort();
		this.store.updateExplorationNode(intentId, { state: "stopped", blockedReason: "killed by planner" });
		return true;
	}

	steerWork(intentId: number, message: string): boolean {
		const worker = this.activeWorkers.get(intentId);
		if (!worker) return false;
		worker.steer({
			role: "user",
			content: [{ type: "text", text: `[Planner Course Correction] ${message}` }],
			timestamp: Date.now(),
		});
		return true;
	}

	async runTask(taskId: number, options?: { maxRounds?: number }): Promise<Task> {
		const task = this.store.getTask(taskId);
		if (!task) throw new Error(`Task #${taskId} not found`);

		this.intercept.seedBuiltinRules();
		const maxRoundsInit = options?.maxRounds ?? Math.min(task.maxTurns, 12);
		const firstEp = this.pool.listEndpoints()[0];
		const ctrl: TaskRunControl = {
			paused: false,
			stopped: false,
			resumeResolvers: [],
			activePlanner: null,
			round: 0,
			maxRounds: maxRoundsInit,
			model: firstEp ? `${firstEp.model.provider}/${firstEp.model.id}` : "unknown",
			startedAt: new Date().toISOString(),
			startedMs: Date.now(),
			totalTokensGenerated: 0,
			agents: new Map(),
		};
		this.taskControls.set(taskId, ctrl);
		this.flushLiveStatus(taskId, "running");
		this.store.updateTaskStatus(taskId, "running");
		this.emit("task_started", taskId, `Started autonomous task #${taskId}: ${task.name}`);

		const maxRounds = options?.maxRounds ?? Math.min(task.maxTurns, 12);
		let idleRounds = 0;

		try {
			for (let round = 1; round <= maxRounds; round++) {
				if (!(await this.waitIfPaused(taskId))) break;

				const endpoint = this.pool.select();
				if (!endpoint) throw new Error("No LLM endpoint configured in LlmPool");

				ctrl.round = round;
				ctrl.model = `${endpoint.model.provider}/${endpoint.model.id}`;
				this.flushLiveStatus(taskId, "running");
				this.emit("planner_round", taskId, `Planner round ${round}/${maxRounds} using ${endpoint.model.id}`);
				const plannerTools = this.createToolSet(taskId, null, `planner-r${round}`);
				const planner = this.createGuardedAgent({
					taskId,
					role: `planner-r${round}`,
					systemPrompt: buildPlannerPrompt(task),
					tools: plannerTools.plannerTools(),
					model: endpoint.model,
					apiKey: endpoint.apiKey,
				});
				ctrl.activePlanner = planner;

				const cov = this.store.getAssetCoverage(taskId);
				const findingsNoEvidence = this.store.listFindings(taskId).filter((f) => f.evidenceIds.length === 0).length;
				const nudges: string[] = [];
				if (cov.untested > 0) nudges.push(`Coverage nudge: ${cov.untested}/${cov.total} assets are still untested.`);
				if (findingsNoEvidence > 0) nudges.push(`Depth nudge: ${findingsNoEvidence} finding(s) lack saved evidence artifacts.`);
				await planner.prompt(
					`Round ${round}/${maxRounds}: Inspect the dual graph with graph_overview, dispatch high-value intents if needed, or prove/complete goals.${nudges.length ? `\n${nudges.join(" ")}` : ""}`,
				);
				ctrl.activePlanner = null;
				this.recordAgentUsage(taskId, null, `planner-r${round}`, endpoint.model, planner);
				this.pool.markSuccess(endpoint.id);

				if (ctrl.stopped) break;

				if (plannerTools.goalMet) {
					this.store.updateTaskStatus(taskId, "completed");
					this.emit("task_completed", taskId, `Task completed: ${plannerTools.goalMetReason}`);
					await this.notifier.dispatch({
						type: "task_completed",
						severity: "info",
						title: `Tengu Task #${taskId} Completed`,
						body: plannerTools.goalMetReason,
						taskId,
					});
					return this.store.getTask(taskId)!;
				}

				if (!(await this.waitIfPaused(taskId))) break;

				const openIntents = this.store
					.listExplorationNodes({ taskId, kind: "intent", state: "open", limit: task.maxWorkers })
					.nodes.reverse();

				if (openIntents.length === 0) {
					idleRounds++;
					if (idleRounds >= 2) break;
					continue;
				}
				idleRounds = 0;

				await Promise.all(
					openIntents.slice(0, task.maxWorkers).map((intent) => this.runWorkerForIntent(task, intent.id, intent.summary)),
				);
				if (ctrl.stopped) break;
			}

			if (!ctrl.stopped) {
				this.store.updateTaskStatus(taskId, "completed");
				this.flushLiveStatus(taskId, "completed");
				this.emit("task_completed", taskId, `Task #${taskId} finished all scheduled rounds.`);
			}
			return this.store.getTask(taskId)!;
		} catch (err) {
			if (ctrl.stopped) {
				return this.store.getTask(taskId)!;
			}
			const msg = err instanceof Error ? err.message : String(err);
			this.store.updateTaskStatus(taskId, "failed");
			this.emit("error", taskId, msg);
			throw err;
		} finally {
			this.taskControls.delete(taskId);
			this.jobs.stopAll();
			await this.listeners.stopAll();
		}
	}

	private async runWorkerForIntent(task: Task, intentId: number, summary: string): Promise<void> {
		if (!(await this.waitIfPaused(task.id))) return;
		const endpoint = this.pool.select();
		if (!endpoint) throw new Error("No LLM endpoint available for worker");

		const workerId = `worker-${intentId}`;
		this.store.updateExplorationNode(intentId, { state: "running", workerId });
		this.emit("worker_started", task.id, `Worker ${workerId} claimed intent #${intentId}: ${summary}`, { intentId });

		const startMs = Date.now();
		const toolSet = this.createToolSet(task.id, intentId, workerId);
		const worker = this.createGuardedAgent({
			taskId: task.id,
			intentId,
			role: workerId,
			systemPrompt: buildWorkerPrompt(task, intentId, summary),
			tools: toolSet.workerTools(),
			model: endpoint.model,
			apiKey: endpoint.apiKey,
		});
		this.activeWorkers.set(intentId, worker);

		try {
			await worker.prompt(`Execute intent #${intentId}: ${summary}`);
			this.recordAgentUsage(task.id, intentId, workerId, endpoint.model, worker);
			const messages = worker.state.messages;
			const lastAssistant = [...messages].reverse().find((m) => m.role === "assistant");
			const finalText =
				lastAssistant && "content" in lastAssistant && Array.isArray(lastAssistant.content)
					? lastAssistant.content
							.filter((c): c is { type: "text"; text: string } => c.type === "text")
							.map((c) => c.text)
							.join("\n")
					: "";

			const refused = detectRefusal(finalText);
			const node = this.store.getExplorationNode(intentId);
			this.store.updateExplorationNode(intentId, {
				state: refused ? "blocked" : "exhausted",
				blockedReason: refused ? "model_refusal" : "",
				payload: {
					...(node?.payload ?? {}),
					finalOutput: finalText.slice(0, 16_000),
					wallMs: Date.now() - startMs,
				},
			});
			this.pool.markSuccess(endpoint.id);
			this.emit("worker_finished", task.id, `Worker ${workerId} finished intent #${intentId}`, { intentId });
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			this.pool.markFailure(endpoint.id, msg);
			this.store.updateExplorationNode(intentId, { state: "blocked", blockedReason: msg });
			this.emit("error", task.id, `Worker ${workerId} failed: ${msg}`, { intentId });
		} finally {
			this.activeWorkers.delete(intentId);
		}
	}

	async retestFinding(taskId: number, findingId: number): Promise<FindingRetest> {
		const task = this.store.getTask(taskId);
		const finding = this.store.getFinding(findingId);
		if (!task || !finding) throw new Error(`Task #${taskId} or Finding #${findingId} not found`);

		const endpoint = this.pool.select();
		if (!endpoint) throw new Error("No LLM endpoint available for retester");

		const toolSet = this.createToolSet(taskId, null, `retester-${findingId}`);
		const agent = this.createGuardedAgent({
			taskId,
			role: `retester-${findingId}`,
			systemPrompt: buildRetesterPrompt(task, finding.id, finding.title, finding.reproduction),
			tools: toolSet.retesterTools(),
			model: endpoint.model,
			apiKey: endpoint.apiKey,
		});
		await agent.prompt(`Verify finding #${finding.id} (${finding.title}) and report whether it is still_vulnerable, fixed, or inconclusive.`);
		this.recordAgentUsage(taskId, null, `retester-${findingId}`, endpoint.model, agent);
		const lastAssistant = [...agent.state.messages].reverse().find((m) => m.role === "assistant");
		const notes =
			lastAssistant && "content" in lastAssistant && Array.isArray(lastAssistant.content)
				? lastAssistant.content
						.filter((c): c is { type: "text"; text: string } => c.type === "text")
						.map((c) => c.text)
						.join("\n")
				: "";

		const lower = notes.toLowerCase();
		const status: FindingRetest["status"] = lower.includes("fixed")
			? "fixed"
			: lower.includes("still_vulnerable") || lower.includes("reproduced")
				? "still_vulnerable"
				: "inconclusive";

		if (status === "fixed") this.store.updateFindingStatus(finding.id, "fixed");
		else if (status === "still_vulnerable") this.store.updateFindingStatus(finding.id, "verified");

		return this.store.addFindingRetest({
			findingId: finding.id,
			taskId,
			status,
			notes: notes.slice(0, 8000),
			evidence: "",
		});
	}

	async askSideQuestion(taskId: number, question: string): Promise<SideQuestion> {
		const sq = this.store.addSideQuestion(taskId, question);
		const endpoint = this.pool.select();
		if (!endpoint) return sq;
		const overview = this.store.getGraphOverview(taskId);
		const agent = new Agent({
			streamFn: this.streamFn,
			getApiKey: endpoint.apiKey ? () => endpoint.apiKey : undefined,
			initialState: {
				systemPrompt: "You are a concise pentest analyst answering an operator's side-question based strictly on the task's dual graph state.",
				model: endpoint.model,
				tools: [],
			},
		});
		await agent.prompt(`Graph Overview:\n${JSON.stringify(overview, null, 2)}\n\nOperator Question: ${question}`);
		this.recordAgentUsage(taskId, null, "sidequestion", endpoint.model, agent);
		const lastAssistant = [...agent.state.messages].reverse().find((m) => m.role === "assistant");
		const answer =
			lastAssistant && "content" in lastAssistant && Array.isArray(lastAssistant.content)
				? lastAssistant.content
						.filter((c): c is { type: "text"; text: string } => c.type === "text")
						.map((c) => c.text)
						.join("\n")
				: "";
		return this.store.answerSideQuestion(sq.id, answer) ?? sq;
	}
}
