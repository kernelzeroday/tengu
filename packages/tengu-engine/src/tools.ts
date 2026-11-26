import type { InterceptEngine } from "@tengu/intercept";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import type { AgentTool, AgentToolResult } from "@earendil-works/pi-agent-core";
import {
	AssetEnricher,
	auditJavaScriptSource,
	diffHttpResponses,
	EvidenceStore,
	executeAuthRequest,
	executeHttpRequest,
	JobManager,
	ListenerManager,
	parseApiContract,
	performSessionLogin,
	probeHttpTargets,
	ReportGenerator,
	type ReportFormat,
	ScriptWorkspace,
	VulnIntelService,
} from "@tengu/ops";
import type { AssetKind, InterceptAction, InterceptClass, Severity, TenguStore } from "@tengu/store";
import { findSkill, formatSkillIndex, renderSkillPlaybook } from "./skills.ts";

export interface TenguToolContext {
	intercept?: InterceptEngine;
	store: TenguStore;
	evidence: EvidenceStore;
	listeners: ListenerManager;
	jobs: JobManager;
	scripts: ScriptWorkspace;
	vulnIntel: VulnIntelService;
	taskId: number;
	intentId?: number | null;
	workerId?: string;
	runDir: string;
	onGoalMet?: (reason: string) => void;
	onKillWork?: (intentId: number) => Promise<boolean> | boolean;
	onSteerWork?: (intentId: number, message: string) => Promise<boolean> | boolean;
	onStartEngagement?: (taskId: number, opts: { background?: boolean; maxRounds?: number }) => Promise<unknown> | unknown;
	onPauseEngagement?: (taskId: number) => boolean;
	onResumeEngagement?: (taskId: number) => boolean;
	onStopEngagement?: (taskId: number) => boolean;
	onTaskChanged?: (taskId: number) => void;
}

function ok(data: unknown): AgentToolResult {
	const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
	return { content: [{ type: "text", text }], details: data as never };
}

function fail(message: string): AgentToolResult {
	return { content: [{ type: "text", text: `Error: ${message}` }], details: { error: message }, isError: true };
}

function makeTool(
	name: string,
	label: string,
	description: string,
	mode: "parallel" | "sequential",
	properties: Record<string, unknown>,
	required: string[],
	handler: (params: Record<string, any>) => Promise<AgentToolResult> | AgentToolResult,
): AgentTool<any> {
	return {
		name,
		label,
		description,
		executionMode: mode,
		parameters: {
			type: "object",
			properties,
			required,
			additionalProperties: true,
		},
		execute: async (_toolCallId, params) => {
			try {
				return await handler((params ?? {}) as Record<string, any>);
			} catch (err) {
				return fail(err instanceof Error ? err.message : String(err));
			}
		},
	};
}

export class TenguToolSet {
	private readonly ctx: TenguToolContext;
	public goalMet = false;
	public goalMetReason = "";

	constructor(ctx: TenguToolContext) {
		this.ctx = ctx;
	}

	// ── Exploration Graph & Multi-Agent Tools (21) ────────────────────────

	private graphOverview(): AgentTool<any> {
		return makeTool(
			"graph_overview",
			"Graph Overview",
			"Get a compact strategic overview of the task's goals, constraints, intents (with lineage and token counts), recent facts, findings, hints, and asset coverage.",
			"parallel",
			{},
			[],
			() => ok(this.ctx.store.getGraphOverview(this.ctx.taskId)),
		);
	}

	private listFindings(): AgentTool<any> {
		return makeTool(
			"list_findings",
			"List Findings",
			"List confirmed vulnerabilities for the current task.",
			"parallel",
			{},
			[],
			() => ok({ findings: this.ctx.store.listFindings(this.ctx.taskId) }),
		);
	}

	private listFacts(): AgentTool<any> {
		return makeTool(
			"list_facts",
			"List Facts",
			"List recorded exploration facts with pagination and optional keyword filter.",
			"parallel",
			{
				limit: { type: "number", description: "Max items (default 20, max 100)" },
				before: { type: "number", description: "Cursor node ID for older pages" },
				q: { type: "string", description: "Substring filter on summary" },
			},
			[],
			(p) => {
				const res = this.ctx.store.listExplorationNodes({
					taskId: this.ctx.taskId,
					kind: "fact",
					limit: p.limit,
					before: p.before,
					q: p.q,
				});
				return ok({ facts: res.nodes, total: res.total, hasMore: res.hasMore, nextBefore: res.nextBefore });
			},
		);
	}

	private nodeDetail(): AgentTool<any> {
		return makeTool(
			"node_detail",
			"Node Detail",
			"Retrieve full payload and metadata of an exploration graph node by ID.",
			"parallel",
			{ id: { type: "number", description: "Exploration node ID" } },
			["id"],
			(p) => {
				const node = this.ctx.store.getExplorationNode(Number(p.id));
				return node ? ok(node) : fail(`Exploration node #${p.id} not found`);
			},
		);
	}

	private expandDigest(): AgentTool<any> {
		return makeTool(
			"expand_digest",
			"Expand Digest",
			"Expand a compact exploration node digest into full node detail plus connected edges.",
			"parallel",
			{ id: { type: "number", description: "Exploration node ID" } },
			["id"],
			(p) => {
				const node = this.ctx.store.getExplorationNode(Number(p.id));
				if (!node) return fail(`Node #${p.id} not found`);
				const edges = this.ctx.store
					.listExplorationEdges(this.ctx.taskId)
					.filter((e) => e.fromNodeId === node.id || e.toNodeId === node.id);
				return ok({ node, edges });
			},
		);
	}

	private addIntent(): AgentTool<any> {
		return makeTool(
			"add_intent",
			"Add Intent",
			"Create a new exploration intent (work directive) for a Worker agent to execute.",
			"sequential",
			{
				summary: { type: "string", description: "Clear, actionable pentest objective for the worker" },
				asset_ids: { type: "array", items: { type: "number" }, description: "Target asset IDs" },
				parent_ids: { type: "array", items: { type: "number" }, description: "Upstream node IDs this intent derives from" },
				priority: { type: "number", description: "Optional priority (1-100)" },
			},
			["summary"],
			(p) => {
				const assetIds = Array.isArray(p.asset_ids) ? p.asset_ids.map(Number) : [];
				const node = this.ctx.store.addExplorationNode({
					taskId: this.ctx.taskId,
					kind: "intent",
					state: "open",
					summary: String(p.summary),
					assetIds,
					payload: { summary: String(p.summary), asset_ids: assetIds, priority: p.priority ?? 50 },
				});
				if (Array.isArray(p.parent_ids)) {
					for (const pid of p.parent_ids) {
						this.ctx.store.addExplorationEdge(this.ctx.taskId, Number(pid), node.id, "derives");
					}
				}
				return ok({ intent_id: node.id, state: node.state, summary: node.summary });
			},
		);
	}

	private retireIntent(): AgentTool<any> {
		return makeTool(
			"retire_intent",
			"Retire Intent",
			"Retire an open or stale intent so no worker claims it.",
			"sequential",
			{
				intent_id: { type: "number", description: "Intent node ID" },
				reason: { type: "string", description: "Why this intent is being retired" },
			},
			["intent_id"],
			(p) => {
				const updated = this.ctx.store.updateExplorationNode(Number(p.intent_id), {
					state: "retired",
					blockedReason: String(p.reason ?? "retired by planner"),
				});
				return updated ? ok({ intent_id: updated.id, state: updated.state }) : fail(`Intent #${p.intent_id} not found`);
			},
		);
	}

	private listGoals(): AgentTool<any> {
		return makeTool(
			"list_goals",
			"List Goals",
			"List all task goal nodes and their status (open/met).",
			"parallel",
			{},
			[],
			() => ok({ goals: this.ctx.store.listExplorationNodes({ taskId: this.ctx.taskId, kind: "goal", limit: 50 }).nodes }),
		);
	}

	private setGoals(): AgentTool<any> {
		return makeTool(
			"set_goals",
			"Set Goals",
			"Define or append engagement goals for the current task.",
			"sequential",
			{ goals: { type: "array", items: { type: "string" }, description: "List of goal statements" } },
			["goals"],
			(p) => {
				const created = (Array.isArray(p.goals) ? p.goals : []).map((g: unknown) =>
					this.ctx.store.addExplorationNode({
						taskId: this.ctx.taskId,
						kind: "goal",
						state: "open",
						summary: String(g),
					}),
				);
				return ok({ created });
			},
		);
	}

	private proveGoal(): AgentTool<any> {
		return makeTool(
			"prove_goal",
			"Prove Goal",
			"Mark a specific goal as met and link it to proving fact/finding node IDs.",
			"sequential",
			{
				goal_id: { type: "number", description: "Goal node ID" },
				evidence_node_ids: { type: "array", items: { type: "number" }, description: "Supporting fact/finding node IDs" },
				note: { type: "string", description: "Justification summary" },
			},
			["goal_id"],
			(p) => {
				const goal = this.ctx.store.updateExplorationNode(Number(p.goal_id), {
					state: "met",
					payload: { note: String(p.note ?? "") },
				});
				if (!goal) return fail(`Goal #${p.goal_id} not found`);
				if (Array.isArray(p.evidence_node_ids)) {
					for (const eid of p.evidence_node_ids) {
						this.ctx.store.addExplorationEdge(this.ctx.taskId, Number(eid), goal.id, "proves");
					}
				}
				return ok({ goal_id: goal.id, state: goal.state });
			},
		);
	}

	private goalMetTool(): AgentTool<any> {
		return makeTool(
			"goal_met",
			"Goal Met",
			"Signal that ALL task goals are completely achieved and conclude the engagement.",
			"sequential",
			{ reason: { type: "string", description: "Overall completion summary" } },
			["reason"],
			(p) => {
				this.goalMet = true;
				this.goalMetReason = String(p.reason ?? "All goals met");
				this.ctx.onGoalMet?.(this.goalMetReason);
				return ok({ goal_met: true, reason: this.goalMetReason });
			},
		);
	}

	private setConstraints(): AgentTool<any> {
		return makeTool(
			"set_constraints",
			"Set Constraints",
			"Set operational constraints/rules of engagement for this task.",
			"sequential",
			{ constraints: { type: "array", items: { type: "string" }, description: "Constraint statements" } },
			["constraints"],
			(p) => {
				const list = this.ctx.store.setTaskConstraints(
					this.ctx.taskId,
					Array.isArray(p.constraints) ? p.constraints.map(String) : [],
				);
				return ok({ constraints: list });
			},
		);
	}

	private addHint(): AgentTool<any> {
		return makeTool(
			"add_hint",
			"Add Hint",
			"Add a strategic operator/planner hint to the exploration graph.",
			"sequential",
			{ text: { type: "string", description: "Hint text" } },
			["text"],
			(p) => {
				const node = this.ctx.store.addExplorationNode({
					taskId: this.ctx.taskId,
					kind: "hint",
					state: "open",
					summary: String(p.text),
				});
				return ok({ hint_id: node.id, summary: node.summary });
			},
		);
	}

	private recordFact(): AgentTool<any> {
		return makeTool(
			"record_fact",
			"Record Fact",
			"Record a verified technical discovery or observation into the exploration graph.",
			"sequential",
			{
				summary: { type: "string", description: "Concise fact summary" },
				detail: { type: "string", description: "Full technical detail and evidence" },
				asset_ids: { type: "array", items: { type: "number" }, description: "Anchored asset IDs" },
			},
			["summary"],
			(p) => {
				const assetIds = Array.isArray(p.asset_ids) ? p.asset_ids.map(Number) : [];
				const missingAssets = assetIds.filter((id: number) => !this.ctx.store.getAsset(id));
				const validAssets = assetIds.filter((id: number) => !missingAssets.includes(id));

				const node = this.ctx.store.addExplorationNode({
					taskId: this.ctx.taskId,
					kind: "fact",
					state: "done",
					summary: String(p.summary),
					assetIds: validAssets,
					workerId: this.ctx.workerId ?? "",
					payload: { detail: String(p.detail ?? "") },
				});
				if (this.ctx.intentId) {
					this.ctx.store.addExplorationEdge(this.ctx.taskId, this.ctx.intentId, node.id, "yields");
				}
				if (validAssets.length > 0) {
					this.ctx.store.markAssetsTested(validAssets, this.ctx.intentId ?? null);
				}
				return ok({ fact_id: node.id, asset_ids: validAssets, missing_assets: missingAssets });
			},
		);
	}

	private reportFinding(): AgentTool<any> {
		return makeTool(
			"report_finding",
			"Report Finding",
			"Record a confirmed security vulnerability with severity, reproduction steps, and verifiable evidence.",
			"sequential",
			{
				title: { type: "string", description: "Vulnerability title" },
				vuln_class: { type: "string", description: "Vulnerability class (e.g., sqli, xss, idor, ssrf, rce)" },
				severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
				summary: { type: "string", description: "Concise impact summary" },
				description: { type: "string", description: "Detailed technical description" },
				reproduction: { type: "string", description: "Deterministic reproduction steps / PoC" },
				remediation: { type: "string", description: "Recommended fix" },
				evidence: { type: "string", description: "Raw command/HTTP evidence proving the issue" },
				evidence_ids: { type: "array", items: { type: "number" }, description: "Saved artifact IDs" },
				asset_ids: { type: "array", items: { type: "number" }, description: "Affected asset IDs" },
				cwe: { type: "string", description: "CWE identifier (e.g. CWE-89)" },
				cvss: { type: "number", description: "CVSS 3.1 score (0-10)" },
			},
			["title", "severity", "summary", "evidence"],
			(p) => {
				const assetIds = Array.isArray(p.asset_ids) ? p.asset_ids.map(Number) : [];
				const evidenceIds = Array.isArray(p.evidence_ids) ? p.evidence_ids.map(Number) : [];
				const vulnClass = String(p.vuln_class ?? "other").toLowerCase();
				const fingerprint = createHash("sha256")
					.update(`${vulnClass}|${String(p.title).toLowerCase().trim()}|${assetIds.sort().join(",")}`)
					.digest("hex")
					.slice(0, 24);
				const duplicate = this.ctx.store.findByFingerprint(fingerprint);

				const node = this.ctx.store.addExplorationNode({
					taskId: this.ctx.taskId,
					kind: "finding",
					state: "open",
					summary: `[${String(p.severity).toUpperCase()}] ${String(p.title)}`,
					assetIds,
					workerId: this.ctx.workerId ?? "",
					payload: { vuln_class: vulnClass, severity: p.severity, summary: p.summary },
				});
				if (this.ctx.intentId) {
					this.ctx.store.addExplorationEdge(this.ctx.taskId, this.ctx.intentId, node.id, "yields");
				}
				const finding = this.ctx.store.addFinding({
					taskId: this.ctx.taskId,
					nodeId: node.id,
					intentId: this.ctx.intentId ?? null,
					title: String(p.title),
					vulnClass,
					severity: String(p.severity) as Severity,
					status: "open",
					summary: String(p.summary),
					description: String(p.description ?? ""),
					reproduction: String(p.reproduction ?? ""),
					remediation: String(p.remediation ?? ""),
					evidence: String(p.evidence),
					evidenceIds,
					assetIds,
					cvss: p.cvss != null ? Number(p.cvss) : null,
					cwe: String(p.cwe ?? ""),
					fingerprint,
				});
				if (assetIds.length > 0) {
					this.ctx.store.markAssetsTested(assetIds, this.ctx.intentId ?? null);
				}
				return ok({
					finding_id: finding.id,
					finding_node_id: node.id,
					duplicate_of: duplicate ? duplicate.id : null,
				});
			},
		);
	}

	private killWork(): AgentTool<any> {
		return makeTool(
			"kill_work",
			"Kill Work",
			"Abort a currently running worker executing the given intent ID.",
			"sequential",
			{ intent_id: { type: "number", description: "Running intent ID to terminate" } },
			["intent_id"],
			async (p) => {
				if (!this.ctx.onKillWork) return fail("kill_work callback unavailable in current context");
				const killed = await this.ctx.onKillWork(Number(p.intent_id));
				return ok({ intent_id: Number(p.intent_id), killed });
			},
		);
	}

	private steerWork(): AgentTool<any> {
		return makeTool(
			"steer_work",
			"Steer Work",
			"Inject a mid-run course-correction message into a running worker without killing it.",
			"sequential",
			{
				intent_id: { type: "number", description: "Running intent ID" },
				message: { type: "string", description: "Steering instruction for the worker" },
			},
			["intent_id", "message"],
			async (p) => {
				if (!this.ctx.onSteerWork) return fail("steer_work callback unavailable in current context");
				const steered = await this.ctx.onSteerWork(Number(p.intent_id), String(p.message));
				return ok({ intent_id: Number(p.intent_id), steered });
			},
		);
	}

	private getWorkerOutput(): AgentTool<any> {
		return makeTool(
			"get_worker_output",
			"Get Worker Output",
			"Retrieve the final summary output recorded for a completed/stopped intent.",
			"parallel",
			{ intent_id: { type: "number", description: "Intent ID" } },
			["intent_id"],
			(p) => {
				const node = this.ctx.store.getExplorationNode(Number(p.intent_id));
				if (!node) return fail(`Intent #${p.intent_id} not found`);
				return ok({
					intent_id: node.id,
					state: node.state,
					blocked_reason: node.blockedReason,
					output: node.payload.finalOutput ?? "",
				});
			},
		);
	}

	private getWorkerTrace(): AgentTool<any> {
		return makeTool(
			"get_worker_trace",
			"Get Worker Trace",
			"Retrieve tool call trace entries for a specific intent.",
			"parallel",
			{
				intent_id: { type: "number", description: "Intent ID" },
				limit: { type: "number", description: "Max entries (default 50)" },
			},
			["intent_id"],
			(p) =>
				ok({
					traces: this.ctx.store.listWorkerTraces({
						taskId: this.ctx.taskId,
						intentId: Number(p.intent_id),
						limit: p.limit ?? 50,
					}),
				}),
		);
	}

	private listWorkerTraces(): AgentTool<any> {
		return makeTool(
			"list_worker_traces",
			"List Worker Traces",
			"List recent tool call traces across the current task.",
			"parallel",
			{ limit: { type: "number", description: "Max entries (default 50)" } },
			[],
			(p) => ok({ traces: this.ctx.store.listWorkerTraces({ taskId: this.ctx.taskId, limit: p.limit ?? 50 }) }),
		);
	}

	private searchAllWorkerTraces(): AgentTool<any> {
		return makeTool(
			"search_all_worker_traces",
			"Search Worker Traces",
			"Search across all worker tool call arguments and outputs in the current task.",
			"parallel",
			{
				q: { type: "string", description: "Search substring" },
				limit: { type: "number", description: "Max entries (default 30)" },
			},
			["q"],
			(p) => ok({ traces: this.ctx.store.searchWorkerTraces(this.ctx.taskId, String(p.q), p.limit ?? 30) }),
		);
	}

	// ── Asset Graph & Scope Tools (6) ─────────────────────────────────────

	private insertAssets(): AgentTool<any> {
		return makeTool(
			"insert_assets",
			"Insert Assets",
			"Insert or update discovered assets (domain, subdomain, ip, cidr, port, service, site, endpoint, parameter, repo, cloud, credential) into the Asset Graph.",
			"sequential",
			{
				assets: {
					type: "array",
					items: {
						type: "object",
						properties: {
							kind: { type: "string" },
							value: { type: "string" },
							label: { type: "string" },
							metadata: { type: "object" },
						},
						required: ["kind", "value"],
					},
				},
			},
			["assets"],
			(p) => {
				const task = this.ctx.store.getTask(this.ctx.taskId);
				const items = (Array.isArray(p.assets) ? p.assets : []).map((a: Record<string, unknown>) => ({
					companyId: task?.companyId ?? null,
					taskId: this.ctx.taskId,
					kind: String(a.kind) as AssetKind,
					value: String(a.value),
					label: a.label ? String(a.label) : "",
					metadata: (a.metadata as Record<string, unknown>) ?? {},
					source: this.ctx.workerId || "agent",
				}));
				const inserted = this.ctx.store.upsertAssets(items);
				new AssetEnricher(this.ctx.store).enrichInBackground(inserted);
				return ok({ count: inserted.length, assets: inserted });
			},
		);
	}

	private listAssets(): AgentTool<any> {
		return makeTool(
			"list_assets",
			"List Assets",
			"List assets in the Asset Graph with optional Asset DSL query (e.g., 'kind:endpoint tested:false value~admin').",
			"parallel",
			{
				query: { type: "string", description: "Asset DSL filter" },
				kind: { type: "string", description: "Asset kind filter" },
				limit: { type: "number", description: "Max results (default 100)" },
			},
			[],
			(p) =>
				ok({
					assets: this.ctx.store.listAssets({
						taskId: this.ctx.taskId,
						kind: p.kind as AssetKind | undefined,
						query: p.query,
						limit: p.limit ?? 100,
					}),
				}),
		);
	}

	private listUntestedAssets(): AgentTool<any> {
		return makeTool(
			"list_untested_assets",
			"List Untested Assets",
			"List assets in this task that have not yet been tested by any worker.",
			"parallel",
			{ limit: { type: "number", description: "Max results (default 50)" } },
			[],
			(p) =>
				ok({
					assets: this.ctx.store.listAssets({
						taskId: this.ctx.taskId,
						tested: false,
						limit: p.limit ?? 50,
					}),
				}),
		);
	}

	private listCompanies(): AgentTool<any> {
		return makeTool(
			"list_companies",
			"List Companies",
			"List all registered companies/organizations.",
			"parallel",
			{},
			[],
			() => ok({ companies: this.ctx.store.listCompanies() }),
		);
	}

	private addCompanyScope(): AgentTool<any> {
		return makeTool(
			"add_company_scope",
			"Add Company Scope",
			"Add an authorized scope rule (or exclusion) to a company.",
			"sequential",
			{
				company_id: { type: "number" },
				pattern: { type: "string" },
				kind: { type: "string", enum: ["domain", "cidr", "ip", "url", "regex"] },
				exclude: { type: "boolean" },
				note: { type: "string" },
			},
			["company_id", "pattern", "kind"],
			(p) =>
				ok(
					this.ctx.store.addCompanyScope({
						companyId: Number(p.company_id),
						pattern: String(p.pattern),
						kind: p.kind,
						exclude: Boolean(p.exclude),
						note: String(p.note ?? ""),
					}),
				),
		);
	}

	private addTaskScope(): AgentTool<any> {
		return makeTool(
			"add_task_scope",
			"Add Task Scope",
			"Add a scope rule (or exclusion) to the current task.",
			"sequential",
			{
				pattern: { type: "string" },
				kind: { type: "string", enum: ["domain", "cidr", "ip", "url", "regex"] },
				exclude: { type: "boolean" },
				note: { type: "string" },
			},
			["pattern", "kind"],
			(p) =>
				ok(
					this.ctx.store.addTaskScope({
						taskId: this.ctx.taskId,
						pattern: String(p.pattern),
						kind: p.kind,
						exclude: Boolean(p.exclude),
						note: String(p.note ?? ""),
					}),
				),
		);
	}

	// ── Evidence & Artifacts (3) ──────────────────────────────────────────

	private saveEvidence(): AgentTool<any> {
		return makeTool(
			"save_evidence",
			"Save Evidence",
			"Save text or file evidence to the SHA-256 content-addressed Evidence Store.",
			"sequential",
			{
				name: { type: "string", description: "Artifact filename" },
				content: { type: "string", description: "Text content to save" },
				source_path: { type: "string", description: "Optional local file path to archive instead of text content" },
				kind: { type: "string", description: "Artifact kind (text, http, screenshot, poc, log)" },
				description: { type: "string" },
			},
			["name"],
			(p) => {
				const art = p.source_path
					? this.ctx.evidence.saveFile({
							taskId: this.ctx.taskId,
							intentId: this.ctx.intentId,
							sourcePath: String(p.source_path),
							name: String(p.name),
							kind: p.kind,
							description: p.description,
						})
					: this.ctx.evidence.saveText({
							taskId: this.ctx.taskId,
							intentId: this.ctx.intentId,
							name: String(p.name),
							content: String(p.content ?? ""),
							kind: p.kind,
							description: p.description,
						});
				return ok(art);
			},
		);
	}

	private listArtifacts(): AgentTool<any> {
		return makeTool(
			"list_artifacts",
			"List Artifacts",
			"List all evidence artifacts archived for the current task.",
			"parallel",
			{},
			[],
			() => ok({ artifacts: this.ctx.store.listArtifacts(this.ctx.taskId) }),
		);
	}

	private evidenceCheck(): AgentTool<any> {
		return makeTool(
			"evidence_check",
			"Evidence Check",
			"Verify SHA-256 integrity of a saved artifact (or all artifacts for the task).",
			"parallel",
			{ artifact_id: { type: "number", description: "Optional artifact ID; omit to check all" } },
			[],
			(p) => {
				if (p.artifact_id != null) {
					return ok(this.ctx.evidence.verifyArtifact(Number(p.artifact_id)));
				}
				const all = this.ctx.store.listArtifacts(this.ctx.taskId);
				return ok({ results: all.map((a) => this.ctx.evidence.verifyArtifact(a.id)) });
			},
		);
	}

	// ── HTTP / Auth / Diff / Contract / Probe / JS Audit (7) ──────────────

	private httpRequest(): AgentTool<any> {
		return makeTool(
			"http_request",
			"HTTP Request",
			"Send an HTTP/HTTPS request and automatically record traffic to the task's traffic log.",
			"parallel",
			{
				url: { type: "string" },
				method: { type: "string" },
				headers: { type: "object" },
				body: { type: "string" },
				follow_redirects: { type: "boolean" },
				timeout_ms: { type: "number" },
			},
			["url"],
			async (p) =>
				ok(
					await executeHttpRequest({
						url: String(p.url),
						method: p.method,
						headers: p.headers,
						body: p.body,
						followRedirects: p.follow_redirects,
						timeoutMs: p.timeout_ms,
						store: this.ctx.store,
						taskId: this.ctx.taskId,
						intentId: this.ctx.intentId,
					}),
				),
		);
	}

	private sessionLogin(): AgentTool<any> {
		return makeTool(
			"session_login",
			"Session Login",
			"Authenticate against a login endpoint and save captured cookies/Bearer tokens as a reusable auth profile.",
			"sequential",
			{
				profile_name: { type: "string" },
				role: { type: "string" },
				login_url: { type: "string" },
				method: { type: "string" },
				headers: { type: "object" },
				body: { type: "string" },
				token_json_path: { type: "string" },
			},
			["profile_name", "login_url"],
			async (p) =>
				ok(
					await performSessionLogin({
						store: this.ctx.store,
						taskId: this.ctx.taskId,
						intentId: this.ctx.intentId,
						profileName: String(p.profile_name),
						role: p.role,
						loginUrl: String(p.login_url),
						method: p.method,
						headers: p.headers,
						body: p.body,
						tokenJsonPath: p.token_json_path,
					}),
				),
		);
	}

	private authRequest(): AgentTool<any> {
		return makeTool(
			"auth_request",
			"Authenticated Request",
			"Send an HTTP request using a previously captured auth profile (cookies/Bearer token).",
			"parallel",
			{
				profile_name: { type: "string" },
				url: { type: "string" },
				method: { type: "string" },
				headers: { type: "object" },
				body: { type: "string" },
			},
			["profile_name", "url"],
			async (p) =>
				ok(
					await executeAuthRequest({
						store: this.ctx.store,
						taskId: this.ctx.taskId,
						intentId: this.ctx.intentId,
						profileName: String(p.profile_name),
						url: String(p.url),
						method: p.method,
						headers: p.headers,
						body: p.body,
					}),
				),
		);
	}

	private diffResponses(): AgentTool<any> {
		return makeTool(
			"diff_responses",
			"Diff Responses",
			"Compare two HTTP responses (status, headers, body length, JSON keys) to detect IDOR/authz differences.",
			"parallel",
			{
				response_a: { type: "object", properties: { status: { type: "number" }, headers: { type: "object" }, body: { type: "string" } }, required: ["status", "body"] },
				response_b: { type: "object", properties: { status: { type: "number" }, headers: { type: "object" }, body: { type: "string" } }, required: ["status", "body"] },
			},
			["response_a", "response_b"],
			(p) => ok(diffHttpResponses(p.response_a, p.response_b)),
		);
	}

	private apiContract(): AgentTool<any> {
		return makeTool(
			"api_contract",
			"API Contract",
			"Fetch or parse an OpenAPI/Swagger JSON contract and list all endpoints and parameters.",
			"parallel",
			{
				url: { type: "string", description: "URL to OpenAPI/Swagger JSON" },
				raw_json: { type: "string", description: "Raw OpenAPI/Swagger JSON string" },
			},
			[],
			async (p) => {
				const raw = p.raw_json
					? String(p.raw_json)
					: (await executeHttpRequest({ url: String(p.url), store: this.ctx.store, taskId: this.ctx.taskId })).body;
				return ok(parseApiContract(raw));
			},
		);
	}

	private httpProbe(): AgentTool<any> {
		return makeTool(
			"http_probe",
			"HTTP Probe",
			"Probe one or more URLs/hosts for liveness, HTTP status, title, and server technology headers.",
			"parallel",
			{
				urls: { type: "array", items: { type: "string" } },
				timeout_ms: { type: "number" },
			},
			["urls"],
			async (p) => ok({ results: await probeHttpTargets(Array.isArray(p.urls) ? p.urls.map(String) : [], p.timeout_ms) }),
		);
	}

	private jsAudit(): AgentTool<any> {
		return makeTool(
			"js_audit",
			"JS Audit",
			"Fetch or analyze JavaScript code to extract API endpoints, hardcoded secrets, and DOM XSS sinks.",
			"parallel",
			{
				url: { type: "string", description: "URL of JS file to fetch" },
				code: { type: "string", description: "Raw JS source to analyze" },
			},
			[],
			async (p) => {
				const source = p.code
					? String(p.code)
					: (await executeHttpRequest({ url: String(p.url), store: this.ctx.store, taskId: this.ctx.taskId })).body;
				return ok(auditJavaScriptSource(source));
			},
		);
	}

	// ── Background Jobs & Scripts (6) ─────────────────────────────────────

	private jobStart(): AgentTool<any> {
		return makeTool(
			"job_start",
			"Start Job",
			"Start a long-running background shell command and return its job ID.",
			"sequential",
			{ command: { type: "string" }, cwd: { type: "string" } },
			["command"],
			(p) => ok(this.ctx.jobs.start(String(p.command), p.cwd ? String(p.cwd) : this.ctx.runDir)),
		);
	}

	private jobStatus(): AgentTool<any> {
		return makeTool(
			"job_status",
			"Job Status",
			"Check status of one or all background jobs.",
			"parallel",
			{ job_id: { type: "string" } },
			[],
			(p) => ok({ jobs: this.ctx.jobs.status(p.job_id) }),
		);
	}

	private jobOutput(): AgentTool<any> {
		return makeTool(
			"job_output",
			"Job Output",
			"Read recent stdout/stderr output from a background job.",
			"parallel",
			{ job_id: { type: "string" }, tail_chars: { type: "number" } },
			["job_id"],
			(p) => {
				const out = this.ctx.jobs.output(String(p.job_id), p.tail_chars);
				return out ? ok(out) : fail(`Job ${p.job_id} not found`);
			},
		);
	}

	private jobStop(): AgentTool<any> {
		return makeTool(
			"job_stop",
			"Stop Job",
			"Terminate a running background job.",
			"sequential",
			{ job_id: { type: "string" } },
			["job_id"],
			(p) => ok({ job_id: String(p.job_id), stopped: this.ctx.jobs.stop(String(p.job_id)) }),
		);
	}

	private saveScript(): AgentTool<any> {
		return makeTool(
			"save_script",
			"Save Script",
			"Save a PoC or helper script into the task's script workspace.",
			"sequential",
			{ name: { type: "string" }, content: { type: "string" } },
			["name", "content"],
			(p) => ok({ path: this.ctx.scripts.saveScript(String(p.name), String(p.content)) }),
		);
	}

	private runScript(): AgentTool<any> {
		return makeTool(
			"run_script",
			"Run Script",
			"Execute a saved script from the task's script workspace.",
			"sequential",
			{
				name: { type: "string" },
				interpreter: { type: "string", enum: ["python3", "node", "bash"] },
				args: { type: "array", items: { type: "string" } },
				timeout_ms: { type: "number" },
			},
			["name"],
			async (p) =>
				ok(
					await this.ctx.scripts.runScript(
						String(p.name),
						p.interpreter ?? "python3",
						Array.isArray(p.args) ? p.args.map(String) : [],
						p.timeout_ms,
					),
				),
		);
	}

	// ── Listener / OOB Callbacks (3) ──────────────────────────────────────

	private listenerStart(): AgentTool<any> {
		return makeTool(
			"listener_start",
			"Start Listener",
			"Start a local HTTP or TCP callback listener for verifying OOB SSRF/XXE/XSS/RCE.",
			"sequential",
			{
				id: { type: "string" },
				protocol: { type: "string", enum: ["http", "tcp"] },
				host: { type: "string" },
				port: { type: "number" },
			},
			[],
			async (p) => ok(await this.ctx.listeners.start(p)),
		);
	}

	private listenerStop(): AgentTool<any> {
		return makeTool(
			"listener_stop",
			"Stop Listener",
			"Stop an active callback listener by ID.",
			"sequential",
			{ id: { type: "string" } },
			["id"],
			async (p) => ok({ id: String(p.id), stopped: await this.ctx.listeners.stop(String(p.id)) }),
		);
	}

	private listenerSessions(): AgentTool<any> {
		return makeTool(
			"listener_sessions",
			"Listener Sessions",
			"List active listeners and captured OOB callback events.",
			"parallel",
			{ id: { type: "string" } },
			[],
			(p) => ok(this.ctx.listeners.listSessions(p.id)),
		);
	}

	// ── Vuln Intel & Nuclei (6) ───────────────────────────────────────────

	private searchVulns(): AgentTool<any> {
		return makeTool(
			"search_vulns",
			"Search Vulns",
			"Search local vulnerability intelligence (CVE/NVD/GHSA/KEV/PoC cache).",
			"parallel",
			{ query: { type: "string" }, limit: { type: "number" } },
			["query"],
			(p) => ok({ results: this.ctx.vulnIntel.search(String(p.query), p.limit) }),
		);
	}

	private getVuln(): AgentTool<any> {
		return makeTool(
			"get_vuln",
			"Get Vuln",
			"Retrieve detailed vulnerability intelligence for a CVE or advisory ID.",
			"parallel",
			{ id: { type: "string" } },
			["id"],
			(p) => {
				const v = this.ctx.vulnIntel.get(String(p.id));
				return v ? ok(v) : fail(`Vulnerability ${p.id} not found in local intel cache`);
			},
		);
	}

	private searchRecentCritical(): AgentTool<any> {
		return makeTool(
			"search_recent_critical",
			"Recent Critical Vulns",
			"List recent critical and high-severity vulnerabilities from local intel.",
			"parallel",
			{ limit: { type: "number" } },
			[],
			(p) => ok({ results: this.ctx.vulnIntel.recentCritical(p.limit) }),
		);
	}

	private getPoc(): AgentTool<any> {
		return makeTool(
			"get_poc",
			"Get PoC",
			"Retrieve cached PoC template and references for a CVE/advisory.",
			"parallel",
			{ id: { type: "string" } },
			["id"],
			(p) => ok(this.ctx.vulnIntel.getPoc(String(p.id))),
		);
	}

	private scanWithNuclei(): AgentTool<any> {
		return makeTool(
			"scan_with_nuclei",
			"Scan with Nuclei",
			"Run nuclei templates against an authorized target URL.",
			"sequential",
			{
				target: { type: "string" },
				templates: { type: "array", items: { type: "string" } },
				severity: { type: "string" },
				timeout_ms: { type: "number" },
			},
			["target"],
			async (p) =>
				ok(
					await this.ctx.vulnIntel.scanWithNuclei({
						target: String(p.target),
						templates: p.templates,
						severity: p.severity,
						timeoutMs: p.timeout_ms,
					}),
				),
		);
	}

	private netContext(): AgentTool<any> {
		return makeTool(
			"net_context",
			"Network Context",
			"Inspect local network interfaces and configured HTTP/HTTPS proxy environment.",
			"parallel",
			{},
			[],
			() => ok(this.ctx.vulnIntel.getNetworkContext()),
		);
	}

	// ── Guarded Shell Execution ───────────────────────────────────────────

	private bashTool(): AgentTool<any> {
		return makeTool(
			"bash",
			"Bash",
			"Execute a shell command in the task workspace (subject to Tengu three-layer intercept rules).",
			"sequential",
			{
				command: { type: "string", description: "Bash command to execute" },
				timeout_ms: { type: "number", description: "Timeout in ms (default 30000)" },
			},
			["command"],
			async (p) => {
				if (this.ctx.intercept) {
					const decision = await this.ctx.intercept.evaluate({
						taskId: this.ctx.taskId,
						intentId: this.ctx.intentId ?? null,
						toolName: "bash",
						toolArgs: p,
					});
					if (!decision.allowed) {
						return ok({ blocked: true, action: decision.action, rule: decision.ruleName ?? null, reason: decision.reason });
					}
				}
				const timeoutMs = Number(p.timeout_ms ?? 30_000);
				return new Promise<AgentToolResult>((resolve) => {
					const child = spawn("bash", ["-lc", String(p.command)], {
						cwd: this.ctx.runDir,
						stdio: ["ignore", "pipe", "pipe"],
					});
					let stdout = "";
					let stderr = "";
					const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
					child.stdout?.on("data", (d: Buffer) => {
						if (stdout.length < 64_000) stdout += d.toString("utf8");
					});
					child.stderr?.on("data", (d: Buffer) => {
						if (stderr.length < 32_000) stderr += d.toString("utf8");
					});
					child.on("close", (code) => {
						clearTimeout(timer);
						resolve(ok({ exit_code: code ?? -1, stdout, stderr }));
					});
				});
			},
		);
	}


	// ── Conversational Configuration & Engagement Control Tools ───────────

	private createTaskTool(): AgentTool<any> {
		return makeTool(
			"create_task",
			"Create Task",
			"Create a new pentest task and switch the active session context to it.",
			"sequential",
			{
				name: { type: "string", description: "Engagement / task name" },
				description: { type: "string", description: "Engagement description" },
				max_workers: { type: "number", description: "Parallel worker limit (default 3)" },
				max_turns: { type: "number", description: "Max planner rounds (default 24)" },
			},
			["name"],
			(p) => {
				const t = this.ctx.store.createTask({
					name: String(p.name),
					description: p.description ? String(p.description) : "",
					maxWorkers: p.max_workers != null ? Number(p.max_workers) : 3,
					maxTurns: p.max_turns != null ? Number(p.max_turns) : 24,
				});
				this.ctx.taskId = t.id;
				this.ctx.onTaskChanged?.(t.id);
				return ok(t);
			},
		);
	}

	private listTasksTool(): AgentTool<any> {
		return makeTool(
			"list_tasks",
			"List Tasks",
			"List all pentest tasks and their statuses.",
			"parallel",
			{},
			[],
			() => ok({ active_task_id: this.ctx.taskId, tasks: this.ctx.store.listTasks() }),
		);
	}

	private configureTaskTool(): AgentTool<any> {
		return makeTool(
			"configure_task",
			"Configure Task",
			"Update parameters of the current pentest task (max_workers, max_turns, autopilot, coverage_enabled, scope_write_guard, description, name).",
			"sequential",
			{
				name: { type: "string" },
				description: { type: "string" },
				max_workers: { type: "number" },
				max_turns: { type: "number" },
				autopilot: { type: "boolean" },
				coverage_enabled: { type: "boolean" },
				scope_write_guard: { type: "boolean" },
			},
			[],
			(p) => {
				const updated = this.ctx.store.updateTaskConfig(this.ctx.taskId, {
					...(p.name != null ? { name: String(p.name) } : {}),
					...(p.description != null ? { description: String(p.description) } : {}),
					...(p.max_workers != null ? { maxWorkers: Number(p.max_workers) } : {}),
					...(p.max_turns != null ? { maxTurns: Number(p.max_turns) } : {}),
					...(p.autopilot != null ? { autopilot: Boolean(p.autopilot) } : {}),
					...(p.coverage_enabled != null ? { coverageEnabled: Boolean(p.coverage_enabled) } : {}),
					...(p.scope_write_guard != null ? { scopeWriteGuard: Boolean(p.scope_write_guard) } : {}),
				});
				return updated ? ok(updated) : fail(`Task #${this.ctx.taskId} not found`);
			},
		);
	}

	private listInterceptRulesTool(): AgentTool<any> {
		return makeTool(
			"list_intercept_rules",
			"List Intercept Rules",
			"List all 3-layer intercept safety rules (hard_deny, judge, ask).",
			"parallel",
			{},
			[],
			() => ok({ rules: this.ctx.store.listInterceptRules({ taskId: this.ctx.taskId }) }),
		);
	}

	private configureInterceptRuleTool(): AgentTool<any> {
		return makeTool(
			"configure_intercept_rule",
			"Configure Intercept Rule",
			"Add or update a safety intercept rule (e.g., ask before POST/DELETE or deny specific patterns).",
			"sequential",
			{
				name: { type: "string", description: "Unique rule identifier" },
				pattern: { type: "string", description: "Regex or substring pattern to match" },
				action: { type: "string", enum: ["deny", "judge", "ask", "allow"] },
				target: { type: "string", enum: ["tool_name", "tool_input"] },
				match_type: { type: "string", enum: ["regex", "string"] },
				enabled: { type: "boolean" },
				priority: { type: "number" },
				message: { type: "string" },
			},
			["name", "pattern", "action"],
			(p) => {
				const action = String(p.action) as InterceptAction;
				const ruleClass: InterceptClass = action === "deny" ? "hard_deny" : action === "judge" ? "judge" : "ask";
				const rule = this.ctx.store.upsertInterceptRule({
					name: String(p.name),
					scope: "task",
					taskId: this.ctx.taskId,
					assetPattern: "",
					target: p.target === "tool_name" ? "tool_name" : "tool_input",
					matchType: p.match_type === "string" ? "string" : "regex",
					pattern: String(p.pattern),
					action,
					ruleClass,
					rationale: "Configured via operator chat",
					message: String(p.message ?? `Triggered custom rule ${p.name}`),
					priority: p.priority != null ? Number(p.priority) : 70,
					enabled: p.enabled !== false,
					seedBatch: "custom",
					timeoutEnabled: action === "judge",
					timeoutSeconds: 20,
					timeoutAction: "deny",
				});
				return ok(rule);
			},
		);
	}

	private startEngagementTool(): AgentTool<any> {
		return makeTool(
			"start_engagement",
			"Start Engagement",
			"Launch the autonomous Planner/Worker penetration test for the current task (supports background daemon mode that survives TUI close).",
			"sequential",
			{
				background: { type: "boolean", description: "Run as detached background daemon (default true)" },
				max_rounds: { type: "number", description: "Optional max planner rounds" },
			},
			[],
			async (p) => {
				if (!this.ctx.onStartEngagement) return fail("Engagement runner unavailable in this context");
				const res = await this.ctx.onStartEngagement(this.ctx.taskId, {
					background: p.background !== false,
					maxRounds: p.max_rounds != null ? Number(p.max_rounds) : undefined,
				});
				return ok({ started: true, task_id: this.ctx.taskId, result: res });
			},
		);
	}

	private pauseEngagementTool(): AgentTool<any> {
		return makeTool(
			"pause_engagement",
			"Pause Engagement",
			"Pause the currently running autonomous engagement.",
			"sequential",
			{},
			[],
			() => ok({ task_id: this.ctx.taskId, paused: Boolean(this.ctx.onPauseEngagement?.(this.ctx.taskId)) }),
		);
	}

	private stopEngagementTool(): AgentTool<any> {
		return makeTool(
			"stop_engagement",
			"Stop Engagement",
			"Cleanly stop the currently running autonomous engagement.",
			"sequential",
			{},
			[],
			() => ok({ task_id: this.ctx.taskId, stopped: Boolean(this.ctx.onStopEngagement?.(this.ctx.taskId)) }),
		);
	}

	private generateReportTool(): AgentTool<any> {
		return makeTool(
			"generate_report",
			"Generate Report",
			"Generate a sanitized penetration test report for the current task in markdown, json, sarif, or html format.",
			"parallel",
			{ format: { type: "string", enum: ["markdown", "json", "sarif", "html"] } },
			[],
			(p) => {
				const fmt = (p.format ?? "markdown") as ReportFormat;
				const content = new ReportGenerator(this.ctx.store).generate(this.ctx.taskId, fmt, true);
				return ok({ format: fmt, content });
			},
		);
	}


	private loadSkillTool(): AgentTool<any> {
		return makeTool(
			"load_skill",
			"Load Skill",
			"Load a specialized penetration testing skill playbook by ID (or omit ID to list all 23 skills).",
			"parallel",
			{ id: { type: "string", description: "Skill ID (e.g. api-security-testing, web-attack-methods, src-hunting)" } },
			[],
			(p) => {
				if (!p.id) return ok(formatSkillIndex());
				const skill = findSkill(String(p.id));
				return skill ? ok(renderSkillPlaybook(skill)) : fail(`Skill "${p.id}" not found. Call load_skill with no arguments to list all skills.`);
			},
		);
	}

	// ── Role-Based Tool Suites ────────────────────────────────────────────

	plannerTools(): AgentTool<any>[] {
		return [
			this.graphOverview(),
			this.listFindings(),
			this.listFacts(),
			this.nodeDetail(),
			this.expandDigest(),
			this.addIntent(),
			this.retireIntent(),
			this.listGoals(),
			this.setGoals(),
			this.proveGoal(),
			this.goalMetTool(),
			this.setConstraints(),
			this.addHint(),
			this.killWork(),
			this.steerWork(),
			this.getWorkerOutput(),
			this.getWorkerTrace(),
			this.listWorkerTraces(),
			this.searchAllWorkerTraces(),
			this.listAssets(),
			this.listUntestedAssets(),
			this.listCompanies(),
			this.listArtifacts(),
			this.evidenceCheck(),
			this.searchVulns(),
			this.getVuln(),
			this.searchRecentCritical(),
			this.loadSkillTool(),
		];
	}

	workerTools(): AgentTool<any>[] {
		return [
			this.graphOverview(),
			this.listFindings(),
			this.listFacts(),
			this.nodeDetail(),
			this.expandDigest(),
			this.recordFact(),
			this.reportFinding(),
			this.insertAssets(),
			this.listAssets(),
			this.listUntestedAssets(),
			this.saveEvidence(),
			this.listArtifacts(),
			this.evidenceCheck(),
			this.httpRequest(),
			this.sessionLogin(),
			this.authRequest(),
			this.diffResponses(),
			this.apiContract(),
			this.httpProbe(),
			this.jsAudit(),
			this.jobStart(),
			this.jobStatus(),
			this.jobOutput(),
			this.jobStop(),
			this.saveScript(),
			this.runScript(),
			this.listenerStart(),
			this.listenerStop(),
			this.listenerSessions(),
			this.searchVulns(),
			this.getVuln(),
			this.searchRecentCritical(),
			this.getPoc(),
			this.scanWithNuclei(),
			this.netContext(),
			this.bashTool(),
			this.loadSkillTool(),
		];
	}

	retesterTools(): AgentTool<any>[] {
		return [
			this.listFindings(),
			this.nodeDetail(),
			this.saveEvidence(),
			this.evidenceCheck(),
			this.httpRequest(),
			this.sessionLogin(),
			this.authRequest(),
			this.diffResponses(),
			this.httpProbe(),
			this.saveScript(),
			this.runScript(),
			this.bashTool(),
		];
	}

	allTools(): AgentTool<any>[] {
		const map = new Map<string, AgentTool<any>>();
		for (const t of [
			...this.plannerTools(),
			...this.workerTools(),
			this.addCompanyScope(),
			this.addTaskScope(),
			this.createTaskTool(),
			this.listTasksTool(),
			this.configureTaskTool(),
			this.listInterceptRulesTool(),
			this.configureInterceptRuleTool(),
			this.startEngagementTool(),
			this.pauseEngagementTool(),
			this.stopEngagementTool(),
			this.generateReportTool(),
		]) {
			map.set(t.name, t);
		}
		return [...map.values()];
	}
}
