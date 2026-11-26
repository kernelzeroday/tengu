import { createInterface } from "node:readline";
import { loadSkills, type TenguOrchestrator } from "@tengu/engine";
import { ReportGenerator, type ReportFormat } from "@tengu/ops";
import type { AssetKind, TenguStore } from "@tengu/store";

export interface JsonRpcRequest {
	jsonrpc: "2.0";
	id?: string | number | null;
	method: string;
	params?: Record<string, any>;
}

export interface JsonRpcResponse {
	jsonrpc: "2.0";
	id: string | number | null;
	result?: unknown;
	error?: { code: number; message: string };
}

export class TenguRpcHandler {
	private readonly store: TenguStore;
	private readonly orchestrator?: TenguOrchestrator;
	private readonly reports: ReportGenerator;

	constructor(store: TenguStore, orchestrator?: TenguOrchestrator) {
		this.store = store;
		this.orchestrator = orchestrator;
		this.reports = new ReportGenerator(store);
	}

	async handle(req: JsonRpcRequest): Promise<JsonRpcResponse> {
		const id = req.id ?? null;
		const p = req.params ?? {};
		try {
			const result = await this.dispatch(req.method, p);
			return { jsonrpc: "2.0", id, result };
		} catch (err) {
			return {
				jsonrpc: "2.0",
				id,
				error: { code: -32000, message: err instanceof Error ? err.message : String(err) },
			};
		}
	}

	private async dispatch(method: string, p: Record<string, any>): Promise<unknown> {
		switch (method) {
			case "ping":
				return { ok: true, name: "tengu", version: "0.1.0" };
			case "task.create":
				return this.store.createTask({
					name: String(p.name ?? "Untitled Task"),
					description: p.description ? String(p.description) : "",
					companyId: p.companyId != null ? Number(p.companyId) : null,
					maxWorkers: p.maxWorkers != null ? Number(p.maxWorkers) : 3,
				});
			case "task.list":
				return { tasks: this.store.listTasks(p.status) };
			case "task.get":
				return this.store.getTask(Number(p.id));
			case "task.overview":
				return this.store.getGraphOverview(Number(p.taskId));
			case "task.run": {
				if (!this.orchestrator) throw new Error("Orchestrator not configured (provide an LLM model/API key)");
				return await this.orchestrator.runTask(Number(p.taskId), { maxRounds: p.maxRounds });
			}
			case "scope.add":
				return this.store.addTaskScope({
					taskId: Number(p.taskId),
					pattern: String(p.pattern),
					kind: p.kind ?? "domain",
					exclude: Boolean(p.exclude),
					note: String(p.note ?? ""),
				});
			case "scope.list":
				return { rules: this.store.listTaskScope(Number(p.taskId)) };
			case "assets.insert":
				return {
					assets: this.store.upsertAssets(
						(Array.isArray(p.assets) ? p.assets : []).map((a: Record<string, unknown>) => ({
							taskId: p.taskId != null ? Number(p.taskId) : null,
							kind: String(a.kind) as AssetKind,
							value: String(a.value),
							label: a.label ? String(a.label) : "",
							source: "rpc",
						})),
					),
				};
			case "assets.list":
				return {
					assets: this.store.listAssets({
						taskId: p.taskId != null ? Number(p.taskId) : undefined,
						query: p.query ? String(p.query) : undefined,
						limit: p.limit != null ? Number(p.limit) : 100,
					}),
				};
			case "assets.coverage":
				return this.store.getAssetCoverage(Number(p.taskId));
			case "findings.list":
				return { findings: this.store.listFindings(p.taskId != null ? Number(p.taskId) : undefined) };
			case "findings.retest": {
				if (!this.orchestrator) throw new Error("Orchestrator not configured");
				return await this.orchestrator.retestFinding(Number(p.taskId), Number(p.findingId));
			}
			case "intercept.rules":
				return { rules: this.store.listInterceptRules({ taskId: p.taskId }) };
			case "intercept.approvals":
				return { approvals: this.store.listApprovalRequests({ taskId: p.taskId, status: p.status }) };
			case "intercept.decide":
				return this.store.resolveApprovalRequest(
					Number(p.id),
					p.approved ? "approved" : "denied",
					String(p.decidedBy ?? "rpc_operator"),
					String(p.reason ?? ""),
				);
			case "report.generate":
				return {
					format: (p.format ?? "markdown") as ReportFormat,
					content: this.reports.generate(Number(p.taskId), (p.format ?? "markdown") as ReportFormat, p.sanitize !== false),
				};
			case "skills.list":
				return { skills: loadSkills(p.customDir) };
			case "vulnintel.search":
				return { results: this.store.searchVulnIntel(String(p.query ?? ""), p.limit ?? 20) };
			default:
				throw new Error(`Unknown RPC method: ${method}`);
		}
	}
}

export function startJsonRpcServer(store: TenguStore, orchestrator?: TenguOrchestrator): void {
	const handler = new TenguRpcHandler(store, orchestrator);
	const rl = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });
	let queue = Promise.resolve();
	rl.on("line", (line) => {
		queue = queue.then(async () => {
			const trimmed = line.trim();
			if (!trimmed) return;
			let req: JsonRpcRequest;
			try {
				req = JSON.parse(trimmed) as JsonRpcRequest;
			} catch {
				process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } })}\n`);
				return;
			}
			const resp = await handler.handle(req);
			process.stdout.write(`${JSON.stringify(resp)}\n`);
		});
	});
}
