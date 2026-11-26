import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { matchesAssetDsl, normalizeAssetKey, parseAssetDsl } from "./asset-dsl.ts";
import type {
	ApprovalRequest,
	ApprovalStatus,
	ArtifactRecord,
	AssetCoverageSummary,
	AssetEdge,
	AssetKind,
	AssetNode,
	Company,
	CompanyScopeRule,
	ExplorationEdge,
	ExplorationNode,
	ExplorationNodeKind,
	Finding,
	FindingRetest,
	FindingStatus,
	GraphOverview,
	InterceptRule,
	InterceptScope,
	LlmUsageRecord,
	NotificationChannel,
	SideQuestion,
	Task,
	TaskAuthProfile,
	TaskConstraint,
	TaskScopeRule,
	TaskStatus,
	TenguStore,
	TrafficRecord,
	VulnIntelEntry,
	WorkerTraceEntry,
} from "./types.ts";

function nowIso(): string {
	return new Date().toISOString();
}

function parseJson<T>(raw: unknown, fallback: T): T {
	if (typeof raw !== "string" || !raw) return fallback;
	try {
		return JSON.parse(raw) as T;
	} catch {
		return fallback;
	}
}

export class SqliteTenguStore implements TenguStore {
	private readonly db: DatabaseSync;

	constructor(dbPath: string) {
		if (dbPath !== ":memory:") {
			mkdirSync(dirname(dbPath), { recursive: true });
		}
		this.db = new DatabaseSync(dbPath);
		this.db.exec("PRAGMA journal_mode = WAL;");
		this.db.exec("PRAGMA foreign_keys = ON;");
		this.initSchema();
	}

	close(): void {
		this.db.close();
	}

	private initSchema(): void {
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS companies (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				description TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS company_scope_rules (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
				pattern TEXT NOT NULL,
				kind TEXT NOT NULL,
				exclude INTEGER NOT NULL DEFAULT 0,
				note TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS tasks (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
				parent_task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
				category TEXT NOT NULL DEFAULT 'pentest',
				status TEXT NOT NULL DEFAULT 'draft',
				autopilot INTEGER NOT NULL DEFAULT 1,
				coverage_enabled INTEGER NOT NULL DEFAULT 1,
				scope_write_guard INTEGER NOT NULL DEFAULT 1,
				scope_inherit_writes INTEGER NOT NULL DEFAULT 0,
				max_workers INTEGER NOT NULL DEFAULT 3,
				max_turns INTEGER NOT NULL DEFAULT 24,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				completed_at TEXT
			);

			CREATE TABLE IF NOT EXISTS task_scope_rules (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				pattern TEXT NOT NULL,
				kind TEXT NOT NULL,
				exclude INTEGER NOT NULL DEFAULT 0,
				note TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS task_constraints (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				text TEXT NOT NULL,
				enforced INTEGER NOT NULL DEFAULT 1,
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS task_auth_profiles (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				name TEXT NOT NULL,
				role TEXT NOT NULL DEFAULT 'user',
				auth_type TEXT NOT NULL DEFAULT 'cookie',
				headers_json TEXT NOT NULL DEFAULT '{}',
				cookies_json TEXT NOT NULL DEFAULT '{}',
				login_url TEXT NOT NULL DEFAULT '',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				updated_at TEXT NOT NULL,
				UNIQUE(task_id, name)
			);

			CREATE TABLE IF NOT EXISTS assets (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
				task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
				kind TEXT NOT NULL,
				value TEXT NOT NULL,
				normalized_key TEXT NOT NULL UNIQUE,
				label TEXT NOT NULL DEFAULT '',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				tested INTEGER NOT NULL DEFAULT 0,
				tested_by_intent_id INTEGER,
				source TEXT NOT NULL DEFAULT 'agent',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_assets_task ON assets(task_id);
			CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);

			CREATE TABLE IF NOT EXISTS asset_edges (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				from_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
				to_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
				relation TEXT NOT NULL,
				metadata_json TEXT NOT NULL DEFAULT '{}',
				created_at TEXT NOT NULL,
				UNIQUE(from_asset_id, to_asset_id, relation)
			);

			CREATE TABLE IF NOT EXISTS exploration_nodes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				kind TEXT NOT NULL,
				state TEXT NOT NULL DEFAULT 'open',
				summary TEXT NOT NULL,
				payload_json TEXT NOT NULL DEFAULT '{}',
				asset_ids_json TEXT NOT NULL DEFAULT '[]',
				blocked_reason TEXT NOT NULL DEFAULT '',
				inherited INTEGER NOT NULL DEFAULT 0,
				source_task_id INTEGER,
				worker_id TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_exp_nodes_task_kind ON exploration_nodes(task_id, kind);

			CREATE TABLE IF NOT EXISTS exploration_edges (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				from_node_id INTEGER NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
				to_node_id INTEGER NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
				relation TEXT NOT NULL,
				created_at TEXT NOT NULL,
				UNIQUE(task_id, from_node_id, to_node_id, relation)
			);

			CREATE TABLE IF NOT EXISTS findings (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				node_id INTEGER REFERENCES exploration_nodes(id) ON DELETE SET NULL,
				intent_id INTEGER,
				title TEXT NOT NULL,
				vuln_class TEXT NOT NULL DEFAULT 'other',
				severity TEXT NOT NULL DEFAULT 'medium',
				status TEXT NOT NULL DEFAULT 'open',
				summary TEXT NOT NULL DEFAULT '',
				description TEXT NOT NULL DEFAULT '',
				reproduction TEXT NOT NULL DEFAULT '',
				remediation TEXT NOT NULL DEFAULT '',
				evidence TEXT NOT NULL DEFAULT '',
				evidence_ids_json TEXT NOT NULL DEFAULT '[]',
				asset_ids_json TEXT NOT NULL DEFAULT '[]',
				cvss REAL,
				cwe TEXT NOT NULL DEFAULT '',
				fingerprint TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);
			CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);

			CREATE TABLE IF NOT EXISTS finding_retests (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				status TEXT NOT NULL,
				notes TEXT NOT NULL DEFAULT '',
				evidence TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS artifacts (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
				intent_id INTEGER,
				name TEXT NOT NULL,
				kind TEXT NOT NULL DEFAULT 'file',
				mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
				sha256 TEXT NOT NULL,
				size_bytes INTEGER NOT NULL,
				path TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS intercept_rules (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				scope TEXT NOT NULL DEFAULT 'global',
				task_id INTEGER,
				asset_pattern TEXT NOT NULL DEFAULT '',
				target TEXT NOT NULL DEFAULT 'tool_input',
				match_type TEXT NOT NULL DEFAULT 'regex',
				pattern TEXT NOT NULL,
				action TEXT NOT NULL DEFAULT 'deny',
				rule_class TEXT NOT NULL DEFAULT 'hard_deny',
				rationale TEXT NOT NULL DEFAULT '',
				message TEXT NOT NULL DEFAULT '',
				priority INTEGER NOT NULL DEFAULT 50,
				enabled INTEGER NOT NULL DEFAULT 1,
				seed_batch TEXT NOT NULL DEFAULT '',
				timeout_enabled INTEGER NOT NULL DEFAULT 0,
				timeout_seconds INTEGER NOT NULL DEFAULT 30,
				timeout_action TEXT NOT NULL DEFAULT 'deny',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS approval_requests (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL,
				intent_id INTEGER,
				rule_id INTEGER,
				rule_name TEXT NOT NULL DEFAULT '',
				tool_name TEXT NOT NULL,
				tool_input TEXT NOT NULL,
				action TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'pending',
				reason TEXT NOT NULL DEFAULT '',
				judge_output TEXT NOT NULL DEFAULT '',
				decided_by TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				decided_at TEXT
			);

			CREATE TABLE IF NOT EXISTS traffic_records (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL,
				intent_id INTEGER,
				finding_id INTEGER,
				method TEXT NOT NULL,
				url TEXT NOT NULL,
				host TEXT NOT NULL,
				status_code INTEGER NOT NULL DEFAULT 0,
				request_headers_json TEXT NOT NULL DEFAULT '{}',
				request_body TEXT NOT NULL DEFAULT '',
				response_headers_json TEXT NOT NULL DEFAULT '{}',
				response_body TEXT NOT NULL DEFAULT '',
				duration_ms INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS worker_traces (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL,
				intent_id INTEGER NOT NULL,
				worker_id TEXT NOT NULL,
				turn INTEGER NOT NULL,
				tool_name TEXT NOT NULL,
				tool_args TEXT NOT NULL DEFAULT '',
				tool_output TEXT NOT NULL DEFAULT '',
				is_error INTEGER NOT NULL DEFAULT 0,
				duration_ms INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_traces_task_intent ON worker_traces(task_id, intent_id);

			CREATE TABLE IF NOT EXISTS llm_usage (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL,
				intent_id INTEGER,
				role TEXT NOT NULL,
				provider TEXT NOT NULL,
				model TEXT NOT NULL,
				input_tokens INTEGER NOT NULL DEFAULT 0,
				output_tokens INTEGER NOT NULL DEFAULT 0,
				cache_read_tokens INTEGER NOT NULL DEFAULT 0,
				cost_usd REAL NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS side_questions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				task_id INTEGER NOT NULL,
				question TEXT NOT NULL,
				answer TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'open',
				created_at TEXT NOT NULL,
				answered_at TEXT
			);

			CREATE TABLE IF NOT EXISTS notification_channels (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				kind TEXT NOT NULL,
				enabled INTEGER NOT NULL DEFAULT 1,
				config_json TEXT NOT NULL DEFAULT '{}',
				events_json TEXT NOT NULL DEFAULT '[]',
				min_severity TEXT NOT NULL DEFAULT 'medium',
				created_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS vuln_intel (
				id TEXT PRIMARY KEY,
				source TEXT NOT NULL,
				cve_id TEXT NOT NULL DEFAULT '',
				title TEXT NOT NULL,
				severity TEXT NOT NULL DEFAULT 'medium',
				cvss REAL,
				affected_product TEXT NOT NULL DEFAULT '',
				affected_versions TEXT NOT NULL DEFAULT '',
				description TEXT NOT NULL DEFAULT '',
				references_json TEXT NOT NULL DEFAULT '[]',
				poc_template TEXT NOT NULL DEFAULT '',
				published_at TEXT NOT NULL DEFAULT '',
				updated_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS settings (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
		`);
	}

	// ── Companies ──────────────────────────────────────────────────────────

	createCompany(name: string, description = ""): Company {
		const ts = nowIso();
		const res = this.db
			.prepare("INSERT INTO companies (name, description, created_at, updated_at) VALUES (?, ?, ?, ?)")
			.run(name, description, ts, ts);
		return this.getCompany(Number(res.lastInsertRowid))!;
	}

	listCompanies(): Company[] {
		const rows = this.db.prepare("SELECT * FROM companies ORDER BY id ASC").all() as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			name: String(r.name),
			description: String(r.description),
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
		}));
	}

	getCompany(id: number): Company | null {
		const r = this.db.prepare("SELECT * FROM companies WHERE id = ?").get(id) as Record<string, unknown> | undefined;
		if (!r) return null;
		return {
			id: Number(r.id),
			name: String(r.name),
			description: String(r.description),
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
		};
	}

	addCompanyScope(rule: Omit<CompanyScopeRule, "id" | "createdAt">): CompanyScopeRule {
		const ts = nowIso();
		const res = this.db
			.prepare("INSERT INTO company_scope_rules (company_id, pattern, kind, exclude, note, created_at) VALUES (?, ?, ?, ?, ?, ?)")
			.run(rule.companyId, rule.pattern, rule.kind, rule.exclude ? 1 : 0, rule.note, ts);
		return { ...rule, id: Number(res.lastInsertRowid), createdAt: ts };
	}

	listCompanyScope(companyId: number): CompanyScopeRule[] {
		const rows = this.db
			.prepare("SELECT * FROM company_scope_rules WHERE company_id = ? ORDER BY id ASC")
			.all(companyId) as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			companyId: Number(r.company_id),
			pattern: String(r.pattern),
			kind: String(r.kind) as CompanyScopeRule["kind"],
			exclude: Boolean(r.exclude),
			note: String(r.note),
			createdAt: String(r.created_at),
		}));
	}

	// ── Tasks ──────────────────────────────────────────────────────────────

	private mapTask(r: Record<string, unknown>): Task {
		return {
			id: Number(r.id),
			name: String(r.name),
			description: String(r.description),
			companyId: r.company_id == null ? null : Number(r.company_id),
			parentTaskId: r.parent_task_id == null ? null : Number(r.parent_task_id),
			category: String(r.category),
			status: String(r.status) as TaskStatus,
			autopilot: Boolean(r.autopilot),
			coverageEnabled: Boolean(r.coverage_enabled),
			scopeWriteGuard: Boolean(r.scope_write_guard),
			scopeInheritWrites: Boolean(r.scope_inherit_writes),
			maxWorkers: Number(r.max_workers),
			maxTurns: Number(r.max_turns),
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
			completedAt: r.completed_at == null ? null : String(r.completed_at),
		};
	}

	createTask(input: {
		name: string;
		description?: string;
		companyId?: number | null;
		parentTaskId?: number | null;
		category?: string;
		autopilot?: boolean;
		coverageEnabled?: boolean;
		scopeWriteGuard?: boolean;
		scopeInheritWrites?: boolean;
		maxWorkers?: number;
		maxTurns?: number;
	}): Task {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO tasks (
					name, description, company_id, parent_task_id, category, status,
					autopilot, coverage_enabled, scope_write_guard, scope_inherit_writes,
					max_workers, max_turns, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				input.name,
				input.description ?? "",
				input.companyId ?? null,
				input.parentTaskId ?? null,
				input.category ?? "pentest",
				input.autopilot === false ? 0 : 1,
				input.coverageEnabled === false ? 0 : 1,
				input.scopeWriteGuard === false ? 0 : 1,
				input.scopeInheritWrites ? 1 : 0,
				input.maxWorkers ?? 3,
				input.maxTurns ?? 24,
				ts,
				ts,
			);
		const task = this.getTask(Number(res.lastInsertRowid))!;
		this.addExplorationNode({
			taskId: task.id,
			kind: "begin",
			state: "done",
			summary: `Task initialized: ${task.name}`,
			payload: { description: task.description },
		});
		return task;
	}

	getTask(id: number): Task | null {
		const r = this.db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as Record<string, unknown> | undefined;
		return r ? this.mapTask(r) : null;
	}

	listTasks(status?: TaskStatus): Task[] {
		const rows = status
			? (this.db.prepare("SELECT * FROM tasks WHERE status = ? ORDER BY id DESC").all(status) as Record<string, unknown>[])
			: (this.db.prepare("SELECT * FROM tasks ORDER BY id DESC").all() as Record<string, unknown>[]);
		return rows.map((r) => this.mapTask(r));
	}

	updateTaskStatus(id: number, status: TaskStatus): Task | null {
		const ts = nowIso();
		const completedAt = status === "completed" || status === "failed" || status === "stopped" ? ts : null;
		this.db
			.prepare("UPDATE tasks SET status = ?, updated_at = ?, completed_at = COALESCE(?, completed_at) WHERE id = ?")
			.run(status, ts, completedAt, id);
		return this.getTask(id);
	}

	updateTaskConfig(
		id: number,
		patch: Partial<Pick<Task, "name" | "description" | "autopilot" | "coverageEnabled" | "scopeWriteGuard" | "scopeInheritWrites" | "maxWorkers" | "maxTurns">>,
	): Task | null {
		const cur = this.getTask(id);
		if (!cur) return null;
		const ts = nowIso();
		this.db
			.prepare(
				`UPDATE tasks SET
				   name = ?, description = ?, autopilot = ?, coverage_enabled = ?,
				   scope_write_guard = ?, scope_inherit_writes = ?, max_workers = ?, max_turns = ?, updated_at = ?
				 WHERE id = ?`,
			)
			.run(
				patch.name ?? cur.name,
				patch.description ?? cur.description,
				(patch.autopilot ?? cur.autopilot) ? 1 : 0,
				(patch.coverageEnabled ?? cur.coverageEnabled) ? 1 : 0,
				(patch.scopeWriteGuard ?? cur.scopeWriteGuard) ? 1 : 0,
				(patch.scopeInheritWrites ?? cur.scopeInheritWrites) ? 1 : 0,
				patch.maxWorkers ?? cur.maxWorkers,
				patch.maxTurns ?? cur.maxTurns,
				ts,
				id,
			);
		return this.getTask(id);
	}

	addTaskScope(rule: Omit<TaskScopeRule, "id" | "createdAt">): TaskScopeRule {
		const ts = nowIso();
		const res = this.db
			.prepare("INSERT INTO task_scope_rules (task_id, pattern, kind, exclude, note, created_at) VALUES (?, ?, ?, ?, ?, ?)")
			.run(rule.taskId, rule.pattern, rule.kind, rule.exclude ? 1 : 0, rule.note, ts);
		return { ...rule, id: Number(res.lastInsertRowid), createdAt: ts };
	}

	listTaskScope(taskId: number): TaskScopeRule[] {
		const rows = this.db
			.prepare("SELECT * FROM task_scope_rules WHERE task_id = ? ORDER BY id ASC")
			.all(taskId) as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			taskId: Number(r.task_id),
			pattern: String(r.pattern),
			kind: String(r.kind) as TaskScopeRule["kind"],
			exclude: Boolean(r.exclude),
			note: String(r.note),
			createdAt: String(r.created_at),
		}));
	}

	setTaskConstraints(taskId: number, constraints: string[]): TaskConstraint[] {
		const ts = nowIso();
		this.db.prepare("DELETE FROM task_constraints WHERE task_id = ?").run(taskId);
		const stmt = this.db.prepare(
			"INSERT INTO task_constraints (task_id, text, enforced, created_at) VALUES (?, ?, 1, ?)",
		);
		for (const c of constraints) {
			if (c.trim()) stmt.run(taskId, c.trim(), ts);
		}
		return this.listTaskConstraints(taskId);
	}

	listTaskConstraints(taskId: number): TaskConstraint[] {
		const rows = this.db
			.prepare("SELECT * FROM task_constraints WHERE task_id = ? ORDER BY id ASC")
			.all(taskId) as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			taskId: Number(r.task_id),
			text: String(r.text),
			enforced: Boolean(r.enforced),
			createdAt: String(r.created_at),
		}));
	}

	// ── Auth Profiles ──────────────────────────────────────────────────────

	private mapAuthProfile(r: Record<string, unknown>): TaskAuthProfile {
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			name: String(r.name),
			role: String(r.role),
			authType: String(r.auth_type) as TaskAuthProfile["authType"],
			headers: parseJson<Record<string, string>>(r.headers_json, {}),
			cookies: parseJson<Record<string, string>>(r.cookies_json, {}),
			loginUrl: String(r.login_url),
			metadata: parseJson<Record<string, unknown>>(r.metadata_json, {}),
			updatedAt: String(r.updated_at),
		};
	}

	upsertAuthProfile(profile: Omit<TaskAuthProfile, "id" | "updatedAt">): TaskAuthProfile {
		const ts = nowIso();
		this.db
			.prepare(
				`INSERT INTO task_auth_profiles (task_id, name, role, auth_type, headers_json, cookies_json, login_url, metadata_json, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT(task_id, name) DO UPDATE SET
				   role = excluded.role,
				   auth_type = excluded.auth_type,
				   headers_json = excluded.headers_json,
				   cookies_json = excluded.cookies_json,
				   login_url = excluded.login_url,
				   metadata_json = excluded.metadata_json,
				   updated_at = excluded.updated_at`,
			)
			.run(
				profile.taskId,
				profile.name,
				profile.role,
				profile.authType,
				JSON.stringify(profile.headers),
				JSON.stringify(profile.cookies),
				profile.loginUrl,
				JSON.stringify(profile.metadata),
				ts,
			);
		return this.getAuthProfile(profile.taskId, profile.name)!;
	}

	getAuthProfile(taskId: number, name: string): TaskAuthProfile | null {
		const r = this.db
			.prepare("SELECT * FROM task_auth_profiles WHERE task_id = ? AND name = ?")
			.get(taskId, name) as Record<string, unknown> | undefined;
		return r ? this.mapAuthProfile(r) : null;
	}

	listAuthProfiles(taskId: number): TaskAuthProfile[] {
		const rows = this.db
			.prepare("SELECT * FROM task_auth_profiles WHERE task_id = ? ORDER BY name ASC")
			.all(taskId) as Record<string, unknown>[];
		return rows.map((r) => this.mapAuthProfile(r));
	}

	// ── Asset Graph ────────────────────────────────────────────────────────

	private mapAsset(r: Record<string, unknown>): AssetNode {
		return {
			id: Number(r.id),
			companyId: r.company_id == null ? null : Number(r.company_id),
			taskId: r.task_id == null ? null : Number(r.task_id),
			kind: String(r.kind) as AssetKind,
			value: String(r.value),
			normalizedKey: String(r.normalized_key),
			label: String(r.label),
			metadata: parseJson<Record<string, unknown>>(r.metadata_json, {}),
			tested: Boolean(r.tested),
			testedByIntentId: r.tested_by_intent_id == null ? null : Number(r.tested_by_intent_id),
			source: String(r.source),
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
		};
	}

	upsertAssets(
		assets: Array<{
			companyId?: number | null;
			taskId?: number | null;
			kind: AssetKind;
			value: string;
			label?: string;
			metadata?: Record<string, unknown>;
			source?: string;
		}>,
	): AssetNode[] {
		const ts = nowIso();
		const out: AssetNode[] = [];
		const insert = this.db.prepare(
			`INSERT INTO assets (company_id, task_id, kind, value, normalized_key, label, metadata_json, source, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(normalized_key) DO UPDATE SET
			   company_id = COALESCE(excluded.company_id, assets.company_id),
			   task_id = COALESCE(excluded.task_id, assets.task_id),
			   label = CASE WHEN excluded.label != '' THEN excluded.label ELSE assets.label END,
			   metadata_json = excluded.metadata_json,
			   updated_at = excluded.updated_at`,
		);
		const selectByKey = this.db.prepare("SELECT * FROM assets WHERE normalized_key = ?");
		for (const a of assets) {
			const key = normalizeAssetKey(a.kind, a.value);
			insert.run(
				a.companyId ?? null,
				a.taskId ?? null,
				a.kind,
				a.value.trim(),
				key,
				a.label ?? "",
				JSON.stringify(a.metadata ?? {}),
				a.source ?? "agent",
				ts,
				ts,
			);
			const row = selectByKey.get(key) as Record<string, unknown> | undefined;
			if (row) out.push(this.mapAsset(row));
		}
		return out;
	}

	getAsset(id: number): AssetNode | null {
		const r = this.db.prepare("SELECT * FROM assets WHERE id = ?").get(id) as Record<string, unknown> | undefined;
		return r ? this.mapAsset(r) : null;
	}

	listAssets(filter?: {
		taskId?: number;
		companyId?: number;
		kind?: AssetKind;
		tested?: boolean;
		query?: string;
		limit?: number;
	}): AssetNode[] {
		const wheres: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.taskId != null) {
			wheres.push("task_id = ?");
			params.push(filter.taskId);
		}
		if (filter?.companyId != null) {
			wheres.push("company_id = ?");
			params.push(filter.companyId);
		}
		if (filter?.kind) {
			wheres.push("kind = ?");
			params.push(filter.kind);
		}
		if (filter?.tested !== undefined) {
			wheres.push("tested = ?");
			params.push(filter.tested ? 1 : 0);
		}
		const sql = `SELECT * FROM assets ${wheres.length ? `WHERE ${wheres.join(" AND ")}` : ""} ORDER BY id ASC`;
		const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
		let nodes = rows.map((r) => this.mapAsset(r));
		if (filter?.query) {
			const clauses = parseAssetDsl(filter.query);
			nodes = nodes.filter((n) => matchesAssetDsl(n, clauses));
		}
		if (filter?.limit && filter.limit > 0) {
			nodes = nodes.slice(0, filter.limit);
		}
		return nodes;
	}

	markAssetsTested(assetIds: number[], intentId: number | null = null): void {
		const ts = nowIso();
		const stmt = this.db.prepare(
			"UPDATE assets SET tested = 1, tested_by_intent_id = COALESCE(?, tested_by_intent_id), updated_at = ? WHERE id = ?",
		);
		for (const id of assetIds) {
			stmt.run(intentId, ts, id);
		}
	}

	addAssetEdge(
		fromAssetId: number,
		toAssetId: number,
		relation: string,
		metadata: Record<string, unknown> = {},
	): AssetEdge {
		const ts = nowIso();
		this.db
			.prepare(
				`INSERT INTO asset_edges (from_asset_id, to_asset_id, relation, metadata_json, created_at)
				 VALUES (?, ?, ?, ?, ?)
				 ON CONFLICT(from_asset_id, to_asset_id, relation) DO UPDATE SET metadata_json = excluded.metadata_json`,
			)
			.run(fromAssetId, toAssetId, relation, JSON.stringify(metadata), ts);
		const r = this.db
			.prepare("SELECT * FROM asset_edges WHERE from_asset_id = ? AND to_asset_id = ? AND relation = ?")
			.get(fromAssetId, toAssetId, relation) as Record<string, unknown>;
		return {
			id: Number(r.id),
			fromAssetId: Number(r.from_asset_id),
			toAssetId: Number(r.to_asset_id),
			relation: String(r.relation),
			metadata: parseJson<Record<string, unknown>>(r.metadata_json, {}),
			createdAt: String(r.created_at),
		};
	}

	getAssetNeighbors(assetId: number): {
		incoming: Array<{ edge: AssetEdge; asset: AssetNode }>;
		outgoing: Array<{ edge: AssetEdge; asset: AssetNode }>;
	} {
		const outRows = this.db
			.prepare("SELECT * FROM asset_edges WHERE from_asset_id = ?")
			.all(assetId) as Record<string, unknown>[];
		const inRows = this.db
			.prepare("SELECT * FROM asset_edges WHERE to_asset_id = ?")
			.all(assetId) as Record<string, unknown>[];

		const toEdge = (r: Record<string, unknown>): AssetEdge => ({
			id: Number(r.id),
			fromAssetId: Number(r.from_asset_id),
			toAssetId: Number(r.to_asset_id),
			relation: String(r.relation),
			metadata: parseJson<Record<string, unknown>>(r.metadata_json, {}),
			createdAt: String(r.created_at),
		});

		const outgoing = outRows
			.map((r) => {
				const edge = toEdge(r);
				const asset = this.getAsset(edge.toAssetId);
				return asset ? { edge, asset } : null;
			})
			.filter((x): x is { edge: AssetEdge; asset: AssetNode } => x !== null);

		const incoming = inRows
			.map((r) => {
				const edge = toEdge(r);
				const asset = this.getAsset(edge.fromAssetId);
				return asset ? { edge, asset } : null;
			})
			.filter((x): x is { edge: AssetEdge; asset: AssetNode } => x !== null);

		return { incoming, outgoing };
	}

	getAssetCoverage(taskId: number): AssetCoverageSummary {
		const assets = this.listAssets({ taskId });
		const byKind: Record<string, { total: number; tested: number }> = {};
		let tested = 0;
		for (const a of assets) {
			if (!byKind[a.kind]) byKind[a.kind] = { total: 0, tested: 0 };
			byKind[a.kind].total++;
			if (a.tested) {
				tested++;
				byKind[a.kind].tested++;
			}
		}
		return {
			total: assets.length,
			tested,
			untested: assets.length - tested,
			byKind,
		};
	}

	// ── Exploration Graph ──────────────────────────────────────────────────

	private mapExpNode(r: Record<string, unknown>): ExplorationNode {
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			kind: String(r.kind) as ExplorationNodeKind,
			state: String(r.state),
			summary: String(r.summary),
			payload: parseJson<Record<string, unknown>>(r.payload_json, {}),
			assetIds: parseJson<number[]>(r.asset_ids_json, []),
			blockedReason: String(r.blocked_reason),
			inherited: Boolean(r.inherited),
			sourceTaskId: r.source_task_id == null ? null : Number(r.source_task_id),
			workerId: String(r.worker_id),
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
		};
	}

	addExplorationNode(input: {
		taskId: number;
		kind: ExplorationNodeKind;
		state?: string;
		summary: string;
		payload?: Record<string, unknown>;
		assetIds?: number[];
		blockedReason?: string;
		inherited?: boolean;
		sourceTaskId?: number | null;
		workerId?: string;
	}): ExplorationNode {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO exploration_nodes (
					task_id, kind, state, summary, payload_json, asset_ids_json,
					blocked_reason, inherited, source_task_id, worker_id, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				input.taskId,
				input.kind,
				input.state ?? "open",
				input.summary,
				JSON.stringify(input.payload ?? {}),
				JSON.stringify(input.assetIds ?? []),
				input.blockedReason ?? "",
				input.inherited ? 1 : 0,
				input.sourceTaskId ?? null,
				input.workerId ?? "",
				ts,
				ts,
			);
		return this.getExplorationNode(Number(res.lastInsertRowid))!;
	}

	getExplorationNode(id: number): ExplorationNode | null {
		const r = this.db
			.prepare("SELECT * FROM exploration_nodes WHERE id = ?")
			.get(id) as Record<string, unknown> | undefined;
		return r ? this.mapExpNode(r) : null;
	}

	updateExplorationNode(
		id: number,
		patch: Partial<Pick<ExplorationNode, "state" | "summary" | "payload" | "blockedReason" | "workerId">>,
	): ExplorationNode | null {
		const existing = this.getExplorationNode(id);
		if (!existing) return null;
		const ts = nowIso();
		this.db
			.prepare(
				`UPDATE exploration_nodes SET
				   state = ?, summary = ?, payload_json = ?, blocked_reason = ?, worker_id = ?, updated_at = ?
				 WHERE id = ?`,
			)
			.run(
				patch.state ?? existing.state,
				patch.summary ?? existing.summary,
				JSON.stringify(patch.payload ?? existing.payload),
				patch.blockedReason ?? existing.blockedReason,
				patch.workerId ?? existing.workerId,
				ts,
				id,
			);
		return this.getExplorationNode(id);
	}

	listExplorationNodes(filter: {
		taskId: number;
		kind?: ExplorationNodeKind;
		state?: string;
		q?: string;
		before?: number;
		limit?: number;
	}): { nodes: ExplorationNode[]; total: number; hasMore: boolean; nextBefore: number | null } {
		const wheres: string[] = ["task_id = ?"];
		const params: Array<string | number> = [filter.taskId];
		if (filter.kind) {
			wheres.push("kind = ?");
			params.push(filter.kind);
		}
		if (filter.state) {
			wheres.push("state = ?");
			params.push(filter.state);
		}
		if (filter.q) {
			wheres.push("LOWER(summary) LIKE ?");
			params.push(`%${filter.q.toLowerCase()}%`);
		}
		const countRow = this.db
			.prepare(`SELECT COUNT(*) AS cnt FROM exploration_nodes WHERE ${wheres.join(" AND ")}`)
			.get(...params) as Record<string, unknown>;
		const total = Number(countRow.cnt);

		const pageWheres = [...wheres];
		const pageParams = [...params];
		if (filter.before && filter.before > 0) {
			pageWheres.push("id < ?");
			pageParams.push(filter.before);
		}
		const limit = Math.min(Math.max(filter.limit ?? 20, 1), 100);
		pageParams.push(limit + 1);

		const rows = this.db
			.prepare(`SELECT * FROM exploration_nodes WHERE ${pageWheres.join(" AND ")} ORDER BY id DESC LIMIT ?`)
			.all(...pageParams) as Record<string, unknown>[];
		const hasMore = rows.length > limit;
		const sliced = hasMore ? rows.slice(0, limit) : rows;
		const nodes = sliced.map((r) => this.mapExpNode(r));
		const nextBefore = hasMore && nodes.length > 0 ? nodes[nodes.length - 1].id : null;
		return { nodes, total, hasMore, nextBefore };
	}

	addExplorationEdge(
		taskId: number,
		fromNodeId: number,
		toNodeId: number,
		relation: ExplorationEdge["relation"],
	): ExplorationEdge {
		const ts = nowIso();
		this.db
			.prepare(
				`INSERT OR IGNORE INTO exploration_edges (task_id, from_node_id, to_node_id, relation, created_at)
				 VALUES (?, ?, ?, ?, ?)`,
			)
			.run(taskId, fromNodeId, toNodeId, relation, ts);
		const r = this.db
			.prepare(
				"SELECT * FROM exploration_edges WHERE task_id = ? AND from_node_id = ? AND to_node_id = ? AND relation = ?",
			)
			.get(taskId, fromNodeId, toNodeId, relation) as Record<string, unknown>;
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			fromNodeId: Number(r.from_node_id),
			toNodeId: Number(r.to_node_id),
			relation: String(r.relation) as ExplorationEdge["relation"],
			createdAt: String(r.created_at),
		};
	}

	listExplorationEdges(taskId: number): ExplorationEdge[] {
		const rows = this.db
			.prepare("SELECT * FROM exploration_edges WHERE task_id = ? ORDER BY id ASC")
			.all(taskId) as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			taskId: Number(r.task_id),
			fromNodeId: Number(r.from_node_id),
			toNodeId: Number(r.to_node_id),
			relation: String(r.relation) as ExplorationEdge["relation"],
			createdAt: String(r.created_at),
		}));
	}

	getGraphOverview(taskId: number): GraphOverview {
		const task = this.getTask(taskId);
		const edges = this.listExplorationEdges(taskId);
		const parentsOf = new Map<number, number[]>();
		const yieldsOf = new Map<number, number[]>();
		for (const e of edges) {
			if (e.relation === "derives") {
				const arr = parentsOf.get(e.toNodeId) ?? [];
				arr.push(e.fromNodeId);
				parentsOf.set(e.toNodeId, arr);
			}
			if (e.relation === "yields") {
				const arr = yieldsOf.get(e.fromNodeId) ?? [];
				arr.push(e.toNodeId);
				yieldsOf.set(e.fromNodeId, arr);
			}
		}

		const goals = this.listExplorationNodes({ taskId, kind: "goal", limit: 50 }).nodes;
		const intentsRaw = this.listExplorationNodes({ taskId, kind: "intent", limit: 100 }).nodes;
		const ownFacts = this.listExplorationNodes({ taskId, kind: "fact", limit: 15 }).nodes;
		const inheritedFacts =
			task?.parentTaskId != null
				? this.listExplorationNodes({ taskId: task.parentTaskId, kind: "fact", limit: 10 }).nodes.map((n) => ({
						...n,
						inherited: true,
						sourceTaskId: task.parentTaskId,
					}))
				: [];
		const recentFacts = [...ownFacts, ...inheritedFacts];
		const hints = this.listExplorationNodes({ taskId, kind: "hint", limit: 20 }).nodes;
		const findings = this.listFindings(taskId);
		const constraints = this.listTaskConstraints(taskId);
		const tokenTotals = this.getTaskTokenTotals(taskId);

		const intents = intentsRaw.map((n) => ({
			id: n.id,
			summary: n.summary,
			state: n.state,
			...(n.blockedReason ? { blockedReason: n.blockedReason } : {}),
			assetIds: n.assetIds,
			parents: parentsOf.get(n.id) ?? [],
			yields: yieldsOf.get(n.id) ?? [],
			tokens: tokenTotals.byIntent[n.id] ?? 0,
			...(typeof n.payload.wallMs === "number" ? { wallMs: n.payload.wallMs } : {}),
		}));

		return {
			taskId,
			goals,
			constraints,
			intents,
			recentFacts,
			findings,
			hints,
			coverage: task?.coverageEnabled ? this.getAssetCoverage(taskId) : null,
		};
	}

	// ── Findings & Retests ─────────────────────────────────────────────────

	private mapFinding(r: Record<string, unknown>): Finding {
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			nodeId: r.node_id == null ? null : Number(r.node_id),
			intentId: r.intent_id == null ? null : Number(r.intent_id),
			title: String(r.title),
			vulnClass: String(r.vuln_class),
			severity: String(r.severity) as Finding["severity"],
			status: String(r.status) as FindingStatus,
			summary: String(r.summary),
			description: String(r.description),
			reproduction: String(r.reproduction),
			remediation: String(r.remediation),
			evidence: String(r.evidence),
			evidenceIds: parseJson<number[]>(r.evidence_ids_json, []),
			assetIds: parseJson<number[]>(r.asset_ids_json, []),
			cvss: r.cvss == null ? null : Number(r.cvss),
			cwe: String(r.cwe),
			fingerprint: String(r.fingerprint),
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
		};
	}

	addFinding(input: Omit<Finding, "id" | "createdAt" | "updatedAt">): Finding {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO findings (
					task_id, node_id, intent_id, title, vuln_class, severity, status,
					summary, description, reproduction, remediation, evidence,
					evidence_ids_json, asset_ids_json, cvss, cwe, fingerprint, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				input.taskId,
				input.nodeId,
				input.intentId,
				input.title,
				input.vulnClass,
				input.severity,
				input.status,
				input.summary,
				input.description,
				input.reproduction,
				input.remediation,
				input.evidence,
				JSON.stringify(input.evidenceIds),
				JSON.stringify(input.assetIds),
				input.cvss,
				input.cwe,
				input.fingerprint,
				ts,
				ts,
			);
		return this.getFinding(Number(res.lastInsertRowid))!;
	}

	getFinding(id: number): Finding | null {
		const r = this.db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as Record<string, unknown> | undefined;
		return r ? this.mapFinding(r) : null;
	}

	listFindings(taskId?: number): Finding[] {
		const task = taskId != null ? this.getTask(taskId) : null;
		const rows =
			taskId != null
				? task?.parentTaskId != null
					? (this.db
							.prepare("SELECT * FROM findings WHERE task_id = ? OR task_id = ? ORDER BY id DESC")
							.all(taskId, task.parentTaskId) as Record<string, unknown>[])
					: (this.db.prepare("SELECT * FROM findings WHERE task_id = ? ORDER BY id DESC").all(taskId) as Record<
							string,
							unknown
						>[])
				: (this.db.prepare("SELECT * FROM findings ORDER BY id DESC").all() as Record<string, unknown>[]);
		return rows.map((r) => this.mapFinding(r));
	}

	updateFindingStatus(id: number, status: FindingStatus): Finding | null {
		const ts = nowIso();
		this.db.prepare("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?").run(status, ts, id);
		return this.getFinding(id);
	}

	findByFingerprint(fingerprint: string): Finding | null {
		if (!fingerprint) return null;
		const r = this.db
			.prepare("SELECT * FROM findings WHERE fingerprint = ? ORDER BY id ASC LIMIT 1")
			.get(fingerprint) as Record<string, unknown> | undefined;
		return r ? this.mapFinding(r) : null;
	}

	addFindingRetest(retest: Omit<FindingRetest, "id" | "createdAt">): FindingRetest {
		const ts = nowIso();
		const res = this.db
			.prepare("INSERT INTO finding_retests (finding_id, task_id, status, notes, evidence, created_at) VALUES (?, ?, ?, ?, ?, ?)")
			.run(retest.findingId, retest.taskId, retest.status, retest.notes, retest.evidence, ts);
		return { ...retest, id: Number(res.lastInsertRowid), createdAt: ts };
	}

	listFindingRetests(findingId: number): FindingRetest[] {
		const rows = this.db
			.prepare("SELECT * FROM finding_retests WHERE finding_id = ? ORDER BY id DESC")
			.all(findingId) as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			findingId: Number(r.finding_id),
			taskId: Number(r.task_id),
			status: String(r.status) as FindingRetest["status"],
			notes: String(r.notes),
			evidence: String(r.evidence),
			createdAt: String(r.created_at),
		}));
	}

	// ── Artifacts ──────────────────────────────────────────────────────────

	private mapArtifact(r: Record<string, unknown>): ArtifactRecord {
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			intentId: r.intent_id == null ? null : Number(r.intent_id),
			name: String(r.name),
			kind: String(r.kind),
			mimeType: String(r.mime_type),
			sha256: String(r.sha256),
			sizeBytes: Number(r.size_bytes),
			path: String(r.path),
			description: String(r.description),
			createdAt: String(r.created_at),
		};
	}

	addArtifact(artifact: Omit<ArtifactRecord, "id" | "createdAt">): ArtifactRecord {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO artifacts (task_id, intent_id, name, kind, mime_type, sha256, size_bytes, path, description, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				artifact.taskId,
				artifact.intentId,
				artifact.name,
				artifact.kind,
				artifact.mimeType,
				artifact.sha256,
				artifact.sizeBytes,
				artifact.path,
				artifact.description,
				ts,
			);
		return this.getArtifact(Number(res.lastInsertRowid))!;
	}

	listArtifacts(taskId: number): ArtifactRecord[] {
		const rows = this.db
			.prepare("SELECT * FROM artifacts WHERE task_id = ? ORDER BY id DESC")
			.all(taskId) as Record<string, unknown>[];
		return rows.map((r) => this.mapArtifact(r));
	}

	getArtifact(id: number): ArtifactRecord | null {
		const r = this.db.prepare("SELECT * FROM artifacts WHERE id = ?").get(id) as Record<string, unknown> | undefined;
		return r ? this.mapArtifact(r) : null;
	}

	// ── Intercept Rules & Approvals ────────────────────────────────────────

	private mapInterceptRule(r: Record<string, unknown>): InterceptRule {
		return {
			id: Number(r.id),
			name: String(r.name),
			scope: String(r.scope) as InterceptScope,
			taskId: r.task_id == null ? null : Number(r.task_id),
			assetPattern: String(r.asset_pattern),
			target: String(r.target) as InterceptRule["target"],
			matchType: String(r.match_type) as InterceptRule["matchType"],
			pattern: String(r.pattern),
			action: String(r.action) as InterceptRule["action"],
			ruleClass: String(r.rule_class) as InterceptRule["ruleClass"],
			rationale: String(r.rationale),
			message: String(r.message),
			priority: Number(r.priority),
			enabled: Boolean(r.enabled),
			seedBatch: String(r.seed_batch),
			timeoutEnabled: Boolean(r.timeout_enabled),
			timeoutSeconds: Number(r.timeout_seconds),
			timeoutAction: String(r.timeout_action) as InterceptRule["timeoutAction"],
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
		};
	}

	upsertInterceptRule(rule: Omit<InterceptRule, "id" | "createdAt" | "updatedAt">): InterceptRule {
		const ts = nowIso();
		this.db
			.prepare(
				`INSERT INTO intercept_rules (
					name, scope, task_id, asset_pattern, target, match_type, pattern, action,
					rule_class, rationale, message, priority, enabled, seed_batch,
					timeout_enabled, timeout_seconds, timeout_action, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(name) DO UPDATE SET
					scope = excluded.scope,
					task_id = excluded.task_id,
					asset_pattern = excluded.asset_pattern,
					target = excluded.target,
					match_type = excluded.match_type,
					pattern = excluded.pattern,
					action = excluded.action,
					rule_class = excluded.rule_class,
					rationale = excluded.rationale,
					message = excluded.message,
					priority = excluded.priority,
					enabled = excluded.enabled,
					seed_batch = excluded.seed_batch,
					timeout_enabled = excluded.timeout_enabled,
					timeout_seconds = excluded.timeout_seconds,
					timeout_action = excluded.timeout_action,
					updated_at = excluded.updated_at`,
			)
			.run(
				rule.name,
				rule.scope,
				rule.taskId,
				rule.assetPattern,
				rule.target,
				rule.matchType,
				rule.pattern,
				rule.action,
				rule.ruleClass,
				rule.rationale,
				rule.message,
				rule.priority,
				rule.enabled ? 1 : 0,
				rule.seedBatch,
				rule.timeoutEnabled ? 1 : 0,
				rule.timeoutSeconds,
				rule.timeoutAction,
				ts,
				ts,
			);
		const row = this.db.prepare("SELECT * FROM intercept_rules WHERE name = ?").get(rule.name) as Record<
			string,
			unknown
		>;
		return this.mapInterceptRule(row);
	}

	listInterceptRules(filter?: { scope?: InterceptScope; taskId?: number; enabledOnly?: boolean }): InterceptRule[] {
		const wheres: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.scope) {
			wheres.push("scope = ?");
			params.push(filter.scope);
		}
		if (filter?.taskId != null) {
			wheres.push("(task_id IS NULL OR task_id = ?)");
			params.push(filter.taskId);
		}
		if (filter?.enabledOnly) {
			wheres.push("enabled = 1");
		}
		const sql = `SELECT * FROM intercept_rules ${wheres.length ? `WHERE ${wheres.join(" AND ")}` : ""} ORDER BY priority DESC, id ASC`;
		const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
		return rows.map((r) => this.mapInterceptRule(r));
	}

	private mapApproval(r: Record<string, unknown>): ApprovalRequest {
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			intentId: r.intent_id == null ? null : Number(r.intent_id),
			ruleId: r.rule_id == null ? null : Number(r.rule_id),
			ruleName: String(r.rule_name),
			toolName: String(r.tool_name),
			toolInput: String(r.tool_input),
			action: String(r.action) as ApprovalRequest["action"],
			status: String(r.status) as ApprovalStatus,
			reason: String(r.reason),
			judgeOutput: String(r.judge_output),
			decidedBy: String(r.decided_by),
			createdAt: String(r.created_at),
			decidedAt: r.decided_at == null ? null : String(r.decided_at),
		};
	}

	createApprovalRequest(req: Omit<ApprovalRequest, "id" | "createdAt" | "decidedAt">): ApprovalRequest {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO approval_requests (
					task_id, intent_id, rule_id, rule_name, tool_name, tool_input,
					action, status, reason, judge_output, decided_by, created_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				req.taskId,
				req.intentId,
				req.ruleId,
				req.ruleName,
				req.toolName,
				req.toolInput,
				req.action,
				req.status,
				req.reason,
				req.judgeOutput,
				req.decidedBy,
				ts,
			);
		return this.getApprovalRequest(Number(res.lastInsertRowid))!;
	}

	getApprovalRequest(id: number): ApprovalRequest | null {
		const r = this.db
			.prepare("SELECT * FROM approval_requests WHERE id = ?")
			.get(id) as Record<string, unknown> | undefined;
		return r ? this.mapApproval(r) : null;
	}

	listApprovalRequests(filter?: { taskId?: number; status?: ApprovalStatus }): ApprovalRequest[] {
		const wheres: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.taskId != null) {
			wheres.push("task_id = ?");
			params.push(filter.taskId);
		}
		if (filter?.status) {
			wheres.push("status = ?");
			params.push(filter.status);
		}
		const sql = `SELECT * FROM approval_requests ${wheres.length ? `WHERE ${wheres.join(" AND ")}` : ""} ORDER BY id DESC`;
		const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
		return rows.map((r) => this.mapApproval(r));
	}

	resolveApprovalRequest(
		id: number,
		status: ApprovalStatus,
		decidedBy: string,
		reason = "",
		judgeOutput = "",
	): ApprovalRequest | null {
		const ts = nowIso();
		this.db
			.prepare(
				`UPDATE approval_requests
				 SET status = ?, decided_by = ?, reason = CASE WHEN ? != '' THEN ? ELSE reason END,
				     judge_output = CASE WHEN ? != '' THEN ? ELSE judge_output END, decided_at = ?
				 WHERE id = ?`,
			)
			.run(status, decidedBy, reason, reason, judgeOutput, judgeOutput, ts, id);
		return this.getApprovalRequest(id);
	}

	// ── Traffic ────────────────────────────────────────────────────────────

	addTrafficRecord(rec: Omit<TrafficRecord, "id" | "createdAt">): TrafficRecord {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO traffic_records (
					task_id, intent_id, finding_id, method, url, host, status_code,
					request_headers_json, request_body, response_headers_json, response_body, duration_ms, created_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				rec.taskId,
				rec.intentId,
				rec.findingId,
				rec.method,
				rec.url,
				rec.host,
				rec.statusCode,
				JSON.stringify(rec.requestHeaders),
				rec.requestBody,
				JSON.stringify(rec.responseHeaders),
				rec.responseBody,
				rec.durationMs,
				ts,
			);
		return { ...rec, id: Number(res.lastInsertRowid), createdAt: ts };
	}

	listTrafficRecords(filter?: {
		taskId?: number;
		intentId?: number;
		findingId?: number;
		limit?: number;
	}): TrafficRecord[] {
		const wheres: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.taskId != null) {
			wheres.push("task_id = ?");
			params.push(filter.taskId);
		}
		if (filter?.intentId != null) {
			wheres.push("intent_id = ?");
			params.push(filter.intentId);
		}
		if (filter?.findingId != null) {
			wheres.push("finding_id = ?");
			params.push(filter.findingId);
		}
		const limit = Math.min(Math.max(filter?.limit ?? 50, 1), 500);
		params.push(limit);
		const sql = `SELECT * FROM traffic_records ${wheres.length ? `WHERE ${wheres.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ?`;
		const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			taskId: Number(r.task_id),
			intentId: r.intent_id == null ? null : Number(r.intent_id),
			findingId: r.finding_id == null ? null : Number(r.finding_id),
			method: String(r.method),
			url: String(r.url),
			host: String(r.host),
			statusCode: Number(r.status_code),
			requestHeaders: parseJson<Record<string, string>>(r.request_headers_json, {}),
			requestBody: String(r.request_body),
			responseHeaders: parseJson<Record<string, string>>(r.response_headers_json, {}),
			responseBody: String(r.response_body),
			durationMs: Number(r.duration_ms),
			createdAt: String(r.created_at),
		}));
	}

	// ── Worker Traces ──────────────────────────────────────────────────────

	private mapTrace(r: Record<string, unknown>): WorkerTraceEntry {
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			intentId: Number(r.intent_id),
			workerId: String(r.worker_id),
			turn: Number(r.turn),
			toolName: String(r.tool_name),
			toolArgs: String(r.tool_args),
			toolOutput: String(r.tool_output),
			isError: Boolean(r.is_error),
			durationMs: Number(r.duration_ms),
			createdAt: String(r.created_at),
		};
	}

	addWorkerTrace(entry: Omit<WorkerTraceEntry, "id" | "createdAt">): WorkerTraceEntry {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO worker_traces (task_id, intent_id, worker_id, turn, tool_name, tool_args, tool_output, is_error, duration_ms, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				entry.taskId,
				entry.intentId,
				entry.workerId,
				entry.turn,
				entry.toolName,
				entry.toolArgs,
				entry.toolOutput,
				entry.isError ? 1 : 0,
				entry.durationMs,
				ts,
			);
		return { ...entry, id: Number(res.lastInsertRowid), createdAt: ts };
	}

	listWorkerTraces(filter: { taskId: number; intentId?: number; limit?: number }): WorkerTraceEntry[] {
		const wheres = ["task_id = ?"];
		const params: Array<string | number> = [filter.taskId];
		if (filter.intentId != null) {
			wheres.push("intent_id = ?");
			params.push(filter.intentId);
		}
		const limit = Math.min(Math.max(filter.limit ?? 100, 1), 500);
		params.push(limit);
		const rows = this.db
			.prepare(`SELECT * FROM worker_traces WHERE ${wheres.join(" AND ")} ORDER BY id ASC LIMIT ?`)
			.all(...params) as Record<string, unknown>[];
		return rows.map((r) => this.mapTrace(r));
	}

	searchWorkerTraces(taskId: number, query: string, limit = 50): WorkerTraceEntry[] {
		const like = `%${query.toLowerCase()}%`;
		const rows = this.db
			.prepare(
				`SELECT * FROM worker_traces
				 WHERE task_id = ? AND (LOWER(tool_name) LIKE ? OR LOWER(tool_args) LIKE ? OR LOWER(tool_output) LIKE ?)
				 ORDER BY id DESC LIMIT ?`,
			)
			.all(taskId, like, like, like, Math.min(Math.max(limit, 1), 200)) as Record<string, unknown>[];
		return rows.map((r) => this.mapTrace(r));
	}

	// ── LLM Usage ──────────────────────────────────────────────────────────

	recordLlmUsage(usage: Omit<LlmUsageRecord, "id" | "createdAt">): LlmUsageRecord {
		const ts = nowIso();
		const res = this.db
			.prepare(
				`INSERT INTO llm_usage (task_id, intent_id, role, provider, model, input_tokens, output_tokens, cache_read_tokens, cost_usd, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				usage.taskId,
				usage.intentId,
				usage.role,
				usage.provider,
				usage.model,
				usage.inputTokens,
				usage.outputTokens,
				usage.cacheReadTokens,
				usage.costUsd,
				ts,
			);
		return { ...usage, id: Number(res.lastInsertRowid), createdAt: ts };
	}

	getTaskTokenTotals(taskId: number): { totalTokens: number; costUsd: number; byIntent: Record<number, number> } {
		const rows = this.db
			.prepare(
				"SELECT intent_id, SUM(input_tokens + output_tokens) AS tokens, SUM(cost_usd) AS cost FROM llm_usage WHERE task_id = ? GROUP BY intent_id",
			)
			.all(taskId) as Record<string, unknown>[];
		let totalTokens = 0;
		let costUsd = 0;
		const byIntent: Record<number, number> = {};
		for (const r of rows) {
			const tok = Number(r.tokens ?? 0);
			totalTokens += tok;
			costUsd += Number(r.cost ?? 0);
			if (r.intent_id != null) {
				byIntent[Number(r.intent_id)] = tok;
			}
		}
		return { totalTokens, costUsd, byIntent };
	}


	getTaskUsageBreakdown(taskId: number): {
		totalInputTokens: number;
		totalOutputTokens: number;
		totalTokens: number;
		knownCostUsd: number | null;
		byModel: Array<{ provider: string; model: string; inputTokens: number; outputTokens: number; totalTokens: number; costUsd: number | null }>;
	} {
		const rows = this.db
			.prepare(
				"SELECT provider, model, SUM(input_tokens) AS inp, SUM(output_tokens) AS outp, SUM(cost_usd) AS cost, COUNT(*) AS cnt FROM llm_usage WHERE task_id = ? GROUP BY provider, model ORDER BY (SUM(input_tokens) + SUM(output_tokens)) DESC",
			)
			.all(taskId) as Record<string, unknown>[];
		let totalInputTokens = 0;
		let totalOutputTokens = 0;
		let sumCost = 0;
		let hasAnyKnownCost = false;
		const byModel = rows.map((r) => {
			const inp = Number(r.inp ?? 0);
			const outp = Number(r.outp ?? 0);
			const rawCost = Number(r.cost ?? 0);
			totalInputTokens += inp;
			totalOutputTokens += outp;
			const known = rawCost > 0;
			if (known) {
				sumCost += rawCost;
				hasAnyKnownCost = true;
			}
			return {
				provider: String(r.provider),
				model: String(r.model),
				inputTokens: inp,
				outputTokens: outp,
				totalTokens: inp + outp,
				costUsd: known ? rawCost : null,
			};
		});
		return {
			totalInputTokens,
			totalOutputTokens,
			totalTokens: totalInputTokens + totalOutputTokens,
			knownCostUsd: hasAnyKnownCost ? sumCost : null,
			byModel,
		};
	}

	// ── Side Questions ─────────────────────────────────────────────────────

	addSideQuestion(taskId: number, question: string): SideQuestion {
		const ts = nowIso();
		const res = this.db
			.prepare("INSERT INTO side_questions (task_id, question, status, created_at) VALUES (?, ?, 'open', ?)")
			.run(taskId, question, ts);
		return { id: Number(res.lastInsertRowid), taskId, question, answer: "", status: "open", createdAt: ts, answeredAt: null };
	}

	answerSideQuestion(id: number, answer: string): SideQuestion | null {
		const ts = nowIso();
		this.db
			.prepare("UPDATE side_questions SET answer = ?, status = 'answered', answered_at = ? WHERE id = ?")
			.run(answer, ts, id);
		const r = this.db.prepare("SELECT * FROM side_questions WHERE id = ?").get(id) as Record<string, unknown> | undefined;
		if (!r) return null;
		return {
			id: Number(r.id),
			taskId: Number(r.task_id),
			question: String(r.question),
			answer: String(r.answer),
			status: String(r.status) as SideQuestion["status"],
			createdAt: String(r.created_at),
			answeredAt: r.answered_at == null ? null : String(r.answered_at),
		};
	}

	listSideQuestions(taskId: number): SideQuestion[] {
		const rows = this.db
			.prepare("SELECT * FROM side_questions WHERE task_id = ? ORDER BY id DESC")
			.all(taskId) as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			taskId: Number(r.task_id),
			question: String(r.question),
			answer: String(r.answer),
			status: String(r.status) as SideQuestion["status"],
			createdAt: String(r.created_at),
			answeredAt: r.answered_at == null ? null : String(r.answered_at),
		}));
	}

	// ── Notification Channels ──────────────────────────────────────────────

	upsertNotificationChannel(ch: Omit<NotificationChannel, "id" | "createdAt">): NotificationChannel {
		const ts = nowIso();
		this.db
			.prepare(
				`INSERT INTO notification_channels (name, kind, enabled, config_json, events_json, min_severity, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT(name) DO UPDATE SET
				   kind = excluded.kind,
				   enabled = excluded.enabled,
				   config_json = excluded.config_json,
				   events_json = excluded.events_json,
				   min_severity = excluded.min_severity`,
			)
			.run(ch.name, ch.kind, ch.enabled ? 1 : 0, JSON.stringify(ch.config), JSON.stringify(ch.events), ch.minSeverity, ts);
		const r = this.db
			.prepare("SELECT * FROM notification_channels WHERE name = ?")
			.get(ch.name) as Record<string, unknown>;
		return {
			id: Number(r.id),
			name: String(r.name),
			kind: String(r.kind) as NotificationChannel["kind"],
			enabled: Boolean(r.enabled),
			config: parseJson<Record<string, unknown>>(r.config_json, {}),
			events: parseJson<string[]>(r.events_json, []),
			minSeverity: String(r.min_severity) as NotificationChannel["minSeverity"],
			createdAt: String(r.created_at),
		};
	}

	listNotificationChannels(): NotificationChannel[] {
		const rows = this.db.prepare("SELECT * FROM notification_channels ORDER BY id ASC").all() as Record<string, unknown>[];
		return rows.map((r) => ({
			id: Number(r.id),
			name: String(r.name),
			kind: String(r.kind) as NotificationChannel["kind"],
			enabled: Boolean(r.enabled),
			config: parseJson<Record<string, unknown>>(r.config_json, {}),
			events: parseJson<string[]>(r.events_json, []),
			minSeverity: String(r.min_severity) as NotificationChannel["minSeverity"],
			createdAt: String(r.created_at),
		}));
	}

	// ── Vuln Intel ─────────────────────────────────────────────────────────

	private mapVuln(r: Record<string, unknown>): VulnIntelEntry {
		return {
			id: String(r.id),
			source: String(r.source) as VulnIntelEntry["source"],
			cveId: String(r.cve_id),
			title: String(r.title),
			severity: String(r.severity) as VulnIntelEntry["severity"],
			cvss: r.cvss == null ? null : Number(r.cvss),
			affectedProduct: String(r.affected_product),
			affectedVersions: String(r.affected_versions),
			description: String(r.description),
			references: parseJson<string[]>(r.references_json, []),
			pocTemplate: String(r.poc_template),
			publishedAt: String(r.published_at),
			updatedAt: String(r.updated_at),
		};
	}

	upsertVulnIntel(entries: VulnIntelEntry[]): number {
		const stmt = this.db.prepare(
			`INSERT INTO vuln_intel (
				id, source, cve_id, title, severity, cvss, affected_product,
				affected_versions, description, references_json, poc_template, published_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				title = excluded.title,
				severity = excluded.severity,
				cvss = excluded.cvss,
				affected_product = excluded.affected_product,
				affected_versions = excluded.affected_versions,
				description = excluded.description,
				references_json = excluded.references_json,
				poc_template = excluded.poc_template,
				updated_at = excluded.updated_at`,
		);
		let count = 0;
		for (const e of entries) {
			stmt.run(
				e.id,
				e.source,
				e.cveId,
				e.title,
				e.severity,
				e.cvss,
				e.affectedProduct,
				e.affectedVersions,
				e.description,
				JSON.stringify(e.references),
				e.pocTemplate,
				e.publishedAt,
				e.updatedAt || nowIso(),
			);
			count++;
		}
		return count;
	}

	searchVulnIntel(query: string, limit = 20): VulnIntelEntry[] {
		const like = `%${query.toLowerCase()}%`;
		const rows = this.db
			.prepare(
				`SELECT * FROM vuln_intel
				 WHERE LOWER(id) LIKE ? OR LOWER(cve_id) LIKE ? OR LOWER(title) LIKE ?
				    OR LOWER(affected_product) LIKE ? OR LOWER(description) LIKE ?
				 ORDER BY COALESCE(cvss, 0) DESC, published_at DESC LIMIT ?`,
			)
			.all(like, like, like, like, like, Math.min(Math.max(limit, 1), 100)) as Record<string, unknown>[];
		return rows.map((r) => this.mapVuln(r));
	}

	getVulnIntel(idOrCve: string): VulnIntelEntry | null {
		const r = this.db
			.prepare("SELECT * FROM vuln_intel WHERE id = ? OR LOWER(cve_id) = LOWER(?) LIMIT 1")
			.get(idOrCve, idOrCve) as Record<string, unknown> | undefined;
		return r ? this.mapVuln(r) : null;
	}

	listRecentCriticalVulns(limit = 20): VulnIntelEntry[] {
		const rows = this.db
			.prepare(
				"SELECT * FROM vuln_intel WHERE severity IN ('critical', 'high') ORDER BY published_at DESC, COALESCE(cvss, 0) DESC LIMIT ?",
			)
			.all(Math.min(Math.max(limit, 1), 100)) as Record<string, unknown>[];
		return rows.map((r) => this.mapVuln(r));
	}

	// ── Settings ───────────────────────────────────────────────────────────

	getSetting(key: string): string | null {
		const r = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as Record<string, unknown> | undefined;
		return r ? String(r.value) : null;
	}

	setSetting(key: string, value: string): void {
		this.db
			.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
			.run(key, value);
	}
}
