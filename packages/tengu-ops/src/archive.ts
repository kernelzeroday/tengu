import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type {
	ArtifactRecord,
	AssetNode,
	ExplorationEdge,
	ExplorationNode,
	Finding,
	FindingRetest,
	Task,
	TaskConstraint,
	TaskScopeRule,
	TenguStore,
	TrafficRecord,
} from "@tengu/store";
import { EvidenceStore } from "./evidence.ts";

export interface PortableArtifactBundle {
	meta: ArtifactRecord;
	base64: string;
}

export interface PortableTaskArchive {
	schema: "tengu-task-archive";
	version: 1;
	exportedAt: string;
	task: Task;
	scopeRules: TaskScopeRule[];
	constraints: TaskConstraint[];
	assets: AssetNode[];
	explorationNodes: ExplorationNode[];
	explorationEdges: ExplorationEdge[];
	findings: Finding[];
	retests: FindingRetest[];
	traffic: TrafficRecord[];
	artifacts: PortableArtifactBundle[];
}

export interface ArchiveValidationResult {
	valid: boolean;
	errors: string[];
	summary: {
		taskName: string;
		assets: number;
		findings: number;
		artifacts: number;
		traffic: number;
	} | null;
}

export function exportTaskArchive(store: TenguStore, taskId: number): PortableTaskArchive {
	const task = store.getTask(taskId);
	if (!task) throw new Error(`Task #${taskId} not found`);

	const findings = store.listFindings(taskId);
	const retests: FindingRetest[] = [];
	for (const f of findings) {
		retests.push(...store.listFindingRetests(f.id));
	}

	const artifacts: PortableArtifactBundle[] = [];
	for (const art of store.listArtifacts(taskId)) {
		if (!existsSync(art.path)) continue;
		const buf = readFileSync(art.path);
		artifacts.push({ meta: art, base64: buf.toString("base64") });
	}

	return {
		schema: "tengu-task-archive",
		version: 1,
		exportedAt: new Date().toISOString(),
		task,
		scopeRules: store.listTaskScope(taskId),
		constraints: store.listTaskConstraints(taskId),
		assets: store.listAssets({ taskId, limit: 10_000 }),
		explorationNodes: store.listExplorationNodes({ taskId, limit: 100 }).nodes,
		explorationEdges: store.listExplorationEdges(taskId),
		findings,
		retests,
		traffic: store.listTrafficRecords({ taskId, limit: 500 }),
		artifacts,
	};
}

export function validateTaskArchive(raw: string | PortableTaskArchive): ArchiveValidationResult {
	const errors: string[] = [];
	let parsed: PortableTaskArchive;
	if (typeof raw === "string") {
		try {
			parsed = JSON.parse(raw) as PortableTaskArchive;
		} catch (err) {
			return { valid: false, errors: [`Invalid JSON: ${err instanceof Error ? err.message : String(err)}`], summary: null };
		}
	} else {
		parsed = raw;
	}

	if (!parsed || parsed.schema !== "tengu-task-archive") {
		errors.push("Missing or invalid archive schema (expected 'tengu-task-archive').");
	}
	if (parsed?.version !== 1) {
		errors.push(`Unsupported archive version: ${String(parsed?.version)}`);
	}
	if (!parsed?.task?.name) {
		errors.push("Archive missing task.name.");
	}
	if (!Array.isArray(parsed?.assets) || !Array.isArray(parsed?.findings) || !Array.isArray(parsed?.artifacts)) {
		errors.push("Archive missing required arrays (assets, findings, artifacts).");
	}

	// Verify SHA-256 of every bundled artifact before any restore is permitted
	for (const item of parsed?.artifacts ?? []) {
		if (!item?.meta?.sha256 || typeof item.base64 !== "string") {
			errors.push("Artifact entry missing meta.sha256 or base64 payload.");
			continue;
		}
		const buf = Buffer.from(item.base64, "base64");
		const actual = createHash("sha256").update(buf).digest("hex");
		if (actual !== item.meta.sha256) {
			errors.push(`Artifact "${item.meta.name}" SHA-256 mismatch: expected ${item.meta.sha256}, got ${actual}`);
		}
	}

	return {
		valid: errors.length === 0,
		errors,
		summary: parsed?.task?.name
			? {
					taskName: parsed.task.name,
					assets: Array.isArray(parsed.assets) ? parsed.assets.length : 0,
					findings: Array.isArray(parsed.findings) ? parsed.findings.length : 0,
					artifacts: Array.isArray(parsed.artifacts) ? parsed.artifacts.length : 0,
					traffic: Array.isArray(parsed.traffic) ? parsed.traffic.length : 0,
				}
			: null,
	};
}

/**
 * Validates and restores a portable task archive into a target store & evidence directory.
 * Fails atomically BEFORE writing any records if validation or artifact hash checks fail.
 */
export function restoreTaskArchive(
	store: TenguStore,
	evidenceDir: string,
	raw: string | PortableTaskArchive,
): { task: Task; restoredAssets: number; restoredFindings: number; restoredArtifacts: number } {
	const check = validateTaskArchive(raw);
	if (!check.valid) {
		throw new Error(`Archive validation failed: ${check.errors.join("; ")}`);
	}
	const archive = typeof raw === "string" ? (JSON.parse(raw) as PortableTaskArchive) : raw;

	const newTask = store.createTask({
		name: archive.task.name,
		description: archive.task.description,
		category: archive.task.category,
		autopilot: archive.task.autopilot,
		coverageEnabled: archive.task.coverageEnabled,
		scopeWriteGuard: archive.task.scopeWriteGuard,
		scopeInheritWrites: archive.task.scopeInheritWrites,
		maxWorkers: archive.task.maxWorkers,
		maxTurns: archive.task.maxTurns,
	});

	for (const s of archive.scopeRules ?? []) {
		store.addTaskScope({ taskId: newTask.id, pattern: s.pattern, kind: s.kind, exclude: s.exclude, note: s.note });
	}
	if (archive.constraints?.length) {
		store.setTaskConstraints(newTask.id, archive.constraints.map((c) => c.text));
	}

	const assetIdMap = new Map<number, number>();
	if (archive.assets.length > 0) {
		const inserted = store.upsertAssets(
			archive.assets.map((a) => ({
				taskId: newTask.id,
				kind: a.kind,
				value: a.value,
				label: a.label,
				metadata: a.metadata,
				source: a.source || "archive_restore",
			})),
		);
		archive.assets.forEach((oldA, idx) => {
			if (inserted[idx]) assetIdMap.set(oldA.id, inserted[idx]!.id);
		});
	}

	const evStore = new EvidenceStore(store, evidenceDir);
	const artifactIdMap = new Map<number, number>();
	for (const bundle of archive.artifacts) {
		const restored = evStore.saveBuffer({
			taskId: newTask.id,
			name: bundle.meta.name,
			buffer: Buffer.from(bundle.base64, "base64"),
			kind: bundle.meta.kind,
			mimeType: bundle.meta.mimeType,
			description: bundle.meta.description,
		});
		artifactIdMap.set(bundle.meta.id, restored.id);
	}

	const findingIdMap = new Map<number, number>();
	for (const f of archive.findings) {
		const restored = store.addFinding({
			taskId: newTask.id,
			nodeId: null,
			intentId: null,
			title: f.title,
			vulnClass: f.vulnClass,
			severity: f.severity,
			status: f.status,
			summary: f.summary,
			description: f.description,
			reproduction: f.reproduction,
			remediation: f.remediation,
			evidence: f.evidence,
			evidenceIds: f.evidenceIds.map((id) => artifactIdMap.get(id)).filter((x): x is number => x != null),
			assetIds: f.assetIds.map((id) => assetIdMap.get(id)).filter((x): x is number => x != null),
			cvss: f.cvss,
			cwe: f.cwe,
			fingerprint: f.fingerprint,
		});
		findingIdMap.set(f.id, restored.id);
	}

	for (const rt of archive.retests ?? []) {
		const newFid = findingIdMap.get(rt.findingId);
		if (newFid) {
			store.addFindingRetest({
				findingId: newFid,
				taskId: newTask.id,
				status: rt.status,
				notes: rt.notes,
				evidence: rt.evidence,
			});
		}
	}

	for (const tr of archive.traffic ?? []) {
		store.addTrafficRecord({
			taskId: newTask.id,
			intentId: null,
			findingId: tr.findingId ? (findingIdMap.get(tr.findingId) ?? null) : null,
			method: tr.method,
			url: tr.url,
			host: tr.host,
			statusCode: tr.statusCode,
			requestHeaders: tr.requestHeaders,
			requestBody: tr.requestBody,
			responseHeaders: tr.responseHeaders,
			responseBody: tr.responseBody,
			durationMs: tr.durationMs,
		});
	}

	return {
		task: newTask,
		restoredAssets: assetIdMap.size,
		restoredFindings: findingIdMap.size,
		restoredArtifacts: artifactIdMap.size,
	};
}
