import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface SessionHeaderEntry {
	type: "session";
	version: 3;
	id: string;
	timestamp: string;
	cwd: string;
	title: string;
	taskId: number | null;
	model: string;
}

export interface SessionMessageEntry {
	type: "message";
	id: string;
	parentId: string | null;
	timestamp: string;
	message: {
		role: "user" | "assistant" | "system";
		content: Array<{ type: "text"; text: string }>;
		thinking?: string;
		tools?: Array<{ name: string; status: string; durationMs: number | null }>;
		model?: string;
		tokens?: number;
		tokensPerSec?: number;
		durationSec?: string;
	};
}

export interface SessionSummary {
	id: string;
	filePath: string;
	title: string;
	taskId: number | null;
	model: string;
	cwd: string;
	messageCount: number;
	preview: string;
	createdAt: string;
	updatedAt: string;
}

export interface LoadedSession {
	header: SessionHeaderEntry;
	messages: SessionMessageEntry[];
	filePath: string;
}

/**
 * Persistent Pi-compatible JSONL session store under ~/.tengu/sessions/<id>.jsonl.
 */
export class TenguSessionManager {
	public readonly sessionsDir: string;

	constructor(tenguHome: string) {
		this.sessionsDir = join(tenguHome, "sessions");
		mkdirSync(this.sessionsDir, { recursive: true });
	}

	private fileFor(id: string): string {
		const safe = id.replace(/[^a-zA-Z0-9._-]/g, "_");
		return join(this.sessionsDir, `${safe}.jsonl`);
	}

	createSession(input?: { title?: string; taskId?: number | null; model?: string; cwd?: string }): LoadedSession {
		const id = `${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}_${randomUUID().slice(0, 8)}`;
		const header: SessionHeaderEntry = {
			type: "session",
			version: 3,
			id,
			timestamp: new Date().toISOString(),
			cwd: input?.cwd ?? process.cwd(),
			title: input?.title ?? "New Engagement",
			taskId: input?.taskId ?? null,
			model: input?.model ?? "",
		};
		const filePath = this.fileFor(id);
		writeFileSync(filePath, `${JSON.stringify(header)}\n`, "utf8");
		return { header, messages: [], filePath };
	}

	appendMessage(
		sessionId: string,
		message: SessionMessageEntry["message"],
		parentId: string | null = null,
	): SessionMessageEntry {
		const entry: SessionMessageEntry = {
			type: "message",
			id: randomUUID().slice(0, 12),
			parentId,
			timestamp: new Date().toISOString(),
			message,
		};
		appendFileSync(this.fileFor(sessionId), `${JSON.stringify(entry)}\n`, "utf8");
		return entry;
	}

	updateHeader(sessionId: string, patch: Partial<Pick<SessionHeaderEntry, "title" | "taskId" | "model">>): void {
		const loaded = this.loadSession(sessionId);
		if (!loaded) return;
		const updated: SessionHeaderEntry = { ...loaded.header, ...patch };
		const lines = [JSON.stringify(updated), ...loaded.messages.map((m) => JSON.stringify(m))];
		writeFileSync(loaded.filePath, `${lines.join("\n")}\n`, "utf8");
	}

	loadSession(sessionId: string): LoadedSession | null {
		const filePath = this.fileFor(sessionId);
		if (!existsSync(filePath)) return null;
		const raw = readFileSync(filePath, "utf8").trim();
		if (!raw) return null;
		const lines = raw.split("\n");
		let header: SessionHeaderEntry | null = null;
		const messages: SessionMessageEntry[] = [];
		for (const line of lines) {
			try {
				const parsed = JSON.parse(line) as SessionHeaderEntry | SessionMessageEntry;
				if (parsed.type === "session" && !header) header = parsed;
				else if (parsed.type === "message") messages.push(parsed);
			} catch {
				// skip malformed line
			}
		}
		if (!header) return null;
		return { header, messages, filePath };
	}

	listSessions(): SessionSummary[] {
		if (!existsSync(this.sessionsDir)) return [];
		const out: SessionSummary[] = [];
		for (const name of readdirSync(this.sessionsDir)) {
			if (!name.endsWith(".jsonl")) continue;
			const id = name.slice(0, -6);
			const loaded = this.loadSession(id);
			if (!loaded) continue;
			const st = statSync(loaded.filePath);
			const firstUser = loaded.messages.find((m) => m.message.role === "user");
			const rawContent = firstUser?.message.content as unknown;
			const rawText = typeof rawContent === "string" ? rawContent : Array.isArray(rawContent) ? String((rawContent[0] as { text?: string } | undefined)?.text ?? "") : "";
			const preview = rawText ? rawText.replace(/\s+/g, " ").slice(0, 80) : "(empty session)";
			out.push({
				id: loaded.header.id,
				filePath: loaded.filePath,
				title: loaded.header.title,
				taskId: loaded.header.taskId,
				model: loaded.header.model,
				cwd: loaded.header.cwd,
				messageCount: loaded.messages.length,
				preview,
				createdAt: loaded.header.timestamp,
				updatedAt: st.mtime.toISOString(),
			});
		}
		return out.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
	}

	getLatestSession(): LoadedSession | null {
		const all = this.listSessions();
		return all.length > 0 ? this.loadSession(all[0]!.id) : null;
	}
}
