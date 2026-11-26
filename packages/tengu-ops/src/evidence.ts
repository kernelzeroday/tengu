import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { ArtifactRecord, TenguStore } from "@tengu/store";
import { maskSecrets } from "./notify.ts";

export class EvidenceStore {
	private readonly baseDir: string;
	private readonly store: TenguStore;

	constructor(store: TenguStore, baseDir: string) {
		this.store = store;
		this.baseDir = resolve(baseDir);
		mkdirSync(this.baseDir, { recursive: true });
	}

	saveText(input: {
		taskId: number;
		intentId?: number | null;
		name: string;
		content: string;
		kind?: string;
		mimeType?: string;
		description?: string;
	}): ArtifactRecord {
		return this.saveBuffer({
			...input,
			buffer: Buffer.from(input.content, "utf8"),
			kind: input.kind ?? "text",
			mimeType: input.mimeType ?? "text/plain; charset=utf-8",
		});
	}

	saveFile(input: {
		taskId: number;
		intentId?: number | null;
		sourcePath: string;
		name?: string;
		kind?: string;
		mimeType?: string;
		description?: string;
	}): ArtifactRecord {
		const buf = readFileSync(input.sourcePath);
		return this.saveBuffer({
			taskId: input.taskId,
			intentId: input.intentId,
			name: input.name || basename(input.sourcePath),
			buffer: buf,
			kind: input.kind ?? "file",
			mimeType: input.mimeType ?? "application/octet-stream",
			description: input.description,
		});
	}

	saveBuffer(input: {
		taskId: number;
		intentId?: number | null;
		name: string;
		buffer: Buffer;
		kind?: string;
		mimeType?: string;
		description?: string;
	}): ArtifactRecord {
		const sha256 = createHash("sha256").update(input.buffer).digest("hex");
		const safeName = input.name.replace(/[^a-zA-Z0-9._-]/g, "_");
		const taskDir = join(this.baseDir, `task-${input.taskId}`);
		mkdirSync(taskDir, { recursive: true });
		const dest = join(taskDir, `${sha256.slice(0, 12)}-${safeName}`);
		writeFileSync(dest, input.buffer);

		return this.store.addArtifact({
			taskId: input.taskId,
			intentId: input.intentId ?? null,
			name: input.name,
			kind: input.kind ?? "file",
			mimeType: input.mimeType ?? "application/octet-stream",
			sha256,
			sizeBytes: input.buffer.byteLength,
			path: dest,
			description: input.description ?? "",
		});
	}

	verifyArtifact(artifactId: number): {
		ok: boolean;
		artifact: ArtifactRecord | null;
		reason: string;
	} {
		const art = this.store.getArtifact(artifactId);
		if (!art) return { ok: false, artifact: null, reason: `Artifact #${artifactId} not found` };
		if (!existsSync(art.path)) return { ok: false, artifact: art, reason: `File missing on disk: ${art.path}` };
		const st = statSync(art.path);
		if (st.size !== art.sizeBytes) {
			return { ok: false, artifact: art, reason: `Size mismatch: expected ${art.sizeBytes}, got ${st.size}` };
		}
		const actualHash = createHash("sha256").update(readFileSync(art.path)).digest("hex");
		if (actualHash !== art.sha256) {
			return { ok: false, artifact: art, reason: `SHA-256 mismatch: expected ${art.sha256}, got ${actualHash}` };
		}
		return { ok: true, artifact: art, reason: "Integrity verified (SHA-256 match)" };
	}

	inspectArtifact(artifactId: number, maxPreviewChars = 4000): {
		status: "readable" | "missing" | "corrupt";
		artifact: ArtifactRecord | null;
		reason: string;
		redactedPreview: string;
	} {
		const art = this.store.getArtifact(artifactId);
		if (!art) return { status: "missing", artifact: null, reason: `Artifact #${artifactId} not found`, redactedPreview: "" };
		if (!existsSync(art.path)) return { status: "missing", artifact: art, reason: `File missing on disk: ${art.path}`, redactedPreview: "" };
		const check = this.verifyArtifact(artifactId);
		if (!check.ok) return { status: "corrupt", artifact: art, reason: check.reason, redactedPreview: "" };
		const buf = readFileSync(art.path);
		const isText = art.mimeType.startsWith("text/") || art.kind === "text" || art.kind === "http" || art.kind === "poc" || art.kind === "log";
		const preview = isText ? maskSecrets(buf.toString("utf8").slice(0, maxPreviewChars)) : `[binary artifact: ${art.mimeType}, ${art.sizeBytes} bytes]`;
		return { status: "readable", artifact: art, reason: check.reason, redactedPreview: preview };
	}

	exportArtifact(artifactId: number, destPath: string): ArtifactRecord {
		const check = this.verifyArtifact(artifactId);
		if (!check.ok || !check.artifact) throw new Error(`Cannot export artifact #${artifactId}: ${check.reason}`);
		copyFileSync(check.artifact.path, destPath);
		return check.artifact;
	}
}
