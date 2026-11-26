import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface LiveAgentStatus {
	role: string;
	intentId: number | null;
	phase: "thinking" | "streaming" | "tool" | "paused" | "idle";
	currentTool: string;
	toolStartedAt: number | null;
	tokensGenerated: number;
	tokensPerSec: number;
	lastSnippet: string;
	updatedAt: string;
}

export interface LiveTaskStatusSnapshot {
	taskId: number;
	pid: number;
	status: "running" | "paused" | "stopped" | "completed" | "failed";
	model: string;
	round: number;
	maxRounds: number;
	totalTokensGenerated: number;
	tokensPerSec: number;
	startedAt: string;
	updatedAt: string;
	agents: LiveAgentStatus[];
}

export function writeLiveStatusSnapshot(filePath: string, snapshot: LiveTaskStatusSnapshot): void {
	try {
		mkdirSync(dirname(filePath), { recursive: true });
		writeFileSync(filePath, JSON.stringify(snapshot, null, 2), "utf8");
	} catch {
		// Best-effort status file
	}
}

export function readLiveStatusSnapshot(filePath: string): LiveTaskStatusSnapshot | null {
	if (!existsSync(filePath)) return null;
	try {
		return JSON.parse(readFileSync(filePath, "utf8")) as LiveTaskStatusSnapshot;
	} catch {
		return null;
	}
}

export function removeLiveStatusSnapshot(filePath: string): void {
	try {
		if (existsSync(filePath)) rmSync(filePath, { force: true });
	} catch {
		// ignore
	}
}

export function isProcessAlive(pid: number): boolean {
	if (!pid || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}
