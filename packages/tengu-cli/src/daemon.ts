import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
	isProcessAlive,
	type LiveTaskStatusSnapshot,
	readLiveStatusSnapshot,
	writeLiveStatusSnapshot,
} from "@tengu/engine";

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const CLI_ENTRY = join(THIS_DIR, "cli.js");

export function getStatusFilePath(tenguHome: string, taskId: number): string {
	return join(tenguHome, `run-${taskId}.status.json`);
}

export function getBackgroundTaskStatus(
	tenguHome: string,
	taskId: number,
): { alive: boolean; snapshot: LiveTaskStatusSnapshot | null } {
	const snapshot = readLiveStatusSnapshot(getStatusFilePath(tenguHome, taskId));
	if (!snapshot) return { alive: false, snapshot: null };
	const alive = isProcessAlive(snapshot.pid) && (snapshot.status === "running" || snapshot.status === "paused");
	return { alive, snapshot };
}

/**
 * Spawns `tengu task run <taskId>` as a detached background daemon that survives closing the TUI/terminal.
 */
export function startBackgroundTask(options: {
	tenguHome: string;
	dbPath: string;
	taskId: number;
	maxRounds?: number;
	provider?: string;
	model?: string;
}): { pid: number; statusFile: string } {
	const existing = getBackgroundTaskStatus(options.tenguHome, options.taskId);
	if (existing.alive && existing.snapshot) {
		return { pid: existing.snapshot.pid, statusFile: getStatusFilePath(options.tenguHome, options.taskId) };
	}

	const args = [CLI_ENTRY, "task", "run", String(options.taskId), "--db", options.dbPath];
	if (options.maxRounds != null) args.push("--rounds", String(options.maxRounds));
	if (options.provider) args.push("--provider", options.provider);
	if (options.model) args.push("--model", options.model);

	const child = spawn(process.execPath, args, {
		detached: true,
		stdio: "ignore",
		env: { ...process.env },
	});
	child.unref();

	const pid = child.pid ?? 0;
	const statusFile = getStatusFilePath(options.tenguHome, options.taskId);
	writeLiveStatusSnapshot(statusFile, {
		taskId: options.taskId,
		pid,
		status: "running",
		model: options.model ? `${options.provider ?? ""}/${options.model}` : "pi-default",
		round: 0,
		maxRounds: options.maxRounds ?? 12,
		totalTokensGenerated: 0,
		tokensPerSec: 0,
		startedAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
		agents: [],
	});
	return { pid, statusFile };
}

export function signalBackgroundPauseToggle(tenguHome: string, taskId: number): boolean {
	const { alive, snapshot } = getBackgroundTaskStatus(tenguHome, taskId);
	if (!alive || !snapshot) return false;
	try {
		process.kill(snapshot.pid, "SIGUSR1");
		return true;
	} catch {
		return false;
	}
}

export function stopBackgroundTask(tenguHome: string, taskId: number): boolean {
	const { alive, snapshot } = getBackgroundTaskStatus(tenguHome, taskId);
	if (!alive || !snapshot) return false;
	try {
		process.kill(snapshot.pid, "SIGTERM");
		return true;
	} catch {
		return false;
	}
}
