import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

export interface JobInfo {
	id: string;
	command: string;
	cwd: string;
	status: "running" | "exited" | "killed";
	exitCode: number | null;
	startedAt: string;
	endedAt: string | null;
}

interface ActiveJob {
	info: JobInfo;
	child: ChildProcess;
	output: string[];
	outputBytes: number;
}

const MAX_OUTPUT_BYTES = 256 * 1024;

export class JobManager {
	private readonly jobs = new Map<string, ActiveJob>();
	private seq = 0;

	start(command: string, cwd: string): JobInfo {
		const id = `job-${++this.seq}`;
		const child = spawn("bash", ["-lc", command], {
			cwd,
			stdio: ["ignore", "pipe", "pipe"],
			detached: true,
		});
		const info: JobInfo = {
			id,
			command,
			cwd,
			status: "running",
			exitCode: null,
			startedAt: new Date().toISOString(),
			endedAt: null,
		};
		const job: ActiveJob = { info, child, output: [], outputBytes: 0 };
		const append = (chunk: Buffer) => {
			const s = chunk.toString("utf8");
			job.output.push(s);
			job.outputBytes += s.length;
			while (job.outputBytes > MAX_OUTPUT_BYTES && job.output.length > 1) {
				const removed = job.output.shift()!;
				job.outputBytes -= removed.length;
			}
		};
		child.stdout?.on("data", append);
		child.stderr?.on("data", append);
		child.on("close", (code) => {
			if (job.info.status === "running") {
				job.info.status = "exited";
			}
			job.info.exitCode = code;
			job.info.endedAt = new Date().toISOString();
		});
		this.jobs.set(id, job);
		return { ...info };
	}

	status(id?: string): JobInfo[] {
		if (id) {
			const j = this.jobs.get(id);
			return j ? [{ ...j.info }] : [];
		}
		return [...this.jobs.values()].map((j) => ({ ...j.info }));
	}

	output(id: string, tailChars = 16_000): { info: JobInfo; output: string } | null {
		const j = this.jobs.get(id);
		if (!j) return null;
		const full = j.output.join("");
		return {
			info: { ...j.info },
			output: full.length > tailChars ? full.slice(-tailChars) : full,
		};
	}

	stop(id: string): boolean {
		const j = this.jobs.get(id);
		if (!j) return false;
		if (j.info.status === "running") {
			j.info.status = "killed";
			try {
				if (j.child.pid) process.kill(-j.child.pid, "SIGTERM");
			} catch {
				j.child.kill("SIGTERM");
			}
		}
		return true;
	}

	stopAll(): void {
		for (const id of this.jobs.keys()) {
			this.stop(id);
		}
	}
}

export class ScriptWorkspace {
	private readonly rootDir: string;

	constructor(rootDir: string) {
		this.rootDir = resolve(rootDir);
		mkdirSync(this.rootDir, { recursive: true });
	}

	saveScript(name: string, content: string): string {
		const safe = name.replace(/[^a-zA-Z0-9._-]/g, "_");
		const fullPath = join(this.rootDir, safe);
		writeFileSync(fullPath, content, { mode: 0o755 });
		return fullPath;
	}

	async runScript(
		name: string,
		interpreter: "python3" | "node" | "bash" = "python3",
		args: string[] = [],
		timeoutMs = 30_000,
	): Promise<{ exitCode: number; stdout: string; stderr: string }> {
		const safe = name.replace(/[^a-zA-Z0-9._-]/g, "_");
		const fullPath = join(this.rootDir, safe);
		return new Promise((resolvePromise) => {
			const child = spawn(interpreter, [fullPath, ...args], {
				cwd: this.rootDir,
				stdio: ["ignore", "pipe", "pipe"],
			});
			let stdout = "";
			let stderr = "";
			const timer = setTimeout(() => {
				child.kill("SIGKILL");
			}, timeoutMs);
			child.stdout?.on("data", (d: Buffer) => {
				if (stdout.length < 64_000) stdout += d.toString("utf8");
			});
			child.stderr?.on("data", (d: Buffer) => {
				if (stderr.length < 32_000) stderr += d.toString("utf8");
			});
			child.on("close", (code) => {
				clearTimeout(timer);
				resolvePromise({ exitCode: code ?? -1, stdout, stderr });
			});
		});
	}
}
