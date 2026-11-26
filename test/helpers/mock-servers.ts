import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function createTempDir(prefix = "tengu-test-"): { dir: string; cleanup: () => void } {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	return {
		dir,
		cleanup: () => {
			try {
				rmSync(dir, { recursive: true, force: true });
			} catch {
				// best-effort cleanup
			}
		},
	};
}

export interface LocalServerHandle {
	server: Server;
	port: number;
	url: string;
	close: () => Promise<void>;
}

export async function startMockHttpServer(
	handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<LocalServerHandle> {
	const server = createServer(handler);
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => resolve());
	});
	const addr = server.address();
	const port = typeof addr === "object" && addr ? addr.port : 0;
	return {
		server,
		port,
		url: `http://127.0.0.1:${port}`,
		close: () =>
			new Promise<void>((resolve) => {
				server.close(() => resolve());
			}),
	};
}

/**
 * Local OpenAI-compatible mock server supporting both streaming SSE and JSON responses.
 * Lets daemon and Pi LLM tests run end-to-end with zero external network calls.
 */
export async function startMockOpenAiServer(options: {
	replyText?: string;
	delayMs?: number;
	statusCode?: number;
} = {}): Promise<LocalServerHandle & { requestCount: () => number }> {
	let count = 0;
	const replyText = options.replyText ?? "Assessment complete. No critical issues found.";
	const delayMs = options.delayMs ?? 25;
	const statusCode = options.statusCode ?? 200;

	const handle = await startMockHttpServer((req, res) => {
		count++;
		const chunks: Buffer[] = [];
		req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
		req.on("end", () => {
			setTimeout(() => {
				if (statusCode !== 200) {
					res.writeHead(statusCode, { "content-type": "application/json" });
					res.end(JSON.stringify({ error: { message: `Mock error ${statusCode}` } }));
					return;
				}
				let body: Record<string, unknown> = {};
				try {
					body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
				} catch {
					// ignore
				}
				const stream = Boolean(body.stream);
				if (stream) {
					res.writeHead(200, {
						"content-type": "text/event-stream",
						"cache-control": "no-cache",
						connection: "keep-alive",
					});
					const chunk1 = {
						id: `chatcmpl-mock-${count}`,
						object: "chat.completion.chunk",
						created: Math.floor(Date.now() / 1000),
						model: String(body.model ?? "mock-model"),
						choices: [{ index: 0, delta: { role: "assistant", content: replyText }, finish_reason: null }],
					};
					const chunk2 = {
						id: `chatcmpl-mock-${count}`,
						object: "chat.completion.chunk",
						created: Math.floor(Date.now() / 1000),
						model: String(body.model ?? "mock-model"),
						choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
						usage: { prompt_tokens: 42, completion_tokens: 18, total_tokens: 60 },
					};
					res.write(`data: ${JSON.stringify(chunk1)}\n\n`);
					res.write(`data: ${JSON.stringify(chunk2)}\n\n`);
					res.write("data: [DONE]\n\n");
					res.end();
				} else {
					res.writeHead(200, { "content-type": "application/json" });
					res.end(
						JSON.stringify({
							id: `chatcmpl-mock-${count}`,
							object: "chat.completion",
							created: Math.floor(Date.now() / 1000),
							model: String(body.model ?? "mock-model"),
							choices: [
								{
									index: 0,
									message: { role: "assistant", content: replyText },
									finish_reason: "stop",
								},
							],
							usage: { prompt_tokens: 42, completion_tokens: 18, total_tokens: 60 },
						}),
					);
				}
			}, delayMs);
		});
	});

	return {
		...handle,
		requestCount: () => count,
	};
}
