import { maskSecrets } from "./notify.ts";
import { createServer, type Server } from "node:http";
import type { TenguStore, TrafficRecord } from "@tengu/store";

export class TrafficRecorderProxy {
	private readonly store: TenguStore;
	private server: Server | null = null;
	private boundPort = 0;

	constructor(store: TenguStore) {
		this.store = store;
	}

	async start(taskId: number, host = "127.0.0.1", port = 0): Promise<{ host: string; port: number }> {
		if (this.server) throw new Error("TrafficRecorderProxy is already running");
		const server = createServer((req, res) => {
			const targetUrl = req.url ?? "/";
			if (!/^https?:\/\//i.test(targetUrl)) {
				res.writeHead(400, { "content-type": "text/plain" });
				res.end("Absolute proxy URL required");
				return;
			}
			const chunks: Buffer[] = [];
			req.on("data", (c: Buffer) => chunks.push(c));
			req.on("end", async () => {
				const reqBody = Buffer.concat(chunks).toString("utf8");
				const reqHeaders: Record<string, string> = {};
				for (const [k, v] of Object.entries(req.headers)) {
					if (v !== undefined && k.toLowerCase() !== "proxy-connection") {
						reqHeaders[k] = Array.isArray(v) ? v.join(", ") : v;
					}
				}
				const start = Date.now();
				try {
					const upstream = await fetch(targetUrl, {
						method: req.method ?? "GET",
						headers: reqHeaders,
						body: req.method === "GET" || req.method === "HEAD" ? undefined : reqBody,
						redirect: "manual",
					});
					const respBuf = Buffer.from(await upstream.arrayBuffer());
					const respHeaders: Record<string, string> = {};
					upstream.headers.forEach((v, k) => {
						respHeaders[k] = v;
					});
					this.store.addTrafficRecord({
						taskId,
						intentId: null,
						findingId: null,
						method: req.method ?? "GET",
						url: targetUrl,
						host: new URL(targetUrl).host,
						statusCode: upstream.status,
						requestHeaders: reqHeaders,
						requestBody: reqBody.slice(0, 32_768),
						responseHeaders: respHeaders,
						responseBody: respBuf.toString("utf8").slice(0, 65_536),
						durationMs: Date.now() - start,
					});
					res.writeHead(upstream.status, respHeaders);
					res.end(respBuf);
				} catch (err) {
					res.writeHead(502, { "content-type": "text/plain" });
					res.end(err instanceof Error ? err.message : String(err));
				}
			});
		});

		await new Promise<void>((resolve, reject) => {
			server.once("error", reject);
			server.listen(port, host, () => resolve());
		});
		const addr = server.address();
		this.boundPort = typeof addr === "object" && addr ? addr.port : port;
		this.server = server;
		return { host, port: this.boundPort };
	}

	async stop(): Promise<void> {
		if (!this.server) return;
		const s = this.server;
		this.server = null;
		await new Promise<void>((resolve) => s.close(() => resolve()));
	}
}

export function exportTrafficAsHar(records: TrafficRecord[]): Record<string, unknown> {
	return {
		log: {
			version: "1.2",
			creator: { name: "tengu", version: "0.1.0" },
			entries: records.map((r) => ({
				startedDateTime: r.createdAt,
				time: r.durationMs,
				request: {
					method: r.method,
					url: r.url,
					httpVersion: "HTTP/1.1",
					headers: Object.entries(r.requestHeaders).map(([name, value]) => ({ name, value })),
					postData: r.requestBody ? { mimeType: r.requestHeaders["content-type"] ?? "text/plain", text: r.requestBody } : undefined,
				},
				response: {
					status: r.statusCode,
					statusText: "",
					httpVersion: "HTTP/1.1",
					headers: Object.entries(r.responseHeaders).map(([name, value]) => ({ name, value })),
					content: {
						size: r.responseBody.length,
						mimeType: r.responseHeaders["content-type"] ?? "text/plain",
						text: r.responseBody,
					},
				},
			})),
		},
	};
}

const SENSITIVE_HEADER_RE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|api-key)$/i;

export function maskTrafficRecord(rec: TrafficRecord): TrafficRecord {
	const maskHeaders = (hdrs: Record<string, string>) => {
		const out: Record<string, string> = {};
		for (const [k, v] of Object.entries(hdrs)) {
			out[k] = SENSITIVE_HEADER_RE.test(k) ? "***REDACTED***" : maskSecrets(v);
		}
		return out;
	};
	return {
		...rec,
		requestHeaders: maskHeaders(rec.requestHeaders),
		responseHeaders: maskHeaders(rec.responseHeaders),
		requestBody: maskSecrets(rec.requestBody),
		responseBody: maskSecrets(rec.responseBody),
	};
}
