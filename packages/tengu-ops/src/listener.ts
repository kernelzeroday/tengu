import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createTcpServer, type Server as TcpServer } from "node:net";

export interface ListenerCallbackEvent {
	id: number;
	listenerId: string;
	protocol: "http" | "tcp";
	remoteAddress: string;
	method?: string;
	path?: string;
	headers?: Record<string, string>;
	payload: string;
	receivedAt: string;
}

export interface ListenerInfo {
	id: string;
	protocol: "http" | "tcp";
	host: string;
	port: number;
	startedAt: string;
	eventCount: number;
}

interface ActiveListener {
	info: ListenerInfo;
	server: HttpServer | TcpServer;
	events: ListenerCallbackEvent[];
}

export class ListenerManager {
	private readonly listeners = new Map<string, ActiveListener>();
	private seq = 0;

	async start(input: {
		id?: string;
		protocol?: "http" | "tcp";
		host?: string;
		port?: number;
	}): Promise<ListenerInfo> {
		const protocol = input.protocol ?? "http";
		const host = input.host ?? "127.0.0.1";
		const port = input.port ?? 0;
		const id = input.id ?? `lst-${++this.seq}`;
		if (this.listeners.has(id)) {
			throw new Error(`Listener "${id}" already exists`);
		}

		const events: ListenerCallbackEvent[] = [];
		let eventSeq = 0;

		if (protocol === "http") {
			const server = createHttpServer((req, res) => {
				const chunks: Buffer[] = [];
				req.on("data", (c: Buffer) => chunks.push(c));
				req.on("end", () => {
					const hdrs: Record<string, string> = {};
					for (const [k, v] of Object.entries(req.headers)) {
						if (v !== undefined) hdrs[k] = Array.isArray(v) ? v.join(", ") : v;
					}
					events.push({
						id: ++eventSeq,
						listenerId: id,
						protocol: "http",
						remoteAddress: req.socket.remoteAddress ?? "",
						method: req.method ?? "GET",
						path: req.url ?? "/",
						headers: hdrs,
						payload: Buffer.concat(chunks).toString("utf8").slice(0, 16_384),
						receivedAt: new Date().toISOString(),
					});
					if (events.length > 200) events.shift();
					res.writeHead(200, { "content-type": "text/plain" });
					res.end("ok");
				});
			});
			await new Promise<void>((resolve, reject) => {
				server.once("error", reject);
				server.listen(port, host, () => resolve());
			});
			const addr = server.address();
			const boundPort = typeof addr === "object" && addr ? addr.port : port;
			const info: ListenerInfo = { id, protocol, host, port: boundPort, startedAt: new Date().toISOString(), eventCount: 0 };
			this.listeners.set(id, { info, server, events });
			return info;
		}

		const server = createTcpServer((socket) => {
			const chunks: Buffer[] = [];
			socket.on("data", (c: Buffer) => chunks.push(c));
			socket.on("end", () => {
				events.push({
					id: ++eventSeq,
					listenerId: id,
					protocol: "tcp",
					remoteAddress: socket.remoteAddress ?? "",
					payload: Buffer.concat(chunks).toString("utf8").slice(0, 16_384),
					receivedAt: new Date().toISOString(),
				});
				if (events.length > 200) events.shift();
			});
		});
		await new Promise<void>((resolve, reject) => {
			server.once("error", reject);
			server.listen(port, host, () => resolve());
		});
		const addr = server.address();
		const boundPort = typeof addr === "object" && addr ? addr.port : port;
		const info: ListenerInfo = { id, protocol, host, port: boundPort, startedAt: new Date().toISOString(), eventCount: 0 };
		this.listeners.set(id, { info, server, events });
		return info;
	}

	async stop(id: string): Promise<boolean> {
		const active = this.listeners.get(id);
		if (!active) return false;
		await new Promise<void>((resolve) => active.server.close(() => resolve()));
		this.listeners.delete(id);
		return true;
	}

	async stopAll(): Promise<void> {
		for (const id of [...this.listeners.keys()]) {
			await this.stop(id);
		}
	}

	listSessions(id?: string): { listeners: ListenerInfo[]; events: ListenerCallbackEvent[] } {
		const listeners: ListenerInfo[] = [];
		const events: ListenerCallbackEvent[] = [];
		for (const [k, v] of this.listeners.entries()) {
			if (id && k !== id) continue;
			listeners.push({ ...v.info, eventCount: v.events.length });
			events.push(...v.events);
		}
		return { listeners, events };
	}
}
