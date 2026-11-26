import type { TaskAuthProfile, TenguStore } from "@tengu/store";

export interface HttpResponseResult {
	url: string;
	method: string;
	status: number;
	statusText: string;
	headers: Record<string, string>;
	body: string;
	durationMs: number;
	trafficId?: number;
}

export async function executeHttpRequest(input: {
	url: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string;
	timeoutMs?: number;
	followRedirects?: boolean;
	store?: TenguStore;
	taskId?: number;
	intentId?: number | null;
}): Promise<HttpResponseResult> {
	const method = (input.method ?? "GET").toUpperCase();
	const headers = { ...(input.headers ?? {}) };
	const start = Date.now();
	const res = await fetch(input.url, {
		method,
		headers,
		body: method === "GET" || method === "HEAD" ? undefined : input.body,
		redirect: input.followRedirects === false ? "manual" : "follow",
		signal: AbortSignal.timeout(input.timeoutMs ?? 15_000),
	});
	const text = await res.text();
	const durationMs = Date.now() - start;
	const respHeaders: Record<string, string> = {};
	res.headers.forEach((v, k) => {
		respHeaders[k] = v;
	});

	let trafficId: number | undefined;
	if (input.store && input.taskId != null) {
		let host = "";
		try {
			host = new URL(input.url).host;
		} catch {
			host = input.url;
		}
		const rec = input.store.addTrafficRecord({
			taskId: input.taskId,
			intentId: input.intentId ?? null,
			findingId: null,
			method,
			url: input.url,
			host,
			statusCode: res.status,
			requestHeaders: headers,
			requestBody: input.body ?? "",
			responseHeaders: respHeaders,
			responseBody: text.slice(0, 65_536),
			durationMs,
		});
		trafficId = rec.id;
	}

	return {
		url: res.url || input.url,
		method,
		status: res.status,
		statusText: res.statusText,
		headers: respHeaders,
		body: text,
		durationMs,
		trafficId,
	};
}

export async function performSessionLogin(input: {
	store: TenguStore;
	taskId: number;
	intentId?: number | null;
	profileName: string;
	role?: string;
	loginUrl: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string;
	tokenJsonPath?: string;
}): Promise<{ profile: TaskAuthProfile; response: HttpResponseResult }> {
	const response = await executeHttpRequest({
		url: input.loginUrl,
		method: input.method ?? "POST",
		headers: { "content-type": "application/json", ...(input.headers ?? {}) },
		body: input.body,
		store: input.store,
		taskId: input.taskId,
		intentId: input.intentId,
	});

	const cookies: Record<string, string> = {};
	const setCookie = response.headers["set-cookie"];
	if (setCookie) {
		for (const part of setCookie.split(/,(?=[^;]+=)/)) {
			const [pair] = part.trim().split(";");
			const eq = pair.indexOf("=");
			if (eq > 0) {
				cookies[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
			}
		}
	}

	const authHeaders: Record<string, string> = {};
	let authType: TaskAuthProfile["authType"] = Object.keys(cookies).length > 0 ? "cookie" : "header";
	try {
		const parsed = JSON.parse(response.body) as Record<string, unknown>;
		const tokenKey = input.tokenJsonPath || "token";
		const tokenVal =
			parsed[tokenKey] ??
			parsed.access_token ??
			parsed.accessToken ??
			(typeof parsed.data === "object" && parsed.data !== null
				? (parsed.data as Record<string, unknown>)[tokenKey] ?? (parsed.data as Record<string, unknown>).token
				: undefined);
		if (typeof tokenVal === "string" && tokenVal.length > 0) {
			authHeaders.authorization = `Bearer ${tokenVal}`;
			authType = "bearer";
		}
	} catch {
		// Non-JSON response; rely on cookies
	}

	const profile = input.store.upsertAuthProfile({
		taskId: input.taskId,
		name: input.profileName,
		role: input.role ?? input.profileName,
		authType,
		headers: authHeaders,
		cookies,
		loginUrl: input.loginUrl,
		metadata: { lastStatus: response.status },
	});

	return { profile, response };
}

export async function executeAuthRequest(input: {
	store: TenguStore;
	taskId: number;
	intentId?: number | null;
	profileName: string;
	url: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string;
}): Promise<HttpResponseResult> {
	const profile = input.store.getAuthProfile(input.taskId, input.profileName);
	if (!profile) {
		throw new Error(`Auth profile "${input.profileName}" not found for task #${input.taskId}`);
	}
	const mergedHeaders: Record<string, string> = { ...profile.headers, ...(input.headers ?? {}) };
	const cookiePairs = Object.entries(profile.cookies).map(([k, v]) => `${k}=${v}`);
	if (cookiePairs.length > 0) {
		mergedHeaders.cookie = mergedHeaders.cookie
			? `${mergedHeaders.cookie}; ${cookiePairs.join("; ")}`
			: cookiePairs.join("; ");
	}
	return executeHttpRequest({
		url: input.url,
		method: input.method,
		headers: mergedHeaders,
		body: input.body,
		store: input.store,
		taskId: input.taskId,
		intentId: input.intentId,
	});
}

export interface ResponseDiffResult {
	statusChanged: boolean;
	statusA: number;
	statusB: number;
	bodyLengthDelta: number;
	bodyEqual: boolean;
	headerDiffs: Array<{ header: string; a: string | null; b: string | null }>;
	jsonKeyDiffs: { onlyInA: string[]; onlyInB: string[]; changedValues: string[] } | null;
}

export function diffHttpResponses(
	a: { status: number; headers?: Record<string, string>; body: string },
	b: { status: number; headers?: Record<string, string>; body: string },
): ResponseDiffResult {
	const hA = a.headers ?? {};
	const hB = b.headers ?? {};
	const allKeys = new Set([...Object.keys(hA), ...Object.keys(hB)]);
	const headerDiffs: ResponseDiffResult["headerDiffs"] = [];
	for (const k of allKeys) {
		if (k.toLowerCase() === "date" || k.toLowerCase() === "x-request-id") continue;
		const va = hA[k] ?? null;
		const vb = hB[k] ?? null;
		if (va !== vb) headerDiffs.push({ header: k, a: va, b: vb });
	}

	let jsonKeyDiffs: ResponseDiffResult["jsonKeyDiffs"] = null;
	try {
		const ja = JSON.parse(a.body) as unknown;
		const jb = JSON.parse(b.body) as unknown;
		if (ja && jb && typeof ja === "object" && typeof jb === "object" && !Array.isArray(ja) && !Array.isArray(jb)) {
			const ka = Object.keys(ja as Record<string, unknown>);
			const kb = Object.keys(jb as Record<string, unknown>);
			const setA = new Set(ka);
			const setB = new Set(kb);
			const onlyInA = ka.filter((k) => !setB.has(k));
			const onlyInB = kb.filter((k) => !setA.has(k));
			const changedValues = ka.filter(
				(k) =>
					setB.has(k) &&
					JSON.stringify((ja as Record<string, unknown>)[k]) !== JSON.stringify((jb as Record<string, unknown>)[k]),
			);
			jsonKeyDiffs = { onlyInA, onlyInB, changedValues };
		}
	} catch {
		// Not JSON objects
	}

	return {
		statusChanged: a.status !== b.status,
		statusA: a.status,
		statusB: b.status,
		bodyLengthDelta: b.body.length - a.body.length,
		bodyEqual: a.body === b.body,
		headerDiffs,
		jsonKeyDiffs,
	};
}

export interface ProbeResult {
	url: string;
	reachable: boolean;
	status?: number;
	title?: string;
	server?: string;
	poweredBy?: string;
	contentType?: string;
	contentLength?: number;
	durationMs: number;
	error?: string;
}

export async function probeHttpTargets(urls: string[], timeoutMs = 8000): Promise<ProbeResult[]> {
	const results: ProbeResult[] = [];
	for (const raw of urls) {
		const url = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
		const start = Date.now();
		try {
			const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: "follow" });
			const body = await res.text();
			const titleMatch = body.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
			results.push({
				url: res.url || url,
				reachable: true,
				status: res.status,
				title: titleMatch ? titleMatch[1].trim() : undefined,
				server: res.headers.get("server") ?? undefined,
				poweredBy: res.headers.get("x-powered-by") ?? undefined,
				contentType: res.headers.get("content-type") ?? undefined,
				contentLength: body.length,
				durationMs: Date.now() - start,
			});
		} catch (err) {
			results.push({
				url,
				reachable: false,
				durationMs: Date.now() - start,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return results;
}

export interface JsAuditFinding {
	endpoints: string[];
	secrets: Array<{ kind: string; match: string }>;
	sinks: Array<{ sink: string; snippet: string }>;
}

export function auditJavaScriptSource(code: string): JsAuditFinding {
	const endpointSet = new Set<string>();
	const endpointRe = /["'`]((?:\/api\/|\/v\d+\/|\/graphql|\/auth\/|\/admin\/|https?:\/\/)[a-zA-Z0-9_./:?&=%-]{2,160})["'`]/g;
	for (const m of code.matchAll(endpointRe)) {
		endpointSet.add(m[1]);
	}

	const secretPatterns: Array<{ kind: string; re: RegExp }> = [
		{ kind: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/g },
		{ kind: "jwt", re: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g },
		{ kind: "generic_api_key", re: /(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']([a-zA-Z0-9_\-/.]{16,120})["']/gi },
		{ kind: "private_key_header", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
	];
	const secrets: JsAuditFinding["secrets"] = [];
	for (const p of secretPatterns) {
		for (const m of code.matchAll(p.re)) {
			secrets.push({ kind: p.kind, match: (m[1] ?? m[0]).slice(0, 64) });
		}
	}

	const sinkPatterns = [
		"dangerouslySetInnerHTML",
		"innerHTML",
		"outerHTML",
		"document.write",
		"eval(",
		"new Function(",
		"postMessage(",
	];
	const sinks: JsAuditFinding["sinks"] = [];
	const lines = code.split("\n");
	for (let i = 0; i < lines.length; i++) {
		for (const s of sinkPatterns) {
			if (lines[i].includes(s)) {
				sinks.push({ sink: s, snippet: `L${i + 1}: ${lines[i].trim().slice(0, 140)}` });
			}
		}
	}

	return {
		endpoints: [...endpointSet].slice(0, 200),
		secrets: secrets.slice(0, 50),
		sinks: sinks.slice(0, 100),
	};
}

export interface ApiContractSummary {
	format: "openapi" | "swagger" | "unknown";
	title: string;
	version: string;
	endpoints: Array<{ method: string; path: string; summary: string; params: string[] }>;
}

export function parseApiContract(rawJson: string): ApiContractSummary {
	const doc = JSON.parse(rawJson) as Record<string, unknown>;
	const format = doc.openapi ? "openapi" : doc.swagger ? "swagger" : "unknown";
	const info = (doc.info ?? {}) as Record<string, unknown>;
	const paths = (doc.paths ?? {}) as Record<string, Record<string, Record<string, unknown>>>;
	const endpoints: ApiContractSummary["endpoints"] = [];
	const methods = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);
	for (const [p, ops] of Object.entries(paths)) {
		if (!ops || typeof ops !== "object") continue;
		for (const [m, op] of Object.entries(ops)) {
			if (!methods.has(m.toLowerCase())) continue;
			const params = Array.isArray(op?.parameters)
				? (op.parameters as Array<Record<string, unknown>>).map((pr) => String(pr.name ?? ""))
				: [];
			endpoints.push({
				method: m.toUpperCase(),
				path: p,
				summary: String(op?.summary ?? op?.operationId ?? ""),
				params: params.filter(Boolean),
			});
		}
	}
	return {
		format,
		title: String(info.title ?? ""),
		version: String(info.version ?? ""),
		endpoints,
	};
}
