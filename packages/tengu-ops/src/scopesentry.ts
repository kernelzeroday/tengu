import type { AssetKind, AssetNode, TenguStore } from "@tengu/store";

export interface ScopeSentryConfig {
	baseUrl: string;
	apiKey: string;
}

export interface ScopeSentrySyncResult {
	imported: number;
	assets: AssetNode[];
}

/**
 * Syncs assets (domains, subdomains, IPs, ports, sites, endpoints) from a ScopeSentry server
 * into Tengu's Asset Graph (reimplementing RuoJi6-ARTEX's ScopeSentry integration).
 */
export class ScopeSentrySyncClient {
	private readonly config: ScopeSentryConfig;
	private readonly store: TenguStore;

	constructor(store: TenguStore, config: ScopeSentryConfig) {
		this.store = store;
		this.config = { baseUrl: config.baseUrl.replace(/\/+$/, ""), apiKey: config.apiKey };
	}

	private async post(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
		const res = await fetch(`${this.config.baseUrl}${path}`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"API-Key": this.config.apiKey,
			},
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(20_000),
		});
		if (!res.ok) {
			throw new Error(`ScopeSentry API ${path} returned HTTP ${res.status}`);
		}
		return (await res.json()) as Record<string, unknown>;
	}

	async syncProjectAssets(input: {
		projectId: string;
		taskId?: number | null;
		companyId?: number | null;
		types?: Array<"subdomain" | "site" | "ip" | "endpoint">;
		pageSize?: number;
	}): Promise<ScopeSentrySyncResult> {
		const types = input.types ?? ["subdomain", "site", "endpoint"];
		const pageSize = input.pageSize ?? 200;
		const toInsert: Array<{
			companyId?: number | null;
			taskId?: number | null;
			kind: AssetKind;
			value: string;
			label?: string;
			metadata?: Record<string, unknown>;
			source?: string;
		}> = [];

		for (const t of types) {
			const endpoint =
				t === "subdomain"
					? "/api/subdomain/data"
					: t === "site"
						? "/api/asset/data"
						: t === "endpoint"
							? "/api/url/data"
							: "/api/ip/data";
			const payload = await this.post(endpoint, {
				pageIndex: 1,
				pageSize,
				filter: { project: [input.projectId] },
			});
			const data = (payload.data as Record<string, unknown> | undefined)?.list;
			if (!Array.isArray(data)) continue;
			for (const item of data as Array<Record<string, unknown>>) {
				const value = String(item.url ?? item.host ?? item.ip ?? item.input ?? "").trim();
				if (!value) continue;
				toInsert.push({
					companyId: input.companyId ?? null,
					taskId: input.taskId ?? null,
					kind: t,
					value,
					label: String(item.title ?? item.service ?? ""),
					metadata: { scopesentryProject: input.projectId, raw: item },
					source: "scopesentry",
				});
			}
		}

		const assets = this.store.upsertAssets(toInsert);
		return { imported: assets.length, assets };
	}
}
