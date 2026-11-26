import { resolve4, resolve6 } from "node:dns/promises";
import type { AssetNode, TenguStore } from "@tengu/store";

export interface EnrichmentResult {
	assetId: number;
	resolvedIps: string[];
	createdAssets: AssetNode[];
}

/**
 * Auto-enriches newly inserted domain/subdomain assets via DNS resolution
 * and links resolved IP assets in the Asset Graph (ARTEX enrich parity).
 */
export class AssetEnricher {
	private readonly store: TenguStore;

	constructor(store: TenguStore) {
		this.store = store;
	}

	async enrichAsset(asset: AssetNode): Promise<EnrichmentResult> {
		if (asset.kind !== "domain" && asset.kind !== "subdomain") {
			return { assetId: asset.id, resolvedIps: [], createdAssets: [] };
		}
		const host = asset.value.replace(/^\*\./, "").trim();
		const ips = new Set<string>();
		try {
			for (const ip of await resolve4(host)) ips.add(ip);
		} catch {
			// no A records
		}
		try {
			for (const ip of await resolve6(host)) ips.add(ip);
		} catch {
			// no AAAA records
		}
		const resolvedIps = [...ips];
		if (resolvedIps.length === 0) {
			return { assetId: asset.id, resolvedIps: [], createdAssets: [] };
		}
		const created = this.store.upsertAssets(
			resolvedIps.map((ip) => ({
				companyId: asset.companyId,
				taskId: asset.taskId,
				kind: "ip" as const,
				value: ip,
				label: `resolved from ${host}`,
				source: "enrich_dns",
			})),
		);
		for (const ipNode of created) {
			this.store.addAssetEdge(asset.id, ipNode.id, "resolves_to");
		}
		return { assetId: asset.id, resolvedIps, createdAssets: created };
	}

	enrichInBackground(assets: AssetNode[]): void {
		for (const a of assets) {
			if (a.kind === "domain" || a.kind === "subdomain") {
				void this.enrichAsset(a).catch(() => {});
			}
		}
	}
}
