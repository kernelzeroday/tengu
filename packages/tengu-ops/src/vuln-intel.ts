import { spawn } from "node:child_process";
import { networkInterfaces } from "node:os";
import type { TenguStore, VulnIntelEntry } from "@tengu/store";

export class VulnIntelService {
	private readonly store: TenguStore;

	constructor(store: TenguStore) {
		this.store = store;
	}

	search(query: string, limit = 20): VulnIntelEntry[] {
		return this.store.searchVulnIntel(query, limit);
	}

	get(idOrCve: string): VulnIntelEntry | null {
		return this.store.getVulnIntel(idOrCve);
	}

	recentCritical(limit = 20): VulnIntelEntry[] {
		return this.store.listRecentCriticalVulns(limit);
	}

	getPoc(idOrCve: string): { found: boolean; cveId: string; pocTemplate: string; references: string[] } {
		const entry = this.store.getVulnIntel(idOrCve);
		if (!entry) {
			return { found: false, cveId: idOrCve, pocTemplate: "", references: [] };
		}
		return {
			found: true,
			cveId: entry.cveId || entry.id,
			pocTemplate: entry.pocTemplate || `No cached PoC template for ${entry.cveId || entry.id}.`,
			references: entry.references,
		};
	}

	async syncCisaKev(limit = 100): Promise<number> {
		const res = await fetch(
			"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			{ signal: AbortSignal.timeout(20_000) },
		);
		if (!res.ok) throw new Error(`CISA KEV fetch failed: HTTP ${res.status}`);
		const json = (await res.json()) as { vulnerabilities?: Array<Record<string, string>> };
		const vulns = (json.vulnerabilities ?? []).slice(0, limit);
		const entries: VulnIntelEntry[] = vulns.map((v) => ({
			id: `kev:${v.cveID}`,
			source: "kev",
			cveId: v.cveID ?? "",
			title: v.vulnerabilityName ?? v.cveID ?? "",
			severity: "critical",
			cvss: 9.0,
			affectedProduct: `${v.vendorProject ?? ""} ${v.product ?? ""}`.trim(),
			affectedVersions: "",
			description: v.shortDescription ?? "",
			references: [],
			pocTemplate: "",
			publishedAt: v.dateAdded ?? new Date().toISOString(),
			updatedAt: new Date().toISOString(),
		}));
		return this.store.upsertVulnIntel(entries);
	}


	async syncNvdRecent(keyword = "", limit = 30): Promise<number> {
		const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
		url.searchParams.set("resultsPerPage", String(Math.min(Math.max(limit, 1), 100)));
		if (keyword) url.searchParams.set("keywordSearch", keyword);
		const res = await fetch(url, { signal: AbortSignal.timeout(20_000) });
		if (!res.ok) throw new Error(`NVD API fetch failed: HTTP ${res.status}`);
		const json = (await res.json()) as { vulnerabilities?: Array<{ cve?: Record<string, any> }> };
		const entries: VulnIntelEntry[] = [];
		for (const item of json.vulnerabilities ?? []) {
			const cve = item.cve;
			if (!cve?.id) continue;
			const desc = (cve.descriptions as Array<{ lang: string; value: string }> | undefined)?.find((d) => d.lang === "en")?.value ?? "";
			const metric = cve.metrics?.cvssMetricV31?.[0]?.cvssData ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData;
			const score = typeof metric?.baseScore === "number" ? metric.baseScore : null;
			const sev = score == null ? "medium" : score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
			entries.push({
				id: `nvd:${cve.id}`,
				source: "nvd",
				cveId: String(cve.id),
				title: String(cve.id),
				severity: sev,
				cvss: score,
				affectedProduct: keyword || "general",
				affectedVersions: "",
				description: desc,
				references: ((cve.references as Array<{ url?: string }> | undefined) ?? []).map((r) => String(r.url ?? "")).filter(Boolean).slice(0, 8),
				pocTemplate: "",
				publishedAt: String(cve.published ?? new Date().toISOString()),
				updatedAt: new Date().toISOString(),
			});
		}
		return this.store.upsertVulnIntel(entries);
	}

	async syncGhsaAdvisories(limit = 30): Promise<number> {
		const res = await fetch(`https://api.github.com/advisories?per_page=${Math.min(Math.max(limit, 1), 100)}&type=reviewed`, {
			headers: { accept: "application/vnd.github+json", "user-agent": "tengu-pentest" },
			signal: AbortSignal.timeout(20_000),
		});
		if (!res.ok) throw new Error(`GHSA API fetch failed: HTTP ${res.status}`);
		const list = (await res.json()) as Array<Record<string, any>>;
		const entries: VulnIntelEntry[] = list.map((a) => ({
			id: `ghsa:${a.ghsa_id}`,
			source: "ghsa",
			cveId: String(a.cve_id ?? ""),
			title: String(a.summary ?? a.ghsa_id ?? ""),
			severity: (["critical", "high", "medium", "low"].includes(String(a.severity).toLowerCase()) ? String(a.severity).toLowerCase() : "medium") as VulnIntelEntry["severity"],
			cvss: typeof a.cvss?.score === "number" ? a.cvss.score : null,
			affectedProduct: String(a.vulnerabilities?.[0]?.package?.name ?? ""),
			affectedVersions: String(a.vulnerabilities?.[0]?.vulnerable_version_range ?? ""),
			description: String(a.description ?? "").slice(0, 2000),
			references: Array.isArray(a.references) ? a.references.map(String).slice(0, 8) : [],
			pocTemplate: "",
			publishedAt: String(a.published_at ?? new Date().toISOString()),
			updatedAt: new Date().toISOString(),
		}));
		return this.store.upsertVulnIntel(entries);
	}

	async scanWithNuclei(input: {
		target: string;
		templates?: string[];
		severity?: string;
		timeoutMs?: number;
	}): Promise<{ available: boolean; exitCode: number; findings: unknown[]; rawOutput: string }> {
		const args = ["-u", input.target, "-jsonl", "-silent"];
		if (input.templates?.length) {
			for (const t of input.templates) args.push("-t", t);
		}
		if (input.severity) {
			args.push("-severity", input.severity);
		}
		return new Promise((resolve) => {
			const child = spawn("nuclei", args, { stdio: ["ignore", "pipe", "pipe"] });
			let stdout = "";
			let stderr = "";
			let settled = false;
			const timer = setTimeout(() => {
				child.kill("SIGKILL");
			}, input.timeoutMs ?? 60_000);

			child.on("error", (err) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				resolve({
					available: false,
					exitCode: -1,
					findings: [],
					rawOutput: `nuclei binary not available: ${err.message}`,
				});
			});
			child.stdout?.on("data", (d: Buffer) => {
				if (stdout.length < 128_000) stdout += d.toString("utf8");
			});
			child.stderr?.on("data", (d: Buffer) => {
				if (stderr.length < 32_000) stderr += d.toString("utf8");
			});
			child.on("close", (code) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				const findings: unknown[] = [];
				for (const line of stdout.split("\n")) {
					const trimmed = line.trim();
					if (!trimmed) continue;
					try {
						findings.push(JSON.parse(trimmed));
					} catch {
						// skip non-json
					}
				}
				resolve({
					available: true,
					exitCode: code ?? 0,
					findings,
					rawOutput: (stdout || stderr).slice(0, 16_000),
				});
			});
		});
	}

	getNetworkContext(): {
		interfaces: Array<{ name: string; address: string; family: string; internal: boolean }>;
		proxyEnv: Record<string, string>;
	} {
		const ifaces = networkInterfaces();
		const list: Array<{ name: string; address: string; family: string; internal: boolean }> = [];
		for (const [name, addrs] of Object.entries(ifaces)) {
			for (const a of addrs ?? []) {
				list.push({ name, address: a.address, family: String(a.family), internal: a.internal });
			}
		}
		const proxyEnv: Record<string, string> = {};
		for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy"]) {
			if (process.env[k]) proxyEnv[k] = process.env[k]!;
		}
		return { interfaces: list, proxyEnv };
	}
}
