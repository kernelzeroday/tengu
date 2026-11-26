import type { AssetNode, CompanyScopeRule, TaskScopeRule } from "./types.ts";

export interface AssetDslClause {
	field: "kind" | "value" | "label" | "tested" | "source" | "any";
	op: ":" | "~" | "!=" | "=";
	value: string;
}

/**
 * Parse a lightweight ARTEX-compatible Asset DSL query such as:
 *   kind:endpoint tested:false value~admin
 */
export function parseAssetDsl(query: string): AssetDslClause[] {
	const trimmed = query.trim();
	if (!trimmed) return [];
	const tokens = trimmed.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
	const clauses: AssetDslClause[] = [];
	for (const raw of tokens) {
		if (raw.toUpperCase() === "AND") continue;
		const match = raw.match(/^(kind|value|label|tested|source)(!=|:|~|=)(.+)$/);
		if (match) {
			const field = match[1] as AssetDslClause["field"];
			const op = match[2] as AssetDslClause["op"];
			const value = match[3].replace(/^"|"$/g, "");
			clauses.push({ field, op, value });
		} else {
			clauses.push({ field: "any", op: "~", value: raw.replace(/^"|"$/g, "") });
		}
	}
	return clauses;
}

export function matchesAssetDsl(asset: AssetNode, clauses: AssetDslClause[]): boolean {
	for (const c of clauses) {
		const target = c.value.toLowerCase();
		if (c.field === "tested") {
			const expected = target === "true" || target === "1" || target === "yes";
			const ok = c.op === "!=" ? asset.tested !== expected : asset.tested === expected;
			if (!ok) return false;
			continue;
		}
		const haystack =
			c.field === "kind"
				? asset.kind.toLowerCase()
				: c.field === "value"
					? asset.value.toLowerCase()
					: c.field === "label"
						? asset.label.toLowerCase()
						: c.field === "source"
							? asset.source.toLowerCase()
							: `${asset.kind} ${asset.value} ${asset.label} ${asset.source}`.toLowerCase();

		if (c.op === "!=") {
			if (haystack === target) return false;
		} else if (c.op === "~" || c.field === "any") {
			if (!haystack.includes(target)) return false;
		} else {
			if (haystack !== target) return false;
		}
	}
	return true;
}

function ipv4ToInt(ip: string): number | null {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	let acc = 0;
	for (const p of parts) {
		if (!/^\d+$/.test(p)) return null;
		const n = Number(p);
		if (n < 0 || n > 255) return null;
		acc = (acc << 8) | n;
	}
	return acc >>> 0;
}

export function matchCidr(ip: string, cidr: string): boolean {
	const [net, prefixStr] = cidr.split("/");
	if (!net || !prefixStr) return ip === cidr;
	const ipInt = ipv4ToInt(ip);
	const netInt = ipv4ToInt(net);
	const prefix = Number(prefixStr);
	if (ipInt === null || netInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
		return false;
	}
	const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
	return (ipInt & mask) === (netInt & mask);
}

export function extractHost(target: string): string {
	const trimmed = target.trim();
	if (/^https?:\/\//i.test(trimmed)) {
		try {
			return new URL(trimmed).hostname.toLowerCase();
		} catch {
			return trimmed.toLowerCase();
		}
	}
	return trimmed.replace(/:\d+$/, "").toLowerCase();
}

export function matchScopeRule(
	target: string,
	rule: Pick<TaskScopeRule | CompanyScopeRule, "pattern" | "kind">,
): boolean {
	const host = extractHost(target);
	const pat = rule.pattern.trim().toLowerCase();
	switch (rule.kind) {
		case "domain": {
			if (pat.startsWith("*.")) {
				const suffix = pat.slice(2);
				return host === suffix || host.endsWith(`.${suffix}`);
			}
			return host === pat || host.endsWith(`.${pat}`);
		}
		case "ip":
			return host === pat;
		case "cidr":
			return matchCidr(host, pat);
		case "url": {
			try {
				const tUrl = new URL(target.trim());
				const pUrl = new URL(pat);
				if (tUrl.origin.toLowerCase() !== pUrl.origin.toLowerCase()) return false;
				if (pUrl.pathname === "/" || pUrl.pathname === "") return true;
				const normPath = pUrl.pathname.endsWith("/") ? pUrl.pathname : pUrl.pathname + "/";
				return tUrl.pathname === pUrl.pathname || tUrl.pathname.startsWith(normPath);
			} catch {
				return target.toLowerCase().startsWith(pat);
			}
		}
		case "regex":
			try {
				return new RegExp(rule.pattern, "i").test(target);
			} catch {
				return false;
			}
	}
}

export interface ScopeCheckResult {
	inScope: boolean;
	matchedRule?: string;
	excludedBy?: string;
}

/**
 * Evaluates target against scope rules. Exclusions always take precedence over inclusions.
 * If no inclusion rules exist, defaults to true (unrestricted) unless explicitly excluded.
 */
export function checkTargetScope(
	target: string,
	rules: Array<Pick<TaskScopeRule | CompanyScopeRule, "pattern" | "kind" | "exclude">>,
): ScopeCheckResult {
	const excludes = rules.filter((r) => r.exclude);
	for (const r of excludes) {
		if (matchScopeRule(target, r)) {
			return { inScope: false, excludedBy: r.pattern };
		}
	}
	const includes = rules.filter((r) => !r.exclude);
	if (includes.length === 0) {
		return { inScope: true };
	}
	for (const r of includes) {
		if (matchScopeRule(target, r)) {
			return { inScope: true, matchedRule: r.pattern };
		}
	}
	return { inScope: false };
}

export function normalizeAssetKey(kind: string, value: string): string {
	const v = value.trim();
	if (kind === "domain" || kind === "subdomain" || kind === "ip" || kind === "cidr") {
		return `${kind}:${v.toLowerCase()}`;
	}
	if (kind === "site" || kind === "endpoint") {
		try {
			const u = new URL(v);
			return `${kind}:${u.protocol}//${u.host.toLowerCase()}${u.pathname}${u.search}`;
		} catch {
			return `${kind}:${v}`;
		}
	}
	return `${kind}:${v}`;
}
