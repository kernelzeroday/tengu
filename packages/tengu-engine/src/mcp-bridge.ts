import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface McpServerSpec {
	name: string;
	transport: "stdio" | "http";
	command?: string;
	args?: string[];
	url?: string;
	headers?: Record<string, string>;
	enabled?: boolean;
}

/**
 * Loads user-configured external MCP servers from ~/.tengu/mcp.json (e.g., Playwright MCP, FOFA).
 */
export function loadMcpServerConfigs(tenguHome: string): McpServerSpec[] {
	const cfgPath = join(tenguHome, "mcp.json");
	if (!existsSync(cfgPath)) return [];
	try {
		const raw = JSON.parse(readFileSync(cfgPath, "utf8")) as { servers?: Record<string, Partial<McpServerSpec>> };
		const out: McpServerSpec[] = [];
		for (const [name, spec] of Object.entries(raw.servers ?? {})) {
			if (spec.enabled === false) continue;
			out.push({
				name,
				transport: spec.url ? "http" : "stdio",
				command: spec.command,
				args: spec.args ?? [],
				url: spec.url,
				headers: spec.headers,
				enabled: true,
			});
		}
		return out;
	} catch {
		return [];
	}
}
