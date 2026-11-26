import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";

export interface HostToolInfo {
	name: string;
	category: "recon" | "web" | "scanner" | "network" | "crypto_tls" | "supply_chain" | "runtime";
	path: string;
	note: string;
}

const KNOWN_HOST_TOOLS: Array<Omit<HostToolInfo, "path">> = [
	// Recon & Network
	{ name: "nmap", category: "recon", note: "Port & service scanner" },
	{ name: "masscan", category: "recon", note: "High-speed TCP port scanner" },
	{ name: "subfinder", category: "recon", note: "Passive subdomain enumeration" },
	{ name: "amass", category: "recon", note: "Attack surface & ASN mapping" },
	{ name: "dig", category: "network", note: "DNS lookup utility" },
	{ name: "doggo", category: "network", note: "Modern DNS client" },
	{ name: "ss", category: "network", note: "Local socket inspection" },
	{ name: "nc", category: "network", note: "Netcat TCP/UDP utility" },
	{ name: "tshark", category: "network", note: "CLI packet analyzer" },
	// Web & API
	{ name: "httpx", category: "web", note: "Fast HTTP prober & tech fingerprinter" },
	{ name: "ffuf", category: "web", note: "Fast web fuzzer" },
	{ name: "gobuster", category: "web", note: "Directory & DNS brute-forcer" },
	{ name: "feroxbuster", category: "web", note: "Recursive content discovery" },
	{ name: "curl", category: "web", note: "HTTP client" },
	{ name: "xh", category: "web", note: "Friendly HTTP/JSON client" },
	{ name: "websocat", category: "web", note: "WebSocket CLI client" },
	{ name: "grpcurl", category: "web", note: "gRPC inspection & invocation" },
	// Scanners
	{ name: "nuclei", category: "scanner", note: "Template-based vulnerability scanner" },
	{ name: "sqlmap", category: "scanner", note: "SQL injection verification tool" },
	{ name: "nikto", category: "scanner", note: "Web server scanner" },
	{ name: "hydra", category: "scanner", note: "Auth testing utility (rate-limit carefully)" },
	// TLS & Crypto
	{ name: "openssl", category: "crypto_tls", note: "TLS certificate & cipher inspection" },
	{ name: "step", category: "crypto_tls", note: "X.509/JWT/PKI toolkit" },
	{ name: "jwtui", category: "crypto_tls", note: "JWT inspector" },
	// Supply chain & secrets
	{ name: "trivy", category: "supply_chain", note: "Container/FS/IaC vulnerability scanner" },
	{ name: "grype", category: "supply_chain", note: "SBOM vulnerability scanner" },
	{ name: "syft", category: "supply_chain", note: "SBOM generator" },
	{ name: "osv-scanner", category: "supply_chain", note: "OSV dependency vulnerability scanner" },
	{ name: "gitleaks", category: "supply_chain", note: "Secret & credential scanner" },
	{ name: "zizmor", category: "supply_chain", note: "GitHub Actions security auditor" },
	// Runtimes
	{ name: "python3", category: "runtime", note: "Python 3 scripting" },
	{ name: "node", category: "runtime", note: "Node.js runtime" },
	{ name: "jq", category: "runtime", note: "JSON processor" },
];

function findExecutableOnPath(bin: string, pathDirs: string[]): string | null {
	for (const dir of pathDirs) {
		if (!dir) continue;
		const full = join(dir, bin);
		try {
			accessSync(full, constants.X_OK);
			return full;
		} catch {
			// not here
		}
	}
	return null;
}

/**
 * Discovers installed security/pentest binaries on the host PATH (ARTEX hosttools parity).
 */
export function discoverHostTools(envPath = process.env.PATH ?? ""): HostToolInfo[] {
	const dirs = envPath.split(delimiter).filter(Boolean);
	const found: HostToolInfo[] = [];
	for (const spec of KNOWN_HOST_TOOLS) {
		const resolved = findExecutableOnPath(spec.name, dirs);
		if (resolved) {
			found.push({ ...spec, path: resolved });
		}
	}
	return found;
}

export function formatHostToolsForPrompt(tools: HostToolInfo[]): string {
	if (tools.length === 0) return "No external security binaries detected on PATH.";
	const byCat = new Map<string, string[]>();
	for (const t of tools) {
		const arr = byCat.get(t.category) ?? [];
		arr.push(t.name);
		byCat.set(t.category, arr);
	}
	const lines = ["Available host security binaries:"];
	for (const [cat, names] of byCat.entries()) {
		lines.push(`- ${cat}: ${names.join(", ")}`);
	}
	return lines.join("\n");
}
