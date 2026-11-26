import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface TenguSkill {
	id: string;
	name: string;
	tags: string[];
	summary: string;
	guidance: string;
	source: "builtin" | "custom";
}

/**
 * 100% original Tengu pentest skill catalog covering all 23 ARTEX skill domains.
 */
export const BUILTIN_TENGU_SKILLS: TenguSkill[] = [
	{
		id: "attack-surface-recon",
		name: "Attack Surface Recon",
		tags: ["recon", "assets", "discovery"],
		summary: "Enumerate domains, subdomains, IPs, ports, HTTP services, and populate the Asset Graph.",
		guidance: "Start with passive/active host discovery, run http_probe on live hosts, record every discovered asset via insert_assets, and link relationships.",
		source: "builtin",
	},
	{
		id: "web-attack-methods",
		name: "Web Attack Methods",
		tags: ["web", "owasp", "injection", "xss", "ssrf"],
		summary: "Systematic testing for SQLi, XSS, SSRF, CSRF, SSTI, XXE, path traversal, and file upload flaws.",
		guidance: "Enumerate input vectors, test minimal non-destructive proof payloads, verify OOB callbacks with listener_start when testing blind SSRF/XXE, and capture evidence.",
		source: "builtin",
	},
	{
		id: "api-recon",
		name: "API Recon",
		tags: ["api", "openapi", "graphql", "rest"],
		summary: "Discover REST/GraphQL schemas, undocumented endpoints, versioning, and parameter contracts.",
		guidance: "Check /openapi.json, /swagger.json, /v3/api-docs, /graphql introspection, and run api_contract + js_audit on frontend bundles.",
		source: "builtin",
	},
	{
		id: "api-security-testing",
		name: "API Security Testing",
		tags: ["api", "bola", "idor", "authz", "jwt"],
		summary: "Test BOLA/IDOR, BFLA, mass assignment, JWT flaws, and rate-limit bypasses.",
		guidance: "Establish multiple auth profiles via session_login, replay requests with auth_request across roles, and compare responses with diff_responses.",
		source: "builtin",
	},
	{
		id: "active-directory-attack",
		name: "Active Directory Attack",
		tags: ["ad", "kerberos", "ldap", "windows"],
		summary: "Assess AD trust boundaries, Kerberoasting, AS-REP roasting, ACL abuse, and ADCS misconfigurations.",
		guidance: "Enumerate domain controllers, SPNs, delegations, and certificate templates carefully within authorized scope.",
		source: "builtin",
	},
	{
		id: "ai-llm-app-attack",
		name: "AI & LLM App Attack",
		tags: ["ai", "llm", "prompt-injection", "rag"],
		summary: "Test LLM applications for prompt injection, system prompt leakage, tool misuse, and RAG data exfiltration.",
		guidance: "Probe direct and indirect injection boundaries, tool parameter validation, and cross-tenant retrieval isolation.",
		source: "builtin",
	},
	{
		id: "apk-reverse",
		name: "APK Reverse Engineering",
		tags: ["mobile", "android", "apk"],
		summary: "Decompile Android APKs to audit hardcoded secrets, exported components, deep links, and API endpoints.",
		guidance: "Inspect AndroidManifest.xml, decompiled classes, network security config, and embedded API keys.",
		source: "builtin",
	},
	{
		id: "binary-mobile-reversing",
		name: "Binary & Mobile Reversing",
		tags: ["reversing", "binary", "elf", "macho"],
		summary: "Static and dynamic analysis of native binaries and mobile libraries for memory corruption and logic flaws.",
		guidance: "Check security mitigations (PIE, NX, Canary, RELRO), symbols, unsafe string/buffer routines, and IPC handlers.",
		source: "builtin",
	},
	{
		id: "cloud-attack-methods",
		name: "Cloud Attack Methods",
		tags: ["cloud", "aws", "gcp", "azure", "k8s"],
		summary: "Audit IAM privilege escalation, metadata SSRF (IMDS), public storage buckets, and Kubernetes RBAC.",
		guidance: "Check exposed storage, misconfigured IAM trust policies, IMDSv1 reachability via SSRF, and kubelet/API exposure.",
		source: "builtin",
	},
	{
		id: "component-vuln-intel",
		name: "Component Vuln Intel",
		tags: ["cve", "nuclei", "intel", "sca"],
		summary: "Map fingerprinted software versions to known CVEs, CISA KEV advisories, and Nuclei templates.",
		guidance: "Fingerprint headers/versions via http_probe, query search_vulns/get_poc, and validate safely with scan_with_nuclei.",
		source: "builtin",
	},
	{
		id: "pentest-output-standards",
		name: "Pentest Output Standards",
		tags: ["reporting", "evidence", "standards"],
		summary: "Ensure every finding has clear severity, CWE/CVSS, deterministic reproduction, raw evidence, and remediation.",
		guidance: "Always attach SHA-256 artifacts via save_evidence and verify completeness with evidence_check before finalizing.",
		source: "builtin",
	},
	{
		id: "pentest-verification",
		name: "Pentest Verification",
		tags: ["verification", "retest", "validation"],
		summary: "Independently reproduce and validate candidate vulnerabilities to eliminate false positives.",
		guidance: "Re-execute minimal PoCs from a clean state, verify impact directly, and distinguish true positives from scanner noise.",
		source: "builtin",
	},
	{
		id: "playwright-cli",
		name: "Browser & Playwright Testing",
		tags: ["browser", "dom-xss", "spa", "playwright"],
		summary: "Automate headless browser flows for SPA auth, DOM XSS verification, and client-side state inspection.",
		guidance: "Inspect runtime DOM sinks, localStorage/sessionStorage tokens, postMessage listeners, and network XHR/fetch calls.",
		source: "builtin",
	},
	{
		id: "redteam-ops",
		name: "Red Team Operations",
		tags: ["redteam", "lateral-movement", "c2"],
		summary: "Objective-driven adversary emulation across initial access, privilege escalation, and lateral movement.",
		guidance: "Chain verified low/medium findings toward engagement goals while documenting every pivot in the exploration graph.",
		source: "builtin",
	},
	{
		id: "redteam-opsec",
		name: "Red Team OPSEC",
		tags: ["opsec", "stealth", "safety"],
		summary: "Minimize operational noise, avoid destructive payloads, and clean up test artifacts cleanly.",
		guidance: "Throttle noisy scans, avoid account lockouts, track all created test objects, and clean up on wrap-up.",
		source: "builtin",
	},
	{
		id: "scopesentry",
		name: "ScopeSentry Asset Sync",
		tags: ["scopesentry", "assets", "sync"],
		summary: "Ingest and reconcile external ScopeSentry project assets into Tengu's Asset Graph.",
		guidance: "Sync subdomains, sites, IPs, and endpoints by project ID and verify scope alignment before launching workers.",
		source: "builtin",
	},
	{
		id: "smart-contract-audit",
		name: "Smart Contract Audit",
		tags: ["web3", "solidity", "defi"],
		summary: "Audit smart contracts for reentrancy, access control flaws, oracle manipulation, and arithmetic bugs.",
		guidance: "Inspect state transitions, external calls before state updates, privilege modifiers, and flash-loan invariants.",
		source: "builtin",
	},
	{
		id: "source-code-hunting",
		name: "Source Code Hunting",
		tags: ["sast", "code-audit", "whitebox"],
		summary: "Whitebox source review tracing untrusted sources to dangerous sinks across web and backend repos.",
		guidance: "Map route handlers, auth middleware, deserialization/SQL/command sinks, and verify findings dynamically when possible.",
		source: "builtin",
	},
	{
		id: "src-acceptance",
		name: "SRC Acceptance & Triage",
		tags: ["bounty", "triage", "src"],
		summary: "Structure high-signal vulnerability submissions aligned with bug bounty / SRC acceptance criteria.",
		guidance: "Focus on demonstrable business impact, deduplicate against known fingerprints, and provide one-click reproduction.",
		source: "builtin",
	},
	{
		id: "src-hunting",
		name: "SRC Hunting",
		tags: ["bounty", "recon", "src"],
		summary: "High-efficiency asset discovery and vulnerability hunting for bug bounty / SRC programs.",
		guidance: "Target newly deployed subdomains, JS bundle endpoints, and overlooked staging/API surfaces.",
		source: "builtin",
	},
	{
		id: "vuln-hunting",
		name: "Vulnerability Hunting",
		tags: ["vuln", "exploitation", "deep-dive"],
		summary: "Deep hypothesis-driven vulnerability discovery on high-value target components.",
		guidance: "Combine code/JS analysis, differential testing, and protocol fuzzing to uncover non-trivial logic and injection bugs.",
		source: "builtin",
	},
	{
		id: "wireless-hardware-attack",
		name: "Wireless & Hardware Assessment",
		tags: ["wireless", "iot", "firmware"],
		summary: "Assess IoT firmware, UART/JTAG interfaces, BLE/Wi-Fi protocols, and embedded web panels.",
		guidance: "Extract firmware images, inspect default credentials, hardcoded keys, and exposed local management services.",
		source: "builtin",
	},
	{
		id: "zero-day-research",
		name: "Zero-Day Research",
		tags: ["0day", "fuzzing", "variant-analysis"],
		summary: "Variant analysis, patch diffing, and targeted fuzzing to discover novel vulnerabilities.",
		guidance: "Study prior CVEs in the target stack, search for analogous patterns across endpoints/parsers, and craft minimal reproducers.",
		source: "builtin",
	},
];

export function loadSkills(customDir?: string): TenguSkill[] {
	const skills = [...BUILTIN_TENGU_SKILLS];
	if (!customDir || !existsSync(customDir)) return skills;
	for (const entry of readdirSync(customDir, { withFileTypes: true })) {
		if (!entry.isDirectory()) continue;
		const skillFile = join(customDir, entry.name, "SKILL.md");
		if (!existsSync(skillFile)) continue;
		const content = readFileSync(skillFile, "utf8");
		const firstLine = content.split("\n").find((l) => l.trim().startsWith("#")) ?? entry.name;
		skills.push({
			id: entry.name,
			name: firstLine.replace(/^#+\s*/, "").trim() || entry.name,
			tags: ["custom"],
			summary: content.slice(0, 180).replace(/\s+/g, " ").trim(),
			guidance: content,
			source: "custom",
		});
	}
	return skills;
}

export function findSkill(idOrName: string, customDir?: string): TenguSkill | null {
	const q = idOrName.trim().toLowerCase();
	return loadSkills(customDir).find((s) => s.id.toLowerCase() === q || s.name.toLowerCase() === q) ?? null;
}

export function renderSkillPlaybook(skill: TenguSkill): string {
	return [
		`# Skill Playbook: ${skill.name} (\`${skill.id}\`)`,
		`**Tags:** ${skill.tags.join(", ")}`,
		"",
		"## Objective",
		skill.summary,
		"",
		"## Methodology & Tool Sequence",
		skill.guidance,
		"",
		"## Verification & Evidence Standards",
		"- Anchor every newly discovered host/port/endpoint with `insert_assets`.",
		"- Record concrete, non-duplicate technical facts with `record_fact`.",
		"- Confirm vulnerability impact with minimal non-destructive proof, archive raw output via `save_evidence`, and file via `report_finding`.",
	].join("\n");
}

export function formatSkillIndex(customDir?: string): string {
	const skills = loadSkills(customDir);
	return [
		`Available Security Skills (${skills.length} — call load_skill with an ID to read full methodology):`,
		...skills.map((s) => `- ${s.id}: ${s.summary}`),
	].join("\n");
}
