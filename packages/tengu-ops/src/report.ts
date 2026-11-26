import type { Finding, Severity, TenguStore } from "@tengu/store";
import { buildDocxBuffer, type DocxParagraph } from "./docx.ts";
import { maskSecrets } from "./notify.ts";

export type ReportFormat = "markdown" | "json" | "sarif" | "html" | "docx";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function escapeHtml(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function codeFence(text: string): string {
	const longestRun = (text.match(/`+/g) ?? []).reduce((longest, run) => Math.max(longest, run.length), 0);
	return "`".repeat(Math.max(3, longestRun + 1));
}

function sarifLevel(sev: Severity): "error" | "warning" | "note" {
	if (sev === "critical" || sev === "high") return "error";
	if (sev === "medium") return "warning";
	return "note";
}

export class ReportGenerator {
	private readonly store: TenguStore;

	constructor(store: TenguStore) {
		this.store = store;
	}

	generate(taskId: number, format: ReportFormat = "markdown", sanitize = true): string {
		const task = this.store.getTask(taskId);
		if (!task) throw new Error(`Task #${taskId} not found`);

		const overview = this.store.getGraphOverview(taskId);
		const findings = [...overview.findings].sort(
			(a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
		);
		const artifacts = this.store.listArtifacts(taskId);
		const tokenTotals = this.store.getTaskTokenTotals(taskId);
		const clean = (s: string) => (sanitize ? maskSecrets(s) : s);
		const serialize = (value: object) =>
			JSON.stringify(value, (_key, field) => (typeof field === "string" ? clean(field) : field), 2);

		if (format === "json") {
			return serialize({
				generatedAt: new Date().toISOString(),
				task,
				coverage: overview.coverage,
				goals: overview.goals,
				findings,
				artifacts,
				usage: tokenTotals,
			});
		}

		if (format === "sarif") {
			const sarif = {
				version: "2.1.0",
				$schema: "https://json.schemastore.org/sarif-2.1.0.json",
				runs: [
					{
						tool: { driver: { name: "Tengu", version: "0.1.0", informationUri: "https://tengu.local" } },
						results: findings.map((f) => ({
							ruleId: f.vulnClass || "tengu-finding",
							level: sarifLevel(f.severity),
							message: { text: `${f.title}: ${f.summary}` },
							properties: {
								severity: f.severity,
								status: f.status,
								cwe: f.cwe,
								cvss: f.cvss,
								findingId: f.id,
							},
						})),
					},
				],
			};
			return serialize(sarif);
		}

		const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
		for (const f of findings) counts[f.severity]++;

		if (format === "html") {
			const rows = findings
				.map(
					(f: Finding) => `
				<section class="finding sev-${f.severity}">
					<h3>[${f.severity.toUpperCase()}] #${f.id} ${escapeHtml(clean(f.title))}</h3>
					<p><strong>Class:</strong> ${escapeHtml(clean(f.vulnClass))} | <strong>Status:</strong> ${escapeHtml(f.status)} | <strong>CWE:</strong> ${escapeHtml(clean(f.cwe || "N/A"))}</p>
					<p>${escapeHtml(clean(f.summary))}</p>
					${f.reproduction ? `<h4>Reproduction</h4><pre>${escapeHtml(clean(f.reproduction))}</pre>` : ""}
					${f.evidence ? `<h4>Evidence</h4><pre>${escapeHtml(clean(f.evidence))}</pre>` : ""}
					${f.remediation ? `<h4>Remediation</h4><p>${escapeHtml(clean(f.remediation))}</p>` : ""}
				</section>`,
				)
				.join("\n");
			return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Tengu Report - ${escapeHtml(clean(task.name))}</title>
<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#111}pre{background:#f5f5f5;padding:1rem;overflow:auto;border-radius:6px}.finding{border-left:4px solid #888;padding-left:1rem;margin:1.5rem 0}.sev-critical{border-color:#b91c1c}.sev-high{border-color:#ea580c}.sev-medium{border-color:#ca8a04}.sev-low{border-color:#2563eb}</style>
</head>
<body>
<h1>Tengu Penetration Test Report: ${escapeHtml(clean(task.name))}</h1>
<p><strong>Task ID:</strong> ${task.id} | <strong>Status:</strong> ${task.status} | <strong>Generated:</strong> ${new Date().toISOString()}</p>
<h2>Summary</h2>
<p>Critical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low} | Info: ${counts.info}</p>
<h2>Findings (${findings.length})</h2>
${rows || "<p>No findings recorded.</p>"}
</body></html>`;
		}

		// Default: Markdown
		const lines: string[] = [
			`# Tengu Penetration Test Report — ${clean(task.name)}`,
			"",
			`- **Task ID**: #${task.id}`,
			`- **Status**: ${task.status}`,
			`- **Generated**: ${new Date().toISOString()}`,
			`- **Tokens Used**: ${tokenTotals.totalTokens.toLocaleString()} ($${tokenTotals.costUsd.toFixed(4)})`,
			"",
			"## Executive Summary",
			"",
			`| Severity | Count |`,
			`| :--- | ---: |`,
			`| Critical | ${counts.critical} |`,
			`| High | ${counts.high} |`,
			`| Medium | ${counts.medium} |`,
			`| Low | ${counts.low} |`,
			`| Info | ${counts.info} |`,
			"",
		];

		if (overview.coverage) {
			lines.push(
				"## Asset Coverage",
				"",
				`Tested **${overview.coverage.tested} / ${overview.coverage.total}** assets (${overview.coverage.untested} untested).`,
				"",
			);
		}

		if (overview.goals.length > 0) {
			lines.push("## Goals", "");
			for (const g of overview.goals) {
				lines.push(`- [${g.state === "met" ? "x" : " "}] (#${g.id}) ${clean(g.summary)}`);
			}
			lines.push("");
		}

		lines.push(`## Findings (${findings.length})`, "");
		if (findings.length === 0) {
			lines.push("_No vulnerabilities reported._", "");
		} else {
			for (const f of findings) {
				lines.push(`### [${f.severity.toUpperCase()}] #${f.id} ${clean(f.title)}`, "");
				lines.push(`- **Class**: ${clean(f.vulnClass)} | **Status**: ${f.status} | **CWE**: ${clean(f.cwe || "N/A")} | **CVSS**: ${f.cvss ?? "N/A"}`);
				if (f.assetIds.length > 0) lines.push(`- **Assets**: ${f.assetIds.map((id) => `#${id}`).join(", ")}`);
				lines.push("", clean(f.summary), "");
				if (f.description) lines.push("#### Description", "", clean(f.description), "");
				for (const [title, value] of [["Reproduction", f.reproduction], ["Evidence", f.evidence]] as const) {
					if (!value) continue;
					const content = clean(value);
					const fence = codeFence(content);
					lines.push(`#### ${title}`, "", fence, content, fence, "");
				}
				if (f.remediation) lines.push("#### Remediation", "", clean(f.remediation), "");
			}
		}

		if (artifacts.length > 0) {
			lines.push("## Evidence Artifacts", "");
			for (const a of artifacts) {
				lines.push(`- **#${a.id} ${clean(a.name)}** (${clean(a.kind)}, ${a.sizeBytes} bytes, sha256: \`${a.sha256.slice(0, 16)}...\`)`);
			}
			lines.push("");
		}

		return lines.join("\n");
	}

	generateDocx(taskId: number, sanitize = true): Buffer {
		const task = this.store.getTask(taskId);
		if (!task) throw new Error(`Task #${taskId} not found`);
		const clean = (s: string) => (sanitize ? maskSecrets(s) : s);
		const findings = this.store.listFindings(taskId);
		const paragraphs: DocxParagraph[] = [
			{ text: `Tengu Penetration Test Report — ${task.name}`, heading: 1 },
			{ text: `Task #${task.id} | Status: ${task.status} | Generated: ${new Date().toISOString()}` },
			{ text: `Findings (${findings.length})`, heading: 2 },
		];
		for (const f of findings) {
			const retests = this.store.listFindingRetests(f.id);
			paragraphs.push({ text: `[${f.severity.toUpperCase()}] #${f.id} ${f.title}`, heading: 3 });
			paragraphs.push({ text: `Class: ${f.vulnClass} | Status: ${f.status} | CWE: ${f.cwe || "N/A"} | CVSS: ${f.cvss ?? "N/A"}` });
			paragraphs.push({ text: clean(f.summary) });
			if (f.reproduction) paragraphs.push({ text: `Reproduction:\n${clean(f.reproduction)}`, code: true });
			if (f.evidence) paragraphs.push({ text: `Evidence:\n${clean(f.evidence)}`, code: true });
			if (f.remediation) paragraphs.push({ text: `Remediation: ${f.remediation}` });
			if (retests.length > 0) {
				paragraphs.push({ text: `Verification History: ${retests.map((r) => `${r.status} (${r.createdAt.slice(0, 10)})`).join(", ")}` });
			}
		}
		return buildDocxBuffer(paragraphs);
	}

	generateFinding(findingId: number, format: Exclude<ReportFormat, "docx"> = "markdown", sanitize = true): string {
		const f = this.store.getFinding(findingId);
		if (!f) throw new Error(`Finding #${findingId} not found`);
		const clean = (s: string) => (sanitize ? maskSecrets(s) : s);
		const retests = this.store.listFindingRetests(findingId);
		const artifacts = f.evidenceIds.map((id) => this.store.getArtifact(id)).filter((a) => a !== null);

		if (format === "json") {
			return JSON.stringify(
				{
					finding: { ...f, summary: clean(f.summary), description: clean(f.description), reproduction: clean(f.reproduction), evidence: clean(f.evidence) },
					retests: retests.map((r) => ({ ...r, notes: clean(r.notes), evidence: clean(r.evidence) })),
					artifacts,
				},
				null,
				2,
			);
		}
		if (format === "sarif") {
			return JSON.stringify(
				{
					version: "2.1.0",
					$schema: "https://json.schemastore.org/sarif-2.1.0.json",
					runs: [
						{
							tool: { driver: { name: "Tengu", version: "0.1.0" } },
							results: [{ ruleId: f.vulnClass, level: sarifLevel(f.severity), message: { text: clean(`${f.title}: ${f.summary}`) } }],
						},
					],
				},
				null,
				2,
			);
		}
		if (format === "html") {
			return `<!doctype html><html><head><meta charset="utf-8"><title>Finding #${f.id}</title></head><body><h1>[${f.severity.toUpperCase()}] ${escapeHtml(f.title)}</h1><p>${escapeHtml(clean(f.summary))}</p><pre>${escapeHtml(clean(f.evidence))}</pre></body></html>`;
		}
		const lines = [
			`# [${f.severity.toUpperCase()}] Finding #${f.id}: ${f.title}`,
			"",
			`- **Class**: ${f.vulnClass} | **Status**: ${f.status} | **CWE**: ${f.cwe || "N/A"} | **CVSS**: ${f.cvss ?? "N/A"}`,
			"",
			"## Summary",
			clean(f.summary),
			"",
			"## Reproduction",
			f.reproduction ? `\`\`\`\n${clean(f.reproduction)}\n\`\`\`` : "_None_",
			"",
			"## Evidence",
			f.evidence ? `\`\`\`\n${clean(f.evidence)}\n\`\`\`` : "_None_",
			"",
			"## Remediation",
			f.remediation || "_None_",
		];
		if (retests.length > 0) {
			lines.push("", "## Verification History");
			for (const r of retests) {
				lines.push(`- **${r.status}** (${r.createdAt}): ${clean(r.notes)}`);
			}
		}
		if (artifacts.length > 0) {
			lines.push("", "## Linked Evidence Artifacts");
			for (const a of artifacts) {
				lines.push(`- #${a!.id} ${a!.name} (sha256: \`${a!.sha256.slice(0, 16)}...\`)`);
			}
		}
		return lines.join("\n");
	}

	generateFindingDocx(findingId: number, sanitize = true): Buffer {
		const f = this.store.getFinding(findingId);
		if (!f) throw new Error(`Finding #${findingId} not found`);
		const clean = (s: string) => (sanitize ? maskSecrets(s) : s);
		const retests = this.store.listFindingRetests(findingId);
		const paragraphs: DocxParagraph[] = [
			{ text: `[${f.severity.toUpperCase()}] Finding #${f.id}: ${f.title}`, heading: 1 },
			{ text: `Class: ${f.vulnClass} | Status: ${f.status} | CWE: ${f.cwe || "N/A"} | CVSS: ${f.cvss ?? "N/A"}` },
			{ text: clean(f.summary) },
			...(f.reproduction ? [{ text: clean(f.reproduction), code: true }] : []),
			...(f.evidence ? [{ text: clean(f.evidence), code: true }] : []),
			...(f.remediation ? [{ text: `Remediation: ${f.remediation}` }] : []),
			...retests.map((r) => ({ text: `Retest (${r.status}): ${clean(r.notes)}` })),
		];
		return buildDocxBuffer(paragraphs);
	}
}
