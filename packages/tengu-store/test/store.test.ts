import assert from "node:assert/strict";
import test from "node:test";
import { checkTargetScope, SqliteTenguStore } from "../src/index.ts";

test("SqliteTenguStore dual graph, Asset DSL, scope guard, and findings", () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		const company = store.createCompany("Acme Corp", "Authorized pentest target");
		store.addCompanyScope({ companyId: company.id, pattern: "*.acme.test", kind: "domain", exclude: false, note: "" });
		store.addCompanyScope({ companyId: company.id, pattern: "prod-db.acme.test", kind: "domain", exclude: true, note: "out of scope" });
		store.addCompanyScope({ companyId: company.id, pattern: "10.20.0.0/16", kind: "cidr", exclude: false, note: "" });

		const scopeRules = store.listCompanyScope(company.id);
		assert.equal(checkTargetScope("https://api.acme.test/v1", scopeRules).inScope, true);
		assert.equal(checkTargetScope("https://prod-db.acme.test", scopeRules).inScope, false);
		assert.equal(checkTargetScope("10.20.5.9", scopeRules).inScope, true);
		assert.equal(checkTargetScope("192.168.1.1", scopeRules).inScope, false);

		const task = store.createTask({ name: "Q4 API Audit", companyId: company.id });
		const assets = store.upsertAssets([
			{ taskId: task.id, companyId: company.id, kind: "site", value: "https://api.acme.test" },
			{ taskId: task.id, companyId: company.id, kind: "endpoint", value: "https://api.acme.test/admin/users" },
			{ taskId: task.id, companyId: company.id, kind: "endpoint", value: "https://api.acme.test/health" },
		]);
		assert.equal(assets.length, 3);
		store.addAssetEdge(assets[0].id, assets[1].id, "hosts_endpoint");
		const neighbors = store.getAssetNeighbors(assets[0].id);
		assert.equal(neighbors.outgoing.length, 1);

		const dslMatches = store.listAssets({ taskId: task.id, query: "kind:endpoint tested:false value~admin" });
		assert.equal(dslMatches.length, 1);
		assert.equal(dslMatches[0].value, "https://api.acme.test/admin/users");

		const intent = store.addExplorationNode({
			taskId: task.id,
			kind: "intent",
			state: "open",
			summary: "Check IDOR on /admin/users",
			assetIds: [assets[1].id],
		});
		const fact = store.addExplorationNode({
			taskId: task.id,
			kind: "fact",
			state: "done",
			summary: "Confirmed missing role check",
			assetIds: [assets[1].id],
		});
		store.addExplorationEdge(task.id, intent.id, fact.id, "yields");
		store.markAssetsTested([assets[1].id], intent.id);

		const overview = store.getGraphOverview(task.id);
		assert.equal(overview.intents.length, 1);
		assert.deepEqual(overview.intents[0].yields, [fact.id]);
		assert.equal(overview.coverage?.tested, 1);
		assert.equal(overview.coverage?.total, 3);
	} finally {
		store.close();
	}
});

test("Cross-task inheritance surfaces parent facts (inherited=true) and findings in child task", () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		const parent = store.createTask({ name: "Baseline Recon" });
		store.addExplorationNode({ taskId: parent.id, kind: "fact", state: "done", summary: "Parent discovered Caddy :8080" });
		store.addFinding({
			taskId: parent.id,
			nodeId: null,
			intentId: null,
			title: "Parent Finding",
			vulnClass: "info-disclosure",
			severity: "low",
			status: "verified",
			summary: "Leaks version",
			description: "",
			reproduction: "",
			remediation: "",
			evidence: "v1.1.70",
			evidenceIds: [],
			assetIds: [],
			cvss: null,
			cwe: "",
			fingerprint: "fp-parent",
		});

		const child = store.createTask({ name: "Follow-up Deep Dive", parentTaskId: parent.id });
		store.addExplorationNode({ taskId: child.id, kind: "fact", state: "done", summary: "Child tested /metrics" });

		const ov = store.getGraphOverview(child.id);
		assert.equal(ov.recentFacts.length, 2);
		const inherited = ov.recentFacts.find((f) => f.inherited);
		assert.ok(inherited, "Child overview should include inherited parent fact");
		assert.equal(inherited!.sourceTaskId, parent.id);
		assert.equal(ov.findings.length, 1);
		assert.equal(ov.findings[0]!.title, "Parent Finding");
	} finally {
		store.close();
	}
});
