import assert from "node:assert/strict";
import test from "node:test";
import { assertProperty } from "../../../test/helpers/prng.ts";
import { checkTargetScope, matchCidr, matchesAssetDsl, parseAssetDsl, SqliteTenguStore } from "../src/index.ts";

function ipToUint32(ip: string): number {
	const [a, b, c, d] = ip.split(".").map(Number);
	return (((a! << 24) | (b! << 16) | (c! << 8) | d!) >>> 0);
}

test("Property P1: ScopeGuard exclusion dominance, anti-spoofing, and CIDR bitwise equivalence", () => {
	assertProperty(
		"ScopeGuard invariants",
		(rng) => {
			const baseDomain = rng.domain();
			const sub = `${rng.asciiString(1, 6, "abcdefghijklmnopqrstuvwxyz")}.${baseDomain}`;
			const spoofed = `evil-${baseDomain}`;
			const suffixSpoof = `${baseDomain}.evil.com`;
			const ip = rng.ipv4();
			const net = rng.ipv4();
			const prefix = rng.int(0, 32);
			return { baseDomain, sub, spoofed, suffixSpoof, ip, net, prefix };
		},
		({ baseDomain, sub, spoofed, suffixSpoof, ip, net, prefix }) => {
			// (a) Exclusion always dominates inclusion
			const exRes = checkTargetScope(`https://${sub}/x`, [
				{ pattern: baseDomain, kind: "domain", exclude: false },
				{ pattern: sub, kind: "domain", exclude: true },
			]);
			assert.equal(exRes.inScope, false);
			assert.equal(exRes.excludedBy, sub);

			// (b) Exact/wildcard domain never matches spoofed prefix/suffix domains
			const incRules = [{ pattern: baseDomain, kind: "domain" as const, exclude: false }];
			assert.equal(checkTargetScope(`https://${spoofed}/`, incRules).inScope, false);
			assert.equal(checkTargetScope(`https://${suffixSpoof}/`, incRules).inScope, false);
			assert.equal(checkTargetScope(`https://${sub}/`, incRules).inScope, true);

			// (c) CIDR match equals exact 32-bit bitwise arithmetic
			const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
			const expected = (ipToUint32(ip) & mask) === (ipToUint32(net) & mask);
			assert.equal(matchCidr(ip, `${net}/${prefix}`), expected);
		},
	);
});

test("Property P2: AssetDSL parser & matcher are total on arbitrary hostile strings", () => {
	const sampleAsset = {
		id: 1,
		taskId: 1,
		kind: "endpoint" as const,
		value: "https://api.example.com/v1/admin",
		label: "admin-api",
		metadata: {},
		tested: false,
		source: "nuclei",
		inherited: false,
		createdAt: "",
		updatedAt: "",
	};
	assertProperty(
		"AssetDSL totality",
		(rng) => rng.hostileString(0, 60),
		(query) => {
			const clauses = parseAssetDsl(query);
			assert.ok(Array.isArray(clauses));
			const matched = matchesAssetDsl(sampleAsset, clauses);
			assert.equal(typeof matched, "boolean");
		},
	);
});

test("Property P11: Dual-graph upsert is idempotent and inheritance never mutates parent", () => {
	assertProperty(
		"Dual graph upsert idempotency",
		(rng) => {
			const count = rng.int(1, 8);
			const items = Array.from({ length: count }, () => ({
				kind: rng.pick(["domain", "subdomain", "ip", "endpoint"] as const),
				value: rng.domain(),
			}));
			return { items, shuffled: rng.shuffle([...items, ...items]) };
		},
		({ items, shuffled }) => {
			const store = new SqliteTenguStore(":memory:");
			try {
				const parent = store.createTask({ name: "p", target: "example.com" });
				store.upsertAssets(shuffled.map((a) => ({ taskId: parent.id, kind: a.kind, value: a.value, label: a.value, source: "prop" })));
				const uniqueKeys = new Set(items.map((a) => `${a.kind}:${a.value.toLowerCase()}`));
				const parentAssets = store.listAssets({ taskId: parent.id });
				assert.equal(parentAssets.length, uniqueKeys.size);

				store.addExplorationNode({ taskId: parent.id, kind: "fact", state: "done", summary: "parent-fact" });
				const child = store.createTask({ name: "c", target: "example.com", parentTaskId: parent.id });
				store.upsertAssets([{ taskId: child.id, kind: "domain", value: "child-only.example.com", label: "child", source: "prop" }]);
				assert.equal(store.listAssets({ taskId: parent.id }).length, uniqueKeys.size);
				const ov = store.getGraphOverview(child.id);
				assert.ok(ov.recentFacts.some((n) => n.inherited && n.summary === "parent-fact"));
			} finally {
				store.close();
			}
		},
		{ runs: 60 },
	);
});
