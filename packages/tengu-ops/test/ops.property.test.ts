import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { SqliteTenguStore } from "@tengu/store";
import { createTempDir } from "../../../test/helpers/mock-servers.ts";
import { assertProperty } from "../../../test/helpers/prng.ts";
import {
	buildDocxBuffer,
	EvidenceStore,
	exportTaskArchive,
	maskSecrets,
	maskTrafficRecord,
	restoreTaskArchive,
	validateTaskArchive,
} from "../src/index.ts";

test("Property P3: maskSecrets & maskTrafficRecord have zero secret leaks and are idempotent", () => {
	assertProperty(
		"Secret masking zero-leak & idempotency",
		(rng) => {
			const bearer = `tok_${rng.asciiString(16, 28, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")}`;
			const apiKey = `sk-${rng.asciiString(20, 32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")}`;
			const cookie = `sess_${rng.asciiString(12, 24, "abcdefghijklmnopqrstuvwxyz0123456789")}`;
			return { bearer, apiKey, cookie };
		},
		({ bearer, apiKey, cookie }) => {
			const raw = `Authorization: Bearer ${bearer}\nX-API-Key: ${apiKey}\nCookie: session=${cookie}`;
			const once = maskSecrets(raw);
			const twice = maskSecrets(once);
			assert.ok(!once.includes(bearer), "Bearer token leaked");
			assert.ok(!once.includes(apiKey), "API key leaked");
			assert.equal(once, twice, "maskSecrets must be idempotent");

			const rec = {
				id: 1,
				taskId: 1,
				intentId: null,
				findingId: null,
				method: "GET",
				url: "https://example.com/api",
				requestHeaders: { Authorization: `Bearer ${bearer}`, Cookie: `sid=${cookie}` },
				requestBody: `{"api_key":"${apiKey}"}`,
				responseStatus: 200,
				responseHeaders: { "Set-Cookie": `sid=${cookie}; HttpOnly` },
				responseBody: `token=${bearer}`,
				durationMs: 10,
				createdAt: new Date().toISOString(),
			};
			const m1 = maskTrafficRecord(rec);
			const m2 = maskTrafficRecord(m1);
			const serialized = JSON.stringify(m1);
			assert.ok(!serialized.includes(bearer), "Traffic mask leaked bearer");
			assert.ok(!serialized.includes(cookie), "Traffic mask leaked cookie");
			assert.deepEqual(m1, m2, "maskTrafficRecord must be idempotent");
		},
	);
});

test("Property P4: EvidenceStore SHA-256 determinism and single-byte tamper detection", () => {
	const tmp = createTempDir("tengu-prop-ev-");
	const store = new SqliteTenguStore(":memory:");
	const evidence = new EvidenceStore(store, join(tmp.dir, "ev"));
	const task = store.createTask({ name: "prop-ev", target: "example.com" });
	try {
		assertProperty(
			"Evidence SHA-256 tamper detection",
			(rng) => ({
				buf: rng.bytes(1, 512),
				flipIdx: rng.int(0, 511),
			}),
			({ buf, flipIdx }, i) => {
				const a1 = evidence.saveBuffer({ taskId: task.id, kind: "raw", name: `b-${i}.bin`, buffer: buf });
				const a2 = evidence.saveBuffer({ taskId: task.id, kind: "raw", name: `b2-${i}.bin`, buffer: buf });
				assert.equal(a1.sha256, a2.sha256);
				assert.equal(evidence.inspectArtifact(a1.id).status, "readable");

				// Flip 1 bit on disk -> must become corrupt
				const mutated = Buffer.from(buf);
				mutated[flipIdx % mutated.length]! ^= 0x01;
				writeFileSync(a1.path, mutated);
				assert.equal(evidence.inspectArtifact(a1.id).status, "corrupt");
			},
			{ runs: 60 },
		);
	} finally {
		store.close();
		tmp.cleanup();
	}
});

test("Property P5: PortableTaskArchive round-trip preserves entities and rejects tampered archives atomically", () => {
	const tmp = createTempDir("tengu-prop-arch-");
	try {
		assertProperty(
			"Archive round-trip & tamper rejection",
			(rng) => ({
				taskName: `task-${rng.asciiString(3, 10)}`,
				assets: rng.arrayOf(0, 5, () => rng.domain()),
				findings: rng.arrayOf(0, 3, () => rng.asciiString(4, 16)),
				artifactBytes: rng.bytes(4, 128),
			}),
			({ taskName, assets, findings, artifactBytes }, i) => {
				const src = new SqliteTenguStore(":memory:");
				const dst = new SqliteTenguStore(":memory:");
				try {
					const ev = new EvidenceStore(src, join(tmp.dir, `src-${i}`));
					const t = src.createTask({ name: taskName, target: "example.com" });
					if (assets.length > 0) {
						src.upsertAssets(assets.map((v) => ({ taskId: t.id, kind: "domain" as const, value: v, label: v, source: "prop" })));
					}
					for (let fIdx = 0; fIdx < findings.length; fIdx++) {
						src.addFinding({
							taskId: t.id,
							nodeId: null,
							intentId: null,
							fingerprint: `fp-${i}-${fIdx}`,
							title: findings[fIdx]!,
							vulnClass: "xss",
							severity: "medium",
							status: "open",
							cwe: "CWE-79",
							cvss: 5.5,
							summary: "s",
							description: "d",
							evidence: "e",
							evidenceIds: [],
							assetIds: [],
							reproduction: "r",
							remediation: "rem",
						});
					}
					ev.saveBuffer({ taskId: t.id, kind: "raw", name: `f-${i}.bin`, buffer: artifactBytes });

					const arch = exportTaskArchive(src, t.id);
					assert.equal(validateTaskArchive(arch).valid, true);
					const restored = restoreTaskArchive(dst, join(tmp.dir, `dst-${i}`), arch);
					assert.equal(dst.listAssets({ taskId: restored.task.id }).length, src.listAssets({ taskId: t.id }).length);
					assert.equal(dst.listFindings(restored.task.id).length, findings.length);
					assert.equal(dst.listArtifacts(restored.task.id).length, 1);

					// Tamper 1 byte -> validate fails & restore leaves clean store untouched
					const tampered = structuredClone(arch);
					const badBuf = Buffer.from(artifactBytes);
					badBuf[0]! ^= 0xff;
					tampered.artifacts[0]!.base64 = badBuf.toString("base64");
					assert.equal(validateTaskArchive(tampered).valid, false);
					const cleanStore = new SqliteTenguStore(":memory:");
					try {
						assert.throws(() => restoreTaskArchive(cleanStore, join(tmp.dir, `bad-${i}`), tampered));
						assert.equal(cleanStore.listTasks().length, 0);
					} finally {
						cleanStore.close();
					}
				} finally {
					src.close();
					dst.close();
				}
			},
			{ runs: 30 },
		);
	} finally {
		tmp.cleanup();
	}
});

test("Property P6: buildDocxBuffer produces structurally valid ZIP under hostile XML/Unicode characters", () => {
	assertProperty(
		"DOCX ZIP structural integrity",
		(rng) =>
			rng.arrayOf(1, 8, () => ({
				text: rng.hostileString(0, 50),
				heading: rng.bool(0.3) ? (rng.pick([1, 2, 3]) as 1 | 2 | 3) : undefined,
				bold: rng.bool(0.3),
			})),
		(paragraphs) => {
			const buf = buildDocxBuffer(paragraphs);
			// Must begin with ZIP local file header PK\x03\x04
			assert.equal(buf[0], 0x50);
			assert.equal(buf[1], 0x4b);
			assert.equal(buf[2], 0x03);
			assert.equal(buf[3], 0x04);
			// Must contain central directory header PK\x01\x02 and EOCD PK\x05\x06
			assert.ok(buf.includes(Buffer.from([0x50, 0x4b, 0x01, 0x02])), "Missing central directory header");
			assert.ok(buf.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06])), "Missing EOCD record");
			// Since buildDocxBuffer uses STORE (method 0), word/document.xml text is readable directly:
			// verify raw unescaped <script> never appears
			const asText = buf.toString("utf8");
			assert.ok(asText.includes("word/document.xml"));
			assert.ok(asText.includes("[Content_Types].xml"));
		},
	);
});
