import assert from "node:assert/strict";
import test from "node:test";
import { visibleWidth } from "@earendil-works/pi-tui";
import { InterceptEngine } from "@tengu/intercept";
import { SqliteTenguStore } from "@tengu/store";
import { createTempDir } from "../../../test/helpers/mock-servers.ts";
import { assertProperty } from "../../../test/helpers/prng.ts";
import { sliceWindow, TenguCockpitApp, TenguSessionManager } from "../src/index.ts";

test("Property P7: sliceWindow always stays within [0..items.length] and <= visibleRows", () => {
	assertProperty(
		"sliceWindow bounds",
		(rng) => {
			const len = rng.int(0, 200);
			const items = Array.from({ length: len }, (_, i) => i);
			const selectedIndex = rng.int(-20, len + 20);
			const visibleRows = rng.int(1, 60);
			return { items, selectedIndex, visibleRows };
		},
		({ items, selectedIndex, visibleRows }) => {
			const res = sliceWindow(items, selectedIndex, visibleRows);
			assert.ok(res.start >= 0);
			assert.ok(res.end <= items.length);
			assert.ok(res.start <= res.end);
			assert.ok(res.slice.length <= visibleRows);
			assert.equal(res.slice.length, res.end - res.start);
		},
	);
});

test("Property P8: TenguCockpitApp.render(cols) honors exact viewport rows and visibleWidth <= cols", () => {
	const store = new SqliteTenguStore(":memory:");
	const intercept = new InterceptEngine({ store });
	const tmp = createTempDir("tengu-prop-tui-");
	const sessionMgr = new TenguSessionManager(tmp.dir);
	try {
		let currentRows = 30;
		const app = new TenguCockpitApp({
			store,
			intercept,
			sessionManager: sessionMgr,
			requestRender: () => {},
			getRows: () => currentRows,
		});
		assertProperty(
			"TUI viewport bounds",
			(rng) => ({
				cols: rng.int(40, 180),
				rows: rng.int(14, 50),
				sidebar: rng.bool(0.5),
			}),
			({ cols, rows, sidebar }) => {
				currentRows = rows;
				if (sidebar) app.handleGlobalKey("\t");
				const lines = app.render(cols);
				assert.equal(lines.length, rows, `Expected exact ${rows} rows, got ${lines.length} at ${cols}x${rows}`);
				for (let i = 0; i < lines.length; i++) {
					const w = visibleWidth(lines[i]!);
					assert.ok(w <= cols, `Line ${i} overflowed cols=${cols} with visibleWidth=${w}`);
				}
			},
			{ runs: 80 },
		);
	} finally {
		store.close();
		tmp.cleanup();
	}
});

test("Property P10: TenguSessionManager JSONL append/load round-trips arbitrary Unicode & escaped text", () => {
	const tmp = createTempDir("tengu-prop-sess-");
	const mgr = new TenguSessionManager(tmp.dir);
	try {
		assertProperty(
			"JSONL session round-trip",
			(rng) =>
				rng.arrayOf(1, 10, () => ({
					role: rng.pick(["user", "assistant"] as const),
					text: rng.hostileString(0, 80),
				})),
			(turns, i) => {
				const sess = mgr.createSession({ title: `prop-${i}`, taskId: null });
				for (const t of turns) {
					mgr.appendMessage(sess.header.id, { role: t.role, content: t.text });
				}
				const loaded = mgr.loadSession(sess.header.id);
				assert.ok(loaded);
				assert.equal(loaded.messages.length, turns.length);
				for (let j = 0; j < turns.length; j++) {
					assert.equal(loaded.messages[j]!.message.role, turns[j]!.role);
					assert.equal(loaded.messages[j]!.message.content, turns[j]!.text);
				}
			},
			{ runs: 60 },
		);
	} finally {
		tmp.cleanup();
	}
});
