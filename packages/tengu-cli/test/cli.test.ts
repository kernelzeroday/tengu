import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { visibleWidth } from "@earendil-works/pi-tui";
import { InterceptEngine } from "@tengu/intercept";
import { SqliteTenguStore } from "@tengu/store";
import { TenguCockpitApp, TenguRpcHandler, type SidebarMode } from "../src/index.ts";

test("TenguRpcHandler handles core JSON-RPC 2.0 workflow", async () => {
	const store = new SqliteTenguStore(":memory:");
	try {
		new InterceptEngine({ store }).seedBuiltinRules();
		const rpc = new TenguRpcHandler(store);

		const ping = await rpc.handle({ jsonrpc: "2.0", id: 1, method: "ping" });
		assert.equal((ping.result as { ok: boolean }).ok, true);

		const created = await rpc.handle({ jsonrpc: "2.0", id: 2, method: "task.create", params: { name: "RPC Audit" } });
		const taskId = (created.result as { id: number }).id;
		assert.ok(taskId > 0);

		await rpc.handle({
			jsonrpc: "2.0",
			id: 3,
			method: "assets.insert",
			params: { taskId, assets: [{ kind: "domain", value: "demo.test" }] },
		});

		const rep = await rpc.handle({
			jsonrpc: "2.0",
			id: 4,
			method: "report.generate",
			params: { taskId, format: "markdown" },
		});
		assert.ok((rep.result as { content: string }).content.includes("RPC Audit"));

		const skills = await rpc.handle({ jsonrpc: "2.0", id: 5, method: "skills.list" });
		assert.equal((skills.result as { skills: unknown[] }).skills.length, 23);
	} finally {
		store.close();
	}
});

test("TenguCockpitApp renders chat-first cockpit and all sidebar modes within viewport bounds", () => {
	const dir = mkdtempSync(join(tmpdir(), "tengu-cockpit-"));
	const store = new SqliteTenguStore(":memory:");
	try {
		const intercept = new InterceptEngine({ store });
		const task = store.createTask({ name: "Cockpit Render Test" });
		store.upsertAssets([{ taskId: task.id, kind: "endpoint", value: "https://api.test/v1/users" }]);
		const app = new TenguCockpitApp({
			store,
			intercept,
			tenguHome: dir,
			initialTaskId: task.id,
			getRows: () => 30,
		});

		const modes: SidebarMode[] = ["live", "graph", "findings"];
		for (const mode of modes) {
			app.sidebarMode = mode;
			const lines = app.render(120);
			assert.equal(lines.length, 30);
			for (const line of lines) {
				assert.ok(visibleWidth(line) <= 120, `Mode ${mode} exceeded width 120: ${visibleWidth(line)}`);
			}
		}

		// Collapsed sidebar (full-width chat)
		app.sidebarOpen = false;
		const fullLines = app.render(100);
		assert.equal(fullLines.length, 30);
		for (const line of fullLines) {
			assert.ok(visibleWidth(line) <= 100);
		}
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
});
