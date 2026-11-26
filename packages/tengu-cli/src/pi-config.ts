import type { JudgeCallback } from "@tengu/intercept";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Api, Model } from "@earendil-works/pi-ai";
import { streamSimple } from "@earendil-works/pi-ai/compat";
import type { StreamFn } from "@earendil-works/pi-agent-core";

export interface ResolvedPiEndpoint {
	provider: string;
	model: Model<Api>;
	apiKey?: string;
	isDefault: boolean;
}

export interface PiModelConfig {
	agentDir: string;
	defaultProvider: string | null;
	defaultModelId: string | null;
	active: ResolvedPiEndpoint | null;
	available: ResolvedPiEndpoint[];
	streamFn: StreamFn;
}

interface RawModelsJson {
	providers?: Record<
		string,
		{
			baseUrl?: string;
			api?: string;
			apiKey?: string;
			headers?: Record<string, string>;
			models?: Array<{
				id: string;
				name?: string;
				api?: string;
				reasoning?: boolean;
				input?: Array<"text" | "image">;
				contextWindow?: number;
				maxTokens?: number;
				cost?: { input?: number; output?: number; cacheRead?: number; cacheWrite?: number };
			}>;
		}
	>;
}

function readJsonSafe<T>(path: string): T | null {
	if (!existsSync(path)) return null;
	try {
		return JSON.parse(readFileSync(path, "utf8")) as T;
	} catch {
		return null;
	}
}

function resolveAuthKey(authJson: Record<string, unknown> | null, provider: string): string | undefined {
	if (!authJson) return undefined;
	const entry = authJson[provider];
	if (typeof entry === "string") return entry;
	if (entry && typeof entry === "object") {
		const rec = entry as Record<string, unknown>;
		if (typeof rec.key === "string") return rec.key;
		if (typeof rec.apiKey === "string") return rec.apiKey;
		if (typeof rec.access === "string") return rec.access;
	}
	return undefined;
}

/**
 * Loads the user's Pi agent configuration (~/.pi/agent/settings.json, models.json, auth.json)
 * so Tengu automatically uses the exact same default provider, model, baseUrl, and API key as `pi`.
 */
export function loadPiModelConfig(options?: {
	agentDir?: string;
	overrideProvider?: string;
	overrideModel?: string;
}): PiModelConfig {
	const agentDir = options?.agentDir || process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent");
	const settings = readJsonSafe<{ defaultProvider?: string; defaultModel?: string }>(join(agentDir, "settings.json"));
	const modelsJson = readJsonSafe<RawModelsJson>(join(agentDir, "models.json"));
	const authJson = readJsonSafe<Record<string, unknown>>(join(agentDir, "auth.json"));

	const defaultProvider = options?.overrideProvider || settings?.defaultProvider || null;
	const defaultModelId = options?.overrideModel || settings?.defaultModel || null;

	const available: ResolvedPiEndpoint[] = [];
	const providers = modelsJson?.providers ?? {};

	for (const [providerName, pCfg] of Object.entries(providers)) {
		const apiKey = pCfg.apiKey || resolveAuthKey(authJson, providerName);
		const baseUrl = pCfg.baseUrl || "";
		const providerApi = (pCfg.api || "openai-completions") as Api;
		for (const m of pCfg.models ?? []) {
			const model: Model<Api> = {
				id: m.id,
				name: m.name || m.id,
				api: (m.api as Api | undefined) || providerApi,
				provider: providerName,
				baseUrl,
				reasoning: Boolean(m.reasoning),
				input: m.input && m.input.length > 0 ? m.input : ["text"],
				cost: {
					input: m.cost?.input ?? 0,
					output: m.cost?.output ?? 0,
					cacheRead: m.cost?.cacheRead ?? 0,
					cacheWrite: m.cost?.cacheWrite ?? 0,
				},
				contextWindow: m.contextWindow ?? 128_000,
				maxTokens: m.maxTokens ?? 16_384,
				...(pCfg.headers ? { headers: pCfg.headers } : {}),
			};
			const isDefault = providerName === defaultProvider && m.id === defaultModelId;
			available.push({ provider: providerName, model, apiKey, isDefault });
		}
	}

	let active = available.find((e) => e.isDefault) ?? null;
	if (!active && defaultProvider && defaultModelId) {
		active = available.find((e) => e.provider === defaultProvider) ?? null;
	}
	if (!active && available.length > 0) {
		active = available[0]!;
	}

	return {
		agentDir,
		defaultProvider,
		defaultModelId,
		active,
		available,
		streamFn: streamSimple as unknown as StreamFn,
	};
}

/**
 * Creates a live Layer-2 LLM safety judge backed by the user's active Pi model.
 * Respects the rule's AbortSignal timeout and fails closed on ambiguous output.
 */
export function createPiLlmJudge(piConfig: PiModelConfig): JudgeCallback {
	return async ({ rule, toolName, serializedArgs, staticSignals, signal }) => {
		const active = piConfig.active;
		if (!active) return { allow: false, reason: "No active Pi model available for safety judge." };

		const prompt = [
			"You are a penetration testing safety judge. Evaluate whether this tool call is safe to execute within an authorized engagement.",
			`Rule triggered: ${rule.name} (${rule.rationale})`,
			`Tool: ${toolName}`,
			`Arguments: ${serializedArgs.slice(0, 2000)}`,
			staticSignals.length > 0 ? `Static risk signals: ${staticSignals.map((s) => s.detail).join("; ")}` : "",
			'Respond ONLY with a JSON object: {"allow": true|false, "reason": "concise explanation"}.',
			"Allow only if clearly scoped/non-destructive or targeting self-created test artifacts; otherwise deny.",
		]
			.filter(Boolean)
			.join("\n");

		const stream = await piConfig.streamFn(
			active.model,
			{
				messages: [
					{
						role: "user",
						content: [{ type: "text", text: prompt }],
						timestamp: Date.now(),
					},
				],
			} as unknown as Parameters<StreamFn>[1],
			{ apiKey: active.apiKey, signal },
		);

		let raw = "";
		for await (const ev of stream) {
			if (ev.type === "text_delta") raw += ev.delta;
			else if (ev.type === "done") {
				const text = ev.message.content
					.filter((c): c is { type: "text"; text: string } => c.type === "text")
					.map((c) => c.text)
					.join("");
				if (text) raw = text;
			}
		}

		const jsonMatch = raw.match(/\{[\s\S]*\}/);
		if (jsonMatch) {
			try {
				const parsed = JSON.parse(jsonMatch[0]) as { allow?: boolean; reason?: string };
				return {
					allow: Boolean(parsed.allow),
					reason: String(parsed.reason ?? (parsed.allow ? "Approved by LLM judge" : "Denied by LLM judge")),
					rawOutput: raw.slice(0, 1000),
				};
			} catch {
				// fall through
			}
		}
		return { allow: false, reason: "LLM judge returned non-JSON verdict; failing closed.", rawOutput: raw.slice(0, 1000) };
	};
}
